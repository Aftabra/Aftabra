#!/usr/bin/env python3
"""
recon.py - passive-first recon for AUTHORIZED bug bounty / pentest work.

Subcommands
  subs       passive subdomain enumeration (no traffic to the target at all)
  probe      find which hosts are alive          (touches target; scope-gated)
  crawl      walk pages, collect script + links  (touches target; scope-gated)
  js         download JavaScript assets          (touches target; scope-gated)
  maps       fetch source maps, rebuild original sources
  endpoints  mine JS + rebuilt sources for endpoints, params, secrets
  all        subs -> probe -> crawl -> js -> maps -> endpoints

Every request that touches the target is checked against scope.json first.
Hosts not explicitly in scope are skipped and reported at the end.
Standard library only - no pip install needed.
"""

import argparse
import concurrent.futures as cf
import gzip
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

DEFAULT_UA = "recon.py/1.0 (authorized security testing)"
MAX_BYTES = 12 * 1024 * 1024


def log(msg):
    print(f"[*] {msg}", file=sys.stderr, flush=True)


def warn(msg):
    print(f"[!] {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------
class Scope:
    """Allowlist gate. Nothing gets touched unless the program authorizes it.

    "example.com"   -> that exact host
    "*.example.com" -> subdomains of example.com, NOT the apex
                       (list the apex separately if the program includes it)
    out_of_scope always wins.
    """

    def __init__(self, allow, deny):
        self.allow = [p.strip().lower().rstrip(".") for p in allow if p.strip()]
        self.deny = [p.strip().lower().rstrip(".") for p in deny if p.strip()]
        self.skipped = set()

    @classmethod
    def load(cls, path):
        if not os.path.exists(path):
            sys.exit(f"scope file not found: {path}  (copy scope.example.json)")
        with open(path) as fh:
            cfg = json.load(fh)
        allow = cfg.get("in_scope") or []
        if not allow:
            sys.exit("scope: 'in_scope' is empty - nothing authorized, refusing to run")
        return cls(allow, cfg.get("out_of_scope") or [])

    @staticmethod
    def _match(pattern, host):
        if pattern.startswith("*."):
            return host.endswith("." + pattern[2:])
        return host == pattern

    def allows(self, host):
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        if any(self._match(p, host) for p in self.deny):
            self.skipped.add(host)
            return False
        if any(self._match(p, host) for p in self.allow):
            return True
        self.skipped.add(host)
        return False

    def allows_url(self, url):
        return self.allows(urlsplit(url).hostname)

    def report(self):
        if self.skipped:
            warn(f"skipped {len(self.skipped)} out-of-scope host(s): "
                 + ", ".join(sorted(self.skipped)[:15])
                 + (" ..." if len(self.skipped) > 15 else ""))


# --------------------------------------------------------------------------
# rate limiting / http
# --------------------------------------------------------------------------
class Limiter:
    def __init__(self, rps):
        self.interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self.lock = threading.Lock()
        self.next_at = 0.0

    def wait(self):
        if not self.interval:
            return
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_at - now)
            self.next_at = max(now, self.next_at) + self.interval
        if delay:
            time.sleep(delay)


def http_get_urllib(url, ua=DEFAULT_UA, headers=None, timeout=20, limiter=None,
             max_bytes=MAX_BYTES, insecure=False):
    """Returns dict(status, url, headers, body, err). Never raises."""
    if limiter:
        limiter.wait()
    out = {"status": None, "url": url, "headers": {}, "body": b"", "err": None}
    req = urllib.request.Request(url)
    req.add_header("User-Agent", ua)
    req.add_header("Accept-Encoding", "gzip")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except urllib.error.HTTPError as e:
        resp = e
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {e}"
        return out
    try:
        body = resp.read(max_bytes)
        if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        out["status"] = resp.getcode()
        out["url"] = resp.geturl()
        out["headers"] = {k.lower(): v for k, v in resp.headers.items()}
        out["body"] = body
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return out


def http_get_curl(url, ua=DEFAULT_UA, headers=None, timeout=20, limiter=None,
                  max_bytes=MAX_BYTES, insecure=False):
    """curl transport. Required where the session has no local resolver and all
    egress is a CONNECT proxy. Same contract as http_get_urllib."""
    if limiter:
        limiter.wait()
    out = {"status": None, "url": url, "headers": {}, "body": b"", "err": None}
    bf = tempfile.NamedTemporaryFile(delete=False, suffix=".body"); bf.close()
    hf = tempfile.NamedTemporaryFile(delete=False, suffix=".hdr"); hf.close()
    cmd = ["curl", "-sS", "-L", "--max-redirs", "5", "--max-time", str(timeout),
           "--compressed", "-A", ua, "-D", hf.name, "-o", bf.name,
           "-w", "%{http_code} %{url_effective}"]
    if insecure:
        cmd.append("-k")
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 20)
        meta = proc.stdout.decode("utf-8", "replace").strip().split()
        if meta and meta[0].isdigit() and meta[0] != "000":
            out["status"] = int(meta[0])
            if len(meta) > 1:
                out["url"] = meta[1]
        else:
            out["err"] = (proc.stderr.decode("utf-8", "replace").strip()
                          or "curl: no response")[:200]
        with open(bf.name, "rb") as fh:
            out["body"] = fh.read(max_bytes)
        with open(hf.name, "r", errors="replace") as fh:
            for line in fh:
                if ":" in line and not line.startswith(("HTTP/", " ", "\t")):
                    k, v = line.split(":", 1)
                    out["headers"][k.strip().lower()] = v.strip()
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {e}"
    finally:
        for f in (bf.name, hf.name):
            try:
                os.unlink(f)
            except Exception:
                pass
    return out


TRANSPORT = {"mode": "curl"}
SCOPE_REF = {"scope": None}


def http_get(*args, **kwargs):
    if TRANSPORT["mode"] == "curl":
        return http_get_curl(*args, **kwargs)
    return http_get_urllib(*args, **kwargs)



def pool(items, fn, workers=12):
    results = []
    if not items:
        return results
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(fn, items):
            if r is not None:
                results.append(r)
    return results


# --------------------------------------------------------------------------
# passive subdomain sources (these hit public datasets, never the target)
# --------------------------------------------------------------------------
def _names_from_text(text, domain):
    rx = re.compile(r'(?:[A-Za-z0-9_*\-]+\.)+' + re.escape(domain), re.I)
    return {m.group(0).lower().lstrip("*.").rstrip(".") for m in rx.finditer(text)}


def src_crtsh(domain, ua, limiter):
    r = http_get(f"https://crt.sh/?q=%25.{domain}&output=json", ua, timeout=60, limiter=limiter)
    if not r["body"]:
        return set()
    try:
        rows = json.loads(r["body"].decode("utf-8", "replace"))
    except Exception:
        return _names_from_text(r["body"].decode("utf-8", "replace"), domain)
    found = set()
    for row in rows:
        for nm in str(row.get("name_value", "")).splitlines():
            found |= _names_from_text(nm, domain)
    return found


def src_hackertarget(domain, ua, limiter):
    r = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", ua, limiter=limiter)
    return _names_from_text(r["body"].decode("utf-8", "replace"), domain)


def src_anubis(domain, ua, limiter):
    r = http_get(f"https://jldc.me/anubis/subdomains/{domain}", ua, limiter=limiter)
    return _names_from_text(r["body"].decode("utf-8", "replace"), domain)


def src_certspotter(domain, ua, limiter):
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names")
    r = http_get(url, ua, timeout=45, limiter=limiter)
    return _names_from_text(r["body"].decode("utf-8", "replace"), domain)


def src_otx(domain, ua, limiter):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = http_get(url, ua, timeout=45, limiter=limiter)
    return _names_from_text(r["body"].decode("utf-8", "replace"), domain)


def src_rapiddns(domain, ua, limiter):
    r = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1", ua, timeout=45, limiter=limiter)
    return _names_from_text(r["body"].decode("utf-8", "replace"), domain)


def src_wayback(domain, ua, limiter):
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           "&output=text&fl=original&collapse=urlkey&limit=40000")
    r = http_get(url, ua, timeout=90, limiter=limiter)
    return _names_from_text(r["body"].decode("utf-8", "replace"), domain)


PASSIVE_SOURCES = {
    "crtsh": src_crtsh,
    "hackertarget": src_hackertarget,
    "anubis": src_anubis,
    "certspotter": src_certspotter,
    "otx": src_otx,
    "rapiddns": src_rapiddns,
    "wayback": src_wayback,
}


def cmd_subs(args, scope):
    limiter = Limiter(args.rps)
    all_names, per_source = set(), {}
    for domain in args.domain:
        for name, fn in PASSIVE_SOURCES.items():
            try:
                got = {n for n in fn(domain, args.ua, limiter) if n.endswith(domain)}
            except Exception as e:
                warn(f"{name}({domain}) failed: {e}")
                got = set()
            per_source[f"{name}:{domain}"] = len(got)
            log(f"{name:<13} {domain:<28} {len(got)}")
            all_names |= got

    in_scope = sorted(n for n in all_names if scope.allows(n))
    out_of_scope = sorted(all_names - set(in_scope))

    write_lines(os.path.join(args.out, "subdomains.txt"), in_scope)
    write_lines(os.path.join(args.out, "subdomains-out-of-scope.txt"), out_of_scope)
    write_json(os.path.join(args.out, "subs-sources.json"), per_source)
    log(f"{len(all_names)} unique names -> {len(in_scope)} in scope, "
        f"{len(out_of_scope)} out of scope (listed separately, NOT tested)")
    return in_scope


# --------------------------------------------------------------------------
# probe
# --------------------------------------------------------------------------
TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

# CDN / hosting edges. A CNAME here usually still fronts the target's OWN app,
# so these are informational only and still get probed.
CDN_SUFFIXES = (
    ".cloudfront.net", ".akamaiedge.net", ".akamai.net", ".edgekey.net",
    ".edgesuite.net", ".fastly.net", ".fastlylb.net", ".cloudflare.net",
    ".cdn.cloudflare.net", ".azureedge.net", ".trafficmanager.net",
    ".elb.amazonaws.com", ".awsglobalaccelerator.com", ".cdn77.org",
    ".stackpathdns.com", ".impervadns.net", ".incapdns.net",
)

# Third-party SaaS products. A CNAME here means the host IS a third-party
# service, which Lithero's terms section 1 puts outside the program.
SAAS_SUFFIXES = (
    ".herokuapp.com", ".github.io", ".netlify.app", ".vercel.app",
    ".pages.dev", ".workers.dev", ".surge.sh", ".appspot.com",
    ".azurewebsites.net", ".firebaseapp.com", ".web.app",
    ".zendesk.com", ".freshdesk.com", ".desk.com", ".intercom.io",
    ".helpscoutdocs.com", ".helpjuice.com", ".uservoice.com",
    ".statuspage.io", ".status.io", ".betteruptime.com",
    ".hubspot.com", ".hs-sites.com", ".marketo.com", ".mktoweb.com",
    ".pardot.com", ".unbounce.com", ".instapage.com", ".launchrock.com",
    ".squarespace.com", ".wixdns.net", ".wordpress.com", ".webflow.io",
    ".pantheonsite.io", ".acquia-sites.com", ".wpengine.com", ".kinsta.cloud",
    ".myshopify.com", ".shopify.com", ".bigcommerce.com",
    ".salesforce.com", ".force.com", ".atlassian.net", ".jira.com",
    ".bitbucket.io", ".readthedocs.io", ".gitbook.io", ".discourse.group",
    ".sendgrid.net", ".mailgun.org", ".mandrillapp.com", ".createsend.com",
    ".campaignmonitor.com", ".cmail19.com", ".typeform.com", ".tfaforms.net",
    ".canny.io", ".productboard.com", ".frontify.com", ".olark.com",
    ".brightcove.com", ".wistia.com", ".jwplayer.com", ".optimizely.com",
    ".zohohost.com", ".tealiumiq.com",
)


def classify(host):
    """-> (ip, cname_chain, kind) where kind is 'self' | 'cdn' | 'third-party'."""
    try:
        canon, aliases, ips = socket.gethostbyname_ex(host)
    except Exception:
        # No local resolver (proxy-only egress). Cannot read the CNAME chain
        # here, so fall through to HTTP-response fingerprinting instead of
        # declaring the host dead.
        return None, [], "unknown"
    chain = [c.lower().rstrip(".") for c in ([canon] + list(aliases)) if c]
    chain = [c for c in dict.fromkeys(chain) if c != host.lower()]
    blob = " ".join(chain + [canon.lower()])
    for suf in SAAS_SUFFIXES:
        if suf in blob:
            return (ips[0] if ips else None), chain, "third-party"
    for suf in CDN_SUFFIXES:
        if suf in blob:
            return (ips[0] if ips else None), chain, "cdn"
    return (ips[0] if ips else None), chain, "self"


SAAS_BODY_HINTS = (
    (b"zendesk", "zendesk"), (b"statuspage.io", "statuspage"),
    (b"hs-scripts.com", "hubspot"), (b"hubspot", "hubspot"),
    (b"squarespace", "squarespace"), (b"wix.com", "wix"),
    (b"webflow", "webflow"), (b"wp-content", "wordpress"),
    (b"myshopify", "shopify"), (b"intercom", "intercom"),
    (b"marketo", "marketo"), (b"pardot", "pardot"),
    (b"freshdesk", "freshdesk"), (b"typeform", "typeform"),
    (b"atlassian.net", "atlassian"), (b"readthedocs", "readthedocs"),
    (b"gitbook", "gitbook"), (b"unbounce", "unbounce"),
)


def fingerprint_http(row):
    """Label a probed host as third-party from its HTTP response, for use when
    no resolver is available to read the CNAME chain."""
    host_final = (urlsplit(row.get("final_url") or "").hostname or "").lower()
    server = (row.get("server") or "").lower()
    if host_final and not SCOPE_REF["scope"].allows(host_final):
        for suf in SAAS_SUFFIXES:
            if host_final.endswith(suf.lstrip(".")) or suf in host_final:
                return "third-party", f"redirects to {host_final}"
        for suf in CDN_SUFFIXES:
            if suf in host_final:
                return "cdn", f"redirects to {host_final}"
        return "offsite", f"redirects to {host_final}"
    for suf in SAAS_SUFFIXES:
        if suf.lstrip(".").split(".")[0] in server:
            return "third-party", f"server: {server}"
    return row.get("kind", "unknown"), ""


def cmd_probe(args, scope, hosts=None):
    hosts = hosts or read_lines(args.hosts)
    hosts = [h for h in hosts if scope.allows(h)]
    limiter = Limiter(args.rps)

    # DNS-only pass first. Costs the target nothing and tells us which hosts are
    # actually third-party services before we send them a single request.
    log(f"resolving {len(hosts)} host(s) (DNS only, no traffic to target)...")
    resolved = pool(hosts, lambda h: (h,) + classify(h), args.workers)
    live_dns = [r for r in resolved if r[3] != "dead"]
    if all(r[3] == "unknown" for r in live_dns) and live_dns:
        warn("no local resolver - CNAME classification unavailable; "
             "falling back to HTTP response fingerprinting after probe")
    third = [r for r in live_dns if r[3] == "third-party"]
    probe_set = live_dns if args.probe_third_party else [r for r in live_dns
                                                        if r[3] != "third-party"]

    write_lines(os.path.join(args.out, "third-party-subdomains.txt"),
                [f'{h}  ->  {",".join(c) or "?"}' for h, _ip, c, _k in third])
    if third:
        warn(f"{len(third)} host(s) resolve to third-party SaaS - "
             + ("probing anyway (--probe-third-party)" if args.probe_third_party
                else "NOT probed, see third-party-subdomains.txt")
             + " [Lithero terms s1 excludes third-party services]")
        for h, _ip, c, _k in third[:15]:
            warn(f'  {h} -> {",".join(c)}')

    meta = {h: (ip, chain, kind) for h, ip, chain, kind in live_dns}

    def one(host):
        ip, chain, kind = meta[host]
        for scheme in ("https", "http"):
            r = http_get(f"{scheme}://{host}/", args.ua, hdrs(args),
                         timeout=args.timeout, limiter=limiter, insecure=args.insecure)
            if r["status"]:
                m = TITLE_RE.search(r["body"] or b"")
                title = (m.group(1).decode("utf-8", "replace").strip()[:120]
                         .replace("\n", " ") if m else "")
                return {"host": host, "ip": ip, "cname": chain, "kind": kind,
                        "scheme": scheme, "status": r["status"],
                        "final_url": r["url"],
                        "server": r["headers"].get("server", ""),
                        "title": re.sub(r"\s+", " ", title)}
        return {"host": host, "ip": ip, "cname": chain, "kind": kind,
                "scheme": None, "status": None, "final_url": "",
                "server": "", "title": ""}

    rows = pool([h for h, _i, _c, _k in probe_set], one, args.workers)
    alive = sorted([r for r in rows if r["status"]], key=lambda r: r["host"])
    for r in alive:
        kind, why = fingerprint_http(r)
        r["kind"], r["kind_reason"] = kind, why
    late = [r for r in alive if r["kind"] == "third-party"]
    if late:
        warn(f"{len(late)} probed host(s) fingerprint as third-party SaaS "
             "(Lithero terms s1) - do not test these:")
        for r in late:
            warn(f'  {r["host"]} ({r["kind_reason"]})')
        with open(os.path.join(args.out, "third-party-subdomains.txt"), "a") as fh:
            for r in late:
                fh.write(f'{r["host"]}  ->  {r["kind_reason"]}\n')
    write_json(os.path.join(args.out, "probe.json"), alive)
    urls = [r["final_url"] or f'{r["scheme"]}://{r["host"]}/' for r in alive]
    write_lines(os.path.join(args.out, "alive.txt"), urls)
    log(f"{len(hosts)} in-scope name(s) -> {len(live_dns)} resolve -> "
        f"{len(probe_set)} probed -> {len(alive)} alive")
    for r in alive[:60]:
        tag = "" if r["kind"] == "self" else f' [{r["kind"]}]'
        arrow = "" if r["final_url"].rstrip("/").endswith(r["host"]) else f' -> {r["final_url"]}'
        log(f'  {r["status"]} {r["host"]:<30}{arrow}{tag} {r["title"][:40]}')
    return urls


# --------------------------------------------------------------------------
# crawl
# --------------------------------------------------------------------------
SCRIPT_RE = re.compile(rb'<script[^>]*?\ssrc\s*=\s*["\']?([^"\'\s>]+)', re.I)
HREF_RE = re.compile(rb'(?:href|src)\s*=\s*["\']([^"\'>\s]+)', re.I)
JSCHUNK_RE = re.compile(rb'["\']([A-Za-z0-9_\-./]+\.(?:js|mjs|cjs))(?:\?[^"\']*)?["\']')
ASSET_SKIP = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css",
              ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".webm")


def cmd_crawl(args, scope, seeds=None):
    seeds = seeds or read_lines(args.seeds)
    seeds = [s if "://" in s else "https://" + s for s in seeds]
    seeds = [s for s in seeds if scope.allows_url(s)]
    limiter = Limiter(args.rps)

    seen_pages, js_urls, queue = set(), set(), [(s, 0) for s in seeds]
    while queue:
        url, depth = queue.pop(0)
        if url in seen_pages or depth > args.depth or len(seen_pages) >= args.max_pages:
            continue
        seen_pages.add(url)
        r = http_get(url, args.ua, hdrs(args), timeout=args.timeout,
                     limiter=limiter, insecure=args.insecure)
        if not r["status"] or not r["body"]:
            continue
        body = r["body"]
        base = r["url"]

        for rx in (SCRIPT_RE, JSCHUNK_RE):
            for m in rx.finditer(body):
                cand = urljoin(base, m.group(1).decode("utf-8", "replace"))
                if scope.allows_url(cand):
                    js_urls.add(cand.split("#")[0])

        if depth < args.depth:
            for m in HREF_RE.finditer(body):
                link = urljoin(base, m.group(1).decode("utf-8", "replace")).split("#")[0]
                if not scope.allows_url(link):
                    continue
                if link.lower().endswith(ASSET_SKIP) or link.lower().endswith((".js", ".mjs")):
                    continue
                if link not in seen_pages:
                    queue.append((link, depth + 1))

    js_urls = sorted(js_urls)
    write_lines(os.path.join(args.out, "pages.txt"), sorted(seen_pages))
    write_lines(os.path.join(args.out, "js-urls.txt"), js_urls)
    log(f"crawled {len(seen_pages)} page(s) -> {len(js_urls)} JS url(s)")
    return js_urls


# --------------------------------------------------------------------------
# js download
# --------------------------------------------------------------------------
def local_path(base_dir, url):
    u = urlsplit(url)
    parts = [p for p in u.path.split("/") if p not in ("", ".", "..")]
    if not parts or "." not in parts[-1]:
        parts.append("index.js")
    return os.path.join(base_dir, u.hostname or "unknown", *parts)


def cmd_js(args, scope, js_urls=None):
    js_urls = js_urls or read_lines(args.urls)
    js_urls = [u for u in js_urls if scope.allows_url(u)]
    limiter = Limiter(args.rps)
    js_dir = os.path.join(args.out, "js")

    def one(url):
        r = http_get(url, args.ua, hdrs(args), timeout=args.timeout,
                     limiter=limiter, insecure=args.insecure)
        if r["status"] != 200 or not r["body"]:
            return None
        dest = local_path(js_dir, url)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(r["body"])
        return {"url": url, "path": dest, "bytes": len(r["body"])}

    rows = pool(js_urls, one, args.workers)
    write_json(os.path.join(args.out, "js-downloaded.json"), rows)
    log(f"downloaded {len(rows)}/{len(js_urls)} JS file(s) -> {js_dir}")
    return rows


# --------------------------------------------------------------------------
# source maps
# --------------------------------------------------------------------------
SOURCEMAP_RE = re.compile(rb"[#@]\s*sourceMappingURL\s*=\s*([^\s*'\"]+)")


def safe_rel(src):
    s = str(src)
    for prefix in ("webpack://", "webpack:///", "file://", "rollup://", "vite://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    s = s.replace("\\", "/").split("?")[0]
    parts = [p for p in s.split("/") if p not in ("", ".", "..")]
    if not parts:
        parts = ["unnamed.txt"]
    return os.path.join(*parts)


def cmd_maps(args, scope, js_rows=None):
    js_rows = js_rows or load_json(os.path.join(args.out, "js-downloaded.json")) or []
    limiter = Limiter(args.rps)
    src_dir = os.path.join(args.out, "sources")
    found, rebuilt = [], 0

    def candidates(row):
        cands = []
        try:
            with open(row["path"], "rb") as fh:
                fh.seek(max(0, os.path.getsize(row["path"]) - 4096))
                tail = fh.read()
        except Exception:
            tail = b""
        m = SOURCEMAP_RE.search(tail)
        if m:
            ref = m.group(1).decode("utf-8", "replace")
            if not ref.startswith("data:"):
                cands.append(urljoin(row["url"], ref))
        cands.append(row["url"] + ".map")          # the common guess
        return [c for c in dict.fromkeys(cands) if scope.allows_url(c)]

    for row in js_rows:
        for map_url in candidates(row):
            r = http_get(map_url, args.ua, hdrs(args), timeout=args.timeout,
                         limiter=limiter, insecure=args.insecure)
            if r["status"] != 200 or not r["body"]:
                continue
            try:
                sm = json.loads(r["body"].decode("utf-8", "replace"))
            except Exception:
                continue
            sources = sm.get("sources") or []
            contents = sm.get("sourcesContent") or []
            if not contents:
                found.append({"map": map_url, "sources": len(sources), "contents": 0})
                log(f"map (no sourcesContent): {map_url}  [{len(sources)} source names]")
                break
            n = 0
            for i, src in enumerate(sources):
                if i >= len(contents) or contents[i] is None:
                    continue
                dest = os.path.join(src_dir, urlsplit(map_url).hostname or "unknown",
                                    safe_rel(src))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "w", encoding="utf-8") as fh:
                    fh.write(contents[i])
                n += 1
            rebuilt += n
            found.append({"map": map_url, "sources": len(sources), "contents": n})
            log(f"REBUILT {n} original file(s) from {map_url}")
            break

    write_json(os.path.join(args.out, "sourcemaps.json"), found)
    log(f"{len(found)} source map(s); {rebuilt} original file(s) written -> {src_dir}")
    return found


# --------------------------------------------------------------------------
# endpoint + secret mining
# --------------------------------------------------------------------------
RE_FULLURL = re.compile(r'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]{4,}')
RE_PATH = re.compile(r'''["'`](/[A-Za-z0-9_\-./~%${}:]{1,180})["'`]''')
RE_CALL = re.compile(
    r'''(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|'''
    r'''\$\.(?:get|post|ajax)|request|openapi|url)\s*\(\s*["'`]([^"'`]{2,200})["'`]''')
RE_GQL = re.compile(r'\b(?:query|mutation|subscription)\s+([A-Za-z_]\w{2,60})\s*[({]')
RE_PARAM = re.compile(r'[?&]([A-Za-z_][A-Za-z0-9_\-]{1,40})=')

SECRET_PATTERNS = {
    "aws_access_key":  r'\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b',
    "google_api_key":  r'\bAIza[0-9A-Za-z_\-]{35}\b',
    "slack_token":     r'\bxox[baprs]-[0-9A-Za-z-]{10,}\b',
    "stripe_key":      r'\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b',
    "github_token":    r'\bgh[pousr]_[0-9A-Za-z]{30,}\b',
    "jwt":             r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b',
    "private_key":     r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----',
    "firebase_url":    r'https://[a-z0-9-]+\.firebaseio\.com',
    "bearer_literal":  r'[Bb]earer\s+[A-Za-z0-9_\-.=]{24,}',
    "basic_auth_url":  r'https?://[^/\s:@"\']+:[^/\s:@"\']+@',
    "generic_secret":  r'''["'](?:api[_-]?key|apikey|secret|token|passwd|password|private[_-]?key)'''
                       r'''["']\s*[:=]\s*["']([^"']{8,80})["']''',
}
SECRET_RX = {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}

PATH_NOISE = re.compile(
    r'(\.(png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|map|mp4|webm|avif)$)'
    r'|^/+$|\s|^/[A-Za-z0-9+/]{40,}={0,2}$', re.I)


def interesting_path(p):
    if len(p) < 3 or PATH_NOISE.search(p):
        return False
    if p.count("/") == 1 and len(p) < 5:
        return False
    return True


def iter_files(*dirs):
    for d in dirs:
        for root, _, files in os.walk(d):
            for f in files:
                yield os.path.join(root, f)


def cmd_endpoints(args, scope):
    js_dir = os.path.join(args.out, "js")
    src_dir = os.path.join(args.out, "sources")
    paths, urls, calls, gql, params = set(), set(), set(), set(), set()
    secrets = []
    n_files = 0

    for fp in iter_files(js_dir, src_dir):
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except Exception:
            continue
        n_files += 1
        for m in RE_PATH.finditer(text):
            if interesting_path(m.group(1)):
                paths.add(m.group(1))
        for m in RE_FULLURL.finditer(text):
            urls.add(m.group(0).rstrip('\\",\');'))
        for m in RE_CALL.finditer(text):
            calls.add(m.group(1))
        for m in RE_GQL.finditer(text):
            gql.add(m.group(1))
        for m in RE_PARAM.finditer(text):
            params.add(m.group(1))
        for kind, rx in SECRET_RX.items():
            for m in rx.finditer(text):
                secrets.append({"kind": kind, "file": fp,
                                "match": (m.group(0)[:160])})

    api_like = sorted(p for p in paths
                      if re.search(r'/(api|v\d|graphql|gql|rest|rpc|internal|admin|auth|'
                                   r'oauth|token|user|users|account|me|session|upload|'
                                   r'export|download|webhook|callback)(/|$|\?)', p, re.I))
    third_party = sorted({urlsplit(u).hostname for u in urls
                          if urlsplit(u).hostname and not scope.allows(urlsplit(u).hostname)})

    write_lines(os.path.join(args.out, "paths-all.txt"), sorted(paths))
    write_lines(os.path.join(args.out, "paths-api.txt"), api_like)
    write_lines(os.path.join(args.out, "urls.txt"), sorted(urls))
    write_lines(os.path.join(args.out, "http-calls.txt"), sorted(calls))
    write_lines(os.path.join(args.out, "graphql-ops.txt"), sorted(gql))
    write_lines(os.path.join(args.out, "params.txt"), sorted(params))
    write_lines(os.path.join(args.out, "third-party-hosts.txt"), third_party)
    write_json(os.path.join(args.out, "secrets.json"), secrets)

    log(f"mined {n_files} file(s)")
    log(f"  paths           {len(paths):>6}  -> paths-all.txt")
    log(f"  api-ish paths   {len(api_like):>6}  -> paths-api.txt   <-- start here")
    log(f"  absolute urls   {len(urls):>6}  -> urls.txt")
    log(f"  http call sites {len(calls):>6}  -> http-calls.txt")
    log(f"  graphql ops     {len(gql):>6}  -> graphql-ops.txt")
    log(f"  query params    {len(params):>6}  -> params.txt")
    log(f"  3rd-party hosts {len(third_party):>6}  -> third-party-hosts.txt")
    log(f"  secret hits     {len(secrets):>6}  -> secrets.json (verify by hand, mostly noise)")


# --------------------------------------------------------------------------
# helpers / cli
# --------------------------------------------------------------------------
def hdrs(args):
    out = {}
    for h in (args.header or []):
        if ":" in h:
            k, v = h.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def write_lines(path, lines):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))


def write_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)


def load_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


def read_lines(path):
    if not path:
        return []
    if path == "-":
        return [l.strip() for l in sys.stdin if l.strip()]
    with open(path) as fh:
        return [l.strip() for l in fh if l.strip() and not l.startswith("#")]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", default="scope.json", help="scope file (default scope.json)")
    ap.add_argument("--out", default="out", help="output directory (default out/)")
    ap.add_argument("--ua", default=DEFAULT_UA, help="User-Agent (set your bounty handle)")
    ap.add_argument("--header", action="append", help="extra header 'K: V' (repeatable)")
    ap.add_argument("--rps", type=float, default=5.0, help="max requests/sec (default 5)")
    ap.add_argument("--workers", type=int, default=10, help="concurrency (default 10)")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--probe-third-party", action="store_true",
                    help="also probe hosts that CNAME to third-party SaaS "
                         "(Lithero terms s1 excludes third-party services)")
    ap.add_argument("--transport", choices=("curl", "urllib"), default="curl",
                    help="HTTP backend; curl is required where the session has "
                         "no resolver and egress is a CONNECT proxy")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("subs", help="passive subdomain enumeration")
    p.add_argument("domain", nargs="+")

    p = sub.add_parser("probe", help="which hosts are alive")
    p.add_argument("--hosts", default=None,
                   help="default: <out>/subdomains.txt")

    p = sub.add_parser("crawl", help="walk pages, collect JS urls")
    p.add_argument("--seeds", default=None,
                   help="default: <out>/alive.txt")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--max-pages", type=int, default=400)

    p = sub.add_parser("js", help="download JS assets")
    p.add_argument("--urls", default=None,
                   help="default: <out>/js-urls.txt")

    sub.add_parser("maps", help="fetch source maps, rebuild original sources")
    sub.add_parser("endpoints", help="mine downloaded JS/sources")

    p = sub.add_parser("all", help="run the whole chain")
    p.add_argument("domain", nargs="+")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--max-pages", type=int, default=400)

    args = ap.parse_args()
    TRANSPORT["mode"] = args.transport
    os.makedirs(args.out, exist_ok=True)
    for attr, name in (("hosts", "subdomains.txt"), ("seeds", "alive.txt"),
                       ("urls", "js-urls.txt")):
        if getattr(args, attr, "sentinel") is None:
            setattr(args, attr, os.path.join(args.out, name))
    scope = Scope.load(args.scope)
    SCOPE_REF["scope"] = scope
    log(f"scope: in={scope.allow} out={scope.deny or '[]'}  rps={args.rps}")

    if args.cmd == "subs":
        cmd_subs(args, scope)
    elif args.cmd == "probe":
        cmd_probe(args, scope)
    elif args.cmd == "crawl":
        cmd_crawl(args, scope)
    elif args.cmd == "js":
        cmd_js(args, scope)
    elif args.cmd == "maps":
        cmd_maps(args, scope)
    elif args.cmd == "endpoints":
        cmd_endpoints(args, scope)
    elif args.cmd == "all":
        args.hosts = args.urls = args.seeds = None
        subs = cmd_subs(args, scope)
        alive = cmd_probe(args, scope, hosts=subs)
        js_urls = cmd_crawl(args, scope, seeds=alive)
        js_rows = cmd_js(args, scope, js_urls=js_urls)
        cmd_maps(args, scope, js_rows=js_rows)
        cmd_endpoints(args, scope)

    scope.report()


if __name__ == "__main__":
    main()
