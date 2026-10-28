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


def http_get(url, ua=DEFAULT_UA, headers=None, timeout=20, limiter=None,
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


def cmd_probe(args, scope, hosts=None):
    hosts = hosts or read_lines(args.hosts)
    hosts = [h for h in hosts if scope.allows(h)]
    limiter = Limiter(args.rps)

    def one(host):
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return None
        for scheme in ("https", "http"):
            r = http_get(f"{scheme}://{host}/", args.ua, hdrs(args),
                         timeout=args.timeout, limiter=limiter, insecure=args.insecure)
            if r["status"]:
                m = TITLE_RE.search(r["body"] or b"")
                title = (m.group(1).decode("utf-8", "replace").strip()[:120]
                         .replace("\n", " ") if m else "")
                return {"host": host, "ip": ip, "scheme": scheme,
                        "status": r["status"], "final_url": r["url"],
                        "server": r["headers"].get("server", ""),
                        "title": re.sub(r"\s+", " ", title)}
        return {"host": host, "ip": ip, "scheme": None, "status": None,
                "final_url": "", "server": "", "title": ""}

    rows = pool(hosts, one, args.workers)
    alive = [r for r in rows if r["status"]]
    alive.sort(key=lambda r: r["host"])
    write_json(os.path.join(args.out, "probe.json"), alive)
    write_lines(os.path.join(args.out, "alive.txt"),
                [r["final_url"] or f'{r["scheme"]}://{r["host"]}/' for r in alive])
    log(f"probed {len(hosts)} host(s) -> {len(alive)} alive")
    for r in alive[:60]:
        log(f'  {r["status"]} {r["final_url"]:<60} {r["title"][:50]}')
    return [r["final_url"] or f'{r["scheme"]}://{r["host"]}/' for r in alive]


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
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("subs", help="passive subdomain enumeration")
    p.add_argument("domain", nargs="+")

    p = sub.add_parser("probe", help="which hosts are alive")
    p.add_argument("--hosts", default="out/subdomains.txt")

    p = sub.add_parser("crawl", help="walk pages, collect JS urls")
    p.add_argument("--seeds", default="out/alive.txt")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--max-pages", type=int, default=400)

    p = sub.add_parser("js", help="download JS assets")
    p.add_argument("--urls", default="out/js-urls.txt")

    sub.add_parser("maps", help="fetch source maps, rebuild original sources")
    sub.add_parser("endpoints", help="mine downloaded JS/sources")

    p = sub.add_parser("all", help="run the whole chain")
    p.add_argument("domain", nargs="+")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--max-pages", type=int, default=400)

    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    scope = Scope.load(args.scope)
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
