# recon.py

Passive-first recon for **authorized** bug bounty / pentest work: passive subdomain
enumeration, live-host probing, JS discovery, **source map extraction** (rebuilds the
original pre-bundled source tree), and endpoint / param / secret mining.

Python 3.8+, standard library only. No `pip install`.

## Why source maps matter

If the target ships `.map` files, `sourcemaps` gives you the **original, unminified
source** — real function names, commented-out code, dev-only branches, route tables,
permission checks. That's where non-duplicate bugs live, because most hunters never
look past the minified bundle.

## Setup

```bash
cp scope.example.json scope.json
$EDITOR scope.json          # fill in from the program's scope page
```

Nothing is contacted unless `in_scope` matches it. Subdomain enumeration is fully
passive (public CT logs and DNS datasets) and sends **zero** traffic to the target;
everything after that is gated on scope and rate-limited.

## Run

Whole chain:

```bash
./recon.py --scope scope.json --rps 3 --ua "yourhandle (bugbounty)" all example.com
```

Or step by step, so you can eyeball each stage:

```bash
./recon.py subs example.com
```

```bash
./recon.py probe
```

```bash
./recon.py crawl --depth 2
```

```bash
./recon.py js
```

```bash
./recon.py maps
```

```bash
./recon.py endpoints
```

## Output

```
out/
  subdomains.txt                in-scope names found
  subdomains-out-of-scope.txt   found but NOT touched - check if program covers them
  probe.json / alive.txt        live hosts with status, title, server
  pages.txt / js-urls.txt       crawl results
  js/<host>/...                 downloaded bundles
  sources/<host>/...            ORIGINAL source rebuilt from .map files
  sourcemaps.json               which maps were found
  paths-api.txt                 api/graphql/admin/auth paths  <- start here
  paths-all.txt                 every path literal
  urls.txt / third-party-hosts.txt
  http-calls.txt                fetch/axios call sites
  graphql-ops.txt               GraphQL operation names
  params.txt                    query param names
  secrets.json                  credential-pattern hits (mostly noise - verify by hand)
```

## Flags worth setting

| Flag | Why |
|---|---|
| `--rps 3` | stay under the program's rate limit; be polite |
| `--ua "handle (bugbounty)"` | many programs require an identifying UA |
| `--header 'X-Bug-Bounty: handle'` | some require a marker header — check the policy |
| `--workers 5` | lower concurrency on fragile targets |
| `--depth 3 --max-pages 1000` | deeper crawl on big SPAs |

## Working the output

1. `sources/` first if any maps landed — read the route table and the auth middleware.
2. `paths-api.txt` — anything with `internal`, `admin`, `debug`, `export`, `impersonate`.
3. `graphql-ops.txt` — mutations the UI never calls are often unguarded.
4. Diff `js-urls.txt` + bundle hashes across days; new chunks = new code = fewest eyes.
5. `third-party-hosts.txt` — analytics/support SaaS, sometimes its own scope.

## Scope discipline

Enumeration finds hosts the program does not cover. Those go to
`subdomains-out-of-scope.txt` and are never contacted. Before promoting any of them,
confirm against the program policy — testing out of scope is how people get removed.
