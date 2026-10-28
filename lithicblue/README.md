# LithicBlue - research notes

Reconnaissance and a manual test plan for the LithicBlue Vulnerability Reward
Programme. **No confirmed vulnerabilities.** Everything here is attack-surface
mapping plus hypotheses to test by hand.

Their programme excludes "any vulnerabilities found using automated tooling,
including automated scanners and AI tooling" and requires "original, manual
research". These notes are a structured checklist, used the way you would use
OWASP WSTG - the testing and the findings have to be yours.

## Files

| File | Contents |
|---|---|
| `TEST-PLAN.md` | The main document. 26 sections, newest last; later sections correct earlier ones. |
| `RUNBOOK.md` | Two-organisation setup, then the step-by-step for the `role`/`userTier` mass-assignment test. **Start here.** |
| `server-actions.txt` | 24 named Next.js Server Actions with their per-deployment IDs and the invocation shape. |
| `legacy-routes.txt` | 18-route client manifest recovered from an archived build (pre `engagement`->`project` rename). |
| `scope.lithicblue.json` | Scope file for `recon.py` in the repo root. |
| `email-scope-request.md` | Draft email settling four scope questions. Send before testing storage or delegated cloud access. |

## The target in one paragraph

An AI platform for professional-services firms (M&A, risk advisory, management
consulting, Australian government). Projects hold confidential source documents;
it builds a knowledge base and produces deliverables whose claims trace back to
sources. Next.js on Vercel, tRPC data layer, Better Auth with organisation and
OIDC-provider plugins, PlanetScale for the database, Temporal for workflows,
Fly.io for compute, S3 for storage, Claude for inference, Tavily for the research
agent. Three regional deployments: `na`, `eu`, `au`. 8 hostnames in total,
bounded by certificate transparency.

## The one structural fact that matters

**Authorization is one layer thick.**

- No server-side route gate - every page shell is public (§26.1)
- No database row-level security - PlanetScale is MySQL (§20.1)
- So every tRPC procedure and Server Action is the *only* control

A single missing check is a direct cross-organisation read or write with nothing
behind it. That is where to spend your time, and it is a strong framing sentence
for a report.

## Top of the list

1. `userTier: "paid"` then `role: "admin"` mass assignment - §22.2, `RUNBOOK.md`
2. Server Action authorization sweep over the 24 known actions - §21, §20.2
3. `/articles/edit/[id]` - a live CMS editing the public site, under a CSP with `unsafe-inline` - §24.2
4. `getPresignedUpdateUrl` with a foreign object key - §21.2
5. `/libraries/datagaps/[id]` - the only object route without a project segment - §24.2
6. MCP consent-screen `client_name` spoofing - §23.1
7. Tool poisoning from a source document into the victim's assistant - §23.2

## Already ruled out - do not spend time here

Source maps (disabled), Supabase RLS (migrated off), regional code drift (build
metadata only), `?dpl=` deployment pinning (ignored), `/_next/image` arbitrary-host
SSRF (allowlist enforced), MCP transport variants (uniformly gated), RSC data
disclosure (shells only), Office add-in (no evidence one ships), S3 anonymous
listing (denied), subdomain enumeration (provably complete at 8 hosts). Plus
everything in their published exclusion list - headers, clickjacking, SPF/DMARC,
DoS, brute force, content spoofing, `.well-known` disclosure.

## Corrections made during this work

Logged in §18.3, §20.1, §26.2 and §26.3. Later sections supersede earlier ones;
where a claim was retracted the original is marked rather than deleted.
