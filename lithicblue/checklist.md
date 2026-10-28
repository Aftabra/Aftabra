# Test checklist

Flat index of every test in `TEST-PLAN.md`, for tracking. Mark as you go.
Priority order is in `README.md`; this is for coverage, not sequencing.

Status key: ` ` untested · `~` in progress · `P` pass (no issue) · `F` finding · `X` dropped/N-A

## Setup
```
[ ] Two organisations built per RUNBOOK.md Part 1
[ ] Project 1 (all three members) and Project 2 (owner only)
[ ] Project roles deliberately inverted against org roles
[ ] Baseline get-session captured for all five accounts
[ ] Scope email sent (lithicblue/email-scope-request.md)
[ ] Real route/action list re-extracted from authenticated bundles
```

## Data-layer authorization (the one control - §26.1)
```
[ ] SA1  Server Action direct invocation, no session
[ ] SA2  Server Action authorization as Member, and as Org B
[ ] SA3  Server Action argument tampering (role, userTier)
[ ] SA4  Cross-route action invocation (privileged id POSTed to /login)
[ ] SA5  Capture current action ids per region
[X] SA6  RSC payload disclosure - dropped, shells only (§26.2)
[ ] C1   Object id sweep across orgs (project, file, deliverable, claim, task, scope, gap, contradiction)
[ ] C2   Mismatched id pair: /view/[projectId]/[fileId]
[ ] C3   Session active-organisation binding
[ ] C4   tRPC batch - authorization applied per call
[ ] C5   Cross-region session/token acceptance
[ ] C6   Share token scope, revocation, expiry
[ ] C7   Invitation token: email binding, expiry, reuse, post-removal
[ ] C8   Integration confused deputy (Org B drives Org A's connection)
[ ] C9   Domain-based auto-join
[ ] RT2  /libraries/datagaps/[id] - no project segment in path
[ ] L1   Legacy engagementId parameter alias
[ ] RE1  Legacy routes verbatim
[ ] RE2  Legacy routes with projectId substituted
```

## Privilege escalation
```
[ ] 22.2a userTier: "paid" mass assignment      <- start here
[ ] 22.2b role: "admin" mass assignment
[ ] 22.2c emailVerified / banned
[ ] E1    Escalation -> admin plugin -> list-users oracle
[ ] W1    Invite above your own role level
[ ] W2    Act on a peer Admin
[ ] W3    Ownership transfer as Admin / Member
[ ] W4    Member writing settings (org, research controls, Drive, SharePoint)
[ ] W5    Org role vs project access
[ ] W6    Self-elevation via own user id
[ ] W7    Removal does not revoke (session, share links, MCP tokens)
[ ] W8    Member title field - stored XSS, who can set it
[ ] P1    Project Member editing access
[ ] P2    Project add-member with a cross-org user id
[ ] P3    Removing/demoting the last owner
[ ] P4    Project delete as project Admin
[ ] P5    Org Admin reading a project they are not on
[ ] 26.1  /admin data calls as a Member (shell is public)
[ ] TC1   Tier cookie forgery
[ ] TC2   Tier cookie signing / alg
[ ] TC3   Tier cookie domain scope
[ ] TC4   Server-side gate that reads it
```

## Storage and paths
```
[ ] PS1  Presigned URL with foreign object key
[ ] PS2  getPresignedUpdateUrl - arbitrary object overwrite
[ ] PS3  Signature scope: key vs prefix, method, expiry
[ ] PS4  confirmSourceFileUpload trusting caller metadata
[ ] PS5  Cross-bucket / cross-region signing
[ ] 25.1 ensureFolderPaths prefix escape
```

## OAuth and MCP
```
[ ] O1   Dynamic registration redirect_uri validation
[ ] O2   prompt=none silent authentication
[ ] O3   claims parameter over-disclosure
[ ] O4   Cross-region token and client acceptance
[ ] O5   Logout / removal revoking offline_access refresh tokens
[ ] O6   Scope fidelity on the MCP resource
[ ] LA1  Consent-screen client_name spoofing + escaping
[ ] M1   MCP tool object authorization with foreign ids
[ ] M2   MCP write tools - membership and role
[ ] M3   Paid-tier entitlement enforcement
[ ] M6   Token across regions
[ ] AL1  Social account linking takeover
[X] RT3  MCP transport variants - uniformly gated (§24.2)
```

## Research agent and AI surface
```
[ ] R3   Who can edit organisation research controls
[ ] R5   Personal/organisation merge bypass (out-of-band confirmed)
[ ] R2   Allowlist bypass via redirect / parser confusion
[X] R1   SSRF via research agent - Tavily fetches, out of scope (§20.3)
[ ] LA2  Tool poisoning: document -> MCP output -> victim's assistant
[ ] LA3  Induce a false "verified" verdict
[ ] LA4  Induce a false "contradicted" verdict
[ ] LA5  Win conflict resolution deliberately
[ ] INT4 Knowledge-base poisoning across a trust boundary
```

## Ingestion and integrity
```
[ ] ING1 HTML source -> stored XSS (check every render surface)
[ ] ING2 OOXML XXE / zip traversal; .vsdx
[ ] ING3 Remote content in .eml / HTML -> SSRF on ingestion
[ ] ING4 Malformed images
[ ] ING5 Quick Start scope extraction - second parser
[ ] ING6 Folder names from cloud sync -> path construction
[ ] ING7 Source/deliverable state machine
[ ] INT1 Claim verdict tampering
[ ] INT2 Contradiction override authorization
[ ] INT3 CSV formula injection in claims export
[ ] INT5 Emailed deliverable link authorization
```

## Cloud integrations
```
[ ] DWD1 Drive impersonation subject control
[ ] DWD2 Drive connection record org binding
[ ] DWD3 Who may connect a drive
[ ] DWD4 Google-identity gating enforced server-side
[ ] DWD5 SharePoint / Graph equivalents
[ ] S1   Drive/SharePoint ACL propagation into the knowledge base
[ ] S2   Purview encrypted-label bypass
[ ] S3   Password-protected document password handling
```

## Platform and infrastructure
```
[ ] RC1  lb_region tampering for cross-region data
[ ] RC2  Session cookie Domain scope (incl. transmission to Vanta)
[ ] CP1  lb_region in the CDN cache key
[ ] CP2  Authenticated RSC payload caching
[ ] CP3  Cache deception on authenticated paths
[ ] CP4  Stale cached configuration across deployments
[ ] MW1  Inbound x-matched-path / routing headers
[ ] MW2  Next.js middleware bypass (verify version first)
[ ] TW1  Revocation during an in-flight Temporal workflow
[ ] TW2  Workflow id exposure
[ ] TW3  Result delivery vs current membership
[ ] RT1  /articles/edit/[id] authorization -> first-party content injection
[ ] LA6  Tier transitions (cancel, downgrade mid-workflow, trial lapse)
[ ] LA7  Capacity accounting bypass
[ ] LA8  Entitlement at job start vs job run
[ ] LA11 Region migration (ask; do not trigger against a real tenant)
[ ] LA12 In-region processing flag - who can write it
[ ] LA14 Invitation email header/content injection
[ ] LA15 Email change into a pending invitation
[ ] A1   Email change verification and session invalidation
[ ] A2   Phone field stored XSS
[ ] A3   Password reset token entropy, reuse, session invalidation
[ ] SB7  Is the decommissioned Supabase project still live
```

## Watch items - re-check monthly
```
[ ] LA9  trust.lithicblue.com CNAME to Vanta - takeover if subscription lapses
[ ] LA10 auth.lithicblue.com - certs in CT, no DNS record
[ ] Deployment ids per region (drift)
[ ] New subdomains in CT logs
```

## Ruled out - do not retest
```
[X] Source maps (production build disables them)
[X] Supabase RLS (migrated to PlanetScale)
[X] Regional code drift (build metadata only)
[X] ?dpl= deployment pinning (ignored)
[X] /_next/image arbitrary-host SSRF (allowlist enforced)
[X] RSC data disclosure (shells only)
[X] Office add-in (no evidence one ships - AD0 first)
[X] S3 anonymous listing (403 on all three buckets)
[X] Subdomain enumeration (provably complete: 8 hosts, 112 certs)
[X] Other TLDs (no DNS or certs for .io/.ai/.app/.co/.net/.org/.com.au/.dev/.cloud)
[X] Everything in their published exclusion list
```

## Not done here - yours to do
```
[ ] GitHub OSINT: org and employee repos, commit history, gists
    Search: "lithicblue", "lith-s3-bucket", "pcsyssamsygzgixvvxxc",
            "lithicblue.com", @lithicblue.com addresses, "LithicBlue Pty"
    Look for: configs, .env commits, internal hostnames, action ids,
              Temporal/PlanetScale connection strings, employee side projects
[ ] Vanta trust centre resource documents (SOC 2 report, ISO cert) - request access
```
