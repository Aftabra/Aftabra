# LithicBlue - manual test plan

Built from their published policy, their documentation, and routes recovered from
the public marketing bundle. **Nothing here is a verified finding.** Every item is
a hypothesis for you to test by hand.

> Their policy excludes "vulnerabilities found using automated tooling, including
> automated scanners and AI tooling. Findings must be the result of original,
> manual research." Use this as a structured checklist, the way you'd use OWASP
> WSTG. Test each item yourself, in Burp, and only report what you personally
> reproduced and can explain mechanically.

## 1. What the product is

An AI platform for professional-services firms (M&A due diligence, risk advisory,
management consulting, Australian government). A **project** holds source
documents (board packs, interview notes, financials), from which it builds a
**knowledge base** structured by an **ontological map**, then produces
**deliverables** (PPTX/PDF/Word) whose **claims** are traced back to source
passages.

Customer data = confidential deal and advisory material. Confidentiality impact
is inherently high, which is what their reward scale keys on.

## 2. Stack (inferred, verify as you go)

| Layer | Evidence |
|---|---|
| Next.js on Vercel, Turbopack | `/_next/static/`, `dpl_` deployment IDs |
| tRPC API | `/api/trpc` |
| Better Auth + organization plugin | `/get-session`, `/update-session`, `/revoke-other-sessions`, `/revoke-session`, `/forgot-password`; Owner/Admin/Member roles + invitations match the plugin exactly |
| Regional deployments | `na.` / `eu.` / `au.`, each serving its own build |
| MCP connector | documented at `/api/mcp/mcp`, OAuth with auto client registration |
| Cloudflare | all hosts |
| PostHog, Sentry | analytics / error reporting |

Why Better Auth matters: its org plugin exposes procedures like `inviteMember`,
`updateMemberRole`, `setActive`, `transferOwnership`, and keeps
`activeOrganizationId` **in the session**. Most cross-org bugs in apps built this
way come from a procedure trusting a client-supplied org or project ID instead of
the session's.

Why tRPC matters: procedures are individually authorized by middleware. A router
can be protected while an individual procedure forgets its object-level check.
tRPC also supports **batching** (`?batch=1`), so one request can carry several
calls - worth testing whether authorization is applied per call in a batch.

## 3. Routes recovered (public bundle)

```
/signup  /login  /forgot-password  /account  /admin
/api/auth  /api/trpc
/get-session  /update-session  /revoke-session  /revoke-sessions  /revoke-other-sessions
/invite/:token      /share/:token
/projects  /project/:projectId
/files/:projectId   /view/:projectId/:fileId   /kag/:projectId   /tasks/:projectId
/settings/organization  /settings/googleDrive  /settings/sharepoint
/addin/auth/done
```

`/signup` exists, so you can self-provision. The MCP connector needs a **paid
plan**, so that surface may require a subscription or a vendor-granted entitlement.

## 4. Setup before testing anything

Create, under your own control:

- **Org A** - you as Owner. Second account as Admin. Third as Member.
- **Org B** - entirely separate, different email domain, ideally a different region.
- Inside Org A: **Project 1** (all three members) and **Project 2** (Owner only),
  so you can separate *org* membership from *project* membership.

Never point any of this at a real customer's organisation. Their policy is
explicit: "Never attempt to access anyone else's data." If you do stumble into
real data, stop, report it immediately, and retain nothing.

## 5. Invariants the vendor states - attack these first

A vendor's own written security claims are the best test targets, because a broken
one is unarguable in a report.

| # | Their claim | Source |
|---|---|---|
| I1 | "Admins can invite Members only" / "Owner isn't an invite option" | docs/organization/members |
| I2 | "Admins ... can't change or remove other admins" | same |
| I3 | "can't transfer ownership. Those are owner-only" | same |
| I4 | Member: "View the organization and its resources. No settings or member management" | same |
| I5 | "Access to a given project is set separately" from org role | same |
| I6 | MCP: "the assistant only ever sees projects you are a member of" | docs/mcp |
| I7 | MCP: "requires a paid-tier entitlement" | docs/mcp |
| I8 | Region "can't be set per user, per team or per project" | docs/hosting/changing-region |
| I9 | Research: "organization controls over which sites it may use" | docs overview |
| I10 | Data residency: data stays within the org's region | docs/hosting/data-residency |

## 6. Cross-organisation access - their highest reward tier

Policy: "permit an unaffiliated attacker to gain access to information or
resources in an arbitrary organization" = high severity.

Method: authenticate as Org B's user. Replay Org A's requests with Org A's IDs.
Every endpoint must 403/404, not return data.

- **C1 - Object ID sweep.** From Org A, collect every ID you see: project,
  file, deliverable, claim, task, source, scope section, data gap, contradiction,
  invitation, share token. As Org B, request each. Cover `/project/:id`,
  `/files/:id`, `/view/:projectId/:fileId`, `/kag/:id`, `/tasks/:id`.
- **C2 - The ID pair.** `/view/:projectId/:fileId` takes two IDs. Test a file
  from Org A's project against a project ID you *do* own. If the handler
  authorizes the project but loads the file by ID alone, the file crosses.
  Mismatched-ID-pair bugs are common and often missed.
- **C3 - Session org binding.** Find where the active organisation is set
  (Better Auth `setActive`). Try setting it to Org A's ID while authenticated as
  Org B. Then try any procedure that takes an explicit `organizationId`.
- **C4 - tRPC batching.** Send a batch where the first call is legitimately
  yours and a later one references Org A. Confirm authorization applies to every
  call, not just the first.
- **C5 - Cross-region.** Tokens and sessions are issued per regional host. Take
  a session or MCP token from `eu.` and use it against `na.` and `au.`. Check
  issuer/audience validation. This also tests I8 and I10, and very few people
  look here.
- **C6 - Share tokens.** `/share/:token`: measure entropy, test whether a token
  grants only the intended object or a whole project, whether revocation takes
  effect immediately, and whether an expired or cancelled token still resolves.
- **C7 - Invitations.** `/invite/:token`: can an invite addressed to
  alice@x.com be accepted by an unrelated account? Is expiry enforced
  server-side? Is a cancelled invitation truly dead? Can a token be reused to
  rejoin after removal? Can you guess or enumerate tokens?
- **C8 - Integration confused deputy.** Org A connects Google Drive /
  SharePoint. Can an Org B user trigger a fetch that uses Org A's stored OAuth
  token, by supplying a connection or file ID? Stored third-party credentials
  driven by a client-supplied ID is a classic.
- **C9 - Domain-based auto-join.** Some products auto-add signups whose email
  domain matches an existing org. If that's implemented and a public mail
  provider isn't excluded, you join a stranger's organisation. Test with a
  matching domain.

## 7. Within-organisation escalation

Policy: "member-to-admin escalation, access to restricted resources, or
circumvention of permission controls."

- **W1 - Invite above your level (I1).** As Admin, call the invite procedure with
  `role: "admin"` (and `"owner"`). The UI hides the option; the question is
  whether the server rejects it. Then as **Member**, call it at all. This is the
  highest-probability item on this list - mass assignment on a role field.
- **W2 - Act on a peer Admin (I2).** As Admin, call role-change and remove
  against another Admin directly.
- **W3 - Ownership transfer (I3).** As Admin, then as Member, call the
  make-owner / transfer-ownership procedure.
- **W4 - Member touching settings (I4).** As Member, call every settings
  mutation: org details, research controls, Google Drive and SharePoint settings,
  member list. The UI won't show them; call them anyway.
- **W5 - Org role vs project access (I5).** As an org Member *not* on Project 2,
  try to read it. Then check whether org Admin silently grants access to every
  project - if so, confirm against the docs whether that's intended, because an
  undocumented implicit grant is itself worth asking about.
- **W6 - Self-elevation.** Call role-change with your own user ID and a higher
  role. Check both the dedicated procedure and any generic profile/member update.
- **W7 - Removal doesn't revoke.** Get removed from an org or project while
  holding a live session. Does the session keep working? Do existing share links,
  MCP tokens and integration access survive? Stale authorization after removal is
  a real finding.
- **W8 - Title field.** Owners set member titles. Check the field for stored
  XSS and for whether a Member can set their own or others' titles.

## 8. MCP connector - the most distinctive surface

Endpoint: `https://<region>.lithicblue.com/api/mcp/mcp`. OAuth, with the host
auto-registering itself.

- **M1 - Tool-level object authorization (I6).** "The assistant only ever sees
  projects you are a member of" is a precise, testable claim. Call every tool
  with a project/deliverable/claim/task ID belonging to an org you are not in.
  Tool handlers are often written assuming the ID came from a previous list call.
  A single tool that resolves a foreign ID is **cross-org access = top tier**.
- **M2 - Write tools.** `write_claims`, `add_feedback_comment`, `request_feedback`,
  and the task tools mutate state. Check each enforces project membership *and*
  role - not just a valid token.
- **M3 - Entitlement enforcement (I7).** On a free account, connect and call a
  paid tool. If the entitlement is checked only at connect time, or only in the
  UI, that's circumvention of a permission control.
- **M4 - OAuth client registration.** Auto-registration is the weak point:
  whether `redirect_uri` is validated at registration and at authorization,
  whether PKCE is required, whether `state` is verified, whether an attacker-
  registered client can obtain a victim's code. Test against your own accounts
  only.
- **M5 - Token scope fidelity.** Does the issued token actually match what the
  Approve screen said, or is it a full-account token? Does a Member's token
  respect Member limits?
- **M6 - Token across regions.** See C5. Try an `eu.`-issued token at `na.`.
- **M7 - Prompt injection boundary.** A source document is attacker-controlled
  content that the AI reads. The question that matters is whether injected text
  can make the system cross a *security* boundary - reach another project or org,
  or exfiltrate via the research fetcher. Injection that only affects your own
  project's output is low impact; a boundary crossing is not.

## 9. Research controls / SSRF

The AI researches the web, with an org-level allowlist of permitted sites (I9).

- **R1 - SSRF.** Can the fetcher be pointed at internal addresses - cloud
  metadata (169.254.169.254), localhost, RFC1918? Vercel-hosted, so also consider
  internal service URLs. Note their exclusions bar DoS, not SSRF.
- **R2 - Allowlist bypass.** Open redirect on an allowed host, DNS rebinding,
  URL-parser confusion (`@`, `#`, encoded hosts, trailing dots), scheme
  switching. Circumventing an org permission control is in their threat model.
- **R3 - Who can edit the allowlist.** As Member, then Admin, change research
  controls. Cross-reference I4.
- **R4 - Blind exfiltration.** If injected document text can make the fetcher
  request an attacker-controlled URL carrying project content, that is a
  confidentiality breach with a clean PoC.

## 10. Document and deliverable pipeline

Uploads are parsed (PDF, Word, PPTX, Excel); deliverables are generated.

- **D1** Parser handling of malformed/crafted files - XXE in OOXML, zip path
  traversal in the PPTX/DOCX container, oversized or recursive structures. Keep
  it to correctness, not resource exhaustion, since DoS is excluded.
- **D2** Does generation fetch remote resources (images, templates, fonts)?
  Another SSRF path.
- **D3** Where filenames, titles and claim text are rendered - stored XSS.
  Check the generated PPTX/PDF too, not just the web UI.
- **D4** `/addin/auth/done` - Office add-in auth completion. Add-in flows use a
  dialog plus `postMessage`. Check the origin validation on both ends, and
  whether a token lands anywhere a hostile page can read it. (Clickjacking is
  excluded, but postMessage origin failures are not.)

## 11. Don't waste reports on these

Explicitly excluded: missing security headers, clickjacking, content spoofing,
SPF/DKIM/DMARC, DoS and rate-limiting/brute force, password-policy hardening,
`robots.txt` and `.well-known` disclosure, DNS/HTTP cache poisoning, physical
access, social engineering, operational issues that aren't vulnerabilities.

The Cloudflare "DNS points to prohibited IP" on `proxy.lithicblue.com` is a DNS
misconfiguration, and reads as an excluded operational issue. Don't lead with it.

Also note: rewards drop where the attack assumes you already hold the victim's
account or email. Build every PoC from the position of an **unaffiliated
attacker**.

## 12. Reporting

- **Quality can beat a duplicate.** "We may decide at our discretion to reward a
  later report if the first report is of insufficient quality to enable effective
  remediation." A clearly better writeup of a known issue is not automatically
  worthless.
- **Chain the small stuff.** "Several such findings ... may be considered
  together where they collectively demonstrate meaningful severity." Three
  below-threshold findings that compose into one real attack = one good report.
- **SLA is 2 working days to acknowledge, 5 to assess.** Past that with silence,
  a short factual follow-up is reasonable.
- Include a video or screenshots, exact repro steps, and an explicit impact
  statement in their terms: whose data, how much, from what starting position.
- Rewards are paid after remediation in production.

---

# 13. Recon results (2026-10-28)

**No vulnerabilities were found or confirmed.** This is attack-surface mapping only,
gathered from passive sources, published documentation, public client bundles and
public OAuth discovery documents. Everything in sections 6-10 remains a hypothesis
for manual testing.

## Hosts

| Host | State |
|---|---|
| `www` / apex | Next.js marketing site; `/` redirects to `/landing` |
| `na` / `eu` / `au` | **All three regions live**, each with its own build and its own OAuth issuer |
| `auth.lithicblue.com` | In certificate transparency logs but **does not serve**. The bundles reference `NEXT_PUBLIC_AUTH_URL` / `NEXT_PUBLIC_BETTER_AUTH_URL`, so an auth host is configured somewhere |
| `trust.lithicblue.com` | Trust Center |
| `proxy.lithicblue.com` | Cloudflare returns "DNS points to prohibited IP" - the record points at a reserved/private address. Reads as an excluded operational misconfiguration; do not lead with it |

## Dead ends - don't spend time here

- **No source maps.** Production Next.js build with `productionBrowserSourceMaps`
  off. No original sources to recover.
- **No `/api/` application routes in public bundles.** Only PostHog's own
  (`/api/surveys/`, `/api/early_access_features/`, `/api/web_experiments/`,
  `/api/product_tours/`) plus `/api/auth` and `/api/trpc`. The tRPC procedure
  names live in the authenticated bundles, so you need an account to enumerate them.
- **Internet Archive was offline** when this ran, so historical bundles were not
  retrievable. Retry later - old builds are the best source of removed endpoints
  and legacy logic.
- **No secrets** in any public bundle.

## Confirmed stack details

- Better Auth with the **organization plugin** and the **OIDC provider plugin**
- tRPC at `/api/trpc`, with `trpc-accept` header handling (batching/streaming)
- PostHog drives **feature flags** (`featureFlags`, `feature_flag_payloads`,
  `early_access_features`). Flags gate app behaviour, so unreleased features are
  flag-controlled - a legitimate avenue for finding surface that isn't shipped yet
- Sentry for error reporting; Vercel hosting

# 14. OAuth / OIDC provider - the concrete surface

Public discovery, identical shape on all three regions (example: `na`):

```
issuer                  https://na.lithicblue.com/api/auth
authorization_endpoint  .../api/auth/oauth2/authorize
token_endpoint          .../api/auth/oauth2/token
registration_endpoint   .../api/auth/oauth2/register     <- open dynamic registration
userinfo_endpoint       .../api/auth/oauth2/userinfo
introspection_endpoint  .../api/auth/oauth2/introspect
revocation_endpoint     .../api/auth/oauth2/revoke
end_session_endpoint    .../api/auth/oauth2/end-session
jwks_uri                .../api/auth/jwks                (single RSA RS256 key)
scopes                  openid profile email offline_access mcp:tools
```

`/api/mcp/mcp` unauthenticated returns a JSON-RPC error plus
`WWW-Authenticate: Bearer resource_metadata="..."` - correct RFC 9728 behaviour.

## Already solid - do not report these

| Property | Value | Why it closes an attack |
|---|---|---|
| `code_challenge_methods_supported` | `["S256"]` only | No `plain` PKCE downgrade |
| `response_types_supported` | `["code"]` | No implicit flow |
| `grant_types_supported` | `authorization_code`, `refresh_token` | No password or implicit grant |
| `authorization_response_iss_parameter_supported` | `true` | RFC 9207, blocks mix-up attacks |
| `request_uri_parameter_supported` | `false` | **No SSRF via request objects** |
| `request_parameter_supported` | `false` | No JAR parsing surface |
| introspection / revocation auth methods | exclude `none` | Can't introspect others' tokens anonymously |

## Live test targets (manual, your own accounts only)

- **O1 - Dynamic client registration.** `token_endpoint_auth_methods_supported`
  includes `none`, so public clients are allowed - correct for MCP, but it means
  anyone can register a client. Test `redirect_uri` validation **at registration
  and again at authorization**: wildcards, path traversal within an allowed
  origin, `localhost` with arbitrary ports, scheme switches, multiple URIs where
  only the first is checked. The attack to prove: register a client with a
  redirect you control, get a victim to approve it, capture the code. PKCE S256
  and the consent screen are the mitigations - verify both actually hold.
- **O2 - `prompt=none` silent authentication.** `prompt_values_supported`
  includes `none`. Test whether an already-authenticated victim yields a code to
  a registered client with no interaction. Combined with any weakness in O1 this
  removes the user from the loop entirely - that's the difference between a
  medium and a high.
- **O3 - `claims` parameter.** `claims_parameter_supported: true`. Try requesting
  claims beyond the granted scope (e.g. `email` with only `openid`) and check
  whether `userinfo` and the ID token honour scope boundaries.
- **O4 - Cross-region token acceptance.** Three independent issuers with identical
  path structure. Obtain a token at `eu`, present it to `na`'s and `au`'s
  `/api/mcp/mcp`. Register a client at one region, try its `client_id` at another.
  A correct implementation rejects on `iss`/`aud`. This is the single most
  promising item here: it is cross-organisation *and* cross-region, it maps to
  their top reward tier, and almost nobody tests it.
- **O5 - Logout and revocation actually revoking.** `backchannel_logout_supported`
  is true. After sign-out, after `/revoke-other-sessions`, and after a member is
  **removed from the organisation**, check whether existing MCP access tokens and
  refresh tokens still work. `offline_access` means long-lived refresh tokens
  exist. Stale authorization after removal is a clean, demonstrable finding and
  ties to W7.
- **O6 - Scope fidelity on the MCP resource.** The resource advertises only
  `mcp:tools`. Check whether a token lacking that scope is accepted anyway, and
  whether an org **Member**'s token can call the write tools (`write_claims`,
  `add_feedback_comment`, `request_feedback`).
- **O7 - `acr_values_supported: ["0"]`** - no step-up authentication signalling.
  Not a finding by itself; relevant if you find a sensitive operation that ought
  to require re-authentication (ownership transfer, region change, integration
  disconnect) and doesn't.

## Priority order

1. **O4** cross-region token acceptance - top reward tier, least contested
2. **W1** invite above your own role level - highest probability of landing
3. **M1** MCP tool object authorization with foreign project IDs
4. **O1 + O2** registration redirect validation plus silent auth, chained
5. **O5 / W7** authorization surviving removal
6. **R1 / R2** research-fetcher SSRF and allowlist bypass
