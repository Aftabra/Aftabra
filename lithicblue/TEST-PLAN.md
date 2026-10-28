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

---

# 15. Second pass - project roles, admin plugin, legacy build

## 15.1 Project-level roles: a second permission dimension

From `/docs/project-management/managing-team-members`. Project roles are
**separate from organisation roles**, so every org role x project role pair is a
distinct authorization state.

| Project role | Stated capability |
|---|---|
| Owner | Everything: edit the project, manage access, **delete the project**. A project always has at least one owner. |
| Admin | Everything a member can, plus manage access (add/remove/change roles) and update project settings. |
| Member | Work on the project; sees the member list but **cannot edit it**. |

Stated invariants:

- **P1** "Owners and admins can make changes here; members see the list but can't
  edit it." As a project Member, call add-member, remove-member and change-role.
- **P2** "You add project members from people already in your organisation; you
  can't invite a brand-new email straight onto a project." Call add-member with a
  **user ID from your other organisation**. If the handler doesn't verify the
  target is in your org, you can pull a foreign user into your project - or add
  yourself to theirs. This is a direct cross-organisation path; test it both ways.
- **P3** "You can't remove or demote the last owner." Call remove/demote on the
  last owner via the API. An ownerless project is an integrity bug.
- **P4** Project delete is owner-only. Call it as project Admin.
- **P5** Cross-dimension: can an **org** Admin read a project they are not a
  project member of? Can an org Member who is a project Owner reach org-level
  settings? The docs keep the dimensions separate, so any leakage between them is
  worth a question even if it turns out intended.

## 15.2 Research controls - the personal/organisation merge

From `/docs/organization/research-controls` and `/docs/account`:

- Org setting lives in Settings -> Organization, **editable by owners and admins**,
  applies to every member. Two modes: **Exclude domains** (blocklist) or
  **Restrict to domains** (allowlist).
- Personal **Preferences** have their *own* Web Search Settings, and the docs say
  they are "**merged with your organization's settings**".
- The stated rule: "If your organization restricts searches to an allow-list, you
  can only disable specific domains to narrow your own results further. If your
  organization doesn't restrict searches, you set your own Filter Mode."

**R5 - merge-logic bypass.** This is the most promising item in this section. The
documented behaviour is that a member may only ever *narrow*. Test, as a plain
Member under an org allowlist:

- set a personal Filter Mode of `Exclude domains` (which should be impossible
  while the org restricts), and see whether the effective policy becomes a
  blocklist;
- add a domain to your personal allowlist that is **not** on the org allowlist;
- submit both settings directly to the API rather than through the UI, which is
  where the "you can only disable" constraint is likely enforced;
- check whether the merge is a union (wrong) or an intersection (right).

Widening the research agent's reach past an org policy is "circumvention of
permission controls" verbatim from their threat model, and it is also the gateway
to R1/R2 (SSRF) because it controls which hosts the fetcher will visit.

**R6** Org setting is owner/admin-editable - confirm a Member cannot write it
(ties to W4).

## 15.3 Security-page claims worth attacking

From `/docs/security`, each of these is a vendor security claim:

- **S1 - "Each project is isolated, and access follows your existing permissions,
  including the permissions on connected SharePoint or Google Drive folders, so
  people only see what they could already open."** They propagate *third-party*
  ACLs. Test: put a file in a connected Drive/SharePoint folder that user X
  cannot open in Drive, then have X read it through LithicBlue. If the project
  knowledge base, the ontological map, a claim citation or a generated deliverable
  surfaces that content, the propagation is incomplete. Note the knowledge base is
  built *across* a project's sources - so even if the file view is gated, extracted
  passages may leak through search, claims or verification output. That indirection
  is where this breaks in practice.
- **S2 - Microsoft Purview sensitivity labels.** "A label that encrypts the
  document means LithicBlue cannot read it, so it is marked as protected rather
  than analysed. LithicBlue does not attempt to remove or work around that
  protection." Test whether an encrypted-labelled document can be made to analyse
  anyway - re-upload, rename, change container, submit via a different ingestion
  path (direct upload vs Drive vs SharePoint vs MCP). Getting protected content
  analysed contradicts a stated control.
- **S3 - Password-protected documents** "are not read unless someone supplies the
  password." Where does that password go? Is it stored, logged, or visible to
  other project members? Can a Member retrieve a password an Owner supplied?
- **S4** Encryption claims (AES-256 at rest, TLS 1.2+) are not remotely testable
  beyond TLS configuration, and TLS config issues aren't in their reward criteria.

## 15.4 Account surface

From `/docs/account`:

- **A1 - Email change.** You can update your email in Account Settings. Test:
  does it require verification of the *new* address before taking effect? Does it
  invalidate sessions? Then the interesting chain: change your email to match a
  **pending invitation** at another organisation and accept it, or to a domain
  that triggers any domain-based auto-join (C9). Unverified email change feeding an
  invitation flow is a clean cross-org path.
- **A2 - Phone field** - stored and rendered; check for stored XSS and for
  whether it appears in other members' views.
- **A3 - Password reset** clears the sign-in lockout "immediately, without
  waiting". Check reset-token entropy, single use, expiry, and whether reset
  invalidates existing sessions and outstanding MCP refresh tokens.
- **Not reportable:** "Too many failed email-and-password sign-ins ... temporarily
  pause email-and-password sign-in for it, **whoever the attempts came from**."
  That is a documented account-lockout denial of service, and their exclusions bar
  both DoS and login brute force. Don't report it.

## 15.5 Legacy build (recovered from Internet Archive)

The archived build is on the old `/_next/static/chunks/` path scheme, versus
today's `/_next/static/immutable/chunks/`. 38 archived bundles were recovered and
mined. What it exposed that the current public bundles do not:

**The rename: `engagementId` -> `projectId`.** The old build routed
`/kag/:engagementId` and `/view/:engagementId/:fileId`; today those are
`:projectId`.

- **L1** Test whether the API still accepts the legacy parameter name. Send
  `engagementId` alongside or instead of `projectId` to tRPC procedures and route
  handlers. Renames commonly leave a backward-compatible alias wired to an older
  code path with weaker checks, and a legacy alias that skips the current
  authorization middleware is a cross-org read.

**An admin console**, referenced nowhere in the current public bundles:

```
/admin            /admin/users/        /admin/oauth/clients/
/admin/custom-providers/               /admin/generate_link
/project/_/settings/api                /organizations/
```

- `/admin` on `na` responds differently from a nonexistent path (a 307 carrying a
  Next.js error document, versus the 48 KB 404 page), so the route exists.
- `/admin/users`, `/api/demo/*`, `/api/broadcast`, `/project/_/settings/api` and
  `/faq` all return the 48 KB 404 page on `na` now - **removed, dead ends.**
- `/admin/oauth/clients` suggests OAuth clients registered through dynamic
  registration are administered somewhere; `/admin/custom-providers` suggests
  configurable SSO providers; `/admin/generate_link` suggests server-generated
  sign-in links.

## 15.6 Better Auth admin plugin is enabled - highest-value lead

```
GET /api/auth/admin/list-users   ->  401, empty body     (exists, gated)
GET /api/auth/list-sessions      ->  401 {"code":"UNAUTHORIZED"}
GET /api/auth/oauth2/userinfo    ->  401 {"error":"invalid_request"}
nonexistent path                 ->  48 KB Next.js 404 page
```

`list-users` is a GET route in Better Auth's **admin plugin**, and it answers 401
rather than the Next.js 404 page. The plugin is enabled.

Caveat on method: the plugin's other routes (`impersonate-user`, `set-role`,
`create-user`, `set-user-password`, `ban-user`, `remove-user`,
`revoke-user-session`) are POST, and a GET to them returns Better Auth's own
0-byte 404. That is a **method mismatch, not proof of absence** - their presence
is unconfirmed, though an enabled plugin normally registers its full route set.
These were deliberately not POSTed to; verifying them is manual work on your own
account.

**The escalation chain to test (E1).** Better Auth's admin plugin decides who is
an admin from the user's **`role` field** by default, unless the app pins an
explicit `adminUserIds` list. The recurring implementation mistake is letting the
user-update path write `role`. So:

1. As an ordinary user, attempt to set `role` on your own account - through the
   account-update endpoint, through any profile mutation, and as an extra field on
   unrelated update calls (mass assignment). Try `banned` and `emailVerified` too.
2. If `role` becomes `admin`, call `admin/list-users` - it should now answer.
3. If the plugin's full route set is registered, `admin/impersonate-user` gives a
   session as **any user in any organisation**.

That is member-to-admin escalation chaining into cross-organisation account
takeover: both halves of their threat model, at the top reward tier. It is the
single most promising lead from this engagement.

Report it carefully: demonstrate on accounts you own, do not impersonate a real
customer, and if you do land an admin session, stop and report rather than
exploring. Their policy: "If you come across user data during the course of
discovering vulnerabilities, please report it to us immediately, and do not store,
copy, transfer, disclose, or otherwise retain this information."

## 15.7 Not findings

- **PostHog project key** `phc_Fqv8...` in the bundles - a publishable client-side
  key, public by design.
- **`www.lithicblue.com/9bb3665e28f2b230/script.js`** (200, ~12 KB) - a
  first-party-proxied analytics script on a hashed path. Normal ad-blocker
  avoidance, not a vulnerability.
- `.well-known` documents - their exclusions explicitly bar disclosure of known
  public resources.
- `proxy.lithicblue.com` DNS misconfiguration - excluded operational issue.
- Account lockout via failed sign-ins - excluded DoS, and self-documented.

## 15.8 Revised priority order

1. **E1** self-assign `role` -> admin plugin -> impersonation (15.6)
2. **R5** research-controls personal/org merge bypass (15.2)
3. **P2** add a cross-org user ID to a project (15.1)
4. **O4** cross-region token and client acceptance (section 14)
5. **W1** invite above your own role level (section 7)
6. **M1** MCP tool object authorization with foreign IDs (section 8)
7. **L1** legacy `engagementId` parameter alias (15.5)
8. **S1** Drive/SharePoint ACL propagation into the knowledge base (15.3)
9. **A1** unverified email change feeding the invitation flow (15.4)

---

# 16. Third pass - Supabase, CSP inventory, region cookie, DNS

## 16.1 Supabase is in the data path - likely the single biggest surface

The app's CSP on every page includes:

```
connect-src ... https://*.supabase.co https://*.supabase.in
                wss://*.supabase.co  wss://*.supabase.in
img-src     ... https://*.supabase.co https://*.supabase.in
```

`connect-src` plus `wss:` means the **browser talks directly to Supabase** - not
only through their own API. Where a client speaks straight to Supabase, the
authorization boundary is **Postgres Row Level Security**, not application code.

An archived bundle carries the Supabase client (`supabaseUrl`, `supabaseKey`,
`SupabaseAuthClient`) and an anon JWT whose payload decodes to:

```json
{"iss":"supabase","ref":"pcsyssamsygzgixvvxxc","role":"anon",
 "iat":1745128470,"exp":2060704470}
```

Project ref **`pcsyssamsygzgixvvxxc`** -> `https://pcsyssamsygzgixvvxxc.supabase.co`.
The anon key is **publishable by design and is not itself a finding** - Supabase
intends it to ship in the client. What matters is what RLS permits when it is used.

**Why this is the top lead alongside E1.** Missing or permissive RLS on a single
table in a multi-tenant Supabase app means any holder of the anon key - or any
authenticated user - reads rows belonging to every organisation. That is their
highest-severity category stated verbatim: "access to information or resources in
an arbitrary organization." It is also the most common serious defect in this
exact stack.

**SB1 - RLS coverage per table.** For each table the app touches, attempt a read
with (a) the anon key alone and (b) an authenticated Org B session, using an Org A
row. `select=*&limit=1` is enough; you never need volume.
**SB2 - RLS on writes.** `POST`, `PATCH` and `DELETE` to another organisation's
rows. Read-only RLS policies that forget write paths are common.
**SB3 - Realtime.** `wss://` is permitted, so Realtime is in use. Realtime has its
own authorization model and is frequently left open even where PostgREST is
locked. Subscribe to table changes and see whether events for other organisations
arrive. Very few people test this, and it leaks continuously rather than once.
**SB4 - Storage buckets.** Supabase Storage has per-bucket policies separate from
table RLS. Enumerate buckets and test object reads across organisations.
**SB5 - Exposed schema.** Check whether the PostgREST root serves an OpenAPI
document, and whether RPC functions (`/rest/v1/rpc/...`) are reachable.
`SECURITY DEFINER` functions bypass RLS by design and are a classic escalation.
**SB6 - Key confusion.** Confirm no `service_role` key ever reaches the client -
in any bundle, any API response, any error payload. A leaked `service_role` key
bypasses RLS entirely and would be critical.

**I did not run any of these.** Two reasons, both deliberate:

1. An RLS failure returns **real customer data on the first request** - and this
   is confidential pharmaceutical, M&A and advisory material. Their policy is
   explicit: "Never attempt to access anyone else's data", and if you do encounter
   it, report immediately and retain nothing. There is no way to probe RLS
   "lightly" when success means holding someone's deal documents.
2. Their program excludes findings from automated or AI tooling, so a result I
   produced would not be eligible anyway.

So test these by hand, against **rows in organisations you created**, and the
moment unfamiliar data appears: stop, screenshot only what proves the access
control failed, redact it, and report.

**Scope note worth settling first.** Their criterion is a "web service **owned by
LithicBlue** that handles sensitive user data, *e.g.* properties hosted on
`https://*.lithicblue.com`" - "e.g." reads as illustrative, not exhaustive, and
their Supabase project and S3 buckets are LithicBlue-owned infrastructure holding
customer data. But the hosts are `supabase.co` and `amazonaws.com`. Ask
security@lithicblue.com to confirm these are in scope before testing them. One
email removes the ambiguity, and the answer also tells you how they think about
their own perimeter.

## 16.2 `lb_region` - a client-controlled routing cookie, domain-wide

Issued unauthenticated on first contact:

```
set-cookie: lb_region=na; Path=/; Domain=.lithicblue.com;
            Secure; HttpOnly; SameSite=lax; Max-Age=31536000
```

Two properties matter.

**RC1 - It selects a region and the client holds it.** If any backend path uses
`lb_region` to decide which regional datastore to read, tampering with it is a
cross-region data-access primitive. Authenticate at `na`, then replay requests
with `lb_region=eu` and `lb_region=au`. Also try values the app never sets:
unknown regions, empty, absurdly long, path traversal, SQL and template
metacharacters - wherever this value lands (routing table, URL construction,
connection string) decides what the bug is. A routing value a client controls is
exactly the kind of thing that gets trusted deeper in the stack than intended.

**RC2 - `Domain=.lithicblue.com` spans every subdomain.** This cookie is sent to
`www`, `na`, `eu`, `au`, `proxy` **and `trust`**. Check what scope the *session*
cookie uses once you authenticate:

- If the session cookie is also `Domain=.lithicblue.com`, then a session minted at
  `na` is transmitted automatically to `eu` and `au` - the browser performs the
  cross-region test in RC1/O4 for you, and only server-side `iss`/`aud` validation
  stands between regions.
- Worse, `trust.lithicblue.com` is a **CNAME to `cname.vantatrust.com`** - a
  third-party host. A domain-wide session cookie is therefore transmitted to
  Vanta's infrastructure on every trust-centre request. `HttpOnly` stops script
  access but not transmission. If the session cookie is domain-scoped, that is a
  reportable session-token exposure to a third party; verify the exact `Domain`
  attribute on the authenticated cookie before claiming it.

## 16.3 CSP - complete third-party inventory

Identical policy on all pages (bucket name varies by region). Full allowlist:

| Directive | Notable origins |
|---|---|
| `script-src` | `'self' 'unsafe-inline'`, `*.lithicblue.com`, `*.posthog.com`, `*.i.posthog.com`, `va.vercel-scripts.com`, `apis.google.com`, `accounts.google.com` |
| `connect-src` | `*.supabase.co/.in` + `wss://`, `*.posthog.com`, `vitals.vercel-insights.com`, `*.sentry.io`, `*.googleapis.com`, `accounts.google.com`, `lith-s3-bucket-<region>.s3.<aws-region>.amazonaws.com` |
| `frame-src` | `*.sharepoint.com`, `*.sharepoint-df.com`, `*.officeapps.live.com`, `login.microsoftonline.com`, `docs.google.com`, `drive.google.com`, `content.googleapis.com`, `accounts.google.com` |
| `form-action` | `'self'`, `*.sharepoint.com`, `*.sharepoint-df.com` |
| `img-src` | `blob:`, `data:`, `*.supabase.co/.in`, `*.gstatic.com`, `*.googleusercontent.com`, the S3 bucket |
| hardening present | `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, `upgrade-insecure-requests`, HSTS 2y preload includeSubDomains, `X-Frame-Options: DENY`, `Permissions-Policy` locking camera/mic/geolocation, `Referrer-Policy: strict-origin-when-cross-origin` |

Reading it:

- **`script-src` allows `'unsafe-inline'`.** Not a standalone finding - missing or
  weak headers are in their exclusions - but it is a decisive **amplifier**: any
  HTML injection you find is directly exploitable because CSP will not contain it.
  Say so in the impact section of an XSS report; do not report it alone.
- **`script-src` allows all of `https://*.lithicblue.com`.** Any subdomain that
  can be made to serve attacker-controlled JavaScript becomes a script source for
  the app. Relevant to `proxy.lithicblue.com` (16.5) and to any future subdomain.
- **`form-action` permits SharePoint origins**, so credential-bearing forms may
  target Microsoft hosts. Worth tracing the SharePoint connect flow for where a
  form posts and whether any token rides along.
- `frame-src` for Office/Google viewers means documents render in third-party
  frames - check what is passed in those URLs (file tokens, signed URLs, tenant
  identifiers) and whether such a URL works for a user outside the project.
- `*.supabase.in` is allowed alongside `.co`. Confirm nothing resolves there that
  shouldn't.

## 16.4 DNS and mail

| Record | Value | Note |
|---|---|---|
| NS | `henry/may.ns.cloudflare.com` | Cloudflare DNS |
| apex A | `216.150.1.1` | |
| `www` A | `104.21.64.14`, `172.67.174.25` | Cloudflare proxied |
| `na` | CNAME `0ebb0d8269e3adc9.vercel-dns-016.com` | Vercel |
| `eu` | CNAME `8acb8348f2f7f80d.vercel-dns-016.com` | Vercel, distinct deployment |
| `au` | CNAME `bce2c694a6a3068c.vercel-dns-016.com` | Vercel, distinct deployment |
| `trust` | CNAME `...cname.vantatrust.com` | **third-party host on their domain** |
| `auth` | **no record at all** (SOA only) | has a certificate in CT logs but does not resolve |
| MX | `lithicblue-com.mail.protection.outlook.com` | Microsoft 365 |
| SPF | `v=spf1 include:spf.protection.outlook.com ~all` | |
| DMARC | `p=quarantine`, reports to Cloudflare | |
| TXT | `google-site-verification`, `linkedin-site-verification`, `MS=ms30419786` | Google Workspace + Microsoft verification |
| CAA | letsencrypt, pki.goog, comodoca, ssl.com, digicert (issue + issuewild) | permissive but not a finding |

- **`auth.lithicblue.com` has no DNS record**, yet a certificate exists for it in
  CT logs and the bundles reference `NEXT_PUBLIC_AUTH_URL` /
  `NEXT_PUBLIC_BETTER_AUTH_URL`. No record means **nothing to take over** - there
  is no dangling CNAME. Keep watching it: if it later points at an unclaimed
  provider, it becomes a takeover candidate, and because `script-src` trusts
  `*.lithicblue.com`, control of it would be serious. Re-check periodically.
- Interesting detail: `www.lithicblue.com/landing` serves a CSP naming the **AU**
  bucket while `na.lithicblue.com` names the NA bucket, which suggests the
  www/apex host is served by the AU deployment. If so, `www` and `au` may share
  state, which is useful context for the cross-region work.

## 16.5 Correction and non-findings

- **Correction.** I earlier described `proxy.lithicblue.com` as resolving to a
  private or internal IP. It does not: it resolves to **Cloudflare's own anycast
  addresses** (`104.21.64.14`, `172.67.174.25`), the same as `www`, which creates
  a proxy loop - hence Cloudflare's "DNS points to prohibited IP" page. It is a
  broken record, not an internal-IP leak. Still an excluded operational issue, and
  still worth a one-line mention in any report that already covers `*.lithicblue.com`
  being a trusted script source.
- **S3 buckets are locked down.** `lith-s3-bucket-na` and `lith-s3-bucket-au`
  return `403 AccessDenied` on a root listing; `lith-s3-bucket-eu` exists (a 301
  region redirect) and is likewise not listable. Checked with status codes only, no
  contents retrieved. **Do not report these.**
- Supabase anon key in the bundle: publishable by design, not a finding.
- CAA permissiveness, DMARC at `quarantine` rather than `reject`, and the
  `'unsafe-inline'` CSP: all excluded or non-qualifying on their own.

## 16.6 Priority order, revised again

1. **SB1-SB3** Supabase RLS on reads, writes and Realtime (16.1) - tied for top,
   and settle the scope question by email first
2. **E1** self-assign `role` -> Better Auth admin plugin -> impersonation (15.6)
3. **RC1** `lb_region` cookie tampering for cross-region data access (16.2)
4. **RC2** session cookie `Domain` scope, including transmission to Vanta (16.2)
5. **R5** research-controls personal/organisation merge bypass (15.2)
6. **P2** project add-member with a cross-organisation user ID (15.1)
7. **O4** cross-region OAuth token and client acceptance (section 14)
8. **W1** invite above your own role level (section 7)
9. **M1** MCP tool object authorization with foreign IDs (section 8)
10. **L1** legacy `engagementId` parameter alias (15.5)
11. **S1** Drive/SharePoint ACL propagation into the knowledge base (15.3)

---

# 17. Fourth pass - build drift, delegation, ingestion, the research trigger

## 17.1 Attack surface is provably exhausted at 8 hosts

crt.sh holds **112 certificate records** for `%.lithicblue.com`, covering exactly
the eight hostnames already known. The other passive sources returned nothing for
benign reasons (HackerTarget quota exceeded, Anubis 301, OTX anonymous rate limit,
RapidDNS empty, subdomain.center two names). There is no ninth host to find.

The certificate timeline is more useful than the names:

| Host | Certs | First | Last | Reading |
|---|---|---|---|---|
| `lithicblue.com` | 85 | 2025-08-05 | 2026-08-18 | site live ~Aug 2025 |
| `www` | 14 | 2025-08-05 | 2026-08-12 | |
| `proxy` | 19 | 2025-11-13 | **2026-03-14** | decommissioned ~Mar 2026 |
| `auth` | 12 | 2025-12-12 | **2026-06-07** | decommissioned ~Jun 2026 |
| `na` / `eu` / `au` | 4 each | **2026-06-15** | 2026-08-16 | **regions created Jun 2026** |

**The architecture changed in June 2026**: a centralised `auth.lithicblue.com`
stopped renewing on 2026-06-07 and the three regional hosts appeared on
2026-06-15. The bundles still carry `NEXT_PUBLIC_AUTH_URL` and
`NEXT_PUBLIC_BETTER_AUTH_URL` - leftovers from that era.

**Why this matters for hunting.** The entire multi-region, per-region-issuer
authorization model is roughly four months old. It is the newest code in the
product and has had the fewest eyes on it. Every cross-region item (O4, RC1, C5,
M6) is aimed at code written in the last quarter. `proxy`'s broken Cloudflare-loop
record is a leftover from the same migration.

## 17.2 The regions run different builds - a fix in one may not be in another

Deployment IDs from `/login`:

```
na   dpl_FQ6MTJaUgkFGikVPtzRKUJvTdVpS
eu   dpl_48D46hhDDpodFKXXRss3sKCLoQ7U
au   dpl_H38RUcTopDhSugXUVSYm5FTvYQ4w
www  dpl_48D46hhDDpodFKXXRss3sKCLoQ7U    <- identical to eu
```

All three serve 23 chunks on the login page, but **10 chunk names differ between
every pair**. Three separate Vercel deployments carrying different code.

> **SUPERSEDED - see 18.1.** The chunk-name divergence below turned out to be
> build metadata, not different code. The claim that the regions run different
> logic was wrong. Read 18.1 before acting on BD1/BD2.

**BD1 - Deployment drift.** The regions are not in lockstep, so:
- When you find and report a bug, **check the other two regions** before you
  write it up. "Present on `na` and `au`, fixed on `eu`" is useful intelligence
  for them and strengthens your report.
- After they remediate, re-test the other regions. A fix deployed to one region
  only is a legitimate follow-up finding, not a duplicate.
- Whichever region carries the oldest code is the most likely to still hold an
  already-fixed defect. Track the `dpl_` IDs over time to see which lags.

**BD2 - `www` is the EU deployment.** Note the conflict in evidence, and resolve
it before relying on either: `www`'s `/login` reports the **EU** deployment ID,
while `www`'s `/landing` served a CSP naming the **AU** S3 bucket, with
`x-vercel-cache: HIT` and `x-nextjs-prerender: 1`. The most likely explanation is
a **stale prerendered page cached from an earlier deployment**, still being served
with that older deployment's CSP. Worth confirming: a cached page surviving a
deployment can mean stale JavaScript, stale CSP, or stale embedded configuration
served to users. Check whether any cached page references config that has since
rotated.

## 17.3 Google Drive uses domain-wide delegation - the highest-privilege surface

From `/docs/google-drive`:

> "LithicBlue connects to your Google Workspace through a **service account with
> domain-wide delegation**. Your Workspace administrator authorises the connection
> once for the whole organisation... Access always respects your existing Drive
> permissions, so each person only sees the files they can already open."

Understand what that means. Domain-wide delegation lets the service account
**impersonate any user in the customer's entire Google Workspace**. Google is not
enforcing per-user access here - LithicBlue holds a key that opens everything, and
*LithicBlue's own code* decides which user to impersonate for each request. The
sentence "each person only sees the files they can already open" is therefore an
application-level promise, not a platform guarantee.

**DWD1 - Impersonation subject control.** Find where the backend decides whose
identity to use when fetching a Drive file. If that subject is derived from
anything client-influenced - a user ID, an email, a member record, a project
membership row - try substituting another user's. Success means reading any file
any user in that Workspace can see. That is the highest-impact bug available in
this product, because it reaches beyond LithicBlue into the customer's whole Drive.
**DWD2 - Connection record binding.** The delegation is authorised per
organisation. If connection or drive records are addressed by ID without
validating they belong to *your* organisation, an Org B user could drive Org A's
delegated service account. Test with your two orgs.
**DWD3 - Who may connect.** "Step 1 must be done by a Google Workspace super
administrator... **Step 2 can be done by any LithicBlue user** who signed in with
their Google account." So a non-admin can attach Shared Drives once delegation
exists. Check whether a plain **Member** can connect a drive, and whether that
drive then becomes visible to projects they don't belong to.
**DWD4 - Identity gating.** "Drive settings are only available to Google-identity
users." Test whether an email/password account can reach those endpoints directly,
bypassing a UI-only check.
**DWD5 - SharePoint equivalent.** `/docs/sharepoint`: Microsoft Graph with
**tenant administrator consent** granted org-wide, then "Step 2 can be done by a
project member with access to the site." Graph application permissions granted by
admin consent are typically tenant-wide, so the same analysis applies: LithicBlue
enforces the per-user ACL itself. Run DWD1-DWD4 against SharePoint too.

Report these with care. A successful test here reads a real customer's documents,
so confine it strictly to Workspace/tenant accounts **you** control, connected to
organisations **you** created.

## 17.4 Ingestion surface - very wide, and HTML is accepted

From `/docs/project-management/managing-files`, accepted source types:

> PDF, Word (.docx), PowerPoint (.pptx), Excel (.xlsx) **including their
> macro-enabled and template versions**, **Visio**, CSV, TSV, TXT, MD, **HTML**,
> **emails**, meeting transcripts (**.vtt, .srt**), images "and more".

- **ING1 - HTML as a source document.** The standout. If source HTML is ever
  rendered - in a preview, a claim citation, an excerpt, the file viewer - that is
  stored XSS, and `script-src 'unsafe-inline'` (16.3) means CSP will not contain
  it. Check every place a passage is displayed, not just the file view.
- **ING2 - OOXML containers.** `.docm`/`.xlsm`/`.pptm`/templates plus `.vsdx`
  (Visio is an unusual, rarely-audited parser). Test XXE in the OOXML XML parts and
  zip path traversal in the container. Keep it to correctness - DoS is excluded.
- **ING3 - Email parsing.** `.eml` MIME and `.msg` (OLE compound file) are complex
  formats. Also check whether an email's embedded remote content gets fetched
  during ingestion - that is an SSRF path on upload.
- **ING4 - Images.** Images implies OCR, which implies an image-decoding library.
  Malformed-image handling is worth a look.
- **ING5 - Quick Start scope extraction.** `/docs/project-management/setting-scope`:
  "LithicBlue extracts an initial scope from the proposal or scope-of-work document
  you upload." That is a *second, distinct* parsing pipeline on upload. Separate
  code path, separate bugs.
- **ING6 - Folders and cloud sync.** Mirrored folder structures mean
  server-side path construction from names you control in Drive/SharePoint. Try
  traversal sequences and absolute paths in folder and file names.
- **ING7 - Source/deliverable state machine.** "Each file is a source, a
  deliverable or ignored (a distinction you set, not one baked into the file)" and
  "a document can't be both". A mutable type attribute with an exclusivity rule is
  a state machine. Try flipping a file's role mid-verification, or forcing both
  states, to see whether review logic can be bypassed or confused.

## 17.5 The research agent's trigger - a complete SSRF/bypass PoC chain

`/docs/project-management/data-gaps` gives the missing piece: the web research
agent is invoked from the **Data Gaps tab** via **Run Research** / **Re-run
Research**. That is the entry point for the research-controls work in 15.2 and R1/R2.

So the full chain is now testable end to end, with **out-of-band confirmation**,
which makes for an unambiguous report:

1. As Org A owner, set Research Controls to **Restrict to domains** with a single
   harmless entry (e.g. `example.com`). Save.
2. As a plain **Member**, open Preferences and attempt to widen the policy -
   switch Filter Mode to **Exclude domains**, or add a domain absent from the org
   allowlist. Submit directly to the API, not through the UI, since the
   "you can only disable" constraint is most likely enforced client-side.
3. Trigger **Run Research** on a project's Data Gaps tab.
4. Watch a domain **you control** (your own server, or a Burp Collaborator
   payload). A request arriving there proves the org policy was circumvented -
   no guesswork, no reliance on rendered output.
5. Then escalate the target: internal addresses, `169.254.169.254`, `localhost`,
   RFC1918, and allowlist-bypass tricks (open redirect on an allowed host, DNS
   rebinding, `@`/`#`/encoded-host parser confusion, trailing dots).

Steps 1-4 alone are "circumvention of permission controls", verbatim from their
threat model. Step 5 turns it into SSRF. DoS is excluded, so keep request volume
to a minimum - one confirmed callback is the whole proof.

## 17.6 Integrity surfaces - their threat model covers integrity too

Their criteria say "substantially affect the **confidentiality or integrity** of
user data", and these deliverables are client-facing advisory documents where a
false "verified" verdict is the damage.

- **INT1 - Claim verdict tampering.** `/docs/document-review/managing-findings`:
  "Edit…: change the verdict, rewrite the reasoning, or add and remove sources."
  Verdicts are mutable. Test who may edit them - a project Member, an org Member
  not on the project, someone in another org, and an MCP token via `write_claims`.
  Flipping a contradicted claim to verified in someone else's deliverable is a
  clean integrity finding.
- **INT2 - Contradiction override.** `/docs/project-management/contradictions`:
  LithicBlue picks a winner between conflicting claims and the user may Validate
  or Override. Test authorization on the override action. Changing which of two
  conflicting figures a client report asserts is material.
- **INT3 - CSV formula injection.** The claims panel exports to CSV ("one row per
  claim or one row per source"). Claim text derives from **uploaded documents**,
  which are attacker-controlled. If a cell beginning `=`, `+`, `-` or `@` is not
  neutralised, that is formula injection executing in the reviewer's spreadsheet.
  Not in their exclusion list. Frame impact as code execution in the context of
  the person reviewing the deliverable, plus exfiltration of the sheet's contents.
- **INT4 - Knowledge-base poisoning.** The ontological map "resolves the conflict
  before the information is ever used". A crafted source that reliably wins
  conflict resolution poisons the resolved picture every later answer draws on.
  Within your own project this is low impact; it becomes a finding where the
  source arrives from a shared cloud-synced folder or any path a lower-privileged
  or external party can write to, and it then alters what other members see.
- **INT5 - Emailed deliverable links.** `/docs/project-management/creating-a-project`:
  the first-run flow emails you "a link straight to your deliverable". Examine that
  URL: is it a guessable ID or a token? What entropy? Does it work unauthenticated,
  after you leave the org, or for a different account? Emailed deep links routinely
  carry weaker authorization than the app they point into.

## 17.6a Self-serve onboarding makes all of this reachable

The first-run flow takes an uploaded `.pdf`/`.pptx`/`.docx` deliverable plus
sources and **creates the project for you**, then emails results. So a fresh
signup reaches the document pipeline, the claim engine and the deliverable viewer
within one session - no sales call needed. Only the MCP connector needs a paid plan.

## 17.7 Additional non-findings

- `www.lithicblue.com/9bb3665e28f2b230/script.js` is **Vercel Speed Insights**
  proxied on a hashed path (`first-contentful-paint`, `largest-contentful-paint`,
  `layout-shift`, `data-sdkv`), matching `va.vercel-scripts.com` in the CSP. No
  configuration, no keys. Not a finding.
- The archived `/faq` page (removed from the live site) independently confirms the
  rename: "You create an **engagement**, upload the source materials". Useful
  corroboration for L1, not a finding in itself.
- `/articles` holds four marketing posts, no engineering detail.

## 17.8 Final priority order

Confidentiality, highest reward first:

1. **SB1-SB3** Supabase RLS - reads, writes, Realtime (16.1). Confirm scope by email first.
2. **DWD1/DWD2** Drive domain-wide-delegation impersonation and connection binding (17.3)
3. **E1** self-assign `role` -> admin plugin -> impersonation (15.6)
4. **RC1/RC2** `lb_region` tampering; session cookie domain scope incl. Vanta (16.2)
5. **R5 + 17.5** research-controls merge bypass, confirmed out-of-band, then SSRF
6. **P2** project add-member with a cross-organisation user ID (15.1)
7. **O4** cross-region OAuth token/client acceptance (section 14) - newest code in the product
8. **M1** MCP tool object authorization with foreign IDs (section 8)
9. **W1** invite above your own role level (section 7)
10. **INT5** emailed deliverable link authorization (17.6)
11. **ING1** HTML source rendering -> stored XSS, amplified by `unsafe-inline` (17.4)
12. **L1** legacy `engagementId` parameter alias (15.5)

And on every confirmed finding: **re-test the other two regions** (BD1). The
builds differ, so scope is per-region until proven otherwise.

---

# 18. Corrections and verification pass

Claims from earlier sections, re-tested. Two needed correcting.

## 18.1 CORRECTION: the regions do **not** run different code

Section 17.2 claimed the three regions run different builds, inferring it from 10
differing chunk names per pair, and advised that a fix in one region might not be
in another. **That inference was wrong.** I verified it properly:

Downloaded all 23 login-page chunks from each region (1.4 MB per region) and
compared their string tables:

| Comparison | Differing strings | Out of |
|---|---|---|
| `na` only, vs `eu`+`au` | **1** | 2693 unique strings |
| `eu` only, vs `na`+`au` | **1** | 2693 |
| `au` only, vs `na`+`eu` | **7** | 2700 |

And every differing string is build metadata, not logic:

- The single `na`-only and `eu`-only strings are **Sentry debug IDs** -
  `(e._debugIds||(e._debugIds={}))[n]="b0d3256a-…"`. Sentry injects one UUID per
  built bundle; all three regions carry 46 such references.
- The 7 `au`-only strings are **per-deployment Vercel analytics proxy paths**
  (`fc5fd5697597ae79/script.js|event|session|view`, `ce69be3b314c8aa6/script.js|vitals`)
  plus two more debug-ID UUIDs. These are the same mechanism as
  `9bb3665e28f2b230/script.js` on `www` (17.7) - each deployment gets its own
  hashed first-party path proxying Vercel Speed Insights and Web Analytics.

Chunk **names** diverge because the content hash incorporates the injected debug
ID, which then cascades into every cross-reference between chunks. So three
separate builds of what is, on this evidence, **the same source**.

**Corrected guidance.** There is no evidence of logic drift between regions, and
"fixed in one region, live in another" is not a finding to go looking for.

What survives, weaker and for different reasons:
- These are still **three independent deployments**, so they *can* drift later.
  Re-testing a confirmed finding against the other two regions costs one request
  and occasionally pays - do it as cheap diligence, not as a theory.
- This comparison covers only the **public login-page bundles**. The authenticated
  application chunks were not compared, and cannot be without an account. Treat
  authenticated-side parity as unverified.
- The cross-region authorization tests (O4, RC1, C5, M6) are **unaffected** by
  this correction. They test whether one region's issuer, token or routing cookie
  is honoured by another - that is server-side behaviour, independent of whether
  the client bundles match.

## 18.2 CONFIRMED: the Supabase project is genuinely theirs

Section 16.1 reported project ref `pcsyssamsygzgixvvxxc` from an anon JWT. I
checked whether that was real configuration or just vendored library/test data,
since embedded example keys are common. It is real:

```js
createBrowserClient(
  "https://pcsyssamsygzgixvvxxc.supabase.co",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBjc3lzc2Ftc3lnemdpeHZ2eHhjIiwicm9sZSI6ImFub24i..."
)
```

with `X-Client-Info: supabase-ssr/0.9.0 createBrowserClient`, `flowType: "pkce"`,
`detectSessionInUrl`, `persistSession: true`. A genuine browser-side client
pointed at their project. Section 16.1 stands.

Two refinements:

- **The archived build used Supabase *Auth*** (`flowType: "pkce"`,
  `detectSessionInUrl`), whereas the current build uses **Better Auth**. They
  migrated auth providers, which fits the `auth.lithicblue.com` decommissioning in
  June 2026 (17.1). Supabase appears to have been demoted from identity provider
  to data layer - and a migration between auth systems is exactly the kind of
  change that leaves orphaned rows, stale policies and dual-path authorization.
  Worth probing: do any Supabase RLS policies still key off a
  `auth.uid()` / Supabase-session identity that Better Auth no longer populates?
  A policy whose subject is always NULL can fail open.
- **The anon key is from an ~April 2025 build and may have been rotated.** The
  project ref is almost certainly still current, but extract the live key from the
  authenticated bundle rather than relying on the archived one.
- **No table names were recoverable.** Only the vendored supabase-js library is in
  the public/archived bundles - no `.from("table")` call sites. `postgres_changes`,
  `broadcast` and `presence` appear, but those are library-internal Realtime
  strings, not evidence of specific subscriptions. Table names will come from the
  authenticated bundle or from the PostgREST schema endpoint (SB5).

## 18.3 Standing corrections list

For the record, everything I have had to revise during this engagement:

1. **`proxy.lithicblue.com`** - I first said it resolved to a private/internal IP.
   It resolves to Cloudflare's own anycast addresses, causing a proxy loop.
   Corrected in 16.5.
2. **Regional build drift** - claimed as different code in 17.2; it is build
   metadata only. Corrected in 18.1.
3. **`www` and the AU bucket** - 17.2 noted `www`'s `/landing` CSP naming the AU
   S3 bucket while `/login` reports the EU deployment ID. Given 18.1, the likely
   explanation is simply a stale prerendered page cached across deployments, not
   a cross-region oddity. Still worth confirming whether cached pages can serve
   stale configuration, but it is not evidence of regional divergence.
4. **Better Auth admin POST routes** - a GET returning an empty-body 404 is a
   method mismatch, not proof the route is absent. Stated in 15.6; repeated here
   because it is easy to misread as "those endpoints don't exist".
