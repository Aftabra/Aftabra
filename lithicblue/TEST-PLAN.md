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

> **LARGELY SUPERSEDED - see 20.1.** The trust centre's complete sub-processor
> list names PlanetScale for database hosting and does **not** include Supabase.
> Supabase appears to have been removed from the current stack; the CSP entries
> are stale. Read 20.1 before spending time on SB1-SB6.

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

---

# 19. Legal documents, and the end of unauthenticated collection

## 19.1 What `/privacy` and `/terms` gave up

**No sub-processors are named in either document.** Both defer to the trust
centre: "The names and locations of all current Sub-Processors ... are set forth
in our trust center at trust.lithicblue.com." That page is rendered client-side by
Vanta, so its contents were not retrievable here.

**Remaining collection gap:** open `trust.lithicblue.com` in a real browser and
read the sub-processor list. Every entry is a third party in the data path - which
AI providers, which hosting, which storage - and that list is the last piece of
infrastructure inventory not yet recovered. It also tells you whether the AI
providers are reached directly or via a gateway, which matters for the
prompt-injection and research-agent work.

Useful facts extracted:

- **The entity is "LithicBlue Pty Ltd"** - an Australian company. Consistent with
  the Oceania region and the Australian-government use case. Relevant to the
  jurisdictional notes in their reward terms.
- **MSA:** "Where LithicBlue engages Sub-Processors to process Service Data, it
  will do so **consistent with the Customer's assigned region**."
- **MSA:** "Services **exclude any products or services provided by third
  parties**, even if Customer has connected those products or services to the
  Services." Relevant to the Drive/SharePoint scope question in 17.3 - their
  contract draws the line at the connected system's boundary, which supports
  testing *LithicBlue's* handling of delegated access while leaving the
  customer's Workspace or tenant itself outside.
- Authentication providers are acknowledged as third-party data sources ("single
  sign-on and authentication providers you use to access the Services"), and
  customers "may provision accounts for their authorized users" - so there is a
  customer-provisioned account path worth asking about.

**Not a finding:** the MSA commits sub-processors to the customer's assigned
region, while `/docs/hosting/data-residency` states AI processing "runs across our
global infrastructure by default ... and can be kept fully in-region on request."
That reads as a documentation/contract inconsistency rather than a security
vulnerability, and their criteria require a vulnerability. Don't report it. It is
worth knowing only because it confirms a cross-region data pipeline exists by
default, which is context for the cross-region tests.

## 19.2 Unauthenticated collection is complete

Stating this plainly so no more time goes into it. What was covered:

| Avenue | Result |
|---|---|
| Passive subdomain enumeration | 7 sources; **provably bounded at 8 hosts** by 112 crt.sh certificate records |
| DNS (A/CNAME/MX/TXT/CAA/NS/SOA/DMARC, over DoH) | complete; 16.4 |
| Live-host probing | 7 of 8 respond; `auth` has no DNS record |
| Crawl of all public pages | 67 pages, 120 JS URLs |
| Current bundles | 78 downloaded and mined |
| Chunk-graph walk for app bundles | no further public chunks reachable |
| Source maps | **none** - production build disables them |
| Historical bundles (Internet Archive) | 38 archived bundles recovered and mined; legacy routes, the `engagementId` rename, the Supabase client |
| Archived removed pages | `/faq` recovered |
| OAuth / OIDC discovery, all 3 regions | complete; 14 and section 14's hygiene table |
| MCP protected-resource metadata | complete |
| Better Auth route probing (GET only) | admin plugin confirmed enabled |
| CSP, security headers | complete third-party inventory; 16.3 |
| Cookies (unauthenticated) | `lb_region`, domain-wide; 16.2 |
| S3 buckets | all three reject anonymous listing |
| All published documentation | read |
| Privacy policy, MSA | read; sub-processors deferred to trust centre |
| Regional build comparison | same source, verified; 18.1 |

**Everything remaining requires an account.** Not as a formality - the bugs this
program pays for are cross-organisation access and within-organisation privilege
escalation, both of which are authenticated by definition. No amount of further
external collection substitutes for `/signup`.

Next action is Part 1 of `RUNBOOK.md`: build the two organisations, then capture
one authenticated tRPC call. That single request yields the procedure list, and
with it the real surface for everything in sections 6-17.

The two things to do before testing, both one email to security@lithicblue.com:

1. Confirm whether the Supabase project and the S3 buckets are in scope (16.1).
   Their criterion is LithicBlue **ownership**, with `*.lithicblue.com` given as
   an example rather than a limit - but get it in writing, because that is where
   the highest-severity findings most likely live.
2. Ask whether they want an identifying header on research traffic, and confirm
   manual testing with two self-provisioned organisations is acceptable.

---

# 20. Fifth pass - headless rendering: sub-processors, Server Actions, stack correction

The trust centre and the auth pages are client-rendered, so static fetches had
returned shells. Rendering them in headless Chromium (a normal page visit, no
payloads) closed the last collection gap and opened a surface I had missed.

## 20.1 CORRECTION: the database is PlanetScale, not Supabase

The trust centre publishes the **complete sub-processor list - 15 entries** - and
**Supabase is not among them**:

| Sub-processor | Role |
|---|---|
| **Amazon Web Services** | Cloud provider |
| **PlanetScale** | **Database hosting** |
| **Temporal Technologies Inc.** | Workflow management |
| **Fly.io** | Compute / hosting services |
| **Vercel** | Hosting |
| **Claude** | **LLM services** |
| **Tavily** | **"LLM-friendly web search results for our agents"** |
| **Google Workspace** | Identity provider, IDAM |
| **Stripe** | Finance and payments |
| **PostHog** | Anonymised telemetry |
| **Sentry** | Monitoring |
| **Aikido** | **Vulnerability scanning** |
| **GitHub** | Version control |
| **Vanta** | Compliance monitoring |
| **Instatus** | Status page |

Section 16.1 made Supabase RLS the top priority. That was based on the CSP
allowing `*.supabase.co` plus `wss://`, and on a `createBrowserClient` call found
in an **archived** bundle. Both facts were real, but the conclusion was not:

- The Supabase client appears **only in the archived build**, never in a current
  bundle.
- That archived build used **Supabase Auth**; the current one uses Better Auth.
- The sub-processor list names **PlanetScale** for database hosting.

So they migrated off Supabase, and the `*.supabase.co` CSP entries are **stale
leftovers**. SB1-SB6 are largely moot. Two things survive:

- **SB7 - is the old project still alive?** Project `pcsyssamsygzgixvvxxc` and its
  anon key are published in a bundle the Internet Archive still serves. If that
  project still exists and still holds customer data from the pre-migration era,
  a decommissioned-but-live datastore with a published key is a genuine
  confidentiality finding. Worth one careful check - and the same discipline
  applies: stop at the first sign of real data, retain nothing.
- **The stale CSP entries** are not a finding on their own (excluded as a header
  issue), but they are worth a sentence in any report as evidence of incomplete
  migration cleanup.

**The more important consequence: PlanetScale is MySQL/Vitess, which has no
row-level security.** There is no database-level backstop. Every cross-organisation
check lives in **application code** - the tRPC procedures and Server Actions. A
missing check is therefore a direct cross-org read with nothing behind it to fail
safe. That makes the application-layer authorization tests (C1, C2, P2, M1, W1)
the *primary* path, not a secondary one. Promote them.

## 20.2 NEW SURFACE: Next.js Server Actions

Rendering `/login` and `/signup` shows the client issuing:

```
POST https://na.lithicblue.com/login      <- not a REST endpoint; a Server Action
POST https://na.lithicblue.com/signup
GET  https://na.lithicblue.com/api/auth/get-session
GET  https://na.lithicblue.com/login?_rsc=7h4hBxM0R4J5OFVf
```

Authentication is implemented as **Next.js Server Actions**, POSTed to the page's
own route, not as direct Better Auth REST calls. This also explains the
`createServerReference("7f592e46704fbc2820d016a3c504300…")` found earlier in an
archived bundle - that is a Server Action ID.

Why this matters: a Server Action is an **RPC endpoint reachable by anyone who
knows its ID**. It is invoked by POSTing to any route with a `Next-Action: <id>`
header and the arguments as the body. Consequences to test:

- **SA1 - Direct invocation.** Extract action IDs from the bundles (they appear as
  `createServerReference("<40-hex>")`) and invoke them directly, skipping the UI
  entirely. Every client-side validation is bypassed by construction; the only
  thing left is whatever the action itself checks.
- **SA2 - Authorization inside each action.** Server Actions are a common place
  for missing authorization, because they look like local function calls in the
  source. Enumerate every action and test each as an unauthenticated caller, as a
  Member, and as an Org B user.
- **SA3 - Argument tampering.** Actions receive structured arguments. This is
  where to retry the E1 mass-assignment idea: if an action updates a user or
  member record, add `role` to its argument payload.
- **SA4 - Cross-route invocation.** Action IDs are generally not bound to the
  route that uses them. Try invoking a privileged action's ID while POSTing to an
  unauthenticated page such as `/login` or `/landing`.
- **SA5 - ID stability.** Action IDs are derived at build time, so they are stable
  for a deployment and change when it redeploys. Capture them per region.
- **SA6 - RSC payloads.** The `?_rsc=<token>` requests return React Server
  Component payloads. On a protected route, an RSC payload sometimes contains
  server-rendered data the UI would not display. Request `?_rsc=` variants of
  authenticated routes and read the raw payload rather than the DOM.

Combined with 20.1 - no RLS, all authorization in application code - Server
Actions become the most likely home for a cross-organisation bug in this product.

## 20.3 Tavily changes the research-agent analysis

`Tavily - "Provides LLM-friendly web search results for our agents"`.

The research agent searches via **Tavily's API**, which means **Tavily's
infrastructure performs the fetching**, not LithicBlue's. This refines section
17.5 and downgrades part of R1:

- **Classic SSRF through the research agent is unlikely.** Pointing it at
  `169.254.169.254` or RFC1918 would reach *Tavily's* network, not LithicBlue's -
  and attacking Tavily is attacking a third party, which is out of scope. Do not
  pursue that.
- **The permission-control bypass is still entirely valid, and is the real
  finding.** Tavily's API takes `include_domains` / `exclude_domains` parameters,
  which almost certainly implement Research Controls' "Restrict to domains" and
  "Exclude domains" modes directly. So R5 becomes: **what exactly gets passed to
  Tavily, and who can influence it?** If the personal/organisation merge (15.2) is
  computed client-side or forwarded unsanitised, a Member controls the
  organisation's research filter. Out-of-band confirmation still works - a
  callback to a domain you control proves the filter was widened.
- **SSRF should be hunted in ingestion instead** (ING3): remote content referenced
  by an uploaded email or HTML document, fetched by LithicBlue's own parser, is a
  much more plausible SSRF path than the search agent.

## 20.4 Temporal: authorization at submission versus at execution

`Temporal Technologies Inc. - Workflow management`. Document processing, claim
verification and research runs are long-lived workflows, which is exactly the
shape Temporal exists for.

- **TW1 - Revocation during a workflow.** A workflow authorized at submission
  carries its context forward. Start a long job (upload a large source set, or
  Run Research), then **remove yourself from the project or organisation** while
  it is in flight. Does it still complete? Does its output still land where you
  can read it? Does the result email still arrive? This is the concrete version of
  W7 and a clean finding if authorization is only checked at submission.
- **TW2 - Workflow identifiers.** If a workflow or job ID is exposed to the client
  for status polling, test whether another user's ID can be polled, cancelled or
  signalled.
- **TW3 - Result delivery.** Results are emailed with a link (INT5). Check whether
  completion notifications respect current membership rather than membership at
  submission time.

## 20.5 Signup shape, and other details from rendering

- **`/signup` fields:** `email`, `password` (placeholder "min. 12 characters"),
  `confirmPassword`. **No name and no organisation field** - so organisation
  creation happens after first sign-in, consistent with the first-run flow in
  17.6a. A 12-character minimum is a sensible policy; password-policy suggestions
  are excluded from rewards anyway.
- **`/login` fields:** `email`, `password`. Links to `/forgot-password`, `/signup`.
  Note the rendered login page shows **no Google or Microsoft SSO button** on
  `na`, despite the docs describing Google/Microsoft SSO and Drive settings being
  "only available to Google-identity users". Worth checking whether SSO is
  flag-gated per organisation, and whether the SSO sign-in endpoints are reachable
  directly even where the button is hidden (a UI-only gate is the classic case).
- **Console error:** `na.lithicblue.com/landing?_rsc=…` redirects to
  `www.lithicblue.com/landing` and is then blocked by CORS. A cross-host redirect
  of an RSC fetch - a bug, but a functional one with no security impact. Not a
  finding.
- **PostHog host is `eu-assets.i.posthog.com` even on the NA deployment.** Minor,
  and telemetry is described as anonymised. Not a finding, but note it if you ever
  argue about regional data flow.
- **Aikido provides "vulnerability scanning services".** They run automated
  scanning already. Combined with their exclusion of automated findings, this is
  confirmation that scanner-grade output is worthless here. Logic bugs only.
- **Compliance is achieved, not pending.** The trust centre offers a SOC 2 Type 2
  report and an ISO 27001 certificate dated Jul-2026, while `/docs/security` still
  says they are "actively pursuing" both. Stale documentation, not a vulnerability.
- **Declared data categories** include customer PII, employee PII, **credit card
  information** and **personal health information**. Useful for impact framing: a
  confidentiality breach here is not merely commercial.

## 20.6 Priority order, final

With no RLS backstop, application-layer authorization is everything:

1. **SA1-SA4** Server Action direct invocation and authorization (20.2) - new, and the most likely home for a cross-org bug
2. **E1 / SA3** `role` mass assignment, now also via Server Action arguments (15.6, 20.2)
3. **DWD1/DWD2** Drive domain-wide-delegation impersonation and connection binding (17.3)
4. **C1/C2/P2** object-ID authorization across organisations, including the `projectId`/`fileId` pair and project add-member (6, 15.1)
5. **RC1/RC2** `lb_region` tampering; session cookie domain scope incl. Vanta (16.2)
6. **R5 + 20.3** research-controls merge bypass, confirmed out of band
7. **TW1** revocation during an in-flight Temporal workflow (20.4)
8. **M1/M3** MCP tool object authorization and paid-tier entitlement (8)
9. **O4** cross-region OAuth token/client acceptance (14)
10. **INT1-INT3** verdict tampering, contradiction override, CSV formula injection (17.6)
11. **ING1/ING3** HTML source rendering -> stored XSS; remote content in email/HTML ingestion -> SSRF (17.4)
12. **SB7** whether the decommissioned Supabase project is still live (20.1)
13. **SSO gating** whether hidden Google/Microsoft sign-in endpoints are reachable (20.5)

---

# 21. Server Action inventory - 24 named RPC endpoints

Recovered without an account. `createServerReference` carries the action's
**source function name** as its final argument:

```js
createServerReference("7f592e46704fbc2820d016a3c50430016d10056e07",
                      callServer, void 0, findSourceMapURL, "getUserProfile")
```

So the public bundles give up the complete named server-side RPC surface. 98 IDs
resolve to **24 distinct actions** - roughly four IDs each, one per deployment
(`na`/`eu`/`au`/`www`), confirming SA5: IDs are per-build and rotate on redeploy.
Full ID map in **`lithicblue/server-actions.txt`**.

Invocation shape:

```
POST https://na.lithicblue.com/<any-route>
Next-Action: <action-id>
Content-Type: text/plain;charset=UTF-8

[<arg1>, <arg2>, ...]
```

## 21.1 The inventory

| Action | Category | What to test |
|---|---|---|
| `getCurrentUser` | identity | baseline; compare to `/api/auth/get-session` |
| `getUserProfile` *(legacy)* | identity | archived build - try the old ID (L1) |
| `getProjectsForUser` | read | whose projects? pass another user/org id |
| `getEngagementsForUser` *(legacy)* | read | **legacy naming** - old ID still live? (L1) |
| `getUserEngagement` *(legacy)* | read | as above |
| `getProjectFileCapacity` | read | takes a project id -> cross-org read |
| `getProjectProcessingStatus` | read | takes a project id -> cross-org read |
| **`getPresignedUploadUrls`** | **S3 write** | see 21.2 |
| **`getPresignedUpdateUrl`** | **S3 write** | see 21.2 - *update*, not upload |
| **`getBackendFileUploadUrl`** | **S3 write** | see 21.2 |
| **`getDeliverableUploadUrl`** | **S3 write** | see 21.2 |
| `confirmSourceFileUpload` | upload state | confirm an upload into someone else's project |
| `discardDeliverableUpload` | upload state | discard another project's pending upload |
| `createDeliverableFromUpload` | mutation | create a deliverable in a foreign project |
| **`ensureFolderPaths`** | **path handling** | see 21.3 |
| `createSharedProject` | mutation | a "shared project" concept absent from the docs - investigate what sharing means here |
| `updateProjectSettings` | mutation | settings write as a project Member; cross-org |
| `updateProjectContext` | mutation | as above |
| `saveProjectScope` | mutation | as above |
| `deleteDeliverable` | **destructive** | deleting another org's deliverable = integrity. Test read-only first; confirm authz before any destructive call, and only ever on your own objects |
| `extractProjectDetailsFromUploadedFile` | parsing | the second ingestion pipeline (ING5) |
| `requestScopeQuestionsGeneration` | AI job | triggers generation - cost and authz |
| `retryFailedKAGProcessing` | AI job | re-run the knowledge pipeline on a project id |
| `dismissFailedKAGProcessing` | AI job | dismiss another project's failure state |
| **`clearUserTierCookie`** | **entitlement** | see 21.4 |
| `submitFeedback` | input | stored-XSS sink candidate |
| `submitOfferRequest` | input | ditto; also check for unauthenticated reachability |

Notably **absent**: no organisation, member or invitation actions. That supports
the earlier inference (RUNBOOK 1.6) that org and member management lives in tRPC,
not Server Actions. Capture those from the UI.

## 21.2 Presigned URL generation - the strongest lead in this inventory

Four separate actions mint S3 URLs: `getPresignedUploadUrls`,
`getPresignedUpdateUrl`, `getBackendFileUploadUrl`, `getDeliverableUploadUrl`. The
buckets are `lith-s3-bucket-{na,eu,au}` (16.1), and anonymous listing is correctly
denied - so presigned URLs are the *intended* access path.

**PS1 - Client-supplied object key.** If any of these accepts a key, path or file
id from the caller and signs it without validating that it belongs to a project
you are a member of, you obtain a signed URL for an arbitrary object. Test with an
object identifier from Org B. A signed **GET** is cross-organisation document
disclosure; a signed **PUT** is worse.
**PS2 - `getPresignedUpdateUrl` specifically.** "Update" implies a signed write
over an **existing** object. If the target is caller-controlled, that is arbitrary
overwrite of another organisation's source documents or deliverables - direct
integrity compromise of client advisory material. This is the single highest-impact
item in the inventory.
**PS3 - Scope of the signature.** Inspect the returned URL: is it scoped to one
key, or does it carry a prefix or wildcard? Does it permit `PUT` when only `GET`
was needed? What expiry? Signed URLs with broad prefixes are a common mistake.
**PS4 - Confirm-step trust.** `confirmSourceFileUpload` presumably records that an
upload completed. If it trusts caller-supplied metadata (key, size, type, project
id), you may be able to register a file into a project you do not belong to, or
mislabel what was uploaded.
**PS5 - Bucket crossing.** Each region has its own bucket. Can a presigned URL
request made at `na` be made to sign an object in `lith-s3-bucket-eu`? That is the
cross-region test with teeth.

Keep every test to objects **you** created. A signed URL to someone else's file is
exactly the "come across user data" case - stop and report.

## 21.3 `ensureFolderPaths` - path construction from caller input

The name says it builds folder paths. Folder structures are mirrored from
Drive/SharePoint (ING6), so path strings flow from names you control.

- Traversal sequences (`../`, encoded variants, absolute paths, UNC, null bytes)
  in folder names, aiming at writing outside the intended project prefix.
- Does it create paths in a project id you pass? If the project id is unvalidated,
  this writes structure into another organisation's project.
- Interaction with 21.2: a traversal here plus a presigned URL there is a chain -
  control the prefix, then sign a write to it.

## 21.4 `clearUserTierCookie` - entitlement held in a cookie

This action's existence proves there is a **user tier cookie**, and "tier" means
plan level. Recall `/docs/mcp`: the MCP connector "requires a paid-tier
entitlement" (I7/M3).

- **TC1 - Is the tier cookie trusted?** Find it (alongside `lb_region`), read its
  format, and try forging a higher tier. If any gate reads the cookie rather than
  re-checking the subscription server-side, that is paid-feature access without
  payment, and plausibly MCP connector access.
- **TC2 - Signed or not?** If it is a bare value or unsigned JSON, that is the bug.
  If it is signed, check the algorithm and whether `alg: none` or a weak key is
  accepted.
- **TC3 - Scope.** `lb_region` is `Domain=.lithicblue.com` (16.2). If the tier
  cookie is domain-wide too, it also travels to the Vanta-hosted `trust` subdomain.
- **TC4 - Where it is enforced.** The reliable finding is a *server-side* gate
  reading it. A merely cosmetic UI gate is weaker; pair it with an action call that
  should be paid-only to show real impact.

Frame impact as circumvention of a permission control (their threat model) plus
revenue loss - not merely a cosmetic unlock.

## 21.5 How to work this inventory

1. Extract the **current** action IDs yourself once signed in - the authenticated
   bundles will hold more actions than these 24, and IDs rotate per deployment.
   Re-run the same `createServerReference` regex against the authenticated chunks.
2. For each action, establish the argument shape by triggering it from the UI once
   and capturing the request.
3. Then replay with (a) no session, (b) an Org A **Member** session, (c) an **Org
   B** session, substituting Org A identifiers.
4. Prefer read-only actions first to map authorization cheaply; only use mutating
   actions against objects you own, and never the destructive ones against
   anything that is not yours.
5. Try each action's ID while POSTing to an unauthenticated route such as
   `/login` (SA4) - action IDs are generally not bound to the route that uses them.

---

# 22. Reverse engineering the client bundles

Analysis of the bundles already collected. Minification mangles identifiers but
preserves string literals, property names and control flow, which is enough.

**Scope caveat worth settling.** Their MSA's acceptable-use clause restricts
reverse engineering ("(d) reverse engineer, att…"). That clause binds *Customers*
under an Order Form, and the VRP - a separate document that solicits security
research and demands "original, manual research" - does not list it as excluded.
Reading JavaScript the browser is served is ordinary research practice. Still, add
it to the scope email (19.2): ask whether client-code analysis is acceptable.
Lithero's programme granted this explicitly; LithicBlue's is silent.

## 22.1 The paid-tier gate, decompiled

Two independent call sites, de-minified:

```js
// login redirect logic
let allowed = "paid" === user.userTier || "admin" === user.role;
window.location.href = next || fallback || (allowed ? APP : "/upgrade");

// navigation component
const isPaid = user?.userTier === "paid";
```

So entitlement is `user.userTier === "paid"` **OR** `user.role === "admin"`.

Two consequences:

- **`userTier` is the field name and `"paid"` is the value.** Combined with the
  `clearUserTierCookie` Server Action (21.4), entitlement is cached client-side.
  TC1 now has concrete values to forge.
- **`role === "admin"` also satisfies the paid gate.** So E1 chains: assign
  yourself `role: "admin"` and you get platform admin *and* paid-tier features,
  the MCP connector among them (I7/M3). One field, two escalations.

## 22.2 E1 refined - `userTier` is the better target, and here's why

The bundle contains Better Auth's error table, which includes:

```
FIELD_NOT_ALLOWED            "Field not allowed to be set"
```

That is Better Auth's **field allowlist** rejection. The library only accepts
fields declared in its `additionalFields` config, and only where that declaration
permits client input. So E1 has a precise, binary outcome:

- `FIELD_NOT_ALLOWED` -> the allowlist is doing its job for that field. Note it
  and move on.
- success -> the field was declared client-writable.

**And `userTier` is almost certainly an app-defined `additionalFields` entry**,
whereas `role` arrives from the admin plugin's own schema. App-defined custom
fields are the ones developers routinely declare with input enabled, because they
set them from their own code and forget the client can too.

**So reorder the E1 attempts:**

1. `userTier: "paid"` - most likely to succeed, immediate paid-feature access
2. `role: "admin"` - bigger prize (admin plugin + paid gate), likelier to be blocked
3. `emailVerified: true`, `banned: false` - other plugin-schema fields

Each via every write path: the Better Auth update route, the tRPC user mutation,
**and the Server Actions** (SA3), since an action may not route through Better
Auth's allowlist at all. That last point matters - the allowlist protects Better
Auth's endpoints, not the app's own actions.

## 22.3 The admin console is gated client-side

From the navigation chunk:

```js
const { user } = useAuth();
const isAdmin = user?.role === "admin";
// ... nav items assembled conditionally
```

The admin area's **visibility** is decided in the browser, from a field on the
session object. That is normal for a UI, but it means:

- The `/admin` route exists (it responds differently from a nonexistent path,
  15.5) and its server-side protection is a separate question from this check.
- If `userTier`/`role` is client-writable (22.2), the nav appears - and then the
  only thing standing between you and the admin console is whatever the server
  enforces on those routes and their data loaders.

Test `/admin`, `/admin/users`, `/admin/oauth/clients`, `/admin/custom-providers`
and `/admin/generate_link` directly as a plain Member, and request their `?_rsc=`
payloads too (SA6) - an RSC payload can carry data the component would not render.

## 22.4 Legacy route manifest - 18 routes, ~8 undocumented feature areas

An archived bundle embeds the full client route table with regexes and parameter
names. Saved to **`lithicblue/legacy-routes.txt`**.

```
/articles/:slug                 /chat/:engagementId
/articles/edit/:id              /document_template/:id
/articles/preview/:id           /documents/:id
/documents/edit/:docId          /documents/list/:engagementId
/engagement/:engagementId       /exemplar/:id
/invite/:token                  /kag/:engagementId
/libraries/datagaps/:id         /libraries/persona/:id
/methods/list/:engagementId     /methods/result/:id
/methods/template/:id           /view/:engagementId/:fileId
```

Param names in use: `docId`, `engagementId`, `fileId`, `id`, `slug`, `token`.

Features here that appear in **no published documentation**:

| Route | Feature | Why it matters |
|---|---|---|
| `/chat/:engagementId` | conversational interface over a project | the docs say "ask questions across the documents" but never expose a chat route. Prompt-injection and cross-project context surface. |
| `/methods/list`, `/methods/template`, `/methods/result` | **"methods"** - the structured-analysis methodology | "run structured analysis using your methodology". Templates are user-authored logic; `/methods/result/:id` is an object id to test cross-org. |
| `/libraries/persona/:id` | a **persona** library | AI personas are prompt content. A shared persona library is a cross-tenant prompt-injection vector if personas are shared or ids are guessable. |
| `/libraries/datagaps/:id` | data-gap library | |
| `/exemplar/:id` | **exemplars** - reference deliverables | likely shared across orgs; test whether yours leak or theirs are readable |
| `/document_template/:id` | document templates | template injection candidate; also shared-object risk |
| `/documents/edit/:docId` | in-app document editing | write surface distinct from upload |
| **`/articles/edit/:id`**, `/articles/preview/:id` | **an in-app article CMS** | see 22.5 |

**These are legacy paths** from the pre-rename build, so most will 404 today. Two
things to do with them:

- **RE1** Try each verbatim - legacy aliases sometimes survive a rename (L1), and
  these come with real `:id` parameter positions.
- **RE2** Try each with `:projectId` substituted for `:engagementId`
  (`/chat/<projectId>`, `/methods/list/<projectId>`, `/kag/<projectId>`). `/kag/`
  and `/view/` already carry over to the current build, so the pattern holds. Each
  surviving route is an object-authorization test with a foreign id.

## 22.5 The article CMS is the most interesting legacy find

`/articles/edit/:id` and `/articles/preview/:id` are an **in-application content
editor** for the public marketing site - `www.lithicblue.com/articles` serves four
live posts, and these routes edit them.

Why that is worth real attention:

1. It is a **content-injection surface on a first-party origin**.
2. The CSP (16.3) sets `script-src 'self' 'unsafe-inline' https://*.lithicblue.com`.
   So script injected into a page on any `lithicblue.com` host executes - CSP will
   not contain it.
3. Published articles are read by prospects and customers on the marketing site.

So if the editor's authorization is weak - reachable by an ordinary account, or by
a user in any organisation - the chain is: edit an article -> inject script ->
execute in every visitor's browser on a trusted origin. Test who can reach
`/articles/edit/:id` (and its current-build equivalent), whether preview renders
unsanitised input, and whether article ids are enumerable.

## 22.6 What the Better Auth error table tells us is configured

The full table is in the bundle. Entries worth noting - several are *good* news
and should save you time:

| Code | Reading |
|---|---|
| `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED` - "This request appears to be a CSRF attack" | CSRF protection on login is present |
| `INVALID_ORIGIN`, `MISSING_OR_NULL_ORIGIN` | origin checking is enforced |
| `INVALID_CALLBACK_URL`, `INVALID_REDIRECT_URL`, `INVALID_ERROR_CALLBACK_URL`, `INVALID_NEW_USER_CALLBACK_URL` | redirect/callback validation exists - tempers O1, though the *registration* redirect_uri path is separate and still worth testing |
| `SESSION_NOT_FRESH` - "Session is not fresh" | freshness is required for sensitive operations (relevant to O7) |
| `FIELD_NOT_ALLOWED` | the field allowlist discussed in 22.2 |
| `EMAIL_CAN_NOT_BE_UPDATED`, `EMAIL_MISMATCH`, `VERIFICATION_EMAIL_NOT_ENABLED`, `EMAIL_ALREADY_VERIFIED` | email-change controls exist; A1 should check *which* are actually enabled |
| `USER_ALREADY_EXISTS` / `..._USE_ANOTHER_EMAIL` | **signup discloses whether an email is registered** - account enumeration. Weak alone and arguably below their severity threshold, but it is not in their exclusion list, and it chains (it tells you which addresses belong to a target organisation). Bank it for a combined report under their "several findings in concert" clause. |
| `FAILED_TO_UNLINK_LAST_ACCOUNT`, `USER_ALREADY_HAS_PASSWORD`, `PASSWORD_ALREADY_SET`, `SOCIAL_ACCOUNT_ALREADY_LINKED`, `LINKED_ACCOUNT_ALREADY_EXISTS` | **account linking is enabled** - a surface not in the docs. Account-linking flows are a classic takeover path: link a social account to a victim's record, or pre-link an unverified email. Worth its own test pass. |

**New item - AL1: account linking.** The presence of link/unlink errors means
social account linking exists. Test whether an account can be linked using an
email that is not verified, whether linking is possible to an address belonging to
another user, and whether a linked provider can then authenticate into the
original account. This is how a Google/Microsoft SSO identity can become a path
into an email/password account.

## 22.7 Revised priorities after RE

1. **22.2** `userTier: "paid"` mass assignment, then `role: "admin"` - via Better Auth, tRPC **and** Server Actions
2. **PS2** `getPresignedUpdateUrl` with a foreign object key (21.2)
3. **TC1** forge the tier cookie (`userTier`/`"paid"`) and find a server-side gate reading it (21.4)
4. **DWD1/DWD2** Drive domain-wide-delegation impersonation (17.3)
5. **SA1-SA4** Server Action authorization sweep across the 24 actions (20.2, 21)
6. **RE2** legacy routes re-tried with `projectId` - `/chat`, `/methods`, `/libraries/persona`, `/exemplar`, `/document_template` (22.4)
7. **22.5** article CMS authorization -> stored XSS on a first-party origin
8. **AL1** account linking takeover paths (22.6)
9. **RC1/RC2** `lb_region` tampering; session cookie domain scope (16.2)
10. **C1/C2/P2** object-id authorization across organisations (6, 15.1)
11. **TW1** revocation during an in-flight Temporal workflow (20.4)
12. **R5** research-controls merge bypass, confirmed out of band (15.2, 20.3)

---

# 23. Lateral angles - the bug classes nobody tests on this target

Everything above is conventional application security. This section is the
unconventional surface, and on an AI-native product it is where the least-trodden
ground is. All of it stays inside their stated scope: LithicBlue-owned services
handling sensitive user data, tested from accounts you control.

## 23.1 The consent screen names the client - can you name it "Claude"?

From `/docs/mcp` and `/docs/integrations/claude`:

> "LithicBlue shows an **Approve access** screen **naming the assistant, the host
> it connects back to**, and what it will be able to do… **No OAuth client ID or
> secret is needed; LithicBlue registers itself automatically.**"

Put those two sentences together. The client is created by **open dynamic
registration** (14, O1), and the consent screen **renders the client's name**. In
dynamic client registration the `client_name` is supplied *by the registering
client* - i.e. by whoever sends the registration request.

**LA1 - Consent-screen spoofing.** Register a client with
`client_name: "Claude"` (and a `client_uri` / logo pointing wherever you like),
then send a victim the authorization URL. The approval screen - the single control
protecting this flow - tells them they are approving Claude. The entire security
model of that screen is the name it displays.

Escalate the test:
- Is `client_name` validated, length-capped, or deduplicated against known hosts?
- Is it **HTML-escaped** on the consent page? An injection there is XSS on an
  OAuth consent screen, which is about the worst place to have one.
- Does the screen show the actual `redirect_uri` host, or only the display name?
  If the name is attacker-chosen and the destination is hidden, the screen is
  decorative.
- Combine with `prompt=none` (O2): a trusted-looking name plus silent
  authorisation removes the user from the loop twice over.

This is high-impact, needs only accounts you own, and is a *design* question that
no scanner will ever ask.

## 23.2 Tool poisoning: pivot out of LithicBlue into the victim's assistant

This is the most interesting attack this product makes possible, and it inverts
the usual direction.

The MCP connector lets a user's AI assistant read their projects. The assistant is
Claude, ChatGPT or Copilot - and in those hosts it typically has **other
connectors attached**: the user's email, calendar, code repositories, file stores.

Now recall that **project sources are attacker-influenceable**. A source document
is untrusted text that LithicBlue reads, structures and later returns through MCP
tools as claims, excerpts and citations.

**LA2 - Indirect prompt injection with cross-system reach.** Place instruction
text in a source document. When the victim asks their assistant about the project,
LithicBlue's MCP tools return that text as tool output. Tool output is frequently
treated with more trust than user input. The injected instructions then execute in
a session that holds the victim's *other* connectors.

Impact is not confined to LithicBlue: it is lateral movement from a document into
whatever else the victim's assistant can reach. Test whether:
- claim text, excerpt text, file names, scope requirement text or task titles are
  returned through MCP tools verbatim;
- any sanitisation or delimiting is applied to document-derived content before it
  becomes tool output;
- the write tools (`write_claims`, `add_feedback_comment`, `request_feedback`) can
  be driven by injected instructions - that is injection achieving **state change**
  inside LithicBlue, not just text echo.

How to get a document in front of a victim legitimately: a shared cloud-synced
folder, a project you are both members of, an exemplar or template if those are
shared across organisations (22.4), or anything the invitation flow lets you
contribute to before full membership.

Frame the report in their terms: the confidentiality and integrity of user data,
compromised by content their own pipeline ingests. This class is barely tested
anywhere, and on a product whose entire purpose is reading untrusted documents it
is squarely in scope.

## 23.3 Attack the verifier, not the data

LithicBlue's core promise is that every claim in a deliverable is checked against
sources and labelled verified, contradicted, citation-issue or unverified. Their
criteria pay for compromising the **integrity** of user data. So:

**LA3 - Induce a false "verified".** Craft a source document that causes the
verifier to mark a factually unsupported claim as verified. A consulting
deliverable asserting a false figure with a green "verified, traced to source"
badge is precisely the harm this product exists to prevent, and the client acts on
it.

**LA4 - Induce a false "contradicted".** The inverse: make a correct claim read as
contradicted, so a true finding is removed from a client report.

**LA5 - Win conflict resolution deliberately.** The ontological map "resolves the
conflict before the information is ever used" and explains which source it trusts
(the documented example reasons from recency and sign-off status). Craft a
document that reliably wins - forged dates, apparent authority markers,
sign-off-looking metadata - so your version becomes the resolved truth every later
answer draws on.

For impact, the crafted document must come from somewhere the victim does not
control: a synced folder, a shared library, a co-member. Within your own project
it is a curiosity; crossing a trust boundary makes it a finding.

## 23.4 Economic and quota logic

Not DoS - DoS is excluded. These are *correctness* bugs about money and limits.

- **LA6 - Tier transitions.** Stripe handles payments and `userTier` gates
  features (22.1). Test the edges: cancel a subscription and check whether
  entitlement actually drops; downgrade while a paid workflow is mid-flight
  (Temporal, 20.4); let a trial lapse and see whether `clearUserTierCookie` is the
  *only* thing standing between you and the feature.
- **LA7 - Capacity accounting.** `getProjectFileCapacity` implies a quota. Test
  whether deleting and re-adding, uploading via different actions, or cloud sync
  bypasses the count - and whether capacity is enforced per project while billing
  is per organisation.
- **LA8 - Entitlement at job start versus job run.** A paid-only AI job queued
  while paid, executed after downgrade. Same shape as TW1.

Keep volume minimal. One request proves a logic flaw; a hundred looks like the
DoS testing they exclude.

## 23.5 Watch items - not findings today, serious if they change

Two conditions worth re-checking periodically, because both would become severe
and both are invisible unless you look:

- **LA9 - `trust.lithicblue.com`** is a CNAME to `cname.vantatrust.com` (16.4). If
  LithicBlue ever ends its Vanta subscription while that CNAME remains, the
  hostname becomes claimable. And because the CSP trusts
  `script-src https://*.lithicblue.com` (16.3), control of **any** subdomain means
  script execution on the application's origin. A routine subdomain takeover
  becomes application compromise here.
- **LA10 - `auth.lithicblue.com`** holds certificates in CT logs (12 of them, to
  2026-06) but has **no DNS record** (16.4, 17.1). Nothing to take over today. If
  it is ever re-pointed at an unclaimed provider, the same CSP logic applies.

Re-check both monthly. A one-line note to them about the CSP consequence of
`*.lithicblue.com` being a trusted script source is reasonable now, as hardening
advice rather than a bounty submission.

## 23.6 Human-mediated processes

Some operations are deliberately handled by staff rather than self-service. Those
are rarely threat-modelled.

- **LA11 - Region migration.** "Region changes are handled by our team rather than
  self-service, because they involve migrating your organization's data"
  (`/docs/hosting/changing-region`). A bulk data move between regions, executed by
  a human, touching every object in an organisation. Questions worth asking (do
  not attempt to trigger one against a real tenant): is data readable from the old
  region during or after the move? Do share links, MCP tokens and presigned URLs
  survive it pointing at the old region? Is the source copy deleted? If you can
  get a test organisation migrated, this is an unusually rich target.
- **LA12 - In-region AI processing** is "enabled for your organization on request",
  so it is a per-org flag (`/docs/hosting/data-residency`). Test who can read or
  write that flag - a Member toggling an organisation's data-residency setting
  would be a permission-control circumvention with compliance consequences for
  their regulated customers.
- **LA13 - Dedicated hosting** is offered for firms with isolation requirements
  (`/docs/hosting/regions`). Dedicated tenancy means a separate deployment path -
  worth asking whether those instances are in programme scope at all.

## 23.7 Email as an attack channel

Microsoft 365 handles their mail (16.4), and several flows depend on email.

- **LA14 - Header and content injection in invitations.** You control the invited
  address field. Test newlines, encoded CRLF, long values and display-name
  constructs - and whether your own attacker-controlled strings (organisation
  name, project name, your display name) land unescaped in the HTML of an email
  sent to a third party.
- **LA15 - Invitation-flow identity confusion.** Combine with A1: change your
  account's email to one with a pending invitation elsewhere, then accept.
  Separately, test whether an invitation addressed to `alice@x.com` can be
  accepted by a session belonging to someone else.
- **LA16 - The emailed deliverable link** (INT5) is an authorization decision made
  at send time and exercised later. Check its entropy, whether it works
  unauthenticated, and whether it still works after you leave the organisation.

## 23.8 What I am not going to help with

Worth stating plainly so the boundary is unambiguous:

- Testing assets that are **not** LithicBlue-owned. Tavily, PostHog, Vanta, Vercel,
  PlanetScale, Fly.io, Stripe and Temporal appear in their stack, and their
  sub-processor list tells you so - but they are other companies' systems. Their
  programme excludes third-party services, and their MSA says "Services exclude
  any products or services provided by third parties" (19.1). Hitting a
  sub-processor is not in-scope research.
- The **customers'** Google Workspaces and Microsoft tenants reachable through
  domain-wide delegation. Test LithicBlue's *handling* of delegated access using a
  Workspace you own; never reach into a real customer's tenant.
- Anything against **real customer organisations**, including read-only probing of
  their objects. Their policy: never attempt to access anyone else's data.
- Social engineering of staff, DoS, and the rest of their exclusion list - not
  because they are hard, but because they are explicitly excluded, so they earn
  nothing and cost you the relationship.

The reason to hold this line is practical, not moral. You have eight reports with
this programme. An out-of-scope test is the fastest way to lose that standing, and
with no safe-harbour clause in their terms the legal exposure is personal.

---

# 24. The `x-matched-path` oracle, and three more lateral surfaces

## 24.1 Technique: free route enumeration with no account

Vercel returns an `x-matched-path` response header naming the **internal Next.js
route** that handled the request:

```
GET /project/abc      ->  x-matched-path: /project/[projectId]
GET /admin            ->  x-matched-path: /admin
GET /nonexistent-xyz  ->  x-matched-path: /_not-found
```

Anything resolving to `/_not-found` does not exist; anything else is a real route,
and **dynamic segments come back with their parameter names**. That is a complete
route-enumeration oracle, unauthenticated, one request per candidate. Derive
candidates from the legacy manifest (22.4) and the documentation rather than
brute-forcing a wordlist - targeted probing is research, a wordlist run is the
automated scanning their programme excludes.

## 24.2 The current route table

Confirmed present on `na`:

```
/project                      /projects
/project/[projectId]          /files/[projectId]
/kag/[projectId]              /tasks/[projectId]
/view/[projectId]/[fileId]
/libraries                    /libraries/datagaps/[id]
/settings/organization        /settings/googleDrive
/settings/sharepoint          /account
/upgrade                      /admin
/invite/[token]               /share/[token]
/articles/edit/[id]           /articles/preview/[id]
/addin/auth/done
/api/mcp/[transport]          /api/auth/[...all]
/api/health
```

**Removed since the legacy build** (all `/_not-found` now): `/chat/:id`,
`/engagement/:id`, `/exemplar/:id`, `/document_template/:id`,
`/libraries/persona/:id`, `/methods/list|result|template`, `/documents/*`,
`/admin/users`, `/admin/oauth/clients`, `/admin/custom-providers`,
`/admin/generate_link`. **Do not spend time on those** - the features are gone.
`/admin` itself survives as a single route, so the console is client-routed now.

Three findings from this table:

**RT1 - `/articles/edit/[id]` and `/articles/preview/[id]` are LIVE.** The
in-application article CMS from 22.5 is not a legacy artifact - it is in the
current build. That makes the chain real and current: if authorization there is
weak, you inject content into the public marketing site, and because the CSP sets
`script-src 'self' 'unsafe-inline' https://*.lithicblue.com`, injected script
executes on a first-party origin against every visitor. Test who can reach it,
whether preview renders unsanitised input, and whether article ids enumerate.
**This is now a top-tier item.**

**RT2 - `/libraries/datagaps/[id]` is the odd one out.** Every other object route
carries `[projectId]` in the path - `/files/[projectId]`, `/kag/[projectId]`,
`/view/[projectId]/[fileId]`. This one takes a **bare `[id]`** with no project in
the path at all. If authorization elsewhere leans on the project segment, this
route has to resolve ownership from the id alone, which is exactly where
object-level checks get forgotten. Probe it with ids from your other
organisation. `/libraries` also exists as an index - check what it lists.

**RT3 - `/api/mcp/[transport]` is a dynamic segment.** I tested ten transport
values (`mcp`, `sse`, `http`, `stream`, `streamable`, `ws`, `message`, `messages`,
`rpc`, `v1`) and **all ten return 401 with a proper `WWW-Authenticate` challenge**,
so the gate is uniform and there is no unauthenticated transport variant. Good
hygiene; do not report it. Worth revisiting **with a token**, though: different
transports can take different code paths, and an SSE or streaming handler that
skips a check the main handler applies is a plausible gap.

## 24.3 The Office add-in - genuinely untested ground

`/addin/auth/done` is live, and `frame-src` permits `*.officeapps.live.com` and
`*.sharepoint.com` (16.3). So there is a Word/PowerPoint add-in.

Why this is worth real attention: an Office add-in runs inside the user's
document, has access to **the client material they have open**, and almost no
bounty hunter has ever looked at one.

- **AD1 - The auth completion handoff.** Add-in OAuth typically opens a dialog and
  returns the result to the parent via `Office.context.ui.messageParent()`. That
  call takes a target-origin option; if it is omitted or wildcarded, any page that
  can host the dialog reads the message. Load `/addin/auth/done` directly, read its
  source, and check: does a token arrive in the query string or fragment? Is it
  reflected into the DOM? Is `messageParent` origin-restricted? Is there a
  `postMessage` listener without an origin check?
- **AD2 - The manifest.** Add-in manifests declare `AppDomains` and the source
  location. Find it (the Office store listing, or a `manifest.xml` on their
  domain). An over-broad `AppDomains` entry widens what can be framed; the source
  URL tells you which routes the add-in actually uses.
- **AD3 - Document reach.** Establish what the add-in can read and write in the
  open document, then ask whether any of it crosses a project or organisation
  boundary.
- Note their exclusions bar clickjacking, but a `postMessage` origin failure is
  not clickjacking - it is a token-theft primitive. Frame it that way.

## 24.4 Cache poisoning and deception on Vercel

Caching is demonstrably active, and I already have evidence of a **stale cached
page**: `www/landing` served a CSP naming the **AU** S3 bucket while its
deployment id was **EU**'s (18.3). Headers in play: `x-vercel-cache: HIT|MISS`,
`x-nextjs-prerender: 1`, `x-nextjs-stale-time: 300`.

- **CP1 - Does the cache key include `lb_region`?** That cookie selects a region
  (16.2) and is set on first contact. If a response varies by it while the cache
  key ignores it, a page cached for one region is served to another - cross-region
  content delivery, and a poisoning primitive if any cached page carries
  configuration.
- **CP2 - RSC payload caching.** `?_rsc=<token>` responses are separately
  cacheable. An authenticated RSC payload that lands in a shared cache and is
  served to another viewer would be serious. Check `x-vercel-cache` and
  `cache-control` on authenticated `?_rsc=` requests specifically.
- **CP3 - Cache deception.** Request an authenticated path shaped like a static
  asset (appended `.css`, `.js`, `/x.css`, encoded separators) and see whether the
  CDN caches a private response under a URL an attacker can then fetch.
- **CP4 - Stale configuration.** The `/landing` observation suggests prerendered
  pages can outlive a deployment. Check whether any cached page serves
  configuration that has since rotated - keys, endpoints, CSP, action ids.

## 24.5 Middleware and routing-header manipulation

`x-matched-path` is an internal Vercel/Next routing header. Two tests follow:

- **MW1 - Supply it as a request header.** Send `x-matched-path: /admin` (and
  `/api/...` variants) on a request to `/login` and see whether routing changes.
  On some Next deployments internal routing headers supplied by the client are
  honoured. If it works, it is a routing bypass.
- **MW2 - The middleware-bypass class.** Next.js had a middleware
  authorization-bypass issue in 2025 in which a crafted internal subrequest header
  (`x-middleware-subrequest`) caused middleware to be skipped entirely - a full
  auth bypass wherever authentication is enforced in middleware. **Verify their
  Next.js version before assuming anything**: they build with Turbopack, which
  implies a recent release that is very likely patched. Determine the version from
  the bundles or a Vercel build artifact, check it against the advisory, and only
  then test. If their auth is enforced in middleware and the version is affected,
  this is critical; if patched, drop it immediately.
- Also test whether `x-middleware-rewrite`, `x-invoke-path` or `x-invoke-status`
  style headers are honoured inbound.

## 24.6 Negative results - do not spend time here

Recorded so they are not re-tested:

| Test | Result |
|---|---|
| `?dpl=<other deployment id>` on an asset | **Ignored.** A garbage `dpl_000…` returns 200 too. It is a cache-buster, not a deployment selector - no Vercel skew-protection pinning attack. No `__vdpl` cookie observed. |
| `/_next/image?url=https://example.com/…` | **`400 INVALID_IMAGE_OPTIMIZE_REQUEST`.** Remote patterns are restrictively configured - no arbitrary-host SSRF via the image optimiser. *Narrower test remains:* try the hosts the CSP already trusts (`*.supabase.co`, `*.googleusercontent.com`, the S3 bucket) to see which are in `remotePatterns`, since an open redirect on an allowed host would reopen it. |
| All ten `/api/mcp/<transport>` values | **401 with auth challenge, uniformly.** No unauthenticated transport. |
| `/api/health` | **`204 No Content`**, empty body, no version disclosure. `access-control-allow-origin: *` on an empty response is harmless. Not a finding. |
| Legacy feature routes (`/chat`, `/methods/*`, `/exemplar`, `/document_template`, `/libraries/persona`, `/documents/*`) | **All `/_not-found`.** Features removed. |
| Legacy admin sub-routes (`/admin/users`, `/admin/oauth/clients`, `/admin/custom-providers`, `/admin/generate_link`) | **All `/_not-found`.** Only `/admin` survives. |

## 24.7 Priorities after this pass

1. **22.2** `userTier: "paid"` then `role: "admin"` mass assignment, via Better Auth, tRPC **and** Server Actions
2. **RT1** `/articles/edit/[id]` authorization -> content injection on a first-party origin with `unsafe-inline` CSP
3. **PS2** `getPresignedUpdateUrl` with a foreign object key (21.2)
4. **RT2** `/libraries/datagaps/[id]` - the only object route without a project segment
5. **LA1** MCP consent-screen client-name spoofing, plus escaping on that page (23.1)
6. **LA2** tool poisoning via source documents into the victim's assistant (23.2)
7. **TC1** forge the tier cookie (21.4)
8. **DWD1/DWD2** Drive domain-wide-delegation impersonation (17.3)
9. **CP1/CP2** `lb_region` cache-key and authenticated RSC payload caching (24.4)
10. **AD1** Office add-in auth handoff and `postMessage` origin (24.3)
11. **SA1-SA4** Server Action authorization sweep (20.2, 21)
12. **MW1** inbound `x-matched-path` routing manipulation (24.5)

---

# 25. Curated payload matrix (not a fuzzing wordlist)

**Why not a fuzzer.** Their exclusions bar "any vulnerabilities found using
automated tooling, including automated scanners" and separately bar DoS, rate
limiting and brute force. So fuzzer output is ineligible by rule *and* looks like
the traffic they say they cannot triage. Cloudflare fronts every host, so volume
also risks flagging you on a programme where you already have standing.

**What works instead.** One reasoned value per hypothesis, sent by hand, with the
response read carefully. Six values that each test a different idea beat six
thousand that test one. Everything below is sized to be run in Repeater.

**Rate discipline.** Target under roughly one request per second overall. Never
loop. If a payload needs a second attempt, change the hypothesis, not the volume.

## 25.1 `ensureFolderPaths` - prefix escape

Hypothesis: paths are built from caller-supplied names (mirrored from
Drive/SharePoint folder names, ING6) and joined into an object prefix.

| Value | Tests |
|---|---|
| `../sibling` | plain traversal |
| `..%2fsibling` | traversal after one decode pass |
| `..%252fsibling` | double decode |
| `/absolute/path` | leading-slash prefix escape |
| `a/../../b` | normalisation applied mid-string |
| `folder%00.txt` | null truncation |
| `folder/./././x` | normalisation loop |
| a 2000-char name | length handling, and whether a truncated key collides with an existing object |

Read the **returned key or path**, not just the status. The finding is a path
outside your project prefix, even if the request appears to succeed normally.

## 25.2 Presigned URL actions - object key authority

Hypothesis: `getPresignedUploadUrls`, `getPresignedUpdateUrl`,
`getBackendFileUploadUrl`, `getDeliverableUploadUrl` sign a key derived from
caller input (21.2).

| Value | Tests |
|---|---|
| a `fileId` from **Org B** | the core cross-org check |
| your own id, with `projectId` swapped to Org B's | mismatched-pair validation (C2) |
| a key with `../` in it | prefix escape at signing time |
| a key naming the **other region's** bucket | PS5 cross-bucket |
| a key for an object that already exists | whether "update" overwrites arbitrary objects |
| omit the project field entirely | whether it defaults to something permissive |

Then inspect the **signed URL itself**: which key, which method, what expiry, and
whether the signature covers a prefix rather than one object. A `PUT` where a
`GET` was needed is a finding on its own.

## 25.3 `lb_region` - a client-controlled routing value

Hypothesis: the cookie selects a regional backend (16.2).

| Value | Tests |
|---|---|
| `eu`, `au` | cross-region routing while authenticated to `na` |
| `NA`, `Na` | case handling in the lookup |
| `` (empty) | default-on-missing behaviour |
| `na eu`, `na,eu` | parser confusion |
| `../na`, `na/../eu` | whether it lands in a path |
| `' OR '1'='1`, `${7*7}`, `{{7*7}}` | whether it reaches a query or template |
| a 4000-char value | length handling |
| `xx` (valid shape, nonexistent region) | error behaviour, and whether it discloses backend detail |

The important observation is **which backend answered** - compare response
timing, `x-vercel-id` region, and whether your own data still appears.

## 25.4 Tier cookie - entitlement forgery

Hypothesis: `clearUserTierCookie` implies a tier cookie, and the gate reads
`userTier === "paid"` or `role === "admin"` (21.4, 22.1).

Find the cookie first, then match the payload to its format:

- plain value -> `paid`, `admin`, `enterprise`, `pro`
- JSON -> `{"userTier":"paid"}`, and add `"role":"admin"`
- base64 JSON -> same, re-encoded
- JWT -> try `alg: none`, strip the signature, and an empty-key HS256 sign

Then **call something paid-only** - the MCP connector endpoint with a token, or
whatever `/upgrade` gates - because a cosmetic UI unlock is a much weaker report
than a server-side gate that accepts the forged value.

## 25.5 Object ids - `/libraries/datagaps/[id]` and friends

Hypothesis: the only object route without a project segment resolves ownership
from a bare id (RT2).

First **establish the id format** from your own objects: UUIDv4, cuid, nanoid,
ULID or sequential. That decides whether enumeration is even meaningful, and it is
a one-glance observation rather than a fuzzing problem.

| Value | Tests |
|---|---|
| a real id from **Org B** | the actual authorization check |
| your id with one character altered | error differentiation: 403 vs 404 vs 500 tells you whether existence leaks |
| a valid id of the **wrong object type** | type confusion in the lookup |
| `1`, `0`, `-1`, `00000000-0000-0000-0000-000000000000` | sentinel handling |
| a ULID/sequential id adjacent to yours | only if the format is ordered |

**Do not iterate ids.** If the format is random, enumeration is both useless and
indistinguishable from scanning. The cross-org read with *one* known foreign id is
the whole finding.

## 25.6 `/invite/[token]` and `/share/[token]`

| Value | Tests |
|---|---|
| a cancelled invitation's token | revocation actually applied |
| an expired token | server-side expiry, not just UI |
| a consumed token, replayed | single use |
| a valid token, accepted by a **different** account | email binding (C7) |
| the same token after you were removed from the org | stale authorization (W7) |

Token **entropy** is an observation, not a fuzzing target: collect five, compare
length, charset and structure. If they are short or structured, say so with the
samples; do not try to guess one.

## 25.7 Document-ingestion payloads (stored XSS and parser behaviour)

Hypothesis: HTML is an accepted source type (ING1) and `script-src` carries
`'unsafe-inline'` (16.3).

Upload **one** crafted file per hypothesis, then check every surface that renders
its content: file viewer, excerpt, claim citation, search result, ontological-map
label, generated PPTX/PDF, and MCP tool output.

| File | Tests |
|---|---|
| `.html` with `<img src=x onerror=…>` and `<svg onload=…>` | stored XSS via the HTML source path |
| `.html` referencing `http://<your-collab>/x.png` | SSRF on ingestion (ING3) |
| `.eml` with a remote image and an external CSS link | SSRF in email parsing |
| `.docx` with an XXE external entity in a document part | OOXML XXE |
| `.xlsx` whose cell text begins `=HYPERLINK("http://<collab>")` | CSV formula injection surviving into export (INT3) |
| a `.pptm` macro-enabled file | whether macro-enabled containers take a different path |
| a `.vsdx` Visio file | the least-audited parser they accept |
| filename `<img src=x onerror=alert(1)>.pdf` | filename rendering, a separate sink from content |

Use an out-of-band collaborator for anything SSRF-shaped - a callback is
unambiguous proof and needs exactly one request.

## 25.8 MCP consent-screen `client_name` (LA1)

At dynamic registration, vary one field:

| `client_name` | Tests |
|---|---|
| `Claude` | plain impersonation of a trusted host |
| `Claude ` (trailing space), `Claude`, `Сlaude` (Cyrillic С) | homoglyph and whitespace handling |
| `<img src=x onerror=alert(1)>` | escaping on the consent page |
| 5000 characters | layout truncation hiding the real destination |
| `Claude\n\nApproved by LithicBlue` | newline injection into the rendered text |

Register, then open your **own** authorization URL and screenshot what the consent
screen shows. Never send one of these to anyone else.

## 25.9 Request-header manipulation (MW1)

Send each as a request header to `/login`, one at a time, and watch for routing or
authorization change:

```
x-matched-path: /admin
x-middleware-subrequest: middleware
x-middleware-rewrite: /admin
x-invoke-path: /admin
x-nextjs-data: 1
x-forwarded-host: evil.example.com
x-forwarded-proto: http
```

Check their Next.js version against the 2025 middleware-bypass advisory **before**
reading anything into `x-middleware-subrequest`; on a patched build it is inert.

## 25.10 What not to do

- No wordlist runs: no directory brute force, no parameter mining, no vhost
  sweeps. The route oracle (24.1) already produced the real route table from about
  seventy reasoned requests.
- No credential work: no password spraying, no login brute force, no token
  guessing. Explicitly excluded, and the account-lockout behaviour is documented.
- No volume on AI endpoints. `requestScopeQuestionsGeneration` and
  `retryFailedKAGProcessing` cost them real inference money; repeated calls read as
  abuse, and cost amplification sits close enough to their DoS exclusion that it is
  not worth the risk.
- No iteration over object ids. One foreign id proves the authorization bug.
- Nothing against real customer organisations, at any volume.

---

# 26. Sixth pass - the authorization model is one layer thick

## 26.1 Every page shell is public; all protection is in the data layer

Requested the RSC payload of every protected route unauthenticated. All returned
**200** with ~16-19 KB, and every one carries an identical component set:

```
AuthProvider  TRPCProvider  ToastProvider  ClientPageRoot
OutletBoundary  MetadataBoundary  SpeedInsights  IconMark  Image
```

`/admin`'s payload contains the string **`"Loading admin panel..."`** and a
spinner class. No user data, no server-rendered content, no route-level redirect -
on `/admin`, `/account`, `/projects`, `/project/[id]`, `/settings/organization`,
`/libraries`, `/files/[id]`, `/kag/[id]` or `/tasks/[id]`.

That means:

- **There is no server-side route gate.** Pages are public shells. Authentication
  and authorization happen *after* hydration, when the client calls tRPC and
  Server Actions.
- **`TRPCProvider` is on every route**, confirming tRPC is the data layer.
- **`/admin` is served to anyone**, and its protection is entirely whatever its
  data calls enforce. Combined with 22.3 (the admin nav is gated on
  `user?.role === "admin"` in the browser), the console's *visibility* is a client
  decision and its *data* is the only real control.

**Put this together with 20.1 and the result is the key structural fact about this
target:**

| Layer | Present? |
|---|---|
| Route-level server gate | **No** - shells are public (this section) |
| Application-layer checks in tRPC / Server Actions | **Yes - the only control** |
| Database row-level security | **No** - PlanetScale/MySQL has none (20.1) |

**The authorization model is exactly one layer thick.** Every tRPC procedure and
every Server Action is load-bearing, and a single missing check is a direct
cross-organisation read or write with nothing behind it to fail safe. There is no
defence in depth to catch a mistake.

That is the argument for where to spend your time, and it is also a strong framing
sentence for any report you file: the finding is not "a check was missed in one
place", it is "the only check was missed".

## 26.2 Negative result: no RSC data disclosure

SA6 (20.2) proposed that `?_rsc=` payloads on protected routes might carry
server-rendered data the UI withholds. Tested across nine routes with `?_rsc=1`
and a captured token, with and without an `RSC: 1` header: **every payload is a
shell.** No data leaks this way. Drop SA6 as written.

What survives is narrower and still worth doing **once authenticated**: compare an
authenticated RSC payload against what the UI renders, in case a server component
fetches more than it displays.

## 26.3 CORRECTION: no evidence an Office add-in ships

Section 24.3 built a test plan around an Office add-in on the strength of the
`/addin/auth/done` route existing and `frame-src` permitting
`*.officeapps.live.com`. Examined the route directly: it returns the standard app
shell (307 plus a 23 KB body) with **no Office.js reference, no
`Office.context.ui`, no `messageParent`, no `displayDialogAsync`** and no inline
token handling. Grepping all 185 collected bundles finds only framework-internal
`addEventListener("message")` / `onmessage` usage - React, Next, PostHog and
Sentry all use `postMessage` routinely.

So **AD1-AD3 are speculative**, not grounded. The route may be vestigial, or an
add-in may load its own bundle not referenced from the public app. Treat it as:

- **AD0** - first establish whether an add-in exists at all. Look for a
  `manifest.xml` on their domain, a Microsoft AppSource listing, or any reference
  once you are authenticated. If none, drop the whole thread.

Only if one exists do the original postMessage-origin and document-reach tests
apply. `frame-src` permitting Office origins is also explained by the SharePoint
integration and document viewers, which is the simpler reading.

## 26.4 Minor observations

- `"admissionLimits"` appears as a string in the `/admin` shell payload - an
  unexplained config or feature key. Worth noting what it gates once you can see
  the admin panel.
- `/articles` resolves with an **empty** `x-matched-path`, unlike every other
  route. Probably a rewrite or a route group rather than a normal page. Minor, but
  if `/articles` is handled by a rewrite then its authorization may differ from
  the rest of the app - relevant to RT1 (the article CMS).
- `/addin/auth/done` returns **307** while serving a full body. A redirect with
  content is odd; worth a glance at the `Location` once authenticated.

## 26.5 Updated priority order

Shaped by 26.1 - the one-layer model means data-layer authorization dominates:

1. **22.2** `userTier: "paid"` then `role: "admin"` mass assignment - Better Auth, tRPC, **and** Server Actions
2. **SA1/SA2** Server Action authorization sweep across the 24 known actions - now the primary surface (20.2, 21)
3. **RT1** `/articles/edit/[id]` -> content injection on a first-party origin under `unsafe-inline` CSP (24.2)
4. **PS2** `getPresignedUpdateUrl` with a foreign object key (21.2)
5. **RT2** `/libraries/datagaps/[id]` - the only object route lacking a project segment (24.2)
6. **`/admin` data calls** - the shell is public, so enumerate what it fetches and test each call as a Member (26.1)
7. **LA1** MCP consent-screen `client_name` spoofing and escaping (23.1)
8. **LA2** tool poisoning via source documents into the victim's assistant (23.2)
9. **TC1** tier-cookie forgery (21.4)
10. **DWD1/DWD2** Drive domain-wide-delegation impersonation (17.3)
11. **C1/C2/P2** cross-organisation object ids, including the mismatched-pair case (6, 15.1)
12. **CP1/CP2** `lb_region` cache-key and authenticated RSC caching (24.4)

Dropped or downgraded: SA6 (no RSC disclosure), AD1-AD3 (no evidence of an
add-in), SB1-SB6 (Supabase gone), BD1 (no regional code drift), `?dpl=` pinning,
`/_next/image` arbitrary-host SSRF, MCP transport variants.

---

# 27. SQL injection - honest assessment and the narrow surface worth testing

## 27.1 What the bundles say: nothing

Searched all 185 collected bundles for ORM and driver signatures (Drizzle, Prisma,
`@planetscale/database`, mysql2, Kysely, Knex, Sequelize, TypeORM), raw-SQL escape
hatches (`$queryRawUnsafe`, `executeRawUnsafe`, `sql.raw`, `sql\``), SQL keywords
and database error strings. **Zero hits for all of it.**

That is the correct result - the database layer is server-side only and never
shipped to the browser - but it means the query builder cannot be identified from
outside. The `"select"`, `"query"`, `"cursor"`, `"page"` and `"offset"` strings
that do appear are React props, TanStack Query internals and CSS.

## 27.2 Why classic SQLi is unlikely here - and why that is worth saying

Do not sink days into this. The architecture argues against it:

- **PlanetScale with TypeScript means an ORM**, almost certainly Drizzle or Prisma
  (Better Auth ships adapters for both, and they use Better Auth). Both
  parameterise by default. Injection requires a developer to have reached for an
  escape hatch.
- **The PlanetScale serverless driver executes one statement per request.** Stacked
  queries - `'; DROP TABLE …` - do not work. That removes the entire category most
  payload lists are built around.
- **Vitess is not plain MySQL.** Cross-shard behaviour, partial
  `information_schema` support and rejected constructs make even successful
  injection awkward to exploit.
- **And the real point:** this target's authorization model is one layer thick
  (26.1). A missing check in a tRPC procedure is a cross-organisation read that
  takes one request to demonstrate. That is strictly better use of your time than
  hunting injection behind an ORM. The architecture tells you where the bugs are.

So: test the narrow surface below, bank the result either way, and move on.

## 27.3 Where injection could actually live on this stack

Injection on a parameterised ORM lives in the positions that **cannot** be
parameterised, because those get string-interpolated:

- **`ORDER BY` column and direction.** A column name is not a bindable parameter,
  so it is either allowlisted or concatenated. This is the single most common real
  SQLi in modern TypeScript applications.
- **Column names in dynamic filters.** Same reason.
- **`LIMIT` / `OFFSET`.** Often interpolated as numbers without validation.
- **Full-text search** (`MATCH … AGAINST`) if document search is SQL-backed
  rather than vector-based.
- **Raw escape hatches** - `sql.raw()`, `$queryRawUnsafe` - used for a reporting
  query, an aggregate, or a migration-style operation.

**The concrete known surface: Better Auth's `admin/list-users`.** Confirmed to
exist (401, §15.6). Its documented parameters include `searchField`,
`searchOperator`, `searchValue`, `filterField`, `filterOperator`, `filterValue`,
`sortBy`, `sortDirection`, `limit`, `offset`. Note what several of those are:
**column names and operators** - values that become query *structure*, not query
*data*. Better Auth constrains them, but this is the one endpoint known to accept
structural input.

Test it the moment E1 (22.2) gives you an account that can call it:

```
GET /api/auth/admin/list-users?sortBy=email&sortDirection=asc&limit=10
```

then vary `sortBy` and `filterField` to a non-column value and read the error.

## 27.4 Test method, tuned to their exclusions

Order matters, because one detection method is effectively banned:

1. **Error-based first.** Send a value that would break SQL syntax if
   interpolated - a bare single quote, an unbalanced parenthesis, a backslash - and
   read the response. A 500 with a parse error, or any message naming a column or
   table, is the finding. One request per parameter.
2. **Differential/boolean second.** Compare `sortBy=email` against
   `sortBy=email, (select 1)` and against a nonsense column. Three distinct
   responses - ordered result, same result, error - tell you whether the value
   reaches the query planner.
3. **Do not use time-based blind.** `SLEEP()` and heavy `BENCHMARK()` probing is
   slow, needs many requests, and lands squarely in their exclusions: "denial of
   service attacks, including but not limited to… rate limiting". Even a successful
   time-based finding would arrive looking like the traffic they refuse to triage.
   If a parameter is injectable, error-based or boolean will show it.
4. **Never attempt `UNION SELECT` against real tables** to prove data access. If
   you establish injection, stop there and report the injection point with the
   syntax error as evidence. Pulling rows means pulling their customers' data,
   which their policy forbids outright.

## 27.5 MySQL/Vitess-appropriate probes

A handful of values, each testing one idea. Not a wordlist.

**Structural positions** (`sortBy`, `filterField`, any column-name parameter):

| Value | Tests |
|---|---|
| `email` | baseline, valid column |
| `nonexistent_column` | error shape - does it name real columns? |
| `email,id` | whether a comma-separated list is accepted |
| `email ASC, (SELECT 1)` | subquery acceptance in ORDER BY |
| `(CASE WHEN 1=1 THEN email ELSE id END)` | expression acceptance |
| `` email` `` | backtick-quoting confusion |
| `email--` | comment handling |

**Value positions** (`searchValue`, `filterValue`, and any string filter):

| Value | Tests |
|---|---|
| `'` | the classic syntax break |
| `\` | escape handling, often missed where quotes are filtered |
| `a' OR '1'='1` | boolean, only to compare result counts |
| `a'||'b` and `a' 'b` | MySQL string concatenation behaviour |
| `0x61` | hex literal interpretation |
| `%` and `_` | LIKE-wildcard injection - weaker, but real: it can widen a search past its intended scope |

**Numeric positions** (`limit`, `offset`, `page`, any id expected to be a number):

| Value | Tests |
|---|---|
| `-1`, `0` | sign and zero handling |
| `99999999999999999999` | overflow |
| `1e3` | scientific notation coercion |
| `1 OR 1=1` | unquoted numeric interpolation |

Note `%` / `_` wildcard injection specifically: on a search that filters by
organisation, a wildcard that widens the LIKE pattern is not classic SQLi but can
still return rows beyond the intended scope. That outcome is a
**cross-organisation read**, which is their top tier - so judge the finding by
what came back, not by whether it technically counts as injection.

## 27.6 The more likely injection class on this stack: ORM operator injection

This is where to actually look, and almost nobody does.

Modern ORMs accept **structured filter objects**. If a procedure passes
user-supplied JSON into a `where` clause without validating its shape, a caller can
substitute an *operator object* for a scalar:

```
expected:  { "projectId": "abc" }
sent:      { "projectId": { "not": "" } }          // Prisma
sent:      { "projectId": { "gt": "" } }           // comparison swap
sent:      { "organizationId": { "in": [...] } }   // widen to many
```

The query stays perfectly parameterised - there is no SQL injection - and yet the
filter no longer constrains what it was meant to constrain. On a target whose only
authorization layer is these same procedures, a filter that stops filtering **is**
a cross-organisation read.

**SQLI-ORM1.** For every tRPC procedure and Server Action that takes an id or a
filter, resend it with the scalar replaced by:
`{"not":""}`, `{"gt":""}`, `{"gte":""}`, `{"contains":""}`, `{"in":[]}`,
`{"notIn":[]}`, `{"startsWith":""}`, `{"mode":"insensitive"}`, `null`, `[]`,
`true`, and an array of two ids from different organisations.

**SQLI-ORM2.** Type juggling: send a number where a string id is expected and vice
versa, and send an array where a scalar is expected. Zod will reject a mismatched
type if the procedure validates its input - and the *absence* of a validation error
tells you the procedure does not validate, which is worth knowing on its own.

**SQLI-ORM3.** Extra keys. Add fields the procedure does not expect
(`organizationId`, `userId`, `role`) to its input object and see whether they are
passed through into the query or the write. This is the read-side sibling of the
mass-assignment test in 22.2.

Of everything in this section, **ORM operator injection is the item worth your
time.** It fits this architecture, it needs no raw SQL anywhere, and it produces
exactly the cross-organisation outcome their programme pays most for.
