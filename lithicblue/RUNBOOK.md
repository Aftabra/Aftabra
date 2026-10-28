# LithicBlue - setup and E1 runbook

Companion to `TEST-PLAN.md`. Part 1 builds the account topology every test in the
plan depends on. Part 2 is the step-by-step for **E1**, the highest-value lead:
self-assigning `role` to reach Better Auth's admin plugin.

**Rules for the whole exercise.** Only accounts and organisations you created.
Never authenticate into, read from, or modify a real customer's organisation. If
you encounter real user data, stop immediately, report it, and retain nothing -
that is their stated requirement. All of this is manual testing in a proxy; do
not point a scanner at any of it, because their program excludes findings from
automated tooling.

---

# Part 1 - Two-organisation setup

## 1.1 Pick one region and stay on it

`na`, `eu` and `au` are separate deployments with separate OAuth issuers. Do all
baseline testing on **one** host so results are comparable, then use the second
region only for the deliberate cross-region tests (O4, C5). Record which you chose.

## 1.2 Email addresses

Use **two genuinely different domains**, not plus-addressing on one. Two reasons:
plus-addressing can be normalised or stripped server-side, which muddies results;
and distinct domains let you test domain-based auto-join (C9) in a controlled way.

| Account | Purpose |
|---|---|
| `a-owner@domain-one.tld` | Org A owner |
| `a-admin@domain-one.tld` | Org A admin |
| `a-member@domain-one.tld` | Org A member |
| `b-owner@domain-two.tld` | Org B owner - the "unaffiliated attacker" |
| `spare@domain-three.tld` | Unaffiliated, no org - for invitation and email-change tests |

Keep every mailbox reachable; invitation, verification and reset flows all need it.

## 1.3 Build the topology

1. Sign up `a-owner` via `/signup`. Note whether an organisation is created
   automatically or you create one, and whether email verification is enforced
   before you can do anything.
2. From Org A: Settings -> Organization -> Members -> Invite Member. Invite
   `a-admin` as **Admin** and `a-member` as **Member**. Accept both from their
   mailboxes.
3. Sign up `b-owner` separately to create **Org B**.
4. In Org A create two projects:
   - **Project 1** - add `a-admin` and `a-member` as project members.
   - **Project 2** - `a-owner` only. This is what separates *org* membership from
     *project* membership and makes P5/W5 testable.
5. In Org A, set a project role matrix on Project 1: make `a-admin` a project
   **Member** and `a-member` a project **Admin**. Deliberately inverting the org
   roles exposes any code that conflates the two dimensions.
6. In Org B create one project with one file, so you have a foreign object graph
   to aim at.

## 1.4 Capture this before testing anything

Keep a scratch file. You will need these constantly.

- Every user ID, organisation ID, member ID, project ID, file ID, invitation ID
  and share token you can see, labelled by which org it belongs to.
- The exact shape of a successful authenticated request: full URL, method,
  headers, cookies, body.
- A `GET /api/auth/get-session` response for each of the five accounts. **Save
  these verbatim** - the baseline `role` value is what E1 compares against.
- Where member/invite operations actually go. Watch the network tab while you
  invite someone and while you change a role. Expect `/api/trpc/...`; see 1.6.

## 1.5 Burp setup

- Scope: `*.lithicblue.com` only. Nothing else, so you never stray off-program.
- Keep each account in its own browser profile or container so cookie jars don't
  mix. Mixing them produces false negatives that look like fixed bugs.
- Turn **off** any active scanning, Intruder-style fuzzing and extension
  auto-scans. Their exclusions bar automated findings and brute force.
- Set a custom header so their team can identify you, and keep it on every
  request: `X-Bug-Bounty: <your-handle>`. Worth asking them whether they prefer a
  specific marker.
- Repeater is the main tool. Use "Request in browser" to replay in another
  session cleanly rather than hand-editing cookies.

## 1.6 Find the real routes first - do not assume

Evidence from unauthenticated probing of `na`:

```
GET /api/auth/admin/list-users             -> 401, empty body          (exists, gated)
GET /api/auth/list-sessions                -> 401 {"code":"UNAUTHORIZED"}
GET /api/auth/oauth2/userinfo              -> 401 {"error":"invalid_request"}
GET /api/auth/organization/list            -> 404, empty body
GET /api/auth/organization/get-full-organization -> 404, empty body
nonexistent path                           -> 48 KB Next.js 404 page
```

Read those carefully:

- A **48 KB HTML 404** means Next.js never routed it to Better Auth. The path
  genuinely isn't handled.
- An **empty-body 404** came *from* Better Auth - either the route isn't
  registered, or it is but rejects your HTTP method. Better Auth's `list-users` is
  GET, so its 401 is meaningful. `impersonate-user`, `set-role`, `update-user` and
  friends are POST, so a GET to them tells you nothing either way.
- `organization/list` **is** a GET route in the org plugin, and it returned an
  empty 404. So the organization plugin's default routes look **unregistered**,
  even though the product clearly has organisations with Owner/Admin/Member.

The practical consequence: **org and member operations are probably implemented in
their own tRPC layer, not Better Auth's org plugin.** So before testing W1-W8 and
P1-P5, capture the real calls from the UI. Don't burn time on
`/api/auth/organization/*`.

tRPC request shapes you'll be replaying:

```
# query (GET), batched
GET /api/trpc/<router>.<procedure>?batch=1&input={"0":{"json":{...}}}

# mutation (POST), batched
POST /api/trpc/<router>.<procedure>?batch=1
{"0":{"json":{ ...input... }}}

# single, unbatched
POST /api/trpc/<router>.<procedure>
{"json":{ ...input... }}
```

The bundles reference `trpc-accept` handling, so streaming/jsonl responses are
supported. Once you can see one authenticated tRPC call, the authenticated bundle
gives you the full procedure list - that is the moment the whole plan opens up.

---

# Part 2 - E1: role mass assignment to admin plugin

**Hypothesis.** Better Auth's admin plugin derives admin status from the user's
`role` field unless the app configures an explicit `adminUserIds` allowlist. If
any user-writable update path lets `role` through, an ordinary member can make
themselves an admin, then reach the plugin's routes - including
`impersonate-user`, which would mean a session as any user in any organisation.

**Why it's worth doing first.** It's cheap to test, it's a single field, and if it
lands it is simultaneously member-to-admin escalation *and* cross-organisation
access - both halves of their published threat model, at the top reward tier.

## Step 0 - Baseline

Use `a-member@domain-one.tld`, your lowest-privilege account.

```
GET /api/auth/get-session
Cookie: <a-member session>
```

Save the response. Note whether a `role` field is present at all, and its value
(commonly `"user"`, or absent). Also confirm the gate is closed before you start:

```
GET /api/auth/admin/list-users
Cookie: <a-member session>
```

Expect `401`. If this returns data **before** you change anything, stop - a
non-admin reading the full user list is already the finding. Document it and
report; don't go further.

## Step 1 - Find every path that writes to your user record

From the UI as `a-member`, perform and capture each of:

- Account Management -> change **Name**, Save Changes
- change **Phone**, Save
- change **Email** (see A1 - note whether verification is required)
- Preferences -> save Web Search Settings
- any avatar/image upload
- project-level and org-level settings saves that are allowed to a Member

For each, record the exact endpoint and body. Candidates will be
`POST /api/auth/update-user`, `POST /api/auth/change-email`, or tRPC procedures
such as `user.update` / `account.update` / `profile.update`. You need the real
ones, not guesses.

## Step 2 - Try to write `role`

For every writable path found in Step 1, replay the legitimate request with
`role` added. Change nothing else, so a 200 is unambiguous.

Better Auth core shape:

```
POST /api/auth/update-user
Content-Type: application/json
Cookie: <a-member session>

{"name":"Member A","role":"admin"}
```

tRPC shape:

```
POST /api/trpc/user.update
Content-Type: application/json
Cookie: <a-member session>

{"json":{"name":"Member A","role":"admin"}}
```

Work through these variants one at a time:

| Variant | Body fragment |
|---|---|
| direct | `"role":"admin"` |
| array form | `"role":["admin"]` |
| case | `"role":"ADMIN"`, `"Admin"` |
| nested data bag | `"data":{"role":"admin"}` |
| alternate names | `"userRole"`, `"roles"`, `"isAdmin":true`, `"admin":true` |
| adjacent flags | `"banned":false`, `"emailVerified":true`, `"impersonatedBy":null` |
| admin-plugin route | `POST /api/auth/admin/set-role` with `{"userId":"<your own id>","role":"admin"}` |

That last row matters: `set-role` taking **your own** user ID is still a
privilege-escalation test, and it does not touch anyone else's account.

Interpreting responses:

- **200 and the field echoes back** - go to Step 3.
- **200 but `role` absent from the response** - inconclusive. The field may have
  been silently dropped, or persisted without being returned. Step 3 settles it.
- **400 / 422 with a validation error naming `role`** - the field is known and
  rejected. Good sign for them; note it and move on.
- **403** - there's an authorization check. Note the message.
- **Empty-body 404** - Better Auth handled it but that route/method isn't there.
  Re-check the method; don't conclude anything.

## Step 3 - Verify, don't assume

A 200 proves nothing on its own. Confirm with two independent reads:

```
GET /api/auth/get-session
Cookie: <a-member session>
```

Compare the `role` value against your Step 0 baseline.

```
GET /api/auth/admin/list-users
Cookie: <a-member session>
```

**This is the real oracle.** It returned 401 at baseline. If it now returns user
data, the escalation is real and demonstrated - a plain organisation Member
reading the platform-wide user list.

Also re-check after signing out and back in: some apps hold role in the session
and refresh it on login, so an escalation may only appear on a fresh session.

## Step 4 - If it lands, stop

The moment `admin/list-users` answers, you have a complete, reportable finding.
Do not continue into `impersonate-user` against anyone else, do not page through
the user list, do not retain what you saw.

Capture only what proves it:

1. Step 0 `get-session` showing the baseline role, and the 401 from `list-users`.
2. The single request that wrote `role`, and its response.
3. Step 3 `get-session` showing the changed role.
4. The 200 from `list-users` - **redact the user data in your report**, show the
   status line and just enough structure to prove it returned records.
5. A short note that the admin plugin's route set would, if registered, include
   `impersonate-user`, and that you deliberately did not exercise it.

Then reverse what you changed: set `role` back to its baseline value, and delete
the test accounts once they've confirmed.

Impact statement to include, in their language: an ordinary organisation Member
can obtain platform administrator privileges, which permits access to information
and resources belonging to arbitrary organisations - their stated high-severity
category - from the position of an unaffiliated attacker who merely holds a
self-service account.

## Step 5 - If it doesn't land

Don't over-invest. Record which paths rejected `role` and how, then move down the
priority list. Next three in order:

- **R5** - research-controls personal/organisation merge (plan 15.2). Member
  under an org allowlist attempting to widen rather than narrow. Submit the
  setting straight to the API, since the "you can only disable" constraint is
  most likely enforced in the UI.
- **P2** - project add-member with a user ID from Org B (plan 15.1). Run it both
  directions: pull a foreign user into your project, and add yourself to theirs.
- **O4** - cross-region token acceptance (plan section 14). Token from `eu`,
  presented to `na`'s `/api/mcp/mcp`.

## Step 6 - Chain anything below threshold

Their policy: "several such findings discovered and reported in concert may be
considered together where they collectively demonstrate meaningful severity."
Keep a running list of small things - a field that shouldn't be writable, an
expiry not enforced, a token that outlives a removal. Three of those composing
into one attack is a single good report rather than three rejections.
