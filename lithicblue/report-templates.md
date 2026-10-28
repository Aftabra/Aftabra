# Report templates

Their reward scale is explicit about what moves the number:

> **Quality of Report** - "a clear PoC (ideally with video or screenshots),
> demonstration of impact/severity, provision of any necessary details to reproduce."
> **Severity** - "the scale of the compromise to confidentiality or integrity of
> user data **in the context of LithicBlue's business goals and customer
> commitments**."
> **Impact** - "the scale of the affected users or aspects of LithicBlue's business."

And two clauses that change how you write:

> "Rewards will be lower where exploiting an issue depends on **pre-existing access
> or a prior breach that is outside our control**… We assess each issue on the
> realistic difficulty of achieving compromise **from the position of an
> unaffiliated attacker**."

> "We may decide at our discretion to reward a **later report if the first report
> is of insufficient quality** to enable effective remediation."

So: always state your starting position explicitly, and write well enough that a
duplicate can still win.

**House rules for every report below**
- Lead with impact in one sentence, before any mechanism.
- State the starting position in the second sentence: "an unaffiliated attacker
  with only a self-service account" beats leaving it implicit.
- Number the repro steps. Include exact requests. Redact any data that is not yours.
- One vulnerability per email, unless you are deliberately using the
  "findings in concert" clause (template E).
- Name the affected region(s) and say whether you verified the others.
- Offer the fix. It costs two lines and it demonstrably speeds triage.

---

## Template A - Cross-organisation access (their highest tier)

```
Subject: Cross-organisation data access via <component> (<region>)

## Summary
An authenticated user of one organisation can read <data> belonging to any other
organisation, via <endpoint/action>. The starting position is a self-service
account with no relationship to the target organisation.

## Impact
<Data class> for arbitrary organisations is readable by any registered user.
Given LithicBlue's customers are advisory firms storing client deal material,
this exposes <board packs / financial models / engagement deliverables> belonging
to third parties. This is the "access to information or resources in an arbitrary
organization" category in your published threat model.

## Affected
- Region(s) verified: na / eu / au
- Component: <route, Server Action id, or tRPC procedure>
- Authorization required: <none | any account | org Member>

## Reproduction
Two organisations, both created by me:
  Org A - <id>, owner a-owner@<domain-one>
  Org B - <id>, owner b-owner@<domain-two>

1. As Org A owner, create <object>. Note its id: <id>.
2. Sign in as Org B owner (no relationship to Org A).
3. Send:
       <exact request, headers and body>
4. Observed: HTTP 200 with Org A's <object>. Expected: 403.

Evidence: <screenshot/video>. Org A's data is redacted in the attachment; the
response structure is visible and the record count is shown.

## Root cause (as far as I can tell from the outside)
<endpoint> appears to resolve <object> by id without verifying the caller's
organisation membership. Note that your page shells are served without a
server-side gate and your datastore has no row-level security, so this check
appears to be the only control on this path.

## Suggested fix
Verify that the requested <object>'s organisation matches the caller's active
organisation, server-side, in <endpoint>. If object ids are resolved in a shared
helper, the check belongs there so sibling endpoints inherit it.

## Disclosure
Not disclosed anywhere. I hold no copy of any data belonging to your customers.
No other organisation's objects were accessed during testing.
```

---

## Template B - Privilege escalation within an organisation

```
Subject: Organisation Member can escalate to <role> via <field/endpoint>

## Summary
A user holding the lowest organisation role (Member) can obtain <Admin/Owner/
platform admin> privileges by <mechanism>, in a single request.

## Impact
Per your documentation, Members "view the organization and its resources. No
settings or member management." After this request the account can <list the
capabilities actually gained - member management, settings writes, access to
every project, paid-tier features>. This is "member-to-admin escalation" from
your threat model.
<If it reaches platform admin, say so here and stop - that crosses into
cross-organisation territory and should be stated as the higher severity.>

## Reproduction
1. Register an account and have it invited as a **Member** of an organisation.
2. Baseline - GET /api/auth/get-session -> role is <x>. GET <admin endpoint> -> 401.
3. Send:
       <exact request>
4. GET /api/auth/get-session -> role is now <y>.
5. GET <admin endpoint> -> HTTP 200 (previously 401).

I stopped at step 5 and did not use the privileges obtained. I reverted the
change afterwards.

## Why this is reachable by an unaffiliated attacker
Membership of an organisation is obtainable by invitation in the ordinary course
of business; no prior breach or pre-existing elevated access is assumed.

## Suggested fix
Exclude <field> from client-writable input on <endpoint>. If it is declared as an
additional field on the user model, set it non-writable from the client and set it
only from server-side code paths.
```

---

## Template C - Circumvention of a permission control

```
Subject: Organisation-level <control> can be overridden by a Member

## Summary
<Control> is documented as an organisation-wide setting editable only by owners
and admins. A Member can <widen/bypass> it by <mechanism>, defeating the control
for their own activity.

## Impact
<Control> exists so firms can constrain <behaviour> to their policy. A Member
overriding it means the organisation's stated policy is not enforced - relevant
to your regulated customers, who rely on this for compliance rather than
convenience. This is "circumvention of permission controls" from your threat model.

## Reproduction
1. As owner, set <control> to <restrictive value>. Confirm it applies.
2. As a Member, send:
       <exact request - note that the UI does not offer this>
3. Trigger <the behaviour> via <exact action>.
4. Observed: <out-of-band evidence - e.g. a request arriving at a host I control,
   with timestamp and source>. Expected: blocked by the organisation policy.

Out-of-band evidence is included because it proves the control was bypassed
without relying on interpretation of the UI.

## Suggested fix
Compute the effective policy server-side as the intersection of organisation and
personal settings, and reject any personal setting that widens the organisation's.
```

---

## Template D - Integrity

```
Subject: <Claim verdicts / deliverable content> can be altered by <actor>

## Summary
<Actor> can modify <object>, changing what a client-facing deliverable asserts.

## Impact
Your product's value proposition is that every claim in a deliverable is verified
and traceable to a source. An attacker who can <flip a verdict / alter a
contradiction resolution / overwrite a source document> causes a false statement
to carry your "verified" marking into a client report. The advisory firm and its
client both act on that. This is a compromise of the **integrity** of user data,
which your criteria cover alongside confidentiality.

## Reproduction
1. <setup>
2. <the modifying request>
3. Observed: the deliverable now shows <false state>, marked <verified>.
4. Screenshot of the rendered deliverable showing the altered verdict.

## Suggested fix
<specific>
```

---

## Template E - Several findings in concert

Use this deliberately, invoking their own clause:

> "Extremely narrow bugs may fall below the threshold… However, several such
> findings discovered and reported in concert may be considered together where
> they collectively demonstrate meaningful severity or impact."

```
Subject: Chained low-severity issues yielding <outcome> (3 findings, reported together)

## Summary
Individually each of the three issues below is narrow. Chained, they let an
unaffiliated attacker <concrete outcome>. I am reporting them together per your
"findings in concert" provision rather than as separate low-severity items.

## The chain
Step 1 - <finding 1>: <one line>. Alone: informational.
Step 2 - <finding 2>: <one line>. Alone: low.
Step 3 - <finding 3>: <one line>. Alone: low.
Combined: <outcome, stated as impact on confidentiality or integrity>.

## Reproduction of the full chain
<numbered, end to end, as one attack - not three separate repros>

## Then each finding separately
### Finding 1 - <title>
<repro, impact alone, suggested fix>
### Finding 2 ...
### Finding 3 ...

## Note
If you would prefer these as separate reports, say so and I will resubmit. I
judged the chain to be the honest representation of impact.
```

---

## Before you send anything

- [ ] Reproduced twice, from a clean session
- [ ] Verified on the other two regions, and said which
- [ ] Every identifier in the report is from an organisation you created
- [ ] No customer data retained; attachments redacted
- [ ] Starting position stated explicitly
- [ ] Impact written in terms of *their* customers' material, not generic severity
- [ ] A fix suggested
- [ ] Checked it is not in their exclusion list
- [ ] Not disclosed anywhere, and will not be until patched (their clause 4 equivalent)
