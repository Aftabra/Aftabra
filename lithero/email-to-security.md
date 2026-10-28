# Draft: scope clarification request

To: security@lithero.com
Subject: Scope clarification request - bug bounty program (existing reporter)

---

Hello,

I have submitted several reports to this address over the past weeks and am
continuing security research on Lithero. Before I go any further I would like to
confirm the boundaries, so that my testing stays clearly inside your terms.

The published terms reference "our products" without enumerating assets, so I
would be grateful for written confirmation on the following:

**1. Assets in scope.** Which domains, subdomains and applications are in scope?
Specifically, is the program limited to the main web application, or does it
cover other subdomains of lithero.com? Are mobile or desktop clients, if any,
included?

**2. Third-party-hosted assets.** Section 1 excludes third-party services. Where
a Lithero subdomain is hosted by an external vendor, I will treat it as out of
scope unless you tell me otherwise. Please confirm.

**3. Automated testing.** Is automated scanning or crawling permitted against
in-scope assets? If so, at what request rate, and would you like me to send an
identifying User-Agent or header so you can distinguish my traffic from real
attacks? If automation is not permitted, I will test manually only.

**4. Test accounts.** A number of the highest-impact issues in a multi-tenant
product are authorization flaws, which require two or more accounts under
different tenants to demonstrate safely. Could you provision test accounts, or
confirm that I may register them myself? This lets me prove impact without ever
touching another customer's data.

**5. Triage status.** I have reports currently pending. Is there an expected
review timeframe? I am not asking to be prioritised, only so that I know when a
follow-up would be appropriate rather than noise.

**6. Disclosure.** Section 4 requires non-disclosure until patched. After a fix
ships, is public write-up permitted, and is there a waiting period or an approval
step?

I will restrict testing to my own accounts and avoid anything that could affect
other users, per section 3. If you would prefer I pause active testing until
scope is confirmed, I am glad to do so - just say.

Thank you,
<your name> / <your handle>
<your contact>

---

## Why each question matters

- **1 & 2** - the terms give no asset list, so right now nothing is explicitly
  authorized. Their answer is what makes your testing defensible.
- **3** - automation is neither permitted nor forbidden. Asking turns ambiguity
  into permission, and an identifying header keeps you from tripping their
  incident response.
- **4** - this is the real prize. Test accounts unlock cross-tenant authorization
  testing, which is the bug class with the lowest duplicate rate and the highest
  severity, and §3a otherwise bars you from touching data you do not own.
- **5** - sets expectations without nagging.
- **6** - lets you build public reputation from this work later.

Send it as plain text, keep it short, do not attach anything.
