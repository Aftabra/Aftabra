# Draft: scope clarification to security@lithicblue.com

Send as plain text. No attachments. Keep it short - they have a 2-working-day
acknowledgement SLA and a stated dislike of noise.

---

To: security@lithicblue.com
Subject: Scope clarification before further testing - existing reporter

Hello,

I have submitted several reports to this address and am continuing research on
LithicBlue. Before going further I would like to confirm four boundary questions,
so my testing stays clearly inside your programme.

**1. Infrastructure on third-party hostnames.** Your criteria cover "a web service
owned by LithicBlue that handles sensitive user data, e.g. properties hosted on
https://*.lithicblue.com". I read "e.g." as illustrative. Does the programme
therefore cover LithicBlue-owned infrastructure that is not under that domain -
for example your object storage, or a data store reached directly from the browser?
I will not test anything on a third-party hostname until you confirm either way.

**2. Sub-processors are out, I assume.** Your trust centre lists your
sub-processors. I am treating all of them as out of scope, and will not send
traffic to any of them. Please correct me if any is considered part of your own
attack surface.

**3. Connected cloud storage.** Your Google Drive and SharePoint integrations rely
on domain-wide delegation and tenant-wide admin consent respectively. I would like
to test *LithicBlue's* handling of that delegated access - whether your per-user
permission enforcement holds - using a Google Workspace and a Microsoft tenant that
I own, connected to organisations I created. I will not touch any other customer's
tenant. Is that acceptable?

**4. Client-code analysis.** Your MSA restricts reverse engineering for customers
under an Order Form. Analysing the JavaScript you serve to browsers is ordinary
security research and I assume it is not what that clause is aimed at, but I would
rather ask than assume.

Two practical requests:

- **Test accounts, or confirmation I may self-provision.** The issues your threat
  model prioritises - cross-organisation access and within-organisation
  escalation - need two organisations and several roles to demonstrate safely. I
  plan to register them myself unless you would prefer to provision them.
- **An identifying marker.** I am sending a descriptive User-Agent and can add any
  header you like, so your team can distinguish my traffic from a real attack. Let
  me know what you prefer.

For completeness: I am testing manually, at low request rates, with no automated
scanners, and I will not attempt to access any data that is not mine. If I
encounter real customer data I will stop, report it immediately, and retain
nothing.

I also have reports currently open with you. I am not asking to jump the queue -
only to know roughly when a follow-up would be appropriate rather than noise.

Thank you,
<name> / <handle>
<contact>

---

## Why each question is worth asking

1. **Question 1 is the valuable one.** Their object storage and data layer are
   where the highest-severity issues would live, and the hostname technicality is
   the only thing making it ambiguous. A written yes materially widens what you can
   work on; a written no saves you from testing something unrewardable.
2. **Question 2 costs nothing and buys credibility.** Volunteering that you treat
   sub-processors as out of scope signals you understand the boundary, which makes
   the answer to question 1 more likely to be generous.
3. **Question 3 unlocks the highest-impact surface** - delegated-access handling -
   with an explicit commitment never to touch a real tenant.
4. **Question 4 removes an MSA argument** before it can be used against a report.

The test-account request matters most for actually finding things: without two
organisations, the bug classes they pay for cannot be demonstrated at all.
