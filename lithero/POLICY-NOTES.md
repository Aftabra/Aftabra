# Lithero bug bounty - policy constraints

Source: https://www.lithero.com/Documents/BugBountyProgram (terms as of 2026-10-28)
This is my reading of the published terms, not legal advice.

## The critical gap: no defined scope

The terms say "our products" and never enumerate a single domain, subdomain,
IP range, or application. There is **no wildcard authorization**. Consequences:

- Broad `*.lithero.com` enumeration-then-probing is **not authorized** by these
  terms. It is unauthorized by omission, not by prohibition - which is worse,
  because nothing covers you.
- Passive enumeration is still fine: CT logs, passive DNS and Wayback are public
  datasets and send zero traffic to Lithero. Use the results as a *question list*
  for the security team, not a target list.

## Hard constraints from the terms

| Ref | Constraint | Practical effect |
|-----|-----------|------------------|
| §1 | No phishing / social engineering | No credential harvesting, no pretexting staff |
| §1 | Program excludes third-party services; "we do not endorse attempted hacking on third party services" | Any subdomain CNAME'd to a SaaS vendor is OFF LIMITS. Check CNAMEs before touching a host. |
| §3a | No access to data or property you do not own | No cross-tenant access with real users' data. Use two accounts you control. |
| §3b | Must not affect other users; "adverse effects solely impacting you are allowed" | No load testing, no destructive fuzzing on prod, careful with races on shared state. Self-impacting tests are explicitly permitted. |
| §4 | No disclosure until patched | No writeups, no tweets, no Discord screenshots. Bounty eligibility dies on disclosure. |
| §5 | Reverse engineering permitted ONLY during good-faith research intended for responsible report | Decompiling a client is allowed if you report it. Not a general license. |
| §6 | Comply with all applicable law | No CFAA/CMA-equivalent waiver. See below. |
| §8 | First report wins, via email to security@lithero.com | No public dupe queue - you cannot see what is taken |

## No safe harbor

There is no clause promising not to pursue legal action for good-faith research.
§5 is a narrow carve-out for reverse engineering, conditioned on staying inside
these terms; §6 affirmatively requires legal compliance. Treat authorization as
limited to what they confirm in writing.

## Why your dupe rate is high

Email-only intake with no public disclosure means zero visibility into what has
already been reported. Breadth-first hunting on a program like this is a lottery.
Depth wins instead:

1. Authorization logic across two accounts you own (permitted by §3a/§3b).
2. Multi-step business logic in the core product flow.
3. Client decompilation + source review (explicitly permitted by §5).
4. New features - code shipped this week has had the fewest eyes.

## Also missing from the terms (worth asking about)

- Reward ranges / severity table - awards are "sole discretion" with no floor
- Triage SLA - nothing stated, so your pending reports have no defined clock
- Automated scanning policy - neither permitted nor forbidden; assume forbidden
- Test account provisioning
- Whether disclosure is allowed *after* patching, and on what timeline
