# RuleForge — Concepts

What this product is, what problem it solves, and why it works the way it does — written for
someone meeting the problem for the first time. The command reference is in the README; this
is the reasoning behind it.

*Hexward Labs · Nizar Tuanku — Cybersecurity. · last reviewed 6 September 2026*

---

## Why firewall migrations frighten the people who have done one
Companies replace firewalls for ordinary reasons: the hardware reaches end of support, the vendor changes, a contract ends. Management takes the decision in a single meeting.
What does not come up in that meeting: the old firewall carries a rule base — the list of rules about who may talk to whom — written by seven different people over nine years. Most of the authors no longer work there. Nobody knows exactly why rule number 43 exists.

Moving it to a new device is not copying a file. Every vendor has its own shape for concepts that are the same in principle, and some concepts on one vendor have no equivalent on another.
## Why the vendor's own tool is not enough
Every vendor ships a migration tool, and all of them run one way — into their own product:
- Cisco FMT only converts into FTD
- FortiConverter only into FortiGate
- SmartMove only into Check Point
- Palo Alto Expedition was discontinued in January 2025
That makes sense from their side of the business: the tool exists to help you in, not to help you go anywhere.
The problem appears when you need a direction no vendor wants — FortiGate to Palo Alto, say, or checking whether a move from ASA to Check Point makes sense before you commit.
## The part people most often misunderstand
Conversion tools are usually judged by what percentage succeeded. That number sounds reassuring and is almost useless.
Take one real job we measured — Cisco ASA to Palo Alto PAN-OS:

| Outcome | Rules |
|---|---|
| Converted successfully | 130 |
| Partially converted | 6 |
| Needs a human decision | 10 |

What decides whether cut-over night succeeds or fails is not the 130 that worked. It is the 10.
Those ten items are the things with no automatic equivalent: features the target device does not have, rules that depend on the old vendor's specific behaviour, constructs that could be translated two different ways where only a human knows which is right.
A tool that hides those ten items is not helping you — it is postponing the problem until 2am.
RuleForge writes them down as a list, with the reason for each. That list is what people actually use during a migration.
## Why the config must never be uploaded anywhere
A firewall config is a map of your network. It contains internal addresses, segment names, which services may be reached from where. Whoever holds it does not need to guess anything about your network.
Many web-based conversion tools ask you to upload it.
RuleForge is a single binary that runs on your laptop or a jump host, with no outbound connection at all. Not because we deserve more trust — but because uploading it should never have been part of this job.
## One limit we put up front — and what fixing it uncovered
RuleForge has a feature called round-trip verification: the generated config is read back by its own parser and compared against the internal model.

For its first releases, that comparison only counted things — the number of interfaces, the number of rules. An interface address 198.51.100.2/28 that became 198.51.100.0/28 slipped straight past it, because the number of interfaces was still right.
On 5 September the review was rebuilt to compare values: interface addresses, routes, object contents. And the very first time it ran with values, it caught two more defects that had already shipped — the generators for two vendors were writing network addresses where interface addresses belonged, and a stray comment line was landing inside a block where the firewall would have silently dropped everything after it. Both are fixed, both have tests.
We tell you this because it is the whole argument for the product: a check that only counts cannot see the mistakes that matter. And we tell you what is still excluded, on purpose — rule bodies and NAT, whose names and ordering are legitimately rewritten during conversion. For those, the Conversion Process Report stays your source of truth.
## What changes once you are using it
Before: a migration begins by copying thousands of lines into a spreadsheet, then hoping nothing was missed.
After: you have a target config, two documents, and a short list of things you must decide yourself — before cut-over night, not during it.
## Look at the output first — without installing anything
Two complete sample reports are at github.com/nizartuanku/ruleforge/docs/samples, public, no email gate.
If after that you want to try it on your own config:
```
curl -LO https://github.com/nizartuanku/ruleforge/releases/latest/download/ruleforge-free-0.1.2-linux-amd64.tar.gz
curl -LO https://github.com/nizartuanku/ruleforge/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf ruleforge-free-0.1.2-linux-amd64.tar.gz && ./ruleforge
```
The free Apache-2.0 edition runs the same engine, up to 50 rules per job — enough to watch the manual-review register appear on your own config, not on an example we made up.
Run it on a config you have sanitised.
Nizar Tuanku — Cybersecurity. · github.com/nizartuanku/ruleforge

## Terms used above

- Rule base — the set of firewall rules, read from top to bottom. The first rule that matches a packet decides that packet's fate.
- Round-trip verification — the conversion output is re-parsed and compared with the source, to make sure nothing fell through.
