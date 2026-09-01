# Sample reports

These are real RuleForge output, not mockups. One job, run end to end, exported exactly as the tool produced it.

**Source:** [`lab-edge-fw01.cfg`](lab-edge-fw01.cfg) — a synthetic Cisco ASA configuration. It is a lab file. No customer configuration was used, and none ever needs to be: RuleForge runs on your own machine and makes no outbound connections.

**Job:** Cisco ASA → Palo Alto PAN-OS.

| | |
|---|---|
| Interfaces | 11 (incl. VLAN sub-interfaces and a port-channel) |
| Zones | 7 |
| Objects / services / groups | 35 / 9 / 12 |
| Rules | 43 |
| NAT statements | 13 |
| Static routes | 6 |
| Unparsed lines | **0** |
| Outcome | 130 converted · 6 partial · 10 manual review · 0 failed |
| Round-trip verification | PASS on every metric |

## The two documents

**[Conversion Process Report](asa-to-panos-conversion-process-report.pdf)** ([HTML](asa-to-panos-conversion-process-report.html)) — every source element, one row each, with the exact generated target lines beside it. This is what the engineer doing the migration reads.

**[Final Migration Report](asa-to-panos-final-migration-report.pdf)** ([HTML](asa-to-panos-final-migration-report.html)) — before/after counts per category, round-trip verification, the mapping that was applied, and the unconverted-item register. This is what goes to the client, or to an auditor.

The HTML files are self-contained: no stylesheet, no script, no font, no image is fetched from anywhere. Save one and it still renders in five years, on an air-gapped machine.

## The part worth reading

The **unconverted-item register** at the end of the Final Migration Report. In this run, 10 items could not be converted automatically: the crypto maps, the IKEv2 policy and IPsec proposal, the PKI trustpoint, and two `object-group` types PAN-OS has no equivalent for.

RuleForge does not convert those. It also does not quietly skip them. Each one is listed with its original source lines and what needs to happen on the target.

That is the design rule the whole tool is built around: **nothing is ever silently dropped.** A migration that reports 100% success and loses a rule is worse than one that reports 94% and tells you which six items you still have to look at.

## Round-trip verification

The generated PAN-OS configuration is re-parsed by RuleForge's own PAN-OS parser and compared back against the intermediate model. The counts in the report are measured on the output, not asserted about it.

Two rows in that table show a deliberate difference rather than a match — network objects (35 → 42) and, in some jobs, interfaces. That is the generator emitting collision-safe `RF-*` helper objects for literals the source expressed inline. The report says so rather than hiding the delta.

## Reproducing this

```bash
go build ./cmd/ruleforge && ./ruleforge
# open http://127.0.0.1:8428, upload docs/samples/lab-edge-fw01.cfg,
# source: Cisco ASA, target: Palo Alto PAN-OS
```

The Conversion Process Report is in the free edition. The Final Migration Report and round-trip verification are Pro features — [whop.com/nizar-tuanku/ruleforge?utm_source=github](https://whop.com/nizar-tuanku/ruleforge?utm_source=github).
