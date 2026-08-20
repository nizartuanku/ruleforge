# RuleForge

**Multivendor firewall migration — any vendor to any vendor, self-hosted and offline.**

Every vendor's migration tool converts one direction: into that vendor. Cisco's Firewall Migration Tool only produces FTD, FortiConverter only FortiGate, SmartMove only Check Point — and Palo Alto's Expedition was end-of-lifed in January 2025. RuleForge converts **between any two of five vendors** (20 directions) through a vendor-neutral intermediate model:

| Vendor | Parse (source) | Generate (target) | Multi-tenant |
|---|---|---|---|
| Cisco ASA | `show running-config` | ASA CLI | multiple context |
| Cisco FTD | `show running-config` | FMC REST JSON bundle + worksheet | multiple instances |
| Palo Alto PAN-OS | `set` format | `set` commands + Panorama device-group variant | Panorama / vsys |
| Fortinet FortiGate | CLI config | FortiOS CLI (central NAT) | VDOMs |
| Check Point | Gaia clish + mgmt_cli JSON | `mgmt_cli` script + Gaia script | policy packages |

## The pipeline

**Deep Analysis → Full Mapping → Convert → Full Review.**

1. **Analyze** — full inventory of everything running: interfaces (VLANs, port-channels, bridges), zones, objects/groups, rules, NAT (all four shapes), routes — plus VPN, certificates, dynamic routing, HA, App-ID/URL features, which are *captured with their source lines* and reported for manual rebuild rather than silently dropped. Nothing is ever silently dropped.
2. **Map** — RuleForge proposes a complete interface/zone map with target-native names; you edit and approve it. Conversion never runs on an unseen map.
3. **Convert** — object names preserved, literals wrapped in collision-safe helper objects, name transforms per target charset rules (all listed).
4. **Review** — per-element outcomes, before/after comparison per category, and **round-trip verification**: the generated config is re-parsed by RuleForge's own parser and diffed against the model.

Every job produces a **Conversion Process Report** (every element and its outcome) — self-contained HTML, prints to PDF.

**Background reading** — [what replaced Expedition after its January 2025 end-of-life](https://nizartuanku.github.io/expedition-alternative.html) · [Cisco ASA to Palo Alto: the mapping, and the traps](https://nizartuanku.github.io/cisco-asa-to-palo-alto.html)

## Quick start

```bash
go build ./cmd/ruleforge && ./ruleforge
# dashboard on http://127.0.0.1:8428
```

Or Docker:

```bash
docker build -t ruleforge . && docker run -p 8428:8428 -v ruleforge-data:/data ruleforge
```

Upload a config, pick the target vendor, walk the four steps.

## Free edition vs Pro/Team

This repository is the **free edition** (Apache-2.0): full deep analysis for all five vendors, conversion up to 50 rules per job, single-tenant conversion, process report, 1 stored job.

The paid edition adds unlimited rules, multi-context / Panorama / VDOM conversion, the Final Migration Report (before/after + cut-over checklist), round-trip verification, and job history — [whop.com/ruleforge](https://whop.com/ruleforge). Licensing is offline Ed25519; nothing ever phones home in either edition.

## Design notes

- One Go binary, SQLite storage, embedded single-file UI. No telemetry, no outbound connections.
- Hub-and-spoke: each vendor implements a parser (vendor → IR) and a generator (IR → vendor); adding a vendor adds both directions against every other vendor at once.
- Honesty invariants are tested: golden multi-feature configs per vendor convert in **all 20 directions** in CI, with per-element accounting and round-trip checks.

## Testing

```bash
go test ./...
go vet ./...
```

## License

Apache-2.0. Part of the [Sentinel line](https://github.com/nizartuanku) of self-hosted security tools.
