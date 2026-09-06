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
4. **Review** — per-element outcomes, before/after comparison per category, and **round-trip verification**: the generated config is re-parsed by RuleForge's own parser and diffed against the model, by **count and by value**. Counting alone can only see loss; comparing values sees change, which is how an interface address that arrives as `198.51.100.0/28` instead of `198.51.100.2/28` gets caught. Interface addresses, static routes, network object values and service object values must survive verbatim; rule and NAT bodies are excluded on purpose, because renaming and remapping there is the job, not a defect.

Every job produces a **Conversion Process Report** (every element and its outcome) — self-contained HTML, prints to PDF.

**See the actual output** — [sample reports from a real job](docs/samples/): a 43-rule Cisco ASA converted to PAN-OS, both documents exported exactly as the tool produced them, including the ten items it refused to convert silently.

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

The paid edition adds unlimited rules, multi-context / Panorama / VDOM conversion, the Final Migration Report (before/after + cut-over checklist), round-trip verification, and job history — [whop.com/nizar-tuanku/ruleforge](https://whop.com/nizar-tuanku/ruleforge?utm_source=gh-ruleforge). Licensing is offline Ed25519; nothing ever phones home in either edition.

**Whop sells paid licences only.** Free: github.com/nizartuanku/ruleforge — this repository is the free edition, Apache-2.0, no time limit; nothing on Whop is free, so try it here first.

## Design notes

- One Go binary, SQLite storage, embedded single-file UI. No telemetry, no outbound connections.
- Hub-and-spoke: each vendor implements a parser (vendor → IR) and a generator (IR → vendor); adding a vendor adds both directions against every other vendor at once.
- Honesty invariants are tested: golden multi-feature configs per vendor convert in **all 20 directions** in CI, with per-element accounting and round-trip checks by count and by value.
- Conversion is linear in the size of the rulebase. Measured end to end (parse → generate → re-parse → review) on a 2 vCPU box: **1k rules 0.02 s · 10k 0.23 s · 20k 0.48 s**. Reproduce with `go test -bench BenchmarkPipeline ./engine/`.

## Honest limits

- **Round-trip verification is structural and value-level, not semantic.** It re-parses what was generated and checks that the elements and the values that must survive verbatim did. It does not prove the two policies permit the same traffic; nothing here evaluates a rulebase for equivalence.
- **Round-trip is only available for targets RuleForge can re-parse** — ASA, PAN-OS and FortiOS text. FTD (an FMC JSON bundle) and Check Point (an mgmt_cli script) are not fed back through a parser, so those jobs rely on the per-item process report alone, and the review says so.
- **Rule and NAT bodies are not compared by value.** Zone names, object names and ordering are rewritten by the mapping and the namer, so a value comparison there would report differences that are not defects. This is a real gap, not an oversight: it means a rule whose *body* was corrupted while its count stayed right would not be caught by the round-trip check.
- **VPN, certificates, App-ID and URL categories are captured and reported, never converted** in v1. They appear as manual-review items with their source lines.

## Testing

```bash
go test ./...
go vet ./...
```

## License

Apache-2.0. Part of the [Hexward line](https://github.com/nizartuanku) of self-hosted security tools.
