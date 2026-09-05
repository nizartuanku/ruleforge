# Changelog

## Unreleased

### Round-trip verification now compares values, not just counts

Round-trip verification re-parsed the generated config and compared how *many*
rules, NATs, routes, objects and interfaces came back. Counting can only see
loss. It cannot see corruption: a generator that writes an interface address as
`198.51.100.0/28` instead of `198.51.100.2/28` still writes exactly one address,
so every count matched and the check reported PASS while the config was wrong.
That is precisely how the v0.1.0 interface-address bug shipped past its own
verification.

The review now also compares the **values** that must survive generation
verbatim — interface addresses, static routes (destination and next hop),
network object values and service object values — and names the specific values
that went missing, so the report points at something you can go and look at.
Values that appear only in the target are listed but never fail the check:
helper objects and split `tcp-udp` services are expected. Rule and NAT bodies
are deliberately excluded, because renaming and remapping there is the job.

**The new check immediately found two shipped defects in the converter itself:**

- **Interface addresses were masked when generating ASA and FortiOS.** The
  generators split the CIDR with `SplitCIDR`, which returns the *network*
  address, so `10.10.0.1/16` was emitted as `ip address 10.10.0.0 255.255.0.0`
  and `203.0.113.2/29` as `203.0.113.0` — a network address the device cannot
  even accept. The same bug was fixed on the parser side in v0.1.1; the
  generator side was never looked at, because the count check kept passing.
  Fixed with a new `fwir.SplitIfaceCIDR` that keeps the host octets. Subnet
  objects and routes genuinely want the network address and are unchanged.
- **Generated ASA put `!` comment lines inside interface blocks.** Aggregate
  interfaces emitted `! member …` notes between `interface Port-channel1` and
  its `ip address` line. `!` ends sub-mode on an ASA, so the device leaves
  interface configuration and never applies the address that follows. The notes
  now precede the block.

### Conversion is linear again

Three linear scans sat inside per-rule loops, which made a job quadratic in the
size of the rulebase: 1k rules took 0.7 s, 10k took 24 s, 20k took 86 s and 100k
would have taken about forty minutes.

- `namer.unique` restarted its `_2, _3, _4 …` collision probe from scratch on
  every call. Every rule in an ASA ACL carries the same ACL name, so the n-th
  name cost n lookups. The counter now resumes per base name; every candidate is
  still checked, so a source object that happens to be called `OUT_7` still
  wins its name.
- The PAN-OS parser rescanned the whole rule, NAT and address slices for every
  `set` line, and PAN-OS set format spreads one rule over many lines. It now
  keeps a per-context name index.
- The generators resolved every rule reference with `Objects.FindNet` /
  `FindSvc`, which scan. They now build one `fwir.ObjIndex` per context.

Measured end to end (parse → generate → re-parse → review) on the same 2 vCPU
box as the numbers above:

| rules | before | after |
|---|---|---|
| 1,000 | 0.7 s | 0.02 s |
| 10,000 | 24 s | 0.23 s |
| 20,000 | 86 s | 0.48 s |
| 100,000 | ≈ 40 min | 2.5 s |

`go test -bench BenchmarkPipeline ./engine/` reproduces the first three.

Behaviour is unchanged: same names, same output, same reports.

## 0.1.1 — 2026-08-27

- Interface addresses keep their host octets when parsed (`fwir.IfaceCIDRFromIPMask`);
  `198.51.100.2/28` was being stored as `198.51.100.0/28`. Affected all 20 directions.
  Release notes at the time were explicit that round-trip verification missed it
  because it compared counts rather than values — the check above closes that gap.

## 0.1.0 — 2026-08-20

- First release: five vendors, all 20 conversion directions, deep analysis,
  mapping, conversion, review with round-trip checks, two HTML reports.
