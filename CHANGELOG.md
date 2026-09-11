# Changelog

## Unreleased

### Uploads stream to disk, and the ceiling is 1 GB

The dashboard read each uploaded configuration into memory in full before it
looked at the size. Two consequences followed from that order. A config larger
than the 32 MB ceiling cost a 32 MB allocation to refuse, and the ceiling
itself had to stay small, because the peak was the file in a byte slice plus a
second copy of it as a string — twice the file, before parsing had begun.

The request is now streamed straight to disk with `multipart.Reader`, one
`io.Copy` buffer at a time, and the text is read back once with a pre-sized
builder rather than copied twice. Refusing a 1.2 GB upload no longer allocates
1.2 GB; it costs the same 32 KB as accepting a small one.

- The default limit is **1 GiB (1,073,741,824 bytes)** for one request, counted
  across all files in it. `-max-upload` moves it, and `-tmp` chooses where
  uploads are written while they are parsed — point it at the same volume as
  `-db` when the system temporary directory is a small tmpfs.
- The limit is an operator setting, not a licence tier: the free edition may
  upload exactly as much as Team.
- An oversize upload still returns **413** with the limit in bytes and in
  megabytes, the size the request declared, and a plain statement that nothing
  was converted.
- Form fields are capped separately at 8 MiB, so the paste box cannot become an
  unbounded allocation.
- Temporary files are removed whether the job succeeds or fails; a test asserts
  the directory is empty afterwards.

### Known limit: accepting an upload is not yet the same as finishing the job

Measured on this change, on a 16-vCPU Ubuntu 24.04 box, with a synthetic Cisco
ASA configuration of 801,946,681 bytes and 8,400,005 lines:

| step | time | peak RSS |
|---|---|---|
| read the streamed upload | — | 0.79 GB |
| parse (8,400,000 rules, 1 context) | 74.2 s | 8.9 GB |
| analyse | 0.3 s | 8.9 GB |
| propose the mapping | 0.2 s | 8.9 GB |
| serialise the job for the store | 23.7 s | 13.6 GB |

The upload itself is no longer the constraint, and analysis stayed linear at
that size. Storing the result is: a job record for 8.4 million rules serialises
to 1,212,437,255 bytes, and SQLite refuses a value over 1,000,000,000 bytes, so
the request ends in `500 string or blob too big` after the work has been done.
That works out at about 144 bytes of job record per rule on this shape of
configuration, which puts the ceiling somewhere near 6.9 million rules — an
extrapolation from one measurement, not a second measurement. It is written
down rather than hidden because a tool that reports a clean conversion it never
persisted would be worse than one that says where it stops.

### A job no longer carries a copy of the upload

`Job.inputs` recorded the full text of every uploaded file. Nothing ever read
it back — every step after parsing works from the parsed model — but it was
written to the database and returned in every API response that returns a job,
so a 600 MB config produced a 600 MB job record and a 600 MB reply. Each input
now records its filename and byte count; the text is held only while the file
is being parsed.

## 0.1.2 — 2026-09-06

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
