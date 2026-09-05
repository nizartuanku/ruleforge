// Package gen renders fwir contexts into target-vendor configuration. One
// generator per vendor; every generator reports per-item outcomes so the
// conversion report can show exactly what was converted, what was partial,
// and what needs hands.
package gen

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// Item statuses.
const (
	StConverted = "converted"
	StPartial   = "partial"
	StManual    = "manual"
	StFailed    = "failed"
	StInfo      = "info"
)

// Item is the outcome of converting one source element.
type Item struct {
	Category string `json:"category"` // interface|zone|object|service|group|rule|nat|route|captured
	Name     string `json:"name"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Output   string `json:"output,omitempty"` // generated snippet (may be long)
}

// File is one generated output file.
type File struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// Mapping carries the user-approved translation decisions.
type Mapping struct {
	ZoneMap  map[string]string `json:"zone_map"`  // source zone → target zone
	IfaceMap map[string]string `json:"iface_map"` // source iface → target iface
}

// MapZone resolves a source zone through the mapping (identity by default).
func (m *Mapping) MapZone(z string) string {
	if m != nil && m.ZoneMap != nil {
		if v, ok := m.ZoneMap[z]; ok && v != "" {
			return v
		}
	}
	return z
}

// MapIface resolves a source interface name (identity by default).
func (m *Mapping) MapIface(i string) string {
	if m != nil && m.IfaceMap != nil {
		if v, ok := m.IfaceMap[i]; ok && v != "" {
			return v
		}
	}
	return i
}

// Result is one context's conversion output.
type Result struct {
	Context string            `json:"context"`
	Files   []File            `json:"files"`
	Items   []Item            `json:"items"`
	Renames map[string]string `json:"renames,omitempty"` // source name → target name
}

// Generate renders one context for the target vendor.
func Generate(target string, ctx *fwir.Context, m *Mapping) (*Result, error) {
	switch target {
	case fwir.VendorASA:
		return genASA(ctx, m), nil
	case fwir.VendorFTD:
		return genFTD(ctx, m), nil
	case fwir.VendorPANOS:
		return genPANOS(ctx, m), nil
	case fwir.VendorFortiGate:
		return genFortiGate(ctx, m), nil
	case fwir.VendorCheckPoint:
		return genCheckPoint(ctx, m), nil
	}
	return nil, fmt.Errorf("unsupported target vendor %q", target)
}

// ---- naming ----

var nameRules = map[string]struct {
	max     int
	allowed *regexp.Regexp
}{
	fwir.VendorASA:        {64, regexp.MustCompile(`[^A-Za-z0-9_.-]`)},
	fwir.VendorFTD:        {64, regexp.MustCompile(`[^A-Za-z0-9_.-]`)},
	fwir.VendorPANOS:      {63, regexp.MustCompile(`[^A-Za-z0-9_. -]`)},
	fwir.VendorFortiGate:  {79, regexp.MustCompile(`[^\x20-\x7e]`)},
	fwir.VendorCheckPoint: {100, regexp.MustCompile(`[^A-Za-z0-9_.-]`)},
}

// namer produces collision-free target names and records renames.
type namer struct {
	vendor  string
	used    map[string]bool
	nextSfx map[string]int // base name -> next disambiguation suffix to try
	Renames map[string]string
}

func newNamer(vendor string) *namer {
	return &namer{vendor: vendor, used: map[string]bool{}, nextSfx: map[string]int{}, Renames: map[string]string{}}
}

// suffixed builds base with "_i" appended, truncating base if the vendor's
// name limit does not leave room for the suffix.
func suffixed(base string, i, max int) string {
	sfx := fmt.Sprintf("_%d", i)
	if len(base)+len(sfx) > max {
		return base[:max-len(sfx)] + sfx
	}
	return base + sfx
}

// disambiguate returns the first unused name derived from base, resuming the
// counter where the previous call for the same base left off.
//
// Resuming matters: a config whose rules all share one ACL name (the normal
// case for ASA and PAN-OS) used to restart the probe at _2 on every rule, so
// the n-th name cost n map lookups and a 20k-rule job spent most of its time
// here. The counter only ever moves forward, so a name it skips is one that
// was taken anyway; every candidate is still checked against `used`, which is
// what keeps it correct when a source name happens to look like "OUT_7".
func (n *namer) disambiguate(base string, max int, stopAt string) string {
	out := base
	i := n.nextSfx[base]
	if i < 2 {
		i = 2
	}
	for n.used[out] && out != stopAt {
		out = suffixed(base, i, max)
		i++
	}
	if i > n.nextSfx[base] {
		n.nextSfx[base] = i
	}
	return out
}

func (n *namer) name(src string) string {
	rule := nameRules[n.vendor]
	out := rule.allowed.ReplaceAllString(src, "_")
	if out == "" {
		out = "obj"
	}
	if len(out) > rule.max {
		out = out[:rule.max]
	}
	// Same name already emitted for the same source: fine (idempotent).
	out = n.disambiguate(out, rule.max, src)
	n.used[out] = true
	if out != src {
		n.Renames[src] = out
	}
	return out
}

// unique always allocates a fresh, never-before-used target name — for
// elements that must be unique per instance (rule names), unlike name(),
// which is idempotent for repeated references to the same object.
func (n *namer) unique(src string) string {
	rule := nameRules[n.vendor]
	out := rule.allowed.ReplaceAllString(src, "_")
	if out == "" {
		out = "rule"
	}
	if len(out) > rule.max {
		out = out[:rule.max]
	}
	out = n.disambiguate(out, rule.max, "")
	n.used[out] = true
	return out
}

// lookup returns the target name previously assigned to src (or src).
func (n *namer) lookup(src string) string {
	if v, ok := n.Renames[src]; ok {
		return v
	}
	return src
}

// ---- shared helpers ----

// refKind classifies a rule/NAT reference against the context's objects.
type refKind int

const (
	refAny refKind = iota
	refNetObj
	refNetGroup
	refLiteralCIDR
	refLiteralRange
	refInterface
	refUnknown
)

func classifyRef(ix *fwir.ObjIndex, r fwir.Ref) refKind {
	if r.IsAny() {
		return refAny
	}
	s := string(r)
	if strings.HasPrefix(s, "interface:") {
		return refInterface
	}
	if ix.Net(s) != nil {
		return refNetObj
	}
	if ix.NetGroup(s) != nil {
		return refNetGroup
	}
	if r.IsLiteral() {
		if strings.Contains(s, "-") && !strings.Contains(s, "/") {
			return refLiteralRange
		}
		return refLiteralCIDR
	}
	return refUnknown
}

type svcKind int

const (
	svcAny svcKind = iota
	svcObj
	svcGroup
	svcLiteral
	svcUnknown
)

func classifySvc(ix *fwir.ObjIndex, s fwir.SvcRef) svcKind {
	if s.IsAny() {
		return svcAny
	}
	name := string(s)
	if ix.Svc(name) != nil {
		return svcObj
	}
	if ix.SvcGroup(name) != nil {
		return svcGroup
	}
	if _, _, ok := s.SplitSvcLiteral(); ok {
		return svcLiteral
	}
	return svcUnknown
}

// captureItems reports every captured feature as a manual-review item so no
// generator can forget them.
func captureItems(x *fwir.Context, res *Result) {
	for _, c := range x.Captured {
		res.Items = append(res.Items, Item{
			Category: "captured", Name: firstNonEmpty(c.Name, c.Category), Status: StManual,
			Detail: c.Category + ": " + c.Detail + " — not auto-converted in v1; source lines preserved in the report",
		})
	}
	for _, u := range x.Unparsed {
		res.Items = append(res.Items, Item{
			Category: "unparsed", Name: truncate(u, 60), Status: StInfo,
			Detail: "line not recognised by the parser; verify whether it needs migrating",
		})
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// zoneOf joins mapped zones with a fallback.
func mapZones(m *Mapping, zs []string) []string {
	var out []string
	for _, z := range zs {
		out = append(out, m.MapZone(z))
	}
	return out
}
