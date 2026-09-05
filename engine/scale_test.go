package engine

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/gen"
	"github.com/nizartuanku/ruleforge/parse"
)

// synthASA builds an ASA config with n rules over n/5 objects, all on one ACL
// — the shape that made the pipeline quadratic, because every rule asks the
// namer for a target name derived from the same ACL name.
func synthASA(n int) string {
	var b strings.Builder
	b.WriteString(": Saved\nASA Version 9.16(4)\nhostname bench-fw\n")
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&b, "interface GigabitEthernet0/%d\n nameif zone%d\n security-level %d\n ip address 10.%d.0.1 255.255.255.0\n", i, i, i*10, i)
	}
	objs := n / 5
	if objs < 50 {
		objs = 50
	}
	for i := 0; i < objs; i++ {
		fmt.Fprintf(&b, "object network NET-%d\n subnet 10.%d.%d.0 255.255.255.0\n", i, i%250, (i/250)%250)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "access-list OUT extended permit tcp object NET-%d object NET-%d eq %d\n", i%objs, (i*7)%objs, 1000+(i%2000))
	}
	b.WriteString("access-group OUT in interface zone0\n")
	return b.String()
}

func runPipeline(tb testing.TB, src string, target string) *Review {
	tb.Helper()
	cfg, err := parse.Parse(fwir.VendorASA, []parse.Input{{Name: "asa.cfg", Content: src}})
	if err != nil {
		tb.Fatal(err)
	}
	var results []*gen.Result
	for i := range cfg.Contexts {
		r, err := gen.Generate(target, &cfg.Contexts[i], nil)
		if err != nil {
			tb.Fatal(err)
		}
		results = append(results, r)
	}
	return BuildReview(cfg, target, results)
}

// A 20k-rule job used to take about 86 seconds and a 100k-rule one about forty
// minutes, because three separate lookups were linear scans inside per-rule
// loops. This is not a timing assertion — CI machines vary — but it does fail
// by timeout if any of those scans comes back, and it asserts that the result
// at scale is still a complete, well-formed review.
func TestScale_TwentyThousandRules(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in -short mode")
	}
	const n = 20000
	rv := runPipeline(t, synthASA(n), fwir.VendorPANOS)
	if rv.Totals.Converted+rv.Totals.Partial+rv.Totals.Manual+rv.Totals.Failed+rv.Totals.Info < n {
		t.Fatalf("review accounts for fewer items than the %d rules that went in: %+v", n, rv.Totals)
	}
	var ruleCat *CategoryReview
	for i := range rv.Categories {
		if rv.Categories[i].Category == "rule" {
			ruleCat = &rv.Categories[i]
		}
	}
	if ruleCat == nil || ruleCat.Source != n {
		t.Fatalf("rule category did not see all %d rules: %+v", n, ruleCat)
	}
	if len(rv.ValueChecks) == 0 {
		t.Fatal("no value checks at scale")
	}
}

func BenchmarkPipeline1k(b *testing.B)  { benchN(b, 1000) }
func BenchmarkPipeline10k(b *testing.B) { benchN(b, 10000) }
func BenchmarkPipeline20k(b *testing.B) { benchN(b, 20000) }

func benchN(b *testing.B, n int) {
	src := synthASA(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runPipeline(b, src, fwir.VendorPANOS)
	}
}
