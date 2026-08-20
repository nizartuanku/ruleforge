package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/gen"
	"github.com/nizartuanku/ruleforge/parse"
)

func load(t *testing.T, name string) parse.Input {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return parse.Input{Name: name, Content: string(b)}
}

var sources = map[string][]string{
	fwir.VendorASA:        {"asa-multictx.cfg"},
	fwir.VendorPANOS:      {"panos-fw.txt"},
	fwir.VendorFortiGate:  {"fortigate-vdom.conf"},
	fwir.VendorCheckPoint: {"checkpoint-gaia.txt", "checkpoint-access.json", "checkpoint-nat.json"},
}

// TestEveryDirection converts every sample source to every other vendor and
// checks the honesty invariants: no error, every context produced items, no
// element category disappears, and no FAILED items on the golden samples.
func TestEveryDirection(t *testing.T) {
	for src, files := range sources {
		var inputs []parse.Input
		for _, f := range files {
			inputs = append(inputs, load(t, f))
		}
		cfg, err := parse.Parse(src, inputs)
		if err != nil {
			t.Fatalf("%s parse: %v", src, err)
		}
		an := Analyze(cfg)
		if an.Totals.Rules == 0 {
			t.Fatalf("%s: no rules analyzed", src)
		}
		for _, dst := range fwir.Vendors() {
			if dst == src || (src == fwir.VendorASA && dst == fwir.VendorFTD) {
				// ASA→FTD covered below; ASA source also exercises FTD parser path
			}
			if dst == src {
				continue
			}
			prop := ProposeMapping(cfg, dst)
			maps := BuildMappings(prop.Entries)
			results, err := Convert(cfg, dst, maps)
			if err != nil {
				t.Fatalf("%s→%s: %v", src, dst, err)
			}
			if len(results) != len(cfg.Contexts) {
				t.Fatalf("%s→%s: %d results for %d contexts", src, dst, len(results), len(cfg.Contexts))
			}
			rv := BuildReview(cfg, dst, results)
			if rv.Totals.Failed > 0 {
				for _, r := range results {
					for _, it := range r.Items {
						if it.Status == gen.StFailed {
							t.Errorf("%s→%s FAILED item: %s %s: %s", src, dst, it.Category, it.Name, it.Detail)
						}
					}
				}
			}
			// honesty: every source rule and NAT is accounted as an item
			itemCount := map[string]int{}
			for _, r := range results {
				for _, it := range r.Items {
					itemCount[it.Category]++
				}
			}
			if itemCount["rule"] < an.Totals.Rules {
				t.Errorf("%s→%s: %d rule items < %d source rules", src, dst, itemCount["rule"], an.Totals.Rules)
			}
			if itemCount["nat"] < an.Totals.NATs {
				t.Errorf("%s→%s: %d nat items < %d source NATs", src, dst, itemCount["nat"], an.Totals.NATs)
			}
			if an.Totals.Captured > 0 && itemCount["captured"] < an.Totals.Captured {
				t.Errorf("%s→%s: captured items %d < %d", src, dst, itemCount["captured"], an.Totals.Captured)
			}
			// generated files exist and are non-trivial
			for _, r := range results {
				if len(r.Files) == 0 {
					t.Errorf("%s→%s ctx %s: no files", src, dst, r.Context)
				}
				for _, f := range r.Files {
					if len(f.Content) < 40 {
						t.Errorf("%s→%s: file %s suspiciously small", src, dst, f.Name)
					}
				}
			}
			// round-trip available for text targets
			switch dst {
			case fwir.VendorASA, fwir.VendorFortiGate, fwir.VendorPANOS:
				if rv.RoundTripOK == nil {
					t.Errorf("%s→%s: round-trip unexpectedly unavailable", src, dst)
				} else if !*rv.RoundTripOK {
					for _, c := range rv.RoundTrip {
						if !c.OK {
							t.Errorf("%s→%s round-trip mismatch %s: before=%d after=%d", src, dst, c.Metric, c.Before, c.After)
						}
					}
				}
			}
		}
	}
}

// TestReports renders both reports for the flagship direction ASA→FTD.
func TestReports(t *testing.T) {
	cfg, err := parse.Parse(fwir.VendorASA, []parse.Input{load(t, "asa-multictx.cfg")})
	if err != nil {
		t.Fatal(err)
	}
	an := Analyze(cfg)
	prop := ProposeMapping(cfg, fwir.VendorFTD)
	results, err := Convert(cfg, fwir.VendorFTD, BuildMappings(prop.Entries))
	if err != nil {
		t.Fatal(err)
	}
	rv := BuildReview(cfg, fwir.VendorFTD, results)
	in := &ReportInput{
		JobID: "job-test", Source: fwir.VendorASA, Target: fwir.VendorFTD,
		Hostname: cfg.Hostname, Analysis: an, Config: cfg, MapEntry: prop.Entries,
		Results: results, Review: rv,
	}
	proc := BuildProcessReport(in)
	final := BuildFinalReport(in)
	for _, want := range []string{"Conversion Process Report", "CTX-DMZ", "WEB-SRV", "manual review"} {
		if !contains(proc, want) {
			t.Errorf("process report missing %q", want)
		}
	}
	for _, want := range []string{"Final Migration Report", "cut-over checklist", "Before / after"} {
		if !containsFold(final, want) {
			t.Errorf("final report missing %q", want)
		}
	}
	if len(proc) < 5000 || len(final) < 3000 {
		t.Errorf("reports too small: proc=%d final=%d", len(proc), len(final))
	}
}

// TestMultiTenantAnalysis confirms tenant detection.
func TestMultiTenantAnalysis(t *testing.T) {
	cfg, _ := parse.Parse(fwir.VendorFortiGate, []parse.Input{load(t, "fortigate-vdom.conf")})
	an := Analyze(cfg)
	if !an.MultiTenant || an.TenantKind != "VDOMs" {
		t.Fatalf("analysis wrong: %+v", an)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && stringIndex(s, sub) >= 0 }

func containsFold(s, sub string) bool {
	return contains(lower(s), lower(sub))
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
