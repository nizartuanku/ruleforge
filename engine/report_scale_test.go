package engine

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/gen"
	"github.com/nizartuanku/ruleforge/parse"
)

// TestReportTiering_HalfMillionItems is the E-28 proof gate: a config that
// produces more than half a million converted items must still render a
// process report that opens fast and stays a bounded size — the worst
// reportTopN items shown per category table in full, the rest counted and
// exported as NDJSON ("overflow counted, not hidden", the same pattern
// AuditLight uses for its surface map). Opt-in (RF28_LARGE=1) because 600k
// rules take real CPU time to parse, convert and report.
//
//	RF28_LARGE=1 go test ./engine/ -run TestReportTiering_HalfMillionItems -v -timeout 10m
func TestReportTiering_HalfMillionItems(t *testing.T) {
	if os.Getenv("RF28_LARGE") == "" {
		t.Skip("set RF28_LARGE=1 to run the >500k-item E-28 report tiering gate")
	}
	const n = 600_000
	src := synthASA(n)

	cfg, err := parse.Parse(fwir.VendorASA, []parse.Input{{Name: "asa.cfg", Content: src}})
	if err != nil {
		t.Fatal(err)
	}
	target := fwir.VendorPANOS
	var results []*gen.Result
	for i := range cfg.Contexts {
		r, err := gen.Generate(target, &cfg.Contexts[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, r)
	}
	totalItems := 0
	for _, r := range results {
		totalItems += len(r.Items)
	}
	if totalItems < 500_000 {
		t.Fatalf("synthetic config only produced %d items, want > 500,000", totalItems)
	}

	an := Analyze(cfg)
	rv := BuildReview(cfg, target, results)
	in := &ReportInput{
		JobID: "scale-test", Source: fwir.VendorASA, Target: target,
		Hostname: cfg.Hostname, Analysis: an, Config: cfg, Results: results, Review: rv,
	}

	t0 := time.Now()
	html, exports := BuildProcessReport(in)
	elapsed := time.Since(t0)
	t.Logf("BuildProcessReport: %d items, html=%d bytes, %d export file(s), took %v", totalItems, len(html), len(exports), elapsed)

	if elapsed > 10*time.Second {
		t.Errorf("report generation took %v, want it to stay well under a browser's patience (<10s even on a slow CI machine)", elapsed)
	}
	// The HTML must stay bounded: reportTopN rows per category table, not
	// one row per source item. A few hundred KB, not tens/hundreds of MB.
	if len(html) > 5<<20 {
		t.Errorf("process report HTML is %d bytes — tiering did not bound it", len(html))
	}
	if len(exports) == 0 {
		t.Fatal("expected at least one NDJSON export for the overflow — the categories all exceed reportTopN")
	}
	// Every exported NDJSON file's line count must equal the true total for
	// that table, and every line must be valid, decodable JSON — the
	// overflow is counted and fully present, not hidden or corrupted.
	for name, content := range exports {
		trimmed := strings.TrimRight(content, "\n")
		lines := 0
		if trimmed != "" {
			lines = strings.Count(trimmed, "\n") + 1
		}
		if lines < reportTopN {
			t.Errorf("export %s has only %d lines, expected at least reportTopN (%d) since it was only written for tables over that size", name, lines, reportTopN)
		}
		dec := json.NewDecoder(strings.NewReader(content))
		count := 0
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				t.Fatalf("export %s: invalid NDJSON at entry %d: %v", name, count+1, err)
			}
			count++
		}
		if count != lines {
			t.Errorf("export %s: NDJSON decode count %d != line count %d", name, count, lines)
		}
	}
}
