package engine

import (
	"fmt"

	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/gen"
)

// StatusCounts tallies item outcomes.
type StatusCounts struct {
	Converted int `json:"converted"`
	Partial   int `json:"partial"`
	Manual    int `json:"manual"`
	Failed    int `json:"failed"`
	Info      int `json:"info"`
}

// CategoryReview compares one category before/after.
type CategoryReview struct {
	Category string       `json:"category"`
	Source   int          `json:"source"` // elements in the source IR
	Counts   StatusCounts `json:"counts"`
}

// RoundTripCheck is one fidelity metric from re-parsing the generated config.
type RoundTripCheck struct {
	Metric string `json:"metric"`
	Before int    `json:"before"`
	After  int    `json:"after"`
	OK     bool   `json:"ok"`
	Note   string `json:"note,omitempty"`
}

// Review is the full post-conversion verdict.
type Review struct {
	Target      string           `json:"target"`
	Categories  []CategoryReview `json:"categories"`
	Totals      StatusCounts     `json:"totals"`
	RoundTrip   []RoundTripCheck `json:"round_trip,omitempty"`
	RoundTripOK *bool            `json:"round_trip_ok,omitempty"` // nil = not available for this target
	Verdict     string           `json:"verdict"`                 // ready | review-needed | blocked
	Notes       []string         `json:"notes,omitempty"`
}

// BuildReview computes the before/after comparison and round-trip verdict.
func BuildReview(cfg *fwir.Config, target string, results []*gen.Result) *Review {
	rv := &Review{Target: target}

	srcCount := map[string]int{}
	for i := range cfg.Contexts {
		x := &cfg.Contexts[i]
		srcCount["interface"] += len(x.Interfaces)
		srcCount["zone"] += len(x.Zones)
		srcCount["object"] += len(x.Objects.Networks)
		srcCount["service"] += len(x.Objects.Services)
		srcCount["group"] += len(x.Objects.NetGroups) + len(x.Objects.SvcGroups)
		srcCount["rule"] += len(x.Rules)
		srcCount["nat"] += len(x.NATs)
		srcCount["route"] += len(x.Routes)
		srcCount["captured"] += len(x.Captured)
		srcCount["unparsed"] += len(x.Unparsed)
	}
	byCat := map[string]*StatusCounts{}
	for _, r := range results {
		for _, it := range r.Items {
			c, ok := byCat[it.Category]
			if !ok {
				c = &StatusCounts{}
				byCat[it.Category] = c
			}
			switch it.Status {
			case gen.StConverted:
				c.Converted++
				rv.Totals.Converted++
			case gen.StPartial:
				c.Partial++
				rv.Totals.Partial++
			case gen.StManual:
				c.Manual++
				rv.Totals.Manual++
			case gen.StFailed:
				c.Failed++
				rv.Totals.Failed++
			default:
				c.Info++
				rv.Totals.Info++
			}
		}
	}
	for _, cat := range []string{"interface", "zone", "object", "service", "group", "rule", "nat", "route", "captured", "unparsed"} {
		counts := byCat[cat]
		if counts == nil {
			counts = &StatusCounts{}
		}
		if srcCount[cat] == 0 && counts.Converted+counts.Partial+counts.Manual+counts.Failed+counts.Info == 0 {
			continue
		}
		rv.Categories = append(rv.Categories, CategoryReview{Category: cat, Source: srcCount[cat], Counts: *counts})
	}

	// round-trip verification
	if rt, ok := RoundTrip(target, results); ok {
		rtCount := map[string]int{}
		for i := range rt.Contexts {
			x := &rt.Contexts[i]
			rtCount["rules"] += len(x.Rules)
			rtCount["nats"] += len(x.NATs)
			rtCount["routes"] += len(x.Routes)
			rtCount["net objects"] += len(x.Objects.Networks)
			rtCount["interfaces"] += len(x.Interfaces)
		}
		checks := []struct {
			metric  string
			before  int
			after   int
			atLeast bool // generated may legitimately exceed (helper objects, split services)
		}{
			{"rules", srcCount["rule"], rtCount["rules"], true},
			{"NAT rules", srcCount["nat"], rtCount["nats"], true},
			{"static routes", srcCount["route"], rtCount["routes"], false},
			{"network objects", srcCount["object"], rtCount["net objects"], true},
			{"interfaces", srcCount["interface"], rtCount["interfaces"], true},
		}
		allOK := true
		for _, c := range checks {
			ok := c.after == c.before || (c.atLeast && c.after >= c.before)
			note := ""
			if c.after > c.before {
				note = "generated config carries helper objects / expanded entries — expected"
			}
			if !ok {
				allOK = false
				note = "MISMATCH — some source elements did not survive generation; inspect the process report"
			}
			rv.RoundTrip = append(rv.RoundTrip, RoundTripCheck{Metric: c.metric, Before: c.before, After: c.after, OK: ok, Note: note})
		}
		rv.RoundTripOK = &allOK
	}

	// verdict
	switch {
	case rv.Totals.Failed > 0:
		rv.Verdict = "blocked"
		rv.Notes = append(rv.Notes, fmt.Sprintf("%d elements failed to convert — fix or migrate them manually before cut-over", rv.Totals.Failed))
	case rv.Totals.Partial > 0 || rv.Totals.Manual > 0:
		rv.Verdict = "review-needed"
		rv.Notes = append(rv.Notes, fmt.Sprintf("%d partial and %d manual-review items — walk the conversion process report before deploying", rv.Totals.Partial, rv.Totals.Manual))
	default:
		rv.Verdict = "ready"
	}
	if rv.RoundTripOK != nil && !*rv.RoundTripOK {
		rv.Verdict = "review-needed"
	}
	if rv.RoundTripOK == nil {
		rv.Notes = append(rv.Notes, "Round-trip verification is not available for this target format (JSON bundle / mgmt_cli script) — rely on the per-item process report.")
	}
	return rv
}
