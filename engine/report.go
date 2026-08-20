package engine

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/gen"
)

// ReportInput carries everything the two report documents need.
type ReportInput struct {
	JobID     string
	Created   time.Time
	Source    string // vendor id
	Target    string // vendor id
	Hostname  string
	Analysis  *Analysis
	Config    *fwir.Config
	MapEntry  []MappingEntry
	Results   []*gen.Result
	Review    *Review
	FreeTier  bool
}

const reportCSS = `
:root{--bg:#ffffff;--ink:#1a2233;--mut:#5b6474;--line:#e4e8ef;--ok:#1e8e5a;--okbg:#e7f5ee;
--warn:#b57d0f;--warnbg:#fdf3dd;--man:#7451c2;--manbg:#efeafb;--bad:#c73a3a;--badbg:#fbe9e9;
--info:#48617e;--infobg:#edf1f7;--accent:#274b8f}
*{box-sizing:border-box}body{font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
color:var(--ink);background:var(--bg);margin:0;padding:40px 48px;max-width:1080px;margin:0 auto}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
h3{font-size:16px;margin:22px 0 8px}.sub{color:var(--mut);margin:0 0 26px}
table{border-collapse:collapse;width:100%;margin:10px 0 18px;font-size:14px}
th{text-align:left;color:var(--mut);font-weight:600;padding:7px 10px;border-bottom:2px solid var(--line);white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.b-converted{background:var(--okbg);color:var(--ok)}.b-partial{background:var(--warnbg);color:var(--warn)}
.b-manual{background:var(--manbg);color:var(--man)}.b-failed{background:var(--badbg);color:var(--bad)}
.b-info{background:var(--infobg);color:var(--info)}
.bar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--line);margin:4px 0 2px}
.bar div{height:100%}.s-ok{background:var(--ok)}.s-warn{background:var(--warn)}.s-man{background:var(--man)}.s-bad{background:var(--bad)}.s-info{background:#9aa7ba}
.kpis{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0}
.kpi{flex:1 1 130px;border:1px solid var(--line);border-radius:10px;padding:12px 16px}
.kpi b{display:block;font-size:24px}.kpi span{color:var(--mut);font-size:12.5px}
code,pre{font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:#f6f8fb;border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;margin:6px 0}
.note{background:var(--infobg);border-left:3px solid var(--accent);padding:9px 14px;border-radius:0 8px 8px 0;margin:8px 0}
.risk{background:var(--warnbg);border-left:3px solid var(--warn);padding:9px 14px;border-radius:0 8px 8px 0;margin:8px 0}
.verdict{font-size:17px;font-weight:700;padding:14px 18px;border-radius:10px;margin:14px 0}
.v-ready{background:var(--okbg);color:var(--ok)}.v-review{background:var(--warnbg);color:var(--warn)}.v-blocked{background:var(--badbg);color:var(--bad)}
footer{margin-top:44px;color:var(--mut);font-size:12.5px;border-top:1px solid var(--line);padding-top:12px}
@media print{body{padding:0}} details summary{cursor:pointer;color:var(--accent)}
.free{color:var(--mut);font-size:12px;letter-spacing:.05em;text-transform:uppercase}
`

func esc(s string) string { return html.EscapeString(s) }

func badge(status string) string {
	label := map[string]string{
		gen.StConverted: "converted", gen.StPartial: "partial",
		gen.StManual: "manual review", gen.StFailed: "failed", gen.StInfo: "info",
	}[status]
	if label == "" {
		label = status
	}
	cls := map[string]string{
		gen.StConverted: "b-converted", gen.StPartial: "b-partial",
		gen.StManual: "b-manual", gen.StFailed: "b-failed", gen.StInfo: "b-info",
	}[status]
	if cls == "" {
		cls = "b-info"
	}
	return fmt.Sprintf(`<span class="badge %s">%s</span>`, cls, label)
}

func statusBar(c StatusCounts) string {
	total := c.Converted + c.Partial + c.Manual + c.Failed + c.Info
	if total == 0 {
		return ""
	}
	seg := func(n int, cls string) string {
		if n == 0 {
			return ""
		}
		return fmt.Sprintf(`<div class="%s" style="width:%.1f%%"></div>`, cls, float64(n)*100/float64(total))
	}
	return `<div class="bar">` + seg(c.Converted, "s-ok") + seg(c.Partial, "s-warn") +
		seg(c.Manual, "s-man") + seg(c.Failed, "s-bad") + seg(c.Info, "s-info") + `</div>`
}

func vendorPair(in *ReportInput) string {
	return esc(fwir.VendorLabel(in.Source)) + " → " + esc(fwir.VendorLabel(in.Target))
}

func header(b *strings.Builder, in *ReportInput, title string) {
	fmt.Fprintf(b, `<!doctype html><html><head><meta charset="utf-8"><title>%s</title><style>%s</style></head><body>`, esc(title), reportCSS)
	free := ""
	if in.FreeTier {
		free = ` <span class="free">— free edition</span>`
	}
	fmt.Fprintf(b, `<h1>%s%s</h1><p class="sub">%s · job %s · host %s · generated %s · RuleForge</p>`,
		esc(title), free, vendorPair(in), esc(in.JobID), esc(orDash(in.Hostname)), in.Created.Format("2006-01-02 15:04 MST"))
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// BuildProcessReport renders the Conversion Process Report: every element and
// its outcome.
func BuildProcessReport(in *ReportInput) string {
	var b strings.Builder
	header(&b, in, "Conversion Process Report")

	if in.Review != nil {
		t := in.Review.Totals
		fmt.Fprintf(&b, `<div class="kpis">
<div class="kpi"><b>%d</b><span>converted</span></div>
<div class="kpi"><b>%d</b><span>partial</span></div>
<div class="kpi"><b>%d</b><span>manual review</span></div>
<div class="kpi"><b>%d</b><span>failed</span></div>
<div class="kpi"><b>%d</b><span>informational</span></div></div>`,
			t.Converted, t.Partial, t.Manual, t.Failed, t.Info)
		b.WriteString(statusBar(t))
	}

	order := []string{"interface", "zone", "object", "service", "group", "rule", "nat", "route", "captured", "unparsed"}
	catTitle := map[string]string{
		"interface": "Interfaces", "zone": "Zones", "object": "Network objects", "service": "Service objects",
		"group": "Object groups", "rule": "Access rules", "nat": "NAT rules", "route": "Static routes",
		"captured": "Captured features (manual review)", "unparsed": "Unrecognised lines",
	}
	for _, res := range in.Results {
		fmt.Fprintf(&b, `<h2>Context: %s</h2>`, esc(res.Context))
		if len(res.Renames) > 0 {
			b.WriteString(`<details><summary>Name transforms applied (` + fmt.Sprint(len(res.Renames)) + `)</summary><table><tr><th>Source name</th><th>Target name</th></tr>`)
			for src, tgt := range res.Renames {
				fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td><code>%s</code></td></tr>`, esc(src), esc(tgt))
			}
			b.WriteString(`</table></details>`)
		}
		byCat := map[string][]gen.Item{}
		for _, it := range res.Items {
			byCat[it.Category] = append(byCat[it.Category], it)
		}
		for _, cat := range order {
			items := byCat[cat]
			if len(items) == 0 {
				continue
			}
			fmt.Fprintf(&b, `<h3>%s (%d)</h3><table><tr><th style="width:26%%">Element</th><th style="width:14%%">Outcome</th><th>Detail / generated output</th></tr>`, catTitle[cat], len(items))
			for _, it := range items {
				detail := ""
				if it.Detail != "" {
					detail = esc(it.Detail)
				}
				if it.Output != "" {
					detail += `<details><summary>output</summary><pre>` + esc(it.Output) + `</pre></details>`
				}
				fmt.Fprintf(&b, `<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>`, esc(it.Name), badge(it.Status), detail)
			}
			b.WriteString(`</table>`)
		}
	}
	// captured raw evidence
	b.WriteString(`<h2>Captured feature source lines</h2><p class="sub">Everything RuleForge recognised but did not auto-convert, preserved verbatim so nothing is lost.</p>`)
	for i := range in.Config.Contexts {
		x := &in.Config.Contexts[i]
		if len(x.Captured) == 0 {
			continue
		}
		fmt.Fprintf(&b, `<h3>Context %s</h3>`, esc(x.Name))
		for _, c := range x.Captured {
			fmt.Fprintf(&b, `<details><summary>[%s] %s — %s</summary><pre>%s</pre></details>`,
				esc(c.Category), esc(orDash(c.Name)), esc(c.Detail), esc(strings.Join(c.Raw, "\n")))
		}
	}
	b.WriteString(`<footer>RuleForge — multivendor firewall migration. This report lists every source element and its conversion outcome; nothing was silently dropped.</footer></body></html>`)
	return b.String()
}

// BuildFinalReport renders the Final Migration Report: executive before/after
// comparison, mapping tables, fidelity metrics, cut-over checklist.
func BuildFinalReport(in *ReportInput) string {
	var b strings.Builder
	header(&b, in, "Final Migration Report")

	if in.Review != nil {
		cls, label := "v-review", "REVIEW NEEDED — walk the partial/manual items before cut-over"
		switch in.Review.Verdict {
		case "ready":
			cls, label = "v-ready", "READY — all elements converted cleanly"
		case "blocked":
			cls, label = "v-blocked", "BLOCKED — failed elements must be resolved before cut-over"
		}
		fmt.Fprintf(&b, `<div class="verdict %s">%s</div>`, cls, label)
		for _, n := range in.Review.Notes {
			fmt.Fprintf(&b, `<div class="note">%s</div>`, esc(n))
		}
	}

	// before/after per category
	b.WriteString(`<h2>Before / after by category</h2><table><tr><th>Category</th><th>Source elements</th><th>Converted</th><th>Partial</th><th>Manual</th><th>Failed</th><th>Distribution</th></tr>`)
	if in.Review != nil {
		for _, c := range in.Review.Categories {
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td></tr>`,
				esc(c.Category), c.Source, c.Counts.Converted, c.Counts.Partial, c.Counts.Manual, c.Counts.Failed, statusBar(c.Counts))
		}
	}
	b.WriteString(`</table>`)

	// round-trip
	b.WriteString(`<h2>Round-trip verification</h2>`)
	if in.Review != nil && in.Review.RoundTripOK != nil {
		verdict := `<span class="badge b-converted">PASS</span>`
		if !*in.Review.RoundTripOK {
			verdict = `<span class="badge b-failed">MISMATCH</span>`
		}
		fmt.Fprintf(&b, `<p>The generated configuration was re-parsed by RuleForge's own %s parser and compared against the intermediate model: %s</p>`, esc(fwir.VendorLabel(in.Target)), verdict)
		b.WriteString(`<table><tr><th>Metric</th><th>Source</th><th>Re-parsed output</th><th>Check</th><th>Note</th></tr>`)
		for _, c := range in.Review.RoundTrip {
			ok := `<span class="badge b-converted">ok</span>`
			if !c.OK {
				ok = `<span class="badge b-failed">mismatch</span>`
			}
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td></tr>`, esc(c.Metric), c.Before, c.After, ok, esc(c.Note))
		}
		b.WriteString(`</table>`)
	} else {
		b.WriteString(`<p class="sub">Not available for this target format (JSON bundle / mgmt_cli script). Use the per-item process report as the verification source.</p>`)
	}

	// source inventory
	if in.Analysis != nil {
		b.WriteString(`<h2>Source inventory (deep analysis)</h2>`)
		if in.Analysis.MultiTenant {
			fmt.Fprintf(&b, `<div class="note">Multi-tenant source: %d %s, each converted to its own tenant on the target.</div>`, len(in.Analysis.Contexts), esc(in.Analysis.TenantKind))
		}
		b.WriteString(`<table><tr><th>Context</th><th>Interfaces</th><th>Zones</th><th>Objects</th><th>Services</th><th>Groups</th><th>Rules</th><th>NAT</th><th>Routes</th><th>Captured</th></tr>`)
		for _, c := range in.Analysis.Contexts {
			i := c.Inventory
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>`,
				esc(c.Name), i.Interfaces, i.Zones, i.NetObjects, i.Services, i.NetGroups+i.SvcGroups, i.Rules, i.NATs, i.Routes, i.Captured)
		}
		b.WriteString(`</table>`)
		for _, c := range in.Analysis.Contexts {
			for _, r := range c.Risks {
				fmt.Fprintf(&b, `<div class="risk"><b>%s:</b> %s</div>`, esc(c.Name), esc(r))
			}
		}
	}

	// mapping as applied
	if len(in.MapEntry) > 0 {
		b.WriteString(`<h2>Mapping applied</h2><table><tr><th>Kind</th><th>Context</th><th>Source</th><th>Target</th><th>Note</th></tr>`)
		for _, e := range in.MapEntry {
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>`,
				esc(e.Kind), esc(e.Context), esc(e.Source), esc(e.Target), esc(e.Note))
		}
		b.WriteString(`</table>`)
	}

	// unconverted register
	b.WriteString(`<h2>Unconverted-item register</h2>`)
	anyManual := false
	b.WriteString(`<table><tr><th>Context</th><th>Element</th><th>Status</th><th>What to do</th></tr>`)
	for _, res := range in.Results {
		for _, it := range res.Items {
			if it.Status != gen.StManual && it.Status != gen.StFailed {
				continue
			}
			anyManual = true
			fmt.Fprintf(&b, `<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>`,
				esc(res.Context), esc(it.Name), badge(it.Status), esc(it.Detail))
		}
	}
	b.WriteString(`</table>`)
	if !anyManual {
		b.WriteString(`<p class="sub">None — every element converted automatically.</p>`)
	}

	// cut-over checklist
	b.WriteString(`<h2>Recommended cut-over checklist</h2><table><tr><th>#</th><th>Step</th></tr>`)
	steps := []string{
		"Load the generated configuration into a lab or maintenance-window device and verify it applies without syntax errors.",
		"Walk every PARTIAL item in the process report and confirm the chosen translation is acceptable.",
		"Rebuild every MANUAL item (VPN, certificates, dynamic routing, URL/app profiles) using the captured source lines in the process report.",
		"Verify interface/zone mapping against the physical cabling plan (see Mapping applied table).",
		"Confirm NAT behaviour with test flows: one per NAT rule kind (static, PAT, pool, twice).",
		"Compare hit counters / traffic logs for the top 10 rules after cut-over against the source device baseline.",
		"Keep the source device configuration archived; do not decommission until the target has passed a full business cycle.",
	}
	for i, s := range steps {
		fmt.Fprintf(&b, `<tr><td>%d</td><td>%s</td></tr>`, i+1, esc(s))
	}
	b.WriteString(`</table>`)

	b.WriteString(`<footer>RuleForge — multivendor firewall migration. Compare this document with the Conversion Process Report for element-level evidence.</footer></body></html>`)
	return b.String()
}
