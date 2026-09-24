package webui

// AI Assist — the optional "✨ Explain" button next to a conversion issue,
// backed by the hexward-ai sidecar (github.com/nizartuanku/hexward-ai).
//
// The rules this file exists to enforce:
//
//   - RuleForge's own generators stay the ONLY source of conversion
//     outcomes. A "finding" here is one per-item outcome the engine already
//     stored on the job (gen.Item: partial, manual, failed, info). Nothing
//     here creates, edits, re-scores or resolves an item, and the model is
//     never asked to write target configuration — the shared system prompt
//     forbids inventing commands, and the packet carries no rule body for
//     it to rewrite.
//   - AI Assist is off unless the operator starts the binary with
//     -ai-assist-url. Off, unreachable, slow, or answering garbage all look
//     the same to the dashboard: {"available": false} with HTTP 200, and the
//     job is untouched.
//   - Only a bounded, sanitised copy of one issue leaves the process
//     (aiclient.NewFindingPacket drops secret-like evidence keys and caps
//     strings). The uploaded configuration, generated output, rule bodies,
//     pre-shared keys and passwords never do — see handleExplainIssue.
//   - Edition gating: the free edition talks to a sidecar without an API
//     key (same host or same Docker network). An endpoint that needs a key
//     (a dedicated AI host serving several products, or your own
//     OpenAI-compatible endpoint) is a Pro/Team capability. The check runs
//     on every request, so a licence added at runtime takes effect at once.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/nizartuanku/ruleforge/engine"
	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/gen"
	"github.com/nizartuanku/ruleforge/internal/aiclient"
	"github.com/nizartuanku/ruleforge/license"
)

// AIConfig is what cmd/ passes in from its flags.
type AIConfig struct {
	URL        string // sidecar or endpoint base URL; "" = AI Assist off
	KeyFile    string // file holding an API key; set = keyed endpoint (Pro/Team)
	Language   string // "en" (default) or "id"
	NoThinking bool   // Qwen3 enterprise profiles: skip reasoning mode
}

// AIAssist is the resolved, ready-to-use AI configuration of a Server.
type AIAssist struct {
	Client   *aiclient.Client
	Endpoint string
	Keyed    bool
	Language string
}

// NewAIAssist validates cfg and builds the client. It returns (nil, nil)
// when cfg.URL is empty — AI Assist off is the default, not an error. It
// never dials: an absent sidecar is discovered per request and degrades
// quietly.
func NewAIAssist(cfg AIConfig) (*AIAssist, error) {
	raw := strings.TrimSpace(cfg.URL)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("ai-assist-url must be an http(s) base URL such as http://127.0.0.1:8435, got %q", raw)
	}
	opts := []aiclient.Option{
		// CPU inference of a 3-8B model takes tens of seconds; measured
		// 13-53 s per explanation on a CPU-only VM (hexward-ai docs/TIERS.md).
		aiclient.WithTimeout(120 * time.Second),
		// No retries: a timed-out narration retried is another two minutes
		// of a person waiting, not a better answer.
		aiclient.WithMaxRetries(0),
		aiclient.WithMaxTokens(300),
	}
	a := &AIAssist{Endpoint: strings.TrimRight(raw, "/"), Language: aiclient.NormalizeLanguage(cfg.Language)}
	if cfg.KeyFile != "" {
		b, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read ai-assist-key-file: %w", err)
		}
		key := strings.TrimSpace(string(b))
		if key == "" {
			return nil, fmt.Errorf("ai-assist-key-file %s is empty", cfg.KeyFile)
		}
		opts = append(opts, aiclient.WithAPIKey(key))
		a.Keyed = true
	}
	if cfg.NoThinking {
		opts = append(opts, aiclient.WithDisableThinking())
	}
	a.Client = aiclient.New(a.Endpoint, opts...)
	return a, nil
}

func (s *Server) registerAI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ai", s.handleAIStatus)
	mux.HandleFunc("POST /api/jobs/{id}/issues/explain", s.handleExplainIssue)
}

// aiAllowed reports whether AI Assist may be used right now, and if not,
// the sentence the dashboard shows instead of the button.
func (s *Server) aiAllowed() (bool, string) {
	if s.AI == nil || s.AI.Client == nil {
		return false, "AI Assist is off. Start with -ai-assist-url to enable it."
	}
	if t := s.Activation().Tier; s.AI.Keyed && t != license.TierPro && t != license.TierTeam {
		return false, "A dedicated AI host or your own endpoint (API key) needs a Pro or Team licence. The free edition works with a hexward-ai sidecar on the same host."
	}
	return true, ""
}

type aiStatusResponse struct {
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason,omitempty"`
	Language string `json:"language,omitempty"`
	Keyed    bool   `json:"keyed,omitempty"`
}

func (s *Server) handleAIStatus(w http.ResponseWriter, r *http.Request) {
	ok, reason := s.aiAllowed()
	resp := aiStatusResponse{Enabled: ok, Reason: reason}
	if s.AI != nil {
		resp.Language, resp.Keyed = s.AI.Language, s.AI.Keyed
	}
	writeJSON(w, 200, resp)
}

type explainResponse struct {
	Available    bool     `json:"available"`
	Reason       string   `json:"reason,omitempty"`
	Explanation  string   `json:"explanation,omitempty"`
	WhatToVerify []string `json:"what_to_verify,omitempty"`
	Disclaimer   string   `json:"disclaimer,omitempty"`
}

// issueSeverity maps a gen.Item status — RuleForge's own outcome scale —
// onto the Hexward severity words the AI prompt is written for. The
// mapping is fixed and deterministic; the model is told the resulting word
// and may not change it:
//
//	failed  → high    the element is absent from the generated output
//	manual  → medium  recognised, but must be configured by hand on the target
//	partial → low     converted with a documented difference
//	info    → info    nothing to convert; verify whether it needs migrating
//
// A "converted" item is not an issue and cannot be explained ("" here).
func issueSeverity(status string) string {
	switch status {
	case gen.StFailed:
		return "high"
	case gen.StManual:
		return "medium"
	case gen.StPartial:
		return "low"
	case gen.StInfo:
		return "info"
	}
	return ""
}

// issueGuidance is RuleForge's own next step for each outcome — the same
// advice the review verdict and the process report already give, so the
// model can restate it but never has to invent a fix.
func issueGuidance(status string) string {
	switch status {
	case gen.StFailed:
		return "This element is missing from the generated configuration. Fix the source element or migrate it by hand on the target before cut-over; do not deploy while the job verdict is 'blocked'."
	case gen.StManual:
		return "Configure this element by hand on the target and record it in the migration runbook; walk the Conversion Process Report before deploying."
	case gen.StPartial:
		return "Compare the source element with the generated output in the Conversion Process Report and confirm the documented difference is acceptable before deploying."
	case gen.StInfo:
		return "No converter action. Decide whether this element needs migrating at all and, if so, add it to the manual work list."
	}
	return ""
}

// secretish matches identifiers that look like they carry a credential
// rather than a name: some captured features are named after the rest of
// their source line (e.g. "isakmp key ..."), and an unparsed line is raw
// configuration text by definition.
var secretish = regexp.MustCompile(`(?i)\b(password|passwd|secret|key|psk|pre-?shared|token|credential|community)\b`)

// safeTarget returns the short identifier that names the item for the
// model, or a neutral placeholder when the name could be configuration
// text rather than an object/rule name.
func safeTarget(category, name string) string {
	if category == "unparsed" {
		return "unparsed source line"
	}
	if secretish.MatchString(name) {
		return category + " (identifier withheld)"
	}
	return name
}

// findIssue locates one stored per-item outcome by context name and item
// index. It reads; it never writes.
func findIssue(j *engine.Job, context string, index int) (*gen.Result, *gen.Item, bool) {
	for _, res := range j.Results {
		if res.Context != context {
			continue
		}
		if index < 0 || index >= len(res.Items) {
			return nil, nil, false
		}
		return res, &res.Items[index], true
	}
	return nil, nil, false
}

// handleExplainIssue narrates one stored conversion issue. Every failure
// after the request itself is validated answers {"available": false} with
// HTTP 200 — the dashboard shows a quiet note and the job is never touched.
func (s *Server) handleExplainIssue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Context string `json:"context"`
		Index   *int   `json:"index"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Index == nil {
		writeErr(w, http.StatusBadRequest, "context and index are required")
		return
	}
	j := s.job(w, r)
	if j == nil {
		return
	}
	if j.Status != engine.JobConverted || len(j.Results) == 0 {
		writeErr(w, http.StatusBadRequest, "run conversion first — there are no conversion issues to explain yet")
		return
	}
	res, it, ok := findIssue(j, req.Context, *req.Index)
	if !ok {
		writeErr(w, http.StatusNotFound, "no such conversion item")
		return
	}
	sev := issueSeverity(it.Status)
	if sev == "" {
		writeErr(w, http.StatusBadRequest, "this element converted cleanly — only partial, manual, failed and info items can be explained")
		return
	}
	if ok, reason := s.aiAllowed(); !ok {
		writeJSON(w, 200, explainResponse{Available: false, Reason: reason})
		return
	}
	target := safeTarget(it.Category, it.Name)
	title := strings.TrimSpace(it.Detail)
	if title == "" || (it.Category == "unparsed" && secretish.MatchString(title)) {
		title = fmt.Sprintf("%s %s: %s", it.Category, target, it.Status)
	}
	// What leaves the process: the outcome, its message, a short identifier
	// and the vendors involved. Never it.Output (generated snippet), never
	// the uploaded configuration, never a rule body.
	evidence := map[string]any{
		"source_vendor": fwir.VendorLabel(j.Source),
		"target_vendor": fwir.VendorLabel(j.Target),
		"context":       res.Context,
		"category":      it.Category,
		"outcome":       it.Status,
		"item_index":    *req.Index,
	}
	if j.Review != nil {
		evidence["job_verdict"] = j.Review.Verdict
	}
	packet, err := aiclient.NewFindingPacket("ruleforge", s.AI.Language, aiclient.CoreFinding{
		Fingerprint: fmt.Sprintf("%s/%s/%d", j.ID, res.Context, *req.Index),
		Module:      "ruleforge",
		Check:       "conversion." + it.Status,
		Title:       title,
		Target:      target,
		Severity:    sev,
		Status:      "open",
		Remediation: issueGuidance(it.Status),
		Evidence:    evidence,
	})
	if err != nil {
		writeJSON(w, 200, explainResponse{Available: false, Reason: "This item has nothing to explain."})
		return
	}
	exp, err := s.AI.Client.Explain(r.Context(), packet)
	if err != nil {
		writeJSON(w, 200, explainResponse{Available: false, Reason: "The AI Assist sidecar did not answer. The conversion result is unaffected."})
		return
	}
	writeJSON(w, 200, explainResponse{
		Available:    true,
		Explanation:  exp.ExplanationText,
		WhatToVerify: exp.WhatToVerify,
		Disclaimer:   exp.Disclaimer,
	})
}
