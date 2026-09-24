package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nizartuanku/ruleforge/engine"
	"github.com/nizartuanku/ruleforge/gen"
	"github.com/nizartuanku/ruleforge/license"
	"github.com/nizartuanku/ruleforge/store"
)

// fakeSidecar answers like a grammar-constrained hexward-ai sidecar and
// records the last request it received.
type fakeSidecar struct {
	srv      *httptest.Server
	calls    atomic.Int32
	lastBody atomic.Value // string
	lastAuth atomic.Value // string
	status   int
}

func newFakeSidecar(t *testing.T) *fakeSidecar {
	t.Helper()
	f := &fakeSidecar{status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		b := new(bytes.Buffer)
		b.ReadFrom(r.Body)
		f.lastBody.Store(b.String())
		f.lastAuth.Store(r.Header.Get("Authorization"))
		if f.status != http.StatusOK {
			w.WriteHeader(f.status)
			return
		}
		content, _ := json.Marshal(map[string]any{
			"explanation":    "This element was not converted automatically.",
			"what_to_verify": []string{"Confirm the element is still needed on the target."},
			"disclaimer":     "model-authored text that must be overwritten",
		})
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": string(content)}}},
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// aiTestServer stores one converted job whose per-item outcomes include a
// manual-review item named after a source line that carries a pre-shared
// key, a generated snippet that must never leave the process, and a clean
// item that is not an issue at all.
func aiTestServer(t *testing.T, ai *AIAssist, tier license.Tier) (*Server, *httptest.Server) {
	t.Helper()
	st := store.NewMem()
	job := &engine.Job{
		ID: "job1", Name: "ASA → FortiGate", Created: time.Now(),
		Source: "cisco-asa", Target: "fortinet", Status: engine.JobConverted,
		Results: []*gen.Result{{
			Context: "single",
			Items: []gen.Item{
				{Category: "rule", Name: "OUTSIDE_in-7", Status: gen.StPartial,
					Detail: "time-range schedule dropped — FortiGate schedules must be created by hand",
					Output: "SNIPPET-DO-NOT-SEND"},
				{Category: "captured", Name: "isakmp key HUNTER2 address 203.0.113.9", Status: gen.StManual,
					Detail: "vpn: crypto configuration — not auto-converted in v1; source lines preserved in the report"},
				{Category: "object", Name: "net-dmz", Status: gen.StConverted},
			},
		}},
		Review: &engine.Review{Verdict: "review-needed"},
	}
	if err := st.Put(job); err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, Version: "test", AI: ai}
	s.activation = license.Activation{Tier: tier}
	api := httptest.NewServer(s.Handler())
	t.Cleanup(api.Close)
	return s, api
}

func postExplain(t *testing.T, api *httptest.Server, jobID, body string) (int, explainResponse) {
	t.Helper()
	resp, err := http.Post(api.URL+"/api/jobs/"+jobID+"/issues/explain", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out explainResponse
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAI_OffByDefault(t *testing.T) {
	ai, err := NewAIAssist(AIConfig{})
	if err != nil || ai != nil {
		t.Fatalf("empty URL must mean AI off, got %v, %v", ai, err)
	}
	_, api := aiTestServer(t, nil, license.TierFree)
	code, out := postExplain(t, api, "job1", `{"context":"single","index":0}`)
	if code != http.StatusOK || out.Available || out.Reason == "" {
		t.Fatalf("AI off: want 200 available=false with a reason, got %d %+v", code, out)
	}
	resp, _ := http.Get(api.URL + "/api/ai")
	var st aiStatusResponse
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if st.Enabled {
		t.Error("/api/ai must report enabled=false when AI Assist is off")
	}
}

func TestAI_RejectsBadURLAndEmptyKey(t *testing.T) {
	if _, err := NewAIAssist(AIConfig{URL: "127.0.0.1:8435"}); err == nil {
		t.Error("URL without scheme must be rejected")
	}
	empty := filepath.Join(t.TempDir(), "k")
	os.WriteFile(empty, []byte("  \n"), 0o600)
	if _, err := NewAIAssist(AIConfig{URL: "http://127.0.0.1:8435", KeyFile: empty}); err == nil {
		t.Error("empty key file must be rejected")
	}
}

func TestAI_ExplainHappyPathSendsOnlySafeFields(t *testing.T) {
	side := newFakeSidecar(t)
	ai, err := NewAIAssist(AIConfig{URL: side.srv.URL, Language: "id"})
	if err != nil {
		t.Fatal(err)
	}
	_, api := aiTestServer(t, ai, license.TierFree)

	// A partial rule: the message, a short identifier and the vendors go;
	// the generated snippet does not.
	code, out := postExplain(t, api, "job1", `{"context":"single","index":0}`)
	if code != http.StatusOK || !out.Available {
		t.Fatalf("want available explanation, got %d %+v", code, out)
	}
	if out.Disclaimer != "AI-generated summary — verify against raw findings" {
		t.Errorf("disclaimer not canonical: %q", out.Disclaimer)
	}
	body, _ := side.lastBody.Load().(string)
	if strings.Contains(body, "SNIPPET-DO-NOT-SEND") {
		t.Error("generated output reached the sidecar")
	}
	for _, want := range []string{"hexward.explain_finding", `\"product\":\"ruleforge\"`, "conversion.partial", "OUTSIDE_in-7",
		"time-range schedule dropped", `\"severity\":\"low\"`, "Cisco ASA", "Bahasa Indonesia"} {
		if !strings.Contains(body, want) {
			t.Errorf("request to sidecar lacks %q", want)
		}
	}

	// A captured feature named after a source line with a pre-shared key:
	// the identifier is withheld, the outcome and category still go.
	if _, out := postExplain(t, api, "job1", `{"context":"single","index":1}`); !out.Available {
		t.Fatalf("manual item must be explainable, got %+v", out)
	}
	body, _ = side.lastBody.Load().(string)
	if strings.Contains(body, "HUNTER2") || strings.Contains(body, "203.0.113.9") {
		t.Error("secret-like identifier reached the sidecar")
	}
	for _, want := range []string{"conversion.manual", `\"severity\":\"medium\"`, "identifier withheld"} {
		if !strings.Contains(body, want) {
			t.Errorf("request to sidecar lacks %q", want)
		}
	}
	if side.calls.Load() != 2 {
		t.Errorf("sidecar calls = %d, want 2", side.calls.Load())
	}
}

func TestAI_SeverityMappingIsFixed(t *testing.T) {
	want := map[string]string{gen.StFailed: "high", gen.StManual: "medium", gen.StPartial: "low", gen.StInfo: "info", gen.StConverted: ""}
	for st, sev := range want {
		if got := issueSeverity(st); got != sev {
			t.Errorf("issueSeverity(%q) = %q, want %q", st, got, sev)
		}
	}
	if safeTarget("unparsed", "enable password 5up3r53cr3t encrypted") != "unparsed source line" {
		t.Error("unparsed lines must never be sent as the target")
	}
	if safeTarget("rule", "OUTSIDE_in-7") != "OUTSIDE_in-7" {
		t.Error("plain rule names must pass through")
	}
}

func TestAI_KeyedEndpointNeedsPaidTier(t *testing.T) {
	side := newFakeSidecar(t)
	kf := filepath.Join(t.TempDir(), "ai_api_key")
	os.WriteFile(kf, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	ai, err := NewAIAssist(AIConfig{URL: side.srv.URL, KeyFile: kf})
	if err != nil {
		t.Fatal(err)
	}

	_, freeAPI := aiTestServer(t, ai, license.TierFree)
	code, out := postExplain(t, freeAPI, "job1", `{"context":"single","index":0}`)
	if code != http.StatusOK || out.Available || !strings.Contains(out.Reason, "Pro or Team") {
		t.Fatalf("free tier + keyed endpoint must be refused with a reason, got %d %+v", code, out)
	}
	if side.calls.Load() != 0 {
		t.Fatal("free tier must not send anything to a keyed endpoint")
	}

	for _, tier := range []license.Tier{license.TierPro, license.TierTeam} {
		_, paidAPI := aiTestServer(t, ai, tier)
		if _, out := postExplain(t, paidAPI, "job1", `{"context":"single","index":0}`); !out.Available {
			t.Fatalf("%s tier + keyed endpoint must work, got %+v", tier, out)
		}
		if auth, _ := side.lastAuth.Load().(string); auth != "Bearer 0123456789abcdef0123456789abcdef" {
			t.Errorf("Authorization header = %q", auth)
		}
	}
}

func TestAI_SidecarDownDegradesQuietly(t *testing.T) {
	side := newFakeSidecar(t)
	side.status = http.StatusServiceUnavailable
	ai, _ := NewAIAssist(AIConfig{URL: side.srv.URL})
	s, api := aiTestServer(t, ai, license.TierFree)
	code, out := postExplain(t, api, "job1", `{"context":"single","index":0}`)
	if code != http.StatusOK || out.Available || out.Reason == "" {
		t.Fatalf("sidecar 503 must give 200 available=false with a reason, got %d %+v", code, out)
	}
	j, err := s.Store.Get("job1")
	if err != nil || j.Status != engine.JobConverted || j.Review.Verdict != "review-needed" ||
		len(j.Results[0].Items) != 3 || j.Results[0].Items[0].Status != gen.StPartial {
		t.Fatalf("job must be untouched after an AI failure, got %+v (%v)", j, err)
	}
}

func TestAI_BadRequests(t *testing.T) {
	side := newFakeSidecar(t)
	ai, _ := NewAIAssist(AIConfig{URL: side.srv.URL})
	_, api := aiTestServer(t, ai, license.TierFree)
	cases := []struct {
		name, job, body string
		want            int
	}{
		{"missing index", "job1", `{"context":"single"}`, http.StatusBadRequest},
		{"not json", "job1", `nope`, http.StatusBadRequest},
		{"unknown job", "job9", `{"context":"single","index":0}`, http.StatusNotFound},
		{"unknown context", "job1", `{"context":"vdom2","index":0}`, http.StatusNotFound},
		{"index out of range", "job1", `{"context":"single","index":7}`, http.StatusNotFound},
		{"converted item is not an issue", "job1", `{"context":"single","index":2}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		if code, _ := postExplain(t, api, c.job, c.body); code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, code, c.want)
		}
	}
	if side.calls.Load() != 0 {
		t.Error("invalid requests must never reach the sidecar")
	}
}
