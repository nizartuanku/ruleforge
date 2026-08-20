package webui

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nizartuanku/ruleforge/engine"
	"github.com/nizartuanku/ruleforge/store"
)

func testdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func createJob(t *testing.T, ts *httptest.Server, source, target, file string) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("source", source)
	_ = mw.WriteField("target", target)
	fw, _ := mw.CreateFormFile("file0", file)
	_, _ = fw.Write([]byte(testdata(t, file)))
	mw.Close()
	resp, err := http.Post(ts.URL+"/api/jobs", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	out["_status"] = resp.StatusCode
	return out
}

func TestFullFlowAndTierLimits(t *testing.T) {
	st := store.NewMem()
	srv := New(st, nil, "", "test") // nil pubkey → free tier
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// meta
	resp, _ := http.Get(ts.URL + "/api/meta")
	var meta map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&meta)
	if meta["tier"] != "free" {
		t.Fatalf("tier = %v", meta["tier"])
	}

	// create PAN→FortiGate job (single tenant, small — allowed on free)
	job := createJob(t, ts, "paloalto", "fortinet", "panos-fw.txt")
	if job["_status"].(int) != 201 {
		t.Fatalf("create: %v", job)
	}
	id := job["id"].(string)
	if job["status"] != engine.JobAnalyzed {
		t.Fatalf("status = %v", job["status"])
	}
	if job["analysis"] == nil || job["proposal"] == nil {
		t.Fatal("analysis/proposal missing")
	}

	// free tier: second job blocked
	j2 := createJob(t, ts, "paloalto", "cisco-asa", "panos-fw.txt")
	if j2["_status"].(int) != 403 {
		t.Fatalf("second job should hit the free cap: %v", j2)
	}

	// convert
	resp, err := http.Post(ts.URL+"/api/jobs/"+id+"/convert", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var conv map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&conv)
	if resp.StatusCode != 200 {
		t.Fatalf("convert: %v", conv)
	}
	if conv["status"] != engine.JobConverted {
		t.Fatalf("status = %v", conv["status"])
	}
	review := conv["review"].(map[string]any)
	// free tier strips round-trip
	if _, has := review["round_trip"]; has && review["round_trip"] != nil {
		t.Fatal("round-trip should be stripped on free tier")
	}

	// process report available
	resp, _ = http.Get(ts.URL + "/api/jobs/" + id + "/report/process")
	if resp.StatusCode != 200 {
		t.Fatalf("process report: %d", resp.StatusCode)
	}
	body := make([]byte, 400)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "Conversion Process Report") {
		t.Fatal("process report content wrong")
	}
	// final report gated
	resp, _ = http.Get(ts.URL + "/api/jobs/" + id + "/report/final")
	if resp.StatusCode != 403 {
		t.Fatalf("final report should be Pro-gated, got %d", resp.StatusCode)
	}

	// file download
	files := []string{}
	for _, r := range conv["results"].([]any) {
		for _, f := range r.(map[string]any)["files"].([]any) {
			files = append(files, f.(map[string]any)["name"].(string))
		}
	}
	if len(files) == 0 {
		t.Fatal("no generated files")
	}
	resp, _ = http.Get(ts.URL + "/api/jobs/" + id + "/file?name=" + files[0])
	if resp.StatusCode != 200 {
		t.Fatalf("file download: %d", resp.StatusCode)
	}
}

func TestMultiTenantGate(t *testing.T) {
	st := store.NewMem()
	srv := New(st, nil, "", "test")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	job := createJob(t, ts, "cisco-asa", "paloalto", "asa-multictx.cfg")
	if job["_status"].(int) != 201 {
		t.Fatalf("create: %v", job)
	}
	id := job["id"].(string)
	resp, _ := http.Post(ts.URL+"/api/jobs/"+id+"/convert", "application/json", nil)
	if resp.StatusCode != 403 {
		t.Fatalf("multi-context convert should be gated on free tier, got %d", resp.StatusCode)
	}
}

func TestVendorValidation(t *testing.T) {
	st := store.NewMem()
	srv := New(st, nil, "", "test")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("source", "cisco-asa")
	_ = mw.WriteField("target", "cisco-asa")
	_ = mw.WriteField("config", "access-list X extended permit ip any any")
	mw.Close()
	resp, _ := http.Post(ts.URL+"/api/jobs", mw.FormDataContentType(), &buf)
	if resp.StatusCode != 400 {
		t.Fatalf("same-vendor should be rejected, got %d", resp.StatusCode)
	}
}
