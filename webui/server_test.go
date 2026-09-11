package webui

import (
	"bytes"
	"encoding/json"
	"io"
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

// TestOversizeUploadRejected guards the core product promise: a config larger
// than the upload limit must be rejected with a numeric 413, never silently
// truncated and converted with a clean-looking report. The limit is lowered
// here so the test proves the behaviour without moving a gigabyte.
func TestOversizeUploadRejected(t *testing.T) {
	st := store.NewMem()
	srv := New(st, nil, "", "test")
	tmp := t.TempDir()
	srv.TempDir = tmp
	srv.MaxUploadBytes = 1 << 20 // 1_048_576
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("source", "cisco-asa")
	_ = mw.WriteField("target", "paloalto")
	fw, _ := mw.CreateFormFile("file0", "huge.cfg")
	line := []byte("access-list OUT extended permit tcp any any eq 443\n")
	var written int64
	for written < 3<<20 { // 3 MB, past the 1 MB limit set above
		n, _ := fw.Write(line)
		written += int64(n)
	}
	mw.Close()

	resp, err := http.Post(ts.URL+"/api/jobs", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 — an oversize config must never convert", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	msg, _ := out["error"].(string)
	for _, want := range []string{"huge.cfg", "1048576", "1 MB", "Nothing was converted"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("413 message missing %q: %s", want, msg)
		}
	}
	if n, _ := st.Count(); n != 0 {
		t.Fatalf("job was stored despite 413: %d jobs", n)
	}
	assertTempDirEmpty(t, tmp)
}

// TestUploadOverDefaultLimitStreamsToDisk checks the two halves of the
// streaming change together: a file far past the old 32 MB ceiling is accepted
// under the new default, and the temporary copy is removed afterwards.
func TestUploadOverDefaultLimitStreamsToDisk(t *testing.T) {
	if testing.Short() {
		t.Skip("moves 40 MB through the handler")
	}
	st := store.NewMem()
	srv := New(st, nil, "", "test")
	tmp := t.TempDir()
	srv.TempDir = tmp
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("source", "cisco-asa")
	_ = mw.WriteField("target", "paloalto")
	fw, _ := mw.CreateFormFile("file0", "big.cfg")
	_, _ = fw.Write([]byte("ASA Version 9.16(1)\nhostname big\n"))
	line := []byte("access-list OUT extended permit tcp any any eq 443\n")
	var written int64
	for written < 40<<20 { // 40 MB: refused before this change, accepted now
		n, _ := fw.Write(line)
		written += int64(n)
	}
	mw.Close()

	resp, err := http.Post(ts.URL+"/api/jobs", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201 for a %d-byte upload: %s", resp.StatusCode, written, b)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)

	// The raw text must not travel back with the job: that is what makes a
	// job of this size affordable to store and to fetch.
	ins, _ := out["inputs"].([]any)
	if len(ins) != 1 {
		t.Fatalf("inputs = %v, want one entry recording the upload", out["inputs"])
	}
	in0, _ := ins[0].(map[string]any)
	if _, ok := in0["content"]; ok {
		t.Fatalf("job response carries the raw upload: %v", in0)
	}
	if size, _ := in0["size"].(float64); int64(size) < written {
		t.Fatalf("recorded size = %v, want at least %d", in0["size"], written)
	}
	assertTempDirEmpty(t, tmp)
}

// TestUploadFieldSizeCapped keeps a form field from becoming an unbounded
// allocation: the paste box is for a few hundred lines, not a rulebase.
func TestUploadFieldSizeCapped(t *testing.T) {
	st := store.NewMem()
	srv := New(st, nil, "", "test")
	tmp := t.TempDir()
	srv.TempDir = tmp
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("source", "cisco-asa")
	_ = mw.WriteField("target", "paloalto")
	_ = mw.WriteField("config", strings.Repeat("a", int(maxFieldBytes)+1024))
	mw.Close()

	resp, err := http.Post(ts.URL+"/api/jobs", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for an oversize form field", resp.StatusCode)
	}
	assertTempDirEmpty(t, tmp)
}

func assertTempDirEmpty(t *testing.T, dir string) {
	t.Helper()
	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		names := make([]string, 0, len(left))
		for _, e := range left {
			names = append(names, e.Name())
		}
		t.Fatalf("temporary uploads left behind: %v", names)
	}
}
