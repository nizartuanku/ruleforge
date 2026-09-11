package webui

import (
	"bufio"
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
// truncated and converted with a clean-looking report. E-27 raised the real
// production ceiling to 1 GiB (see TestLargeUploadStreamsToDisk for the
// literal 800 MB/1.2 GB proof at that size) — this test dials the ceiling
// down to a few MB so the same reject-and-report-the-real-size code path is
// exercised on every `go test ./...`, not just in the opt-in gigabyte run.
func TestOversizeUploadRejected(t *testing.T) {
	origLimit := maxUploadBytes
	maxUploadBytes = 4 << 20 // 4 MiB, just for this test
	defer func() { maxUploadBytes = origLimit }()

	st := store.NewMem()
	srv := New(st, nil, "", "test")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("source", "cisco-asa")
	_ = mw.WriteField("target", "paloalto")
	fw, _ := mw.CreateFormFile("file0", "huge.cfg")
	line := []byte("access-list OUT extended permit tcp any any eq 443\n")
	var written int64
	for written < 5<<20 { // 5 MiB, past the 4 MiB test limit
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
	for _, want := range []string{"huge.cfg", "4194305", "4 MB"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("413 message missing %q: %s", want, msg)
		}
	}
	if n, _ := st.Count(); n != 0 {
		t.Fatalf("job was stored despite 413: %d jobs", n)
	}
}

// streamedMultipartPost posts source/target fields plus one file part read
// straight from filePath, streamed through an io.Pipe. Nothing is buffered
// whole in memory on the client side either — this is meant to look like a
// real browser upload of a large file, matching what the server now does on
// its side (E-27).
func streamedMultipartPost(t *testing.T, url, source, target, filePath, filename string) *http.Response {
	t.Helper()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		_ = mw.WriteField("source", source)
		_ = mw.WriteField("target", target)
		fw, err := mw.CreateFormFile("file0", filename)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		f, err := os.Open(filePath)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		_, cerr := io.Copy(fw, f)
		f.Close()
		if cerr != nil {
			pw.CloseWithError(cerr)
			return
		}
		pw.CloseWithError(mw.Close())
	}()
	req, err := http.NewRequest("POST", url, pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestLargeUploadStreamsToDisk is the E-27 proof gate: a config near the
// real 6-8 million line target (~800 MB) must be accepted and converted, and
// a config past the new 1 GiB ceiling (~1.2 GB) must be rejected with a
// numeric 413 — never silently truncated. Real files on disk, real HTTP,
// same empirical pattern as TestOversizeUploadRejected (RF-1). Opt-in
// because generating and posting ~2 GB combined takes real time and disk:
//
//	RF27_LARGE=1 go test ./webui/ -run TestLargeUploadStreamsToDisk -v -timeout 30m
func TestLargeUploadStreamsToDisk(t *testing.T) {
	if os.Getenv("RF27_LARGE") == "" {
		t.Skip("set RF27_LARGE=1 to run the ~2 GB E-27 proof gate (real 800 MB accept + 1.2 GB reject)")
	}
	dir := t.TempDir()

	writeConfig := func(path string, targetBytes int64) int64 {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		bw := bufio.NewWriterSize(f, 4<<20)
		line := []byte("access-list outside_access_in extended permit tcp 10.0.0.0 255.255.255.0 host 172.16.0.1 eq 443\n")
		var written int64
		for written < targetBytes {
			n, _ := bw.Write(line)
			written += int64(n)
		}
		if err := bw.Flush(); err != nil {
			t.Fatal(err)
		}
		return written
	}

	t.Run("800MB_accepted", func(t *testing.T) {
		st := store.NewMem()
		srv := New(st, nil, "", "test")
		ts := httptest.NewServer(srv.Handler())
		defer ts.Close()

		path := filepath.Join(dir, "big-ok.cfg")
		size := writeConfig(path, 800<<20) // 800 MB — under the 1 GiB cap
		t.Logf("generated %d bytes (%.1f MB)", size, float64(size)/(1<<20))

		resp := streamedMultipartPost(t, ts.URL+"/api/jobs", "cisco-asa", "paloalto", path, "big-ok.cfg")
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != 201 {
			t.Fatalf("800 MB config should be accepted, got %d: %v", resp.StatusCode, out)
		}
		if out["analysis"] == nil {
			t.Fatal("job missing analysis — parse should have run on the full 800 MB body")
		}
		if n, _ := st.Count(); n != 1 {
			t.Fatalf("expected exactly one stored job, got %d", n)
		}
	})

	t.Run("1_2GB_rejected", func(t *testing.T) {
		st := store.NewMem()
		srv := New(st, nil, "", "test")
		ts := httptest.NewServer(srv.Handler())
		defer ts.Close()

		path := filepath.Join(dir, "big-reject.cfg")
		size := writeConfig(path, 1_200<<20) // 1.2 GB — past the 1 GiB cap
		t.Logf("generated %d bytes (%.1f MB)", size, float64(size)/(1<<20))

		resp := streamedMultipartPost(t, ts.URL+"/api/jobs", "cisco-asa", "paloalto", path, "big-reject.cfg")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413 — a config past the 1 GiB cap must never convert", resp.StatusCode)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		msg, _ := out["error"].(string)
		for _, want := range []string{"big-reject.cfg", "1073741824", "1024 MB"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("413 message missing %q: %s", want, msg)
			}
		}
		if n, _ := st.Count(); n != 0 {
			t.Fatalf("job was stored despite 413: %d jobs", n)
		}
	})
}
