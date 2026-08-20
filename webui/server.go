// Package webui serves the RuleForge dashboard: a JSON API plus an embedded
// single-file UI. The surface is the four-step pipeline — Upload → Analyze →
// Map → Convert & Review — with every deep detail one click down.
package webui

import (
	"crypto/ed25519"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nizartuanku/ruleforge/engine"
	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/license"
	"github.com/nizartuanku/ruleforge/parse"
	"github.com/nizartuanku/ruleforge/store"
)

//go:embed static
var staticFS embed.FS

// Caps is what a tier concretely allows in RuleForge terms.
type Caps struct {
	MaxJobs        int  `json:"max_jobs"`          // 0 = unlimited
	MaxRulesPerJob int  `json:"max_rules_per_job"` // 0 = unlimited (conversion cap; analysis is never capped)
	MultiTenant    bool `json:"multi_tenant"`      // convert multi-context/VDOM/device-group sources
	FinalReport    bool `json:"final_report"`
	RoundTrip      bool `json:"round_trip"`
}

// TierCaps is the single source of truth for what each tier buys. The Whop
// product page must match this table.
var TierCaps = map[license.Tier]Caps{
	license.TierFree: {MaxJobs: 1, MaxRulesPerJob: 50},
	license.TierPro:  {MaxJobs: 25, MultiTenant: true, FinalReport: true, RoundTrip: true},
	license.TierTeam: {MultiTenant: true, FinalReport: true, RoundTrip: true},
}

// Server wires the dashboard.
type Server struct {
	Store       store.Store
	IssuerPub   ed25519.PublicKey
	LicenseFile string
	Version     string

	mu         sync.RWMutex
	activation license.Activation
}

// New resolves the initial activation and returns a ready Server.
func New(st store.Store, pub ed25519.PublicKey, licenseFile, version string) *Server {
	s := &Server{Store: st, IssuerPub: pub, LicenseFile: licenseFile, Version: version}
	key := ""
	if licenseFile != "" {
		if b, err := os.ReadFile(licenseFile); err == nil {
			key = strings.TrimSpace(string(b))
		}
	}
	s.activation = license.Activate(pub, "ruleforge", key, time.Now())
	return s
}

// Activation returns the current resolved activation.
func (s *Server) Activation() license.Activation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activation
}

func (s *Server) caps() Caps {
	act := s.Activation()
	if c, ok := TierCaps[act.Tier]; ok {
		return c
	}
	return TierCaps[license.TierFree]
}

// Handler builds the full http.Handler (API + static UI).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/meta", s.handleMeta)
	mux.HandleFunc("POST /api/license", s.handleLicense)
	mux.HandleFunc("GET /api/jobs", s.handleJobs)
	mux.HandleFunc("POST /api/jobs", s.handleCreateJob)
	mux.HandleFunc("GET /api/jobs/{id}", s.handleJob)
	mux.HandleFunc("DELETE /api/jobs/{id}", s.handleDeleteJob)
	mux.HandleFunc("POST /api/jobs/{id}/mapping", s.handleMapping)
	mux.HandleFunc("POST /api/jobs/{id}/convert", s.handleConvert)
	mux.HandleFunc("GET /api/jobs/{id}/file", s.handleFile)
	mux.HandleFunc("GET /api/jobs/{id}/report/{kind}", s.handleReport)

	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	act := s.Activation()
	var vendors []map[string]string
	for _, v := range fwir.Vendors() {
		vendors = append(vendors, map[string]string{"id": v, "label": fwir.VendorLabel(v)})
	}
	writeJSON(w, 200, map[string]any{
		"product": "RuleForge", "version": s.Version,
		"tier": act.Tier, "notice": act.Notice,
		"caps": s.caps(), "vendors": vendors,
	})
}

func (s *Server) handleLicense(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad request body")
		return
	}
	act := license.Activate(s.IssuerPub, "ruleforge", strings.TrimSpace(body.Key), time.Now())
	s.mu.Lock()
	s.activation = act
	s.mu.Unlock()
	if s.LicenseFile != "" && act.Tier != license.TierFree {
		_ = os.WriteFile(s.LicenseFile, []byte(strings.TrimSpace(body.Key)+"\n"), 0o600)
	}
	writeJSON(w, 200, map[string]any{"tier": act.Tier, "notice": act.Notice, "caps": s.caps()})
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.List()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if list == nil {
		list = []engine.Summary{}
	}
	writeJSON(w, 200, list)
}

// handleCreateJob accepts multipart form: fields source, target, name;
// files[] config uploads. Parsing + deep analysis run synchronously (they are
// fast) and the job comes back in "analyzed" state with a mapping proposal.
func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	caps := s.caps()
	if caps.MaxJobs > 0 {
		if n, err := s.Store.Count(); err == nil && n >= caps.MaxJobs {
			writeErr(w, 403, fmt.Sprintf("job limit reached for this tier (%d). Delete a job or upgrade.", caps.MaxJobs))
			return
		}
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeErr(w, 400, "multipart form expected: "+err.Error())
		return
	}
	source := r.FormValue("source")
	target := r.FormValue("target")
	if !validVendor(source) || !validVendor(target) {
		writeErr(w, 400, "source and target must be one of: "+strings.Join(fwir.Vendors(), ", "))
		return
	}
	if source == target {
		writeErr(w, 400, "source and target are the same vendor — pick a different target")
		return
	}
	var inputs []parse.Input
	if r.MultipartForm != nil {
		for _, fhs := range r.MultipartForm.File {
			for _, fh := range fhs {
				f, err := fh.Open()
				if err != nil {
					continue
				}
				data, err := io.ReadAll(io.LimitReader(f, 32<<20))
				f.Close()
				if err != nil {
					continue
				}
				inputs = append(inputs, parse.Input{Name: fh.Filename, Content: string(data)})
			}
		}
	}
	if pasted := strings.TrimSpace(r.FormValue("config")); pasted != "" {
		inputs = append(inputs, parse.Input{Name: "pasted.cfg", Content: pasted})
	}
	if len(inputs) == 0 {
		writeErr(w, 400, "upload at least one configuration file (or paste one)")
		return
	}
	cfg, err := parse.Parse(source, inputs)
	if err != nil {
		writeErr(w, 422, "parse failed: "+err.Error())
		return
	}
	job := &engine.Job{
		ID: store.NewID(), Name: strings.TrimSpace(r.FormValue("name")),
		Created: time.Now(), Source: source, Target: target, Status: engine.JobAnalyzed,
		Inputs: inputs, Config: cfg,
	}
	if job.Name == "" {
		job.Name = fwir.VendorLabel(source) + " → " + fwir.VendorLabel(target)
	}
	job.Analysis = engine.Analyze(cfg)
	job.Proposal = engine.ProposeMapping(cfg, target)
	job.Entries = job.Proposal.Entries
	if err := s.Store.Put(job); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, job)
}

func validVendor(v string) bool {
	for _, x := range fwir.Vendors() {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) job(w http.ResponseWriter, r *http.Request) *engine.Job {
	j, err := s.Store.Get(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "job not found")
		return nil
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return nil
	}
	return j
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	if j := s.job(w, r); j != nil {
		writeJSON(w, 200, j)
	}
}

func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	err := s.Store.Delete(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "job not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

// handleMapping saves the (edited) mapping entries and marks the map approved.
func (s *Server) handleMapping(w http.ResponseWriter, r *http.Request) {
	j := s.job(w, r)
	if j == nil {
		return
	}
	var body struct {
		Entries []engine.MappingEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad request body")
		return
	}
	if len(body.Entries) > 0 {
		j.Entries = body.Entries
	}
	j.Status = engine.JobMapped
	if err := s.Store.Put(j); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, j)
}

// handleConvert runs conversion + review + reports.
func (s *Server) handleConvert(w http.ResponseWriter, r *http.Request) {
	j := s.job(w, r)
	if j == nil {
		return
	}
	caps := s.caps()
	if !caps.MultiTenant && j.Config != nil && len(j.Config.Contexts) > 1 {
		writeErr(w, 403, "this tier converts single-tenant sources only (analysis of multi-tenant sources is included). Upgrade to convert multi-context/VDOM/device-group sources.")
		return
	}
	if caps.MaxRulesPerJob > 0 && j.Analysis != nil && j.Analysis.Totals.Rules > caps.MaxRulesPerJob {
		writeErr(w, 403, fmt.Sprintf("this tier converts up to %d rules per job (this source has %d). Analysis and mapping remain available; upgrade to convert.", caps.MaxRulesPerJob, j.Analysis.Totals.Rules))
		return
	}
	mappings := engine.BuildMappings(j.Entries)
	results, err := engine.Convert(j.Config, j.Target, mappings)
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	j.Results = results
	j.Review = engine.BuildReview(j.Config, j.Target, results)
	if !caps.RoundTrip {
		j.Review.RoundTrip = nil
		j.Review.RoundTripOK = nil
		j.Review.Notes = append(j.Review.Notes, "Round-trip verification is a Pro feature.")
	}
	in := &engine.ReportInput{
		JobID: j.ID, Created: time.Now(), Source: j.Source, Target: j.Target,
		Hostname: j.Config.Hostname, Analysis: j.Analysis, Config: j.Config,
		MapEntry: j.Entries, Results: results, Review: j.Review,
		FreeTier: s.Activation().Tier == license.TierFree,
	}
	j.ProcessHTML = engine.BuildProcessReport(in)
	if caps.FinalReport {
		j.FinalHTML = engine.BuildFinalReport(in)
	}
	j.Status = engine.JobConverted
	if err := s.Store.Put(j); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, j)
}

// handleFile downloads one generated file: ?name=…
func (s *Server) handleFile(w http.ResponseWriter, r *http.Request) {
	j := s.job(w, r)
	if j == nil {
		return
	}
	name := r.URL.Query().Get("name")
	for _, res := range j.Results {
		for _, f := range res.Files {
			if f.Name == name {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Content-Disposition", `attachment; filename="`+f.Name+`"`)
				_, _ = w.Write([]byte(f.Content))
				return
			}
		}
	}
	writeErr(w, 404, "file not found")
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	j := s.job(w, r)
	if j == nil {
		return
	}
	var htmlDoc string
	switch r.PathValue("kind") {
	case "process":
		htmlDoc = j.ProcessHTML
	case "final":
		htmlDoc = j.FinalHTML
		if htmlDoc == "" && j.Status == engine.JobConverted {
			writeErr(w, 403, "the Final Migration Report is a Pro feature")
			return
		}
	default:
		writeErr(w, 404, "unknown report")
		return
	}
	if htmlDoc == "" {
		writeErr(w, 404, "report not generated yet — run conversion first")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(htmlDoc))
}
