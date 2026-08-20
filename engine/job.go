package engine

import (
	"time"

	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/gen"
	"github.com/nizartuanku/ruleforge/parse"
)

// Job statuses.
const (
	JobAnalyzed  = "analyzed"
	JobMapped    = "mapped"
	JobConverted = "converted"
)

// Job is one migration job: source upload → analysis → mapping → conversion.
type Job struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Source  string    `json:"source"`
	Target  string    `json:"target"`
	Status  string    `json:"status"`

	Inputs   []parse.Input  `json:"inputs,omitempty"`
	Config   *fwir.Config   `json:"config,omitempty"`
	Analysis *Analysis      `json:"analysis,omitempty"`
	Proposal *MapProposal   `json:"proposal,omitempty"`
	Entries  []MappingEntry `json:"entries,omitempty"` // approved mapping
	Results  []*gen.Result  `json:"results,omitempty"`
	Review   *Review        `json:"review,omitempty"`

	ProcessHTML string `json:"process_html,omitempty"`
	FinalHTML   string `json:"final_html,omitempty"`
}

// Summary is the light listing form.
type Summary struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Source  string    `json:"source"`
	Target  string    `json:"target"`
	Status  string    `json:"status"`
	Rules   int       `json:"rules"`
	Verdict string    `json:"verdict,omitempty"`
}

// Summarize builds the listing form of a job.
func (j *Job) Summarize() Summary {
	s := Summary{ID: j.ID, Name: j.Name, Created: j.Created, Source: j.Source, Target: j.Target, Status: j.Status}
	if j.Analysis != nil {
		s.Rules = j.Analysis.Totals.Rules
	}
	if j.Review != nil {
		s.Verdict = j.Review.Verdict
	}
	return s
}
