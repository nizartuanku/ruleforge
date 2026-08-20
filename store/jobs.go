// Package store persists migration jobs. SQLite for the product binary,
// memory for tests.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"

	"github.com/nizartuanku/ruleforge/engine"
)

// ErrNotFound is returned for unknown job ids.
var ErrNotFound = errors.New("job not found")

// Store persists jobs.
type Store interface {
	Put(j *engine.Job) error
	Get(id string) (*engine.Job, error)
	List() ([]engine.Summary, error)
	Delete(id string) error
	Count() (int, error)
}

// NewID returns a random job id.
func NewID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "job-" + hex.EncodeToString(b[:])
}

// ---- memory ----

// Mem is an in-memory store for tests.
type Mem struct {
	mu   sync.RWMutex
	jobs map[string]*engine.Job
}

// NewMem returns an empty memory store.
func NewMem() *Mem { return &Mem{jobs: map[string]*engine.Job{}} }

func (m *Mem) Put(j *engine.Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *j
	m.jobs[j.ID] = &cp
	return nil
}

func (m *Mem) Get(id string) (*engine.Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *j
	return &cp, nil
}

func (m *Mem) List() ([]engine.Summary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []engine.Summary
	for _, j := range m.jobs {
		out = append(out, j.Summarize())
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Created.After(out[b].Created) })
	return out, nil
}

func (m *Mem) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[id]; !ok {
		return ErrNotFound
	}
	delete(m.jobs, id)
	return nil
}

func (m *Mem) Count() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.jobs), nil
}

// ---- sqlite ----

// SQLite persists jobs as JSON rows.
type SQLite struct {
	db *sql.DB
	mu sync.Mutex
}

// NewSQLite creates the schema if needed.
func NewSQLite(db *sql.DB) (*SQLite, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS rf_jobs (
		id TEXT PRIMARY KEY,
		created INTEGER NOT NULL,
		data BLOB NOT NULL
	)`)
	if err != nil {
		return nil, err
	}
	return &SQLite{db: db}, nil
}

func (s *SQLite) Put(j *engine.Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO rf_jobs (id, created, data) VALUES (?,?,?)
		ON CONFLICT(id) DO UPDATE SET data=excluded.data`, j.ID, j.Created.UnixMilli(), data)
	return err
}

func (s *SQLite) Get(id string) (*engine.Job, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT data FROM rf_jobs WHERE id=?`, id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var j engine.Job
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

func (s *SQLite) List() ([]engine.Summary, error) {
	rows, err := s.db.Query(`SELECT data FROM rf_jobs ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []engine.Summary
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var j engine.Job
		if err := json.Unmarshal(data, &j); err != nil {
			continue
		}
		out = append(out, j.Summarize())
	}
	return out, rows.Err()
}

func (s *SQLite) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM rf_jobs WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM rf_jobs`).Scan(&n)
	return n, err
}
