// Package store persists migration jobs. SQLite for the product binary,
// memory for tests.
package store

import (
	"compress/gzip"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
//
// A job's full payload (Config, Results, Review, the two HTML reports and
// their E-28 NDJSON overflow exports) is written gzip-compressed to a file
// in dataDir, one file per job (<id>.json.gz). SQLite only ever holds a
// small metadata row per job: the file's path, plus a pre-computed
// engine.Summary so List() never has to open a single payload file.
//
// This exists because the previous design -- the whole Job JSON-marshaled
// into one `data BLOB` column -- hit SQLite's compiled-in SQLITE_MAX_LENGTH
// (1,000,000,000 bytes; not a RAM limit, a constant baked into the bundled
// sqlite3-binding.c and not overridden anywhere in this repo) at roughly
// 470k-810k rows depending on target vendor, long before RuleForge's
// documented 6-8 million row conversion capacity. A filesystem has no
// comparable ceiling, so moving the payload there removes the limit instead
// of just raising it. See TestSQLiteStore_JobPastOldBlobLimit below for the
// regression proof.
//
// Backward compatibility: a `ruleforge.db` created by the previous version
// has only (id, created, data) with data NOT NULL. NewSQLite adds the new
// `path` and `summary` columns via ALTER TABLE if they're missing, and Get/
// List fall back to reading the old `data` column directly for any row that
// predates this change (path/summary empty) -- no forced migration, no
// existing customer install broken by an upgrade.
type SQLite struct {
	db      *sql.DB
	dataDir string
	mu      sync.Mutex
}

// NewSQLite creates the schema if needed and migrates an older schema in
// place. dataDir is where per-job payload files are written; it is created
// on first Put if it doesn't exist yet.
func NewSQLite(db *sql.DB, dataDir string) (*SQLite, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("store: dataDir is required")
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS rf_jobs (
		id TEXT PRIMARY KEY,
		created INTEGER NOT NULL,
		data BLOB NOT NULL
	)`)
	if err != nil {
		return nil, err
	}
	for _, col := range []struct{ name, ddl string }{
		{"path", "path TEXT"},
		{"summary", "summary BLOB"},
	} {
		has, err := hasColumn(db, "rf_jobs", col.name)
		if err != nil {
			return nil, err
		}
		if !has {
			if _, err := db.Exec(`ALTER TABLE rf_jobs ADD COLUMN ` + col.ddl); err != nil {
				return nil, err
			}
		}
	}
	return &SQLite{db: db, dataDir: dataDir}, nil
}

func hasColumn(db *sql.DB, table, col string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *SQLite) jobFile(id string) string {
	return filepath.Join(s.dataDir, id+".json.gz")
}

func writeGzipFileAtomic(path string, data []byte) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("job data dir: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create job file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	gz := gzip.NewWriter(f)
	if _, werr := gz.Write(data); werr != nil {
		gz.Close()
		f.Close()
		return fmt.Errorf("write job file: %w", werr)
	}
	if cerr := gz.Close(); cerr != nil {
		f.Close()
		return fmt.Errorf("flush job file: %w", cerr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("close job file: %w", cerr)
	}
	if rerr := os.Rename(tmp, path); rerr != nil {
		return fmt.Errorf("finalize job file: %w", rerr)
	}
	return nil
}

func readGzipFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(gz)
}

func (s *SQLite) Put(j *engine.Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	full, err := json.Marshal(j)
	if err != nil {
		return err
	}
	sum, err := json.Marshal(j.Summarize())
	if err != nil {
		return err
	}

	path := s.jobFile(j.ID)
	if err := writeGzipFileAtomic(path, full); err != nil {
		return err
	}

	// data is kept as an empty (but non-NULL) blob to satisfy the original
	// `data BLOB NOT NULL` column definition on an un-migrated table; the
	// real payload lives in the file at `path`.
	_, err = s.db.Exec(`INSERT INTO rf_jobs (id, created, data, path, summary) VALUES (?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET data=excluded.data, path=excluded.path, summary=excluded.summary`,
		j.ID, j.Created.UnixMilli(), []byte{}, path, sum)
	if err != nil {
		_ = os.Remove(path) // best-effort: don't leave an orphan file if the row write failed
		return err
	}
	return nil
}

func (s *SQLite) Get(id string) (*engine.Job, error) {
	var data []byte
	var path, summary sql.NullString
	err := s.db.QueryRow(`SELECT data, path, summary FROM rf_jobs WHERE id=?`, id).Scan(&data, &path, &summary)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var raw []byte
	if path.Valid && path.String != "" {
		raw, err = readGzipFile(path.String)
		if err != nil {
			return nil, fmt.Errorf("read job file: %w", err)
		}
	} else {
		raw = data // pre-migration row: payload was stored inline
	}

	var j engine.Job
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

func (s *SQLite) List() ([]engine.Summary, error) {
	rows, err := s.db.Query(`SELECT data, path, summary FROM rf_jobs ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []engine.Summary
	for rows.Next() {
		var data []byte
		var path, summary sql.NullString
		if err := rows.Scan(&data, &path, &summary); err != nil {
			return nil, err
		}
		if summary.Valid && summary.String != "" {
			var s2 engine.Summary
			if err := json.Unmarshal([]byte(summary.String), &s2); err == nil {
				out = append(out, s2)
				continue
			}
			// fall through to the legacy path if the cached summary is somehow corrupt
		}
		// Pre-migration row (or corrupt summary cache): only way to get a
		// summary is to load the full payload, same cost the old code paid
		// for every row on every List() call.
		var raw []byte
		if path.Valid && path.String != "" {
			raw, err = readGzipFile(path.String)
			if err != nil {
				continue
			}
		} else {
			raw = data
		}
		var j engine.Job
		if err := json.Unmarshal(raw, &j); err != nil {
			continue
		}
		out = append(out, j.Summarize())
	}
	return out, rows.Err()
}

func (s *SQLite) Delete(id string) error {
	var path sql.NullString
	_ = s.db.QueryRow(`SELECT path FROM rf_jobs WHERE id=?`, id).Scan(&path)

	res, err := s.db.Exec(`DELETE FROM rf_jobs WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if path.Valid && path.String != "" {
		_ = os.Remove(path.String) // best-effort; a leftover file is a disk-space leak, not a correctness bug
	}
	return nil
}

func (s *SQLite) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM rf_jobs`).Scan(&n)
	return n, err
}
