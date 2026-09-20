package store

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/nizartuanku/ruleforge/engine"
)

func openTestSQLite(t *testing.T) (*SQLite, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st, err := NewSQLite(db, dbPath+"-data")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	return st, dbPath
}

func TestSQLiteStore_RoundTrip(t *testing.T) {
	st, dir := openTestSQLite(t)
	j := &engine.Job{
		ID: NewID(), Name: "hello", Created: time.Now().Truncate(time.Millisecond),
		Source: "cisco-asa", Target: "cisco-ftd", Status: engine.JobConverted,
		ProcessHTML: "<html>report</html>",
	}
	if err := st.Put(j); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Payload must land as a file next to the DB, not inline in SQLite.
	dataDir := dir + "-data"
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("read data dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 job file in %s, got %d", dataDir, len(entries))
	}

	got, err := st.Get(j.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != j.Name || got.ProcessHTML != j.ProcessHTML || !got.Created.Equal(j.Created) {
		t.Fatalf("round trip mismatch: got %+v", got)
	}

	sums, err := st.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(sums) != 1 || sums[0].ID != j.ID || sums[0].Name != j.Name {
		t.Fatalf("List mismatch: %+v", sums)
	}

	n, err := st.Count()
	if err != nil || n != 1 {
		t.Fatalf("Count: got %d, err %v", n, err)
	}

	if err := st.Delete(j.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get(j.ID); err != ErrNotFound {
		t.Fatalf("Get after Delete: want ErrNotFound, got %v", err)
	}
	// Delete must also remove the payload file (no disk leak).
	entries, _ = os.ReadDir(dataDir)
	if len(entries) != 0 {
		t.Fatalf("expected job file removed after Delete, found %d remaining", len(entries))
	}
}

// TestSQLiteStore_BackwardCompat_LegacyRow proves an existing customer
// install's database (rows written by the pre-this-change code: only
// id/created/data, data holding the full JSON inline) keeps working after
// upgrading the binary -- no forced migration, no broken installs.
func TestSQLiteStore_BackwardCompat_LegacyRow(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "legacy.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	// Recreate exactly what the old code wrote: no path/summary columns.
	if _, err := db.Exec(`CREATE TABLE rf_jobs (
		id TEXT PRIMARY KEY, created INTEGER NOT NULL, data BLOB NOT NULL
	)`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	legacy := &engine.Job{
		ID: "job-legacy", Name: "old-job", Created: time.Now().Truncate(time.Millisecond),
		Source: "cisco-asa", Target: "paloalto", Status: engine.JobConverted,
	}
	blob, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy job: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO rf_jobs (id, created, data) VALUES (?,?,?)`,
		legacy.ID, legacy.Created.UnixMilli(), blob); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	// Opening with the new code must migrate the schema (ALTER TABLE ADD
	// COLUMN) without touching the existing row's data.
	st, err := NewSQLite(db, filepath.Join(dir, "job-data"))
	if err != nil {
		t.Fatalf("NewSQLite on legacy db: %v", err)
	}

	got, err := st.Get(legacy.ID)
	if err != nil {
		t.Fatalf("Get legacy row: %v", err)
	}
	if got.Name != legacy.Name || got.Target != legacy.Target {
		t.Fatalf("legacy row mismatch: got %+v", got)
	}

	sums, err := st.List()
	if err != nil {
		t.Fatalf("List with legacy row: %v", err)
	}
	if len(sums) != 1 || sums[0].ID != legacy.ID {
		t.Fatalf("List with legacy row mismatch: %+v", sums)
	}

	// A fresh Put (e.g. re-converting the same job) must upgrade that row to
	// the new file-backed format going forward.
	legacy.Status = engine.JobConverted
	legacy.ProcessHTML = "<html>updated</html>"
	if err := st.Put(legacy); err != nil {
		t.Fatalf("Put over legacy row: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "job-data"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected legacy row upgraded to a payload file, dir read: %v entries=%d", err, len(entries))
	}
}

// TestSQLiteStore_JobPastOldBlobLimit is the regression proof for the fix:
// a job whose JSON marshal exceeds SQLite's compiled-in SQLITE_MAX_LENGTH
// (1,000,000,000 bytes) -- which made the pre-this-change store.Put fail
// with "string or blob too big" at roughly 470k-810k converted rows in the
// 20-Sep empirical test -- must now save and read back cleanly, because the
// payload never goes into a SQLite column at all.
//
// Building a real 1M+ row Job here would make this test slow, so instead we
// force the same failure condition directly: a payload whose JSON encoding
// is deliberately larger than the old ceiling. It's highly compressible
// (repeated text), matching the real NDJSON export content, so gzip keeps
// this test fast even at >1GB of raw JSON.
//
//	RF_STORE_LARGE=1 go test ./store/ -run TestSQLiteStore_JobPastOldBlobLimit -v -timeout 5m
func TestSQLiteStore_JobPastOldBlobLimit(t *testing.T) {
	if os.Getenv("RF_STORE_LARGE") == "" {
		t.Skip("set RF_STORE_LARGE=1 to run the >1GB job-payload proof gate (heavy)")
	}
	st, _ := openTestSQLite(t)

	const oldSQLiteMaxLength = 1_000_000_000
	filler := strings.Repeat("x", 1<<20) // 1 MiB of a repeating byte, highly compressible
	repeats := oldSQLiteMaxLength/len(filler) + 50
	var sb strings.Builder
	sb.Grow(len(filler) * repeats)
	for i := 0; i < repeats; i++ {
		sb.WriteString(filler)
	}

	j := &engine.Job{
		ID: NewID(), Name: "past-old-blob-limit", Created: time.Now().Truncate(time.Millisecond),
		Source: "cisco-asa", Target: "cisco-ftd", Status: engine.JobConverted,
		ProcessHTML: sb.String(),
	}
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(raw) <= oldSQLiteMaxLength {
		t.Fatalf("test payload (%d bytes) does not actually exceed the old ceiling (%d bytes)", len(raw), oldSQLiteMaxLength)
	}
	t.Logf("job JSON is %d bytes (%.2f GB) -- old design would fail store.Put here", len(raw), float64(len(raw))/1e9)

	if err := st.Put(j); err != nil {
		t.Fatalf("Put failed for a >1GB job (this is exactly the bug being fixed): %v", err)
	}
	got, err := st.Get(j.ID)
	if err != nil {
		t.Fatalf("Get failed for a >1GB job: %v", err)
	}
	if len(got.ProcessHTML) != len(j.ProcessHTML) {
		t.Fatalf("round-trip size mismatch: put %d bytes, got %d back", len(j.ProcessHTML), len(got.ProcessHTML))
	}
}
