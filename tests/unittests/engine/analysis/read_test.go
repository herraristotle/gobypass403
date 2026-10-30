package tests

// Task A4 (SPEC-unkover-gaps.md Addendum 5, Phase A): Analyze(dbPath).
//
// The reader must be strictly read-only: it never writes the input DB and
// leaves no -shm/-wal sidecars behind, so analysing a real findings DB is
// always safe. It must also fail clearly (not panic) on a missing file or
// a database that is not a gobypass403 results DB.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/herraristotle/gobypass403/core/engine/analysis"
)

// fixtureDDL mirrors the columns Analyze reads; the full-schema case is
// covered by the curated real testbed DB (Task A5).
const fixtureDDL = `CREATE TABLE scan_results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	target_url TEXT NOT NULL,
	bypass_module TEXT NOT NULL,
	status_code INTEGER,
	content_length INTEGER,
	content_type TEXT,
	response_body_preview TEXT,
	response_body_bytes INTEGER,
	curl_cmd TEXT
)`

func newFixtureDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "results.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open fixture db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(fixtureDDL); err != nil {
		t.Fatalf("create fixture table: %v", err)
	}
	return db, path
}

func insertRows(t *testing.T, db *sql.DB, rows ...analysis.Row) {
	t.Helper()
	for _, r := range rows {
		_, err := db.Exec(
			`INSERT INTO scan_results
			 (target_url, bypass_module, status_code, content_length, content_type,
			  response_body_preview, response_body_bytes, curl_cmd)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			r.TargetURL, r.BypassModule, r.StatusCode, r.ContentLength, r.ContentType,
			r.ResponseBodyPreview, r.ResponseBodyBytes, r.CurlCMD,
		)
		if err != nil {
			t.Fatalf("insert fixture row: %v", err)
		}
	}
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestAnalyzeReportsBypassFromFixtureDB(t *testing.T) {
	db, path := newFixtureDB(t)
	insertRows(t, db,
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("http_methods", 200, len(okBody), okBody, "curl -X get"),
		row("http_methods", 200, len(okBody), okBody, "curl -X acl"),
	)
	_ = db.Close()

	rep, err := analysis.Analyze(path)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(rep.Targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(rep.Targets))
	}
	bypasses := clustersOfClass(rep.Targets[0], analysis.ClassBypass)
	if len(bypasses) != 1 {
		t.Fatalf("want 1 BYPASS cluster, got %d (%+v)", len(bypasses), rep.Targets[0].Clusters)
	}
	if !containsCurl(bypasses[0], "curl -X get") {
		t.Errorf("BYPASS cluster must contain the -X get member")
	}
	if rep.Targets[0].BaselineSource != analysis.BaselineDumbCheck {
		t.Errorf("BaselineSource = %q, want dumb_check", rep.Targets[0].BaselineSource)
	}
}

func TestAnalyzeMissingFileErrors(t *testing.T) {
	_, err := analysis.Analyze(filepath.Join(t.TempDir(), "nope.db"))
	if err == nil {
		t.Fatalf("expected an error for a missing file")
	}
}

func TestAnalyzeWithoutResultsTableErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE not_results (x TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = db.Close()

	if _, err := analysis.Analyze(path); err == nil {
		t.Fatalf("expected an error when scan_results is absent")
	}
}

func TestAnalyzeLeavesInputFileUntouched(t *testing.T) {
	db, path := newFixtureDB(t)
	insertRows(t, db,
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("end_paths", 200, len(okBody), okBody, "curl bypass"),
	)
	_ = db.Close()

	before := sha256File(t, path)
	if _, err := analysis.Analyze(path); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if after := sha256File(t, path); after != before {
		t.Errorf("input DB changed: %s -> %s", before, after)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Stat(sidecar); err == nil {
			t.Errorf("Analyze created sidecar %s", sidecar)
		}
	}
}

func TestAnalyzeToleratesNullColumns(t *testing.T) {
	db, path := newFixtureDB(t)
	if _, err := db.Exec(
		`INSERT INTO scan_results
		 (target_url, bypass_module, status_code, content_length, content_type,
		  response_body_preview, response_body_bytes, curl_cmd)
		 VALUES (?, ?, NULL, NULL, NULL, NULL, NULL, NULL)`,
		"https://t.example/access", "end_paths",
	); err != nil {
		t.Fatalf("insert null row: %v", err)
	}
	_ = db.Close()

	rep, err := analysis.Analyze(path)
	if err != nil {
		t.Fatalf("Analyze with NULL columns must not error: %v", err)
	}
	if len(rep.Targets) != 1 || rep.Targets[0].Rows != 1 {
		t.Errorf("unexpected report for NULL row: %+v", rep)
	}
}
