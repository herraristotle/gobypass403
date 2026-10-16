package tests

// Task D4 (SPEC-unkover-gaps.md Addendum 5, Phase D): -resume.
//
// A restarted run must skip the (target, module) pairs the checkpoint already
// names, send nothing for them, and store no second copy of their findings.
// The DB is read directly here because "no duplicate rows" is the claim.

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/slicingmelon/gobypass403/core/engine/scanner"
)

// resumeOpts builds scanner options for a run over outDir. resume simulates
// what the CLI does for -resume: load the sidecar and hand it to the scanner.
func resumeOpts(t *testing.T, outDir, modules string, resume bool) *scanner.ScannerOpts {
	t.Helper()

	opts := wireOpts(false)
	opts.BypassModule = modules
	opts.OutDir = outDir
	if resume {
		p, err := scanner.LoadProgress(scanner.ProgressPath(outDir))
		if err != nil {
			t.Fatalf("load checkpoint: %v", err)
		}
		opts.Progress = p
	}
	return opts
}

// resumeRows counts the stored findings for one (target, module) pair.
func resumeRows(t *testing.T, target, module string) int {
	t.Helper()

	initWireDB(t)
	db, err := sql.Open("sqlite3", filepath.Join(wireDBDir, "results.db"))
	if err != nil {
		t.Fatalf("open findings db: %v", err)
	}
	defer db.Close()

	var n int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM scan_results WHERE target_url = ? AND bypass_module = ?",
		target, module).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}

func TestResumeSkipsCompletedModulesAndWritesNoDuplicateRows(t *testing.T) {
	initWireDB(t)

	winner := wireWinner(t)
	accept := wireAccept(winner)
	board := startWireBoard(t, func(req string) bool { return accept[req] })
	target := board.url("/access")
	outDir := t.TempDir()

	// Run 1: only the http_methods module, resumable.
	sA := scanner.NewScanner(resumeOpts(t, outDir, wireModule, true), []string{target})
	sA.RunAllBypasses(target)

	firstReqs := len(board.seen())
	rowsA := resumeRows(t, target, wireModule)
	if rowsA == 0 {
		t.Fatal("first run stored no rows, so there is nothing to protect from duplication")
	}

	p, err := scanner.LoadProgress(scanner.ProgressPath(outDir))
	if err != nil {
		t.Fatalf("reload checkpoint: %v", err)
	}
	if !p.Has(target, wireModule) {
		t.Fatalf("finished module %s was not checkpointed for %s", wireModule, target)
	}

	// Run 2: same outdir, same target, the finished module plus a new one.
	sB := scanner.NewScanner(resumeOpts(t, outDir, wireModule+",dumb_check", true), []string{target})
	sB.RunAllBypasses(target)

	newReqs := board.seen()[firstReqs:]
	if len(newReqs) != 1 {
		t.Errorf("second run sent %d requests (%v), want only dumb_check's one", len(newReqs), newReqs)
	}
	if rows := resumeRows(t, target, wireModule); rows != rowsA {
		t.Errorf("rows for %s changed %d -> %d: resuming duplicated findings", wireModule, rowsA, rows)
	}

	p2, err := scanner.LoadProgress(scanner.ProgressPath(outDir))
	if err != nil {
		t.Fatalf("reload checkpoint: %v", err)
	}
	if !p2.Has(target, "dumb_check") {
		t.Error("dumb_check finished but was not checkpointed")
	}
}

func TestResumeWithoutTheFlagCreatesNoCheckpoint(t *testing.T) {
	initWireDB(t)

	winner := wireWinner(t)
	accept := wireAccept(winner)
	board := startWireBoard(t, func(req string) bool { return accept[req] })
	target := board.url("/access")
	outDir := t.TempDir()

	s := scanner.NewScanner(resumeOpts(t, outDir, wireModule, false), []string{target})
	s.RunAllBypasses(target)

	if len(board.seen()) == 0 {
		t.Error("run sent nothing")
	}
	if _, err := os.Stat(scanner.ProgressPath(outDir)); !os.IsNotExist(err) {
		t.Errorf("a checkpoint was written without -resume (stat err = %v)", err)
	}
}

func TestResumeCorruptCheckpointRescansInsteadOfAborting(t *testing.T) {
	initWireDB(t)

	outDir := t.TempDir()
	if err := os.WriteFile(scanner.ProgressPath(outDir), []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write corrupt checkpoint: %v", err)
	}

	// What the CLI does: report the damage, then continue with what it got.
	p, err := scanner.LoadProgress(scanner.ProgressPath(outDir))
	if err == nil {
		t.Fatal("expected the corrupt checkpoint to be reported")
	}

	board := startWireBoard(t, func(req string) bool { return false })
	target := board.url("/access")

	opts := resumeOpts(t, outDir, "dumb_check", false)
	opts.Progress = p

	s := scanner.NewScanner(opts, []string{target})
	s.RunAllBypasses(target)

	if len(board.seen()) == 0 {
		t.Error("a corrupt checkpoint suppressed the scan instead of rescanning")
	}
}
