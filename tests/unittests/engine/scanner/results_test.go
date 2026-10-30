package tests

// Findings-table truncation must announce hidden rows.
//
// PrintResultsTableFromDB groups rows by (module, status, length) and
// prints at most 5 per group. The group separator used to be bare dots,
// so target-rich runs silently showed a handful of rows out of hundreds
// (observed on the unKover testbed: 5 of 453 findings on the nginx/suffix
// board; the -X get -> 200 row was present in every apache/records run's
// DB yet never visible). This pins a "+N more in this group (see
// results.db)" notice on BOTH truncation paths:
//
//  1. mid-table group flush triggered by a major (module/status) change
//  2. the final flush after the last scanned row
//
// and asserts groups under the cap emit no such notice.
//
// NOTE: scanner.InitDB is sync.Once — one DB per test process — so all
// printer scenarios are seeded into this single temp database.

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/scanner"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	// Drain concurrently: rendered tables can exceed the 64KiB pipe buffer.
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		_ = r.Close()
		done <- sb.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = old
	return <-done
}

func TestResultsTableAnnouncesHiddenRows(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "results.db")
	if err := scanner.InitDB(dbFile, 1); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(scanner.CleanupFindingsDB)

	const target = "https://example.com/access"
	mk := func(module string, status, length int, curls ...string) []*scanner.Result {
		out := make([]*scanner.Result, 0, len(curls))
		for _, c := range curls {
			out = append(out, &scanner.Result{
				TargetURL:    target,
				BypassModule: module,
				StatusCode:   status,
				ContentLength: int64(length),
				CurlCMD:      c,
			})
		}
		return out
	}

	// A: 3 rows, under cap → plain dots separator, no count notice.
	if err := scanner.AppendResultsToDB(mk("end_paths", 200, 40,
		"curl -skgi a", "curl -skgi b", "curl -skgi c")); err != nil {
		t.Fatalf("append A: %v", err)
	}
	// B: 7 rows, same (module,status,length), cap 5 → 2 hidden; flushed
	// by the major change to group C.
	if err := scanner.AppendResultsToDB(mk("http_methods", 403, 38,
		"curl -skgi -X get", "curl -skgi -X acl", "curl -skgi -X bind",
		"curl -skgi -X checkout", "curl -skgi -X connect",
		"curl -skgi -X head", "curl -skgi -X trace")); err != nil {
		t.Fatalf("append B: %v", err)
	}
	// C: forces B's flush via a status change.
	if err := scanner.AppendResultsToDB(mk("nginx_bypasses", 404, 10,
		"curl -skgi x")); err != nil {
		t.Fatalf("append C: %v", err)
	}
	// D: last group, 6 rows → 1 hidden; flushed by the final flush.
	if err := scanner.AppendResultsToDB(mk("dumb_check", 500, 55,
		"curl -skgi p", "curl -skgi q", "curl -skgi r",
		"curl -skgi s", "curl -skgi t", "curl -skgi u")); err != nil {
		t.Fatalf("append D: %v", err)
	}

	var printErr error
	out := captureStdout(t, func() {
		printErr = scanner.PrintResultsTableFromDB(target,
			"end_paths,http_methods,nginx_bypasses,dumb_check")
	})
	if printErr != nil {
		t.Fatalf("PrintResultsTableFromDB: %v", printErr)
	}

	for _, want := range []string{"+2 more", "+1 more", "results.db"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if got := regexp.MustCompile(`\+\d+ more`).FindAllString(out, -1); len(got) != 2 {
		t.Errorf("expected exactly 2 hidden-count notices, got %d (%v)\n--- output ---\n%s",
			len(got), got, out)
	}
}
