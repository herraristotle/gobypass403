package tests

// The results table must print the same rows for the same database whatever
// order those rows were inserted in.
//
// PrintResultsTableFromDB caps each (module, status, length) group at five
// rows, and its ORDER BY stopped at the length key, so rows tied on all three
// fell back to SQLite's row order — insertion order, which varies with -cr.
// Two runs of one scan therefore sampled different rows, and because the
// curl lines differ in width the rendered box changed too (observed on the
// loopback wildcard board: 515 tied rows, five shown, different five each
// run). The tiebreakers make the sampled five content-derived and stable, so
// the byte-identity the rest of the suite relies on actually holds.
//
// NOTE: scanner.InitDB is sync.Once (one findings DB per test process), so
// this file seeds the shared DB like its siblings and must sort before
// results_test.go, whose cleanup drops it.

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/scanner"
)

func TestResultsTableTieOrderIsContentDeterministic(t *testing.T) {
	initWireDB(t)

	const target = "https://tie.example/access"
	// Seven rows tied on (module, status, length): only five are printed, so
	// the tie order decides which five. The names sort in this order, and they
	// are inserted in reverse, so insertion order and content order disagree.
	byContent := []string{
		"curl -skgi 'https://tie.example/access-a'",
		"curl -skgi 'https://tie.example/access-b'",
		"curl -skgi 'https://tie.example/access-c'",
		"curl -skgi 'https://tie.example/access-d'",
		"curl -skgi 'https://tie.example/access-e'",
		"curl -skgi 'https://tie.example/access-f'",
		"curl -skgi 'https://tie.example/access-g'",
	}

	rows := make([]*scanner.Result, 0, len(byContent))
	for i := len(byContent) - 1; i >= 0; i-- {
		rows = append(rows, &scanner.Result{
			TargetURL:     target,
			BypassModule:  "tie_module",
			StatusCode:    200,
			ContentLength: 39,
			CurlCMD:       byContent[i],
		})
	}
	if err := scanner.AppendResultsToDB(rows); err != nil {
		t.Fatalf("append: %v", err)
	}

	var printErr error
	out := captureStdout(t, func() {
		printErr = scanner.PrintResultsTableFromDB(target, "tie_module")
	})
	if printErr != nil {
		t.Fatalf("PrintResultsTableFromDB: %v", printErr)
	}

	// The five that sort first must be the five shown...
	for _, want := range byContent[:5] {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q among the sampled five\n--- output ---\n%s", want, out)
		}
	}
	// ...and the two that sort after the cap must not be, however early they
	// were inserted.
	for _, got := range byContent[5:] {
		if strings.Contains(out, got) {
			t.Errorf("%q was shown although it sorts after the cap\n--- output ---\n%s", got, out)
		}
	}
	if !strings.Contains(out, "+2 more") {
		t.Errorf("expected the truncation notice\n--- output ---\n%s", out)
	}
}
