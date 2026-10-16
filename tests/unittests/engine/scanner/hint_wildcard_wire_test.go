package tests

// Addendum 7: the live wildcard hint.
//
// A BYPASS cluster whose members come from many distinct requests is the shape
// of a catch-all. With -warn-wildcard the run says so, after the summary,
// pointing at -calibrate. The hint is read-only: it re-classifies the rows the
// run already stored, sends nothing, and stays quiet when the run carried the
// negative control (that already answered the question).
//
// The assertions read the hints themselves rather than scraping printed output:
// the logger's writer is bound to os.Stdout at package init, so captureStdout
// cannot see it. The operator-facing line is pinned by Hint.String()'s golden
// test in the analysis package, and end to end by the CLI run in the evidence.
//
// Filename note: this file must sort before results_test.go, whose cleanup
// closes the process-wide findings DB writer (the same constraint
// expand_wire_test.go and friends live with).

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
	"github.com/slicingmelon/gobypass403/core/engine/scanner"
)

// wildcardOpts is a run over the soft-404 board with the hint switched on. The
// baseline 403 row has to be stored for the classifier to see it at all, which
// is why this does not keep wireOpts' 200-only filter: without a baseline the
// wildcard 200 becomes the modal baseline and the cluster is a DUP, not a
// BYPASS.
func wildcardOpts(calibrate bool) *scanner.ScannerOpts {
	o := calibrationOpts(calibrate, false)
	o.MatchStatusCodes = []int{200, 403}
	o.WarnWildcard = true
	return o
}

// wildcardHints runs the soft-404 board with the hint on and returns what the
// hint makes of the finished target.
func wildcardHints(t *testing.T, calibrate bool) []analysis.Hint {
	t.Helper()
	initWireDB(t)

	board := startWireBoard(t, soft404Accept)
	target := board.url("/access")

	s := scanner.NewScanner(wildcardOpts(calibrate), []string{target})
	s.RunAllBypasses(target)

	hints, err := scanner.WildcardHintsForTarget(target)
	if err != nil {
		t.Fatalf("WildcardHintsForTarget: %v", err)
	}
	return hints
}

func TestWildcardHintNamesTheCatchAllOnTheWire(t *testing.T) {
	hints := wildcardHints(t, false)

	if len(hints) != 1 {
		t.Fatalf("want exactly 1 hint for one catch-all cluster, got %d (%+v)", len(hints), hints)
	}
	h := hints[0]
	if h.Fingerprint.Status != 200 {
		t.Errorf("hint fingerprint status = %d, want the board's 200", h.Fingerprint.Status)
	}
	if h.Requests < 5 {
		t.Errorf("hint requests = %d, want the distinct requests behind the cluster", h.Requests)
	}
	if h.Module == "" {
		t.Error("hint must name the module behind the cluster")
	}
	if !strings.Contains(h.String(), "-calibrate") {
		t.Errorf("the operator line must name the remedy: %q", h.String())
	}
}

func TestWildcardHintSendsNothing(t *testing.T) {
	initWireDB(t)

	board := startWireBoard(t, soft404Accept)
	target := board.url("/access")

	s := scanner.NewScanner(wildcardOpts(false), []string{target})
	s.RunAllBypasses(target)

	before := len(board.seen())
	if _, err := scanner.WildcardHintsForTarget(target); err != nil {
		t.Fatalf("WildcardHintsForTarget: %v", err)
	}
	if err := scanner.PrintWildcardHints(target); err != nil {
		t.Fatalf("PrintWildcardHints: %v", err)
	}
	if after := len(board.seen()); after != before {
		t.Errorf("the hint is read-only: %d requests before, %d after", before, after)
	}
}

func TestWildcardHintSilentWithCalibrationOnTheWire(t *testing.T) {
	hints := wildcardHints(t, true)

	if len(hints) != 0 {
		t.Errorf("-calibrate already answered the wildcard question; got %+v", hints)
	}
}

func TestWildcardHintSilentOnADenyingBoard(t *testing.T) {
	initWireDB(t)

	// Every request is a 403: nothing departs from the baseline, so there is no
	// BYPASS cluster to hint about.
	board := startWireBoard(t, func(string) bool { return false })
	target := board.url("/access")

	s := scanner.NewScanner(wildcardOpts(false), []string{target})
	s.RunAllBypasses(target)

	hints, err := scanner.WildcardHintsForTarget(target)
	if err != nil {
		t.Fatalf("WildcardHintsForTarget: %v", err)
	}
	if len(hints) != 0 {
		t.Errorf("a denying board must not hint; got %+v", hints)
	}
}
