package tests

// Addendum 6 gap: the negative control's two contracts with -adaptive, which
// the wire had no test for.
//
//   * the probes run right after the baseline and before the modules the
//     fingerprint promotes, so every later module is classified against the
//     wildcard shape;
//   * a CALIBRATED cluster never escalates: the deep families run only on a
//     403 baseline plus a BYPASS cluster, and a suppressed wildcard is neither.

import (
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/analysis"
	"github.com/herraristotle/gobypass403/core/engine/scanner"
)

// adaptiveCalibrationModules is adaptiveModules plus the control, in the
// position -calibrate injects it: right after the baseline.
const adaptiveCalibrationModules = "dumb_check," + analysis.CalibrationModule + ",http_methods,case_substitution"

// isProbePath reports whether a request-target is one of the random
// single-segment control probes (never the scanned target itself).
func isProbePath(path string) bool {
	return path != "/access" && strings.Count(path, "/") == 1 && !strings.ContainsAny(path, ".?")
}

func TestAdaptiveRunsCalibrationBeforeThePromotedModule(t *testing.T) {
	initWireDB(t)

	board := startWireBoardWithServer(t, adaptiveServer, func(string) bool { return false })
	target := board.url("/access")

	opts := adaptiveOpts(adaptiveCalibrationModules, true)
	s := scanner.NewScanner(opts, []string{target})
	s.RunAllBypasses(target)

	// The promoted module's requests are deterministic, so they can be matched
	// on the trace; the probes are random, so they are matched by shape. A
	// request that also belongs to the baseline or to http_methods is
	// ambiguous, exactly as labelled() treats it, and proves nothing.
	promoted := moduleRequests(t, "case_substitution", target)
	ambiguous := moduleRequests(t, analysis.BaselineDumbCheck, target)
	for req := range moduleRequests(t, "http_methods", target) {
		ambiguous[req] = true
	}
	probeIdx, promotedIdx := -1, -1
	for i, req := range board.seen() {
		if probeIdx < 0 && isProbePath(strings.TrimPrefix(req, "GET ")) {
			probeIdx = i
		}
		if promotedIdx < 0 && promoted[req] && !ambiguous[req] {
			promotedIdx = i
		}
	}
	if probeIdx < 0 {
		t.Fatal("no calibration probe reached the wire")
	}
	if promotedIdx < 0 {
		t.Fatal("the promoted module never ran")
	}
	if probeIdx > promotedIdx {
		t.Errorf("calibration probes must run before the promoted module: probe at %d, case_substitution at %d", probeIdx, promotedIdx)
	}
}

// adaptiveSoft404 runs the wildcard board with -adaptive, optionally with the
// control module, bounded so an escalation cannot run away. It returns the
// requests the board saw.
func adaptiveSoft404(t *testing.T, calibrate bool, maxReqs int) []string {
	t.Helper()

	board := startWireBoard(t, soft404Accept)
	target := board.url("/access")

	modules := "dumb_check,http_methods"
	if calibrate {
		modules = "dumb_check," + analysis.CalibrationModule + ",http_methods"
	}
	opts := adaptiveOpts(modules, true)
	opts.MaxReqs = maxReqs

	s := scanner.NewScanner(opts, []string{target})
	s.RunAllBypasses(target)

	return board.seen()
}

func TestCalibrationStopsAdaptiveEscalationOnTheWire(t *testing.T) {
	initWireDB(t)

	// The wildcard 200s are a BYPASS against the 403 baseline, so without the
	// control the deep families run past the triage request count.
	probe := startWireBoard(t, soft404Accept)
	triage := 1 + len(moduleRequests(t, "http_methods", probe.url("/access")))

	seen := adaptiveSoft404(t, false, triage+20)
	if len(seen) <= triage {
		t.Fatalf("control case broken: no escalation without -calibrate (%d requests, triage is %d)", len(seen), triage)
	}
	pathReqs := moduleRequests(t, "path_prefix", probe.url("/access"))
	for _, req := range seen[triage:] {
		if !pathReqs[req] {
			t.Errorf("escalated request is not a path_prefix payload: %q", req)
		}
	}

	// With -calibrate the same responses are CALIBRATED, so the deep families
	// are never earned: the run is the baseline, the 3 probes and http_methods.
	// An escalation would blow past this count (path_prefix alone has far more
	// payloads than the triage), so the exact count is the proof.
	calSeen := adaptiveSoft404(t, true, triage+23)
	if want := triage + 3; len(calSeen) != want {
		t.Errorf("-calibrate must stop escalation: board saw %d requests, want baseline + 3 probes + http_methods (%d)", len(calSeen), want)
	}
}
