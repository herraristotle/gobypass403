package tests

// Addendum 6 (`-calibrate`) on the wire.
//
// The board is a wildcard/soft-404 server: the scanned target path is a 403,
// but every other path answers 200 with the same "dashboard" page — exactly the
// shape that a 403 baseline misreads as a BYPASS. These tests pin the two
// claims that matter end to end:
//
//   * -calibrate sends its negative-control probes to sibling paths;
//   * with the control in place a wildcard no longer counts as a BYPASS, so
//     -expand sends nothing extra — while without it, the same run expands.

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
	"github.com/slicingmelon/gobypass403/core/engine/scanner"
)

// soft404Accept answers every path except the scanned target with a 200, and
// the target itself with the board's default 403.
func soft404Accept(req string) bool { return req != "GET /access" }

// calibrationOpts is a plain wire run with the control module in the list:
// `-calibrate` reaches the scanner as the synthetic module, so the module list
// is what turns the control on.
func calibrationOpts(calibrate, expand bool) *scanner.ScannerOpts {
	o := wireOpts(expand)
	if calibrate {
		o.BypassModule = "dumb_check," + analysis.CalibrationModule + ",http_methods"
	} else {
		o.BypassModule = "dumb_check,http_methods"
	}
	return o
}

// runSoft404 scans the wildcard board once and returns the requests it saw.
func runSoft404(t *testing.T, calibrate, expand bool) []string {
	t.Helper()
	initWireDB(t)
	board := startWireBoard(t, soft404Accept)
	target := board.url("/access")
	s := scanner.NewScanner(calibrationOpts(calibrate, expand), []string{target})
	s.RunAllBypasses(target)
	return board.seen()
}

func TestCalibrateSendsProbesToSiblings(t *testing.T) {
	seen := runSoft404(t, true, false)

	probes := 0
	for _, req := range seen {
		path := strings.TrimPrefix(req, "GET ")
		if path == "/access" || path == req {
			continue
		}
		// A probe is a single random segment at the root, nothing else.
		if strings.Count(path, "/") == 1 && !strings.ContainsAny(path, ".?") {
			probes++
		}
	}
	if probes != 3 {
		t.Errorf("want 3 calibration probes on the wire, got %d (%v)", probes, seen)
	}
}

func TestCalibrateSuppressesWildcardExpansionOnTheWire(t *testing.T) {
	// Control case: without -calibrate the wildcard 200 is a BYPASS, so
	// -expand derives and sends an extra batch.
	plain := runSoft404(t, false, false)
	withExpand := runSoft404(t, false, true)
	if len(withExpand) <= len(plain) {
		t.Fatalf("control case broken: -expand added no requests (%d plain vs %d)", len(plain), len(withExpand))
	}

	// With -calibrate the same wildcard is CALIBRATED, never BYPASS, so the
	// identical -expand run must add exactly nothing.
	calPlain := runSoft404(t, true, false)
	calExpand := runSoft404(t, true, true)
	if len(calExpand) != len(calPlain) {
		t.Errorf("-calibrate must stop expansion on a wildcard: %d requests with -expand, %d without",
			len(calExpand), len(calPlain))
	}
}
