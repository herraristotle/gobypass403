package tests

// Addendum 6 (`-calibrate`) — negative-control suppression.
//
// A control is the fingerprint of a request to a path that cannot exist. Any
// cluster that matches a control is the server's default (wildcard/soft-404)
// response, not a bypass, and must never be classified BYPASS — even when its
// status class "improves" on the baseline. Controls are ordinary rows tagged
// BypassModule == analysis.CalibrationModule, so the offline report and the
// live scan share one rule.
//
// Match rule: same status AND same media type, and either an equal body
// digest (exact wildcard) or a length within ±50 bytes (echoing soft-404).

import (
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/analysis"
)

// compact builds a row with an explicit media type (the shared row() helper
// pins text/html, which is what most of these tests want anyway).
func mediaRow(module string, status, length int, mediaType, body, curl string) analysis.Row {
	r := row(module, status, length, body, curl)
	r.ContentType = mediaType
	return r
}

func TestCalibrationExactWildcardIsNotBypass(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row(analysis.CalibrationModule, 200, len(okBody), okBody, "curl cal"),
		row("end_paths", 200, len(okBody), okBody, "curl end"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if got := clustersOfClass(tr, analysis.ClassBypass); len(got) != 0 {
		t.Fatalf("a wildcard matching the control must not be BYPASS; got %d (%+v)", len(got), got)
	}
	cal := clustersOfClass(tr, analysis.ClassCalibrated)
	if len(cal) != 1 {
		t.Fatalf("want 1 CALIBRATED cluster, got %d (%+v)", len(cal), tr.Clusters)
	}
	if cal[0].Count != 2 {
		t.Errorf("CALIBRATED count = %d, want 2 (control + payload)", cal[0].Count)
	}
	if tr.CalibrationControls != 1 {
		t.Errorf("CalibrationControls = %d, want 1", tr.CalibrationControls)
	}
}

func TestCalibrationEchoSoft404IsNotBypass(t *testing.T) {
	// Different bodies (an echoing soft-404 stamps the requested path), but the
	// lengths are within the tolerance, so the control still matches.
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row(analysis.CalibrationModule, 200, 100, "not found: /access/aaaaaaaa", "curl cal"),
		row("end_paths", 200, 130, "not found: /access/bbbbbbbbbbbbbbbbbbbb", "curl end"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if got := clustersOfClass(tr, analysis.ClassBypass); len(got) != 0 {
		t.Fatalf("an echoing soft-404 within tolerance must not be BYPASS; got %d (%+v)", len(got), got)
	}
	// Two clusters: the control itself, and the payload that matched it.
	if got := clustersOfClass(tr, analysis.ClassCalibrated); len(got) != 2 {
		t.Fatalf("want 2 CALIBRATED clusters (control + match), got %d (%+v)", len(got), tr.Clusters)
	}
}

func TestCalibrationKeepsGenuineBypass(t *testing.T) {
	// Same status and media type as the control, but a much larger body: this
	// is real content, not the wildcard, so it stays a BYPASS.
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row(analysis.CalibrationModule, 200, 100, "not found", "curl cal"),
		row("end_paths", 200, 5000, strings.Repeat("real content ", 64), "curl end"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if got := clustersOfClass(tr, analysis.ClassBypass); len(got) != 1 {
		t.Fatalf("a genuine 200 far from the control must stay BYPASS; got %d (%+v)", len(got), tr.Clusters)
	}
}

func TestCalibrationRequiresSameStatus(t *testing.T) {
	// Control is a 404 (ordinary not-found); a 200 with an unrelated body is a
	// genuine status improvement and must not be suppressed.
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row(analysis.CalibrationModule, 404, 40, "no such page", "curl cal"),
		row("end_paths", 200, 40, "granted", "curl end"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if got := clustersOfClass(tr, analysis.ClassBypass); len(got) != 1 {
		t.Fatalf("a 200 against a 404 control must stay BYPASS; got %d (%+v)", len(got), tr.Clusters)
	}
}

func TestCalibrationRequiresSameMediaType(t *testing.T) {
	// Same status and length, different media type: not the wildcard page.
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		mediaRow(analysis.CalibrationModule, 200, 40, "text/html", "html wildcard page", "curl cal"),
		mediaRow("end_paths", 200, 40, "application/json", `{"ok":true,"data":[1,2,3,4,5,6]}`, "curl end"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if got := clustersOfClass(tr, analysis.ClassBypass); len(got) != 1 {
		t.Fatalf("a different media type must not match the control; got %d (%+v)", len(got), tr.Clusters)
	}
}

func TestNoCalibrationRowsLeaveClassificationUnchanged(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("end_paths", 200, len(okBody), okBody, "curl end"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if tr.CalibrationControls != 0 {
		t.Errorf("CalibrationControls = %d, want 0", tr.CalibrationControls)
	}
	if got := clustersOfClass(tr, analysis.ClassCalibrated); len(got) != 0 {
		t.Errorf("without controls there can be no CALIBRATED cluster; got %d", len(got))
	}
	if got := clustersOfClass(tr, analysis.ClassBypass); len(got) != 1 {
		t.Errorf("the ordinary 403->200 BYPASS must survive; got %d", len(got))
	}
}

func TestCalibratedClassRendersAndSortsLast(t *testing.T) {
	if got := analysis.ClassCalibrated.String(); got != "CALIBRATED" {
		t.Errorf("ClassCalibrated.String() = %q, want CALIBRATED", got)
	}

	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row(analysis.CalibrationModule, 200, len(okBody), okBody, "curl cal"),
		row("end_paths", 200, len(altBody1), altBody1, "curl var"), // a VARIANT
	}
	tr := analysis.Classify("https://t.example/access", rows)
	if len(tr.Clusters) == 0 {
		t.Fatal("no clusters")
	}
	if last := tr.Clusters[len(tr.Clusters)-1]; last.Class != analysis.ClassCalibrated {
		t.Errorf("CALIBRATED must sort last, got %s", last.Class)
	}
}

func TestCalibrationReportLine(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row(analysis.CalibrationModule, 200, len(okBody), okBody, "curl cal"),
	}
	rep := analysis.ClassifyReport(rows)
	if txt := rep.Text(); !strings.Contains(txt, "calibration: 1 control") {
		t.Errorf("report must announce the calibration control; got:\n%s", txt)
	}

	// No controls -> no calibration line, report unchanged.
	plain := analysis.ClassifyReport([]analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
	})
	if strings.Contains(plain.Text(), "calibration:") {
		t.Errorf("report must stay silent when calibration did not run; got:\n%s", plain.Text())
	}
}
