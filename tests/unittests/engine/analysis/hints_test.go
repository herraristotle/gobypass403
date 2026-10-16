package tests

// Addendum 9: the wildcard hint.
//
// A BYPASS cluster whose members come from many distinct requests is the shape
// of a catch-all: one page served for everything, classified BYPASS only
// because the run had no negative control to compare against. The hint names
// that shape and points at -calibrate. It is never a verdict and never
// suppresses anything (Addendum 6 owns suppression).
//
// Datum is distinct stored request lines (curl_cmd): raw-URI variants of one
// path count separately, so the rule is stricter than a path count.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
)

// catchAll is the body a wildcard board serves for every path it does not
// know; wildcardRows builds n members of that one fingerprint, each from a
// distinct request.
const catchAll = "catch-all page for everything"

func wildcardRows(module string, n int) []analysis.Row {
	rows := make([]analysis.Row, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, row(module, 200, len(catchAll), catchAll,
			fmt.Sprintf("curl -skgi --path-as-is 'https://t.example/access/%s%d'", module, i)))
	}
	return rows
}

func TestWildcardHintFiresOnCatchAllCluster(t *testing.T) {
	rows := append([]analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
	}, wildcardRows("end_paths", 6)...)

	hints := analysis.WildcardHints(analysis.ClassifyReport(rows))
	if len(hints) != 1 {
		t.Fatalf("want exactly 1 hint for one catch-all cluster, got %d (%+v)", len(hints), hints)
	}

	h := hints[0]
	if h.TargetURL != "https://t.example/access" {
		t.Errorf("TargetURL = %q, want the scanned target", h.TargetURL)
	}
	if h.Requests != 6 {
		t.Errorf("Requests = %d, want 6 distinct request lines", h.Requests)
	}
	if h.Module != "end_paths" {
		t.Errorf("Module = %q, want end_paths", h.Module)
	}
	if h.Fingerprint.Status != 200 || h.Fingerprint.Length != int64(len(catchAll)) {
		t.Errorf("Fingerprint = %+v, want the catch-all shape", h.Fingerprint)
	}

	want := fmt.Sprintf("wildcard-shaped cluster: 6 requests returned the same 200 text/html %dB (end_paths) - the shape of a catch-all/soft-404; rerun with -calibrate to confirm", len(catchAll))
	if got := h.String(); got != want {
		t.Errorf("hint text:\n got %q\nwant %q", got, want)
	}
}

func TestWildcardHintIgnoresFewDistinctRequests(t *testing.T) {
	rows := append([]analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
	}, wildcardRows("end_paths", 4)...)

	if hints := analysis.WildcardHints(analysis.ClassifyReport(rows)); len(hints) != 0 {
		t.Fatalf("4 distinct requests is below the threshold; got %d hints (%+v)", len(hints), hints)
	}
}

// TestWildcardHintFiresAtTheThreshold pins the boundary itself. The rule's
// documented minimum is five distinct requests; without this case a mutation
// that shifted the comparison by one (firing only from six) would pass every
// other test, because they only ever use four or six. Four is covered as
// silent above, six as firing below.
func TestWildcardHintFiresAtTheThreshold(t *testing.T) {
	const threshold = 5
	rows := append([]analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
	}, wildcardRows("end_paths", threshold)...)

	hints := analysis.WildcardHints(analysis.ClassifyReport(rows))
	if len(hints) != 1 {
		t.Fatalf("want 1 hint at exactly %d distinct requests, got %d (%+v)", threshold, len(hints), hints)
	}
	if hints[0].Requests != threshold {
		t.Errorf("Requests = %d, want %d", hints[0].Requests, threshold)
	}
}

func TestWildcardHintCountsDistinctRequestsNotMembers(t *testing.T) {
	// Six members, but only two distinct request lines: not a catch-all.
	rows := append([]analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
	}, wildcardRows("end_paths", 2)...)
	rows = append(rows, wildcardRows("end_paths", 2)...)
	rows = append(rows, wildcardRows("end_paths", 2)...)

	hints := analysis.WildcardHints(analysis.ClassifyReport(rows))
	if len(hints) != 0 {
		t.Fatalf("distinct requests = 2; got %d hints (%+v)", len(hints), hints)
	}
}

func TestWildcardHintIgnoresNonBypassClasses(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
	}
	// VARIANT: many distinct requests, same non-improving 404 body.
	for i := 0; i < 6; i++ {
		rows = append(rows, row("end_paths", 404, len(altBody1), altBody1,
			fmt.Sprintf("curl variant %d", i)))
	}
	// NOISE: many distinct requests, empty non-improving bodies.
	for i := 0; i < 6; i++ {
		rows = append(rows, row("headers", 403, 0, "",
			fmt.Sprintf("curl noise %d", i)))
	}

	tr := analysis.ClassifyReport(rows).Targets[0]
	if len(clustersOfClass(tr, analysis.ClassVariant)) != 1 || len(clustersOfClass(tr, analysis.ClassNoise)) != 1 {
		t.Fatalf("fixture must build one VARIANT and one NOISE cluster; got %+v", tr.Clusters)
	}
	if hints := analysis.WildcardHints(analysis.ClassifyReport(rows)); len(hints) != 0 {
		t.Fatalf("only BYPASS-shaped clusters hint; got %d (%+v)", len(hints), hints)
	}
}

func TestWildcardHintSilentWhenControlsRan(t *testing.T) {
	// A catch-all-shaped BYPASS cluster (a control response that does NOT match
	// it -- different media type, so the match rule's status+type gate fails),
	// plus a control row: the run already answered the wildcard question, so
	// the hint stays quiet.
	rows := append([]analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		mediaRow(analysis.CalibrationModule, 200, 4, "text/plain", "nope", "curl cal"),
	}, wildcardRows("end_paths", 6)...)

	rep := analysis.ClassifyReport(rows)
	if rep.Targets[0].CalibrationControls != 1 {
		t.Fatalf("fixture must carry 1 control row, got %d", rep.Targets[0].CalibrationControls)
	}
	if len(clustersOfClass(rep.Targets[0], analysis.ClassBypass)) != 1 {
		t.Fatalf("fixture must leave one BYPASS cluster; got %+v", rep.Targets[0].Clusters)
	}
	if hints := analysis.WildcardHints(rep); len(hints) != 0 {
		t.Fatalf("a calibrated run must not hint; got %d (%+v)", len(hints), hints)
	}
}

func TestWildcardHintIsPerTarget(t *testing.T) {
	other := "https://t.example/other"
	var rows []analysis.Row
	for _, target := range []string{"https://t.example/access", other} {
		base := row("dumb_check", 403, len(forbidden), forbidden, "curl dumb "+target)
		base.TargetURL = target
		rows = append(rows, base)
		for _, r := range wildcardRows("end_paths", 6) {
			r.TargetURL = target
			r.CurlCMD = target + " " + r.CurlCMD
			rows = append(rows, r)
		}
	}

	hints := analysis.WildcardHints(analysis.ClassifyReport(rows))
	if len(hints) != 2 {
		t.Fatalf("want one hint per target, got %d (%+v)", len(hints), hints)
	}
	if hints[0].TargetURL != "https://t.example/access" || hints[1].TargetURL != other {
		t.Errorf("hints must be ordered per target, never aggregated: %+v", hints)
	}
	for _, h := range hints {
		if h.Requests != 6 {
			t.Errorf("%s: Requests = %d, want 6 (per-target count, not summed)", h.TargetURL, h.Requests)
		}
	}
}

func TestWildcardHintsLeaveTheReportUntouched(t *testing.T) {
	rows := append([]analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
	}, wildcardRows("end_paths", 6)...)

	rep := analysis.ClassifyReport(rows)
	text, jsonBefore := rep.Text(), mustJSON(t, rep)

	_ = analysis.WildcardHints(rep)

	if after := rep.Text(); after != text {
		t.Errorf("Text() changed by WildcardHints:\n--- before ---\n%s\n--- after ---\n%s", text, after)
	}
	if after := mustJSON(t, rep); after != jsonBefore {
		t.Errorf("JSON changed by WildcardHints:\n got %s\nwant %s", after, jsonBefore)
	}
}

func mustJSON(t *testing.T, rep analysis.Report) string {
	t.Helper()
	data, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !strings.Contains(string(data), "targets") {
		t.Fatalf("JSON looks wrong: %s", data)
	}
	return string(data)
}

// TestWildcardHintSilentForACalibratedDatabase goes through the database: a run
// whose control rows are present has already answered the wildcard question, so
// the offline analyzer must stay quiet on the very same catch-all shape.
func TestWildcardHintSilentForACalibratedDatabase(t *testing.T) {
	db, path := newFixtureDB(t)
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		// A control the catch-all does not match (different media type), so the
		// catch-all stays a BYPASS and only the control rule can silence it.
		mediaRow(analysis.CalibrationModule, 200, 4, "text/plain", "nope", "curl cal"),
	}
	rows = append(rows, wildcardRows("end_paths", 6)...)
	insertRows(t, db, rows...)
	_ = db.Close()

	rep := mustAnalyze(t, path)
	if rep.Targets[0].CalibrationControls != 1 {
		t.Fatalf("fixture must carry 1 control row, got %d", rep.Targets[0].CalibrationControls)
	}
	if len(clustersOfClass(rep.Targets[0], analysis.ClassBypass)) != 1 {
		t.Fatalf("fixture must leave one BYPASS cluster; got %+v", rep.Targets[0].Clusters)
	}
	if hints := analysis.WildcardHints(rep); len(hints) != 0 {
		t.Fatalf("a calibrated database must not hint; got %d (%+v)", len(hints), hints)
	}
}

// TestWildcardHintIgnoresTheRealMarkerShape rebuilds the 2026-10-16 testbed
// reading: four distinct requests returning the board's "Parser confusion
// bypass -- resource loaded." marker next to a genuine catch-all. Only the
// catch-all is hinted; a finding served for a handful of requests is not.
func TestWildcardHintIgnoresTheRealMarkerShape(t *testing.T) {
	const marker = "Parser confusion bypass - resource loaded."

	db, path := newFixtureDB(t)
	rows := []analysis.Row{row("dumb_check", 403, len(forbidden), forbidden, "curl dumb")}
	for i := 0; i < 4; i++ {
		rows = append(rows, row("end_paths", 200, len(marker), marker,
			fmt.Sprintf("curl -skgi --path-as-is 'https://t.example/access/profile;.json%d'", i)))
	}
	rows = append(rows, wildcardRows("end_paths", 6)...)
	insertRows(t, db, rows...)
	_ = db.Close()

	hints := analysis.WildcardHints(mustAnalyze(t, path))
	if len(hints) != 1 {
		t.Fatalf("want exactly 1 hint (the catch-all), got %d (%+v)", len(hints), hints)
	}
	if hints[0].Fingerprint.Length != int64(len(catchAll)) || hints[0].Requests != 6 {
		t.Errorf("hint = %+v, want the six-request catch-all, not the four markers", hints[0])
	}
}
