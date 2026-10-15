package tests

// Task A2 (SPEC-unkover-gaps.md Addendum 5, Phase A): cluster a target's
// rows and classify each cluster against the target's baseline.
//
// Contract under test:
//   DUP     = fingerprint identical to the baseline (dumb_check rows;
//             modal fingerprint of the target when there is no dumb_check)
//   BYPASS  = not in the baseline AND the status class improves on it
//             (e.g. baseline 403 -> 2xx). A 403 with a *different* body is
//             a VARIANT, never a BYPASS.
//   NOISE   = empty-body, non-improving artifacts (e.g. an empty 403)
//   VARIANT = anything else (same class, distinct body)
//
// Ordering: BYPASS -> VARIANT -> DUP -> NOISE, then member-count desc.

import (
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
)

const (
	forbidden = "Forbidden"
	okBody    = "ok-40-byte-body........................"
	altBody1  = "a different block page"
	altBody2  = "another block page, still 4xx"
)

func row(module string, status, length int, body, curl string) analysis.Row {
	return analysis.Row{
		TargetURL: "https://t.example/access", BypassModule: module,
		StatusCode: status, ContentLength: int64(length),
		ContentType: "text/html", ResponseBodyPreview: body, CurlCMD: curl,
	}
}

func clustersOfClass(tr analysis.TargetReport, c analysis.Class) []analysis.Cluster {
	var out []analysis.Cluster
	for _, cl := range tr.Clusters {
		if cl.Class == c {
			out = append(out, cl)
		}
	}
	return out
}

func containsCurl(cl analysis.Cluster, curl string) bool {
	for _, m := range cl.Members {
		if m.CurlCMD == curl {
			return true
		}
	}
	return cl.Representative.CurlCMD == curl
}

func TestClassifyBypassWhenStatusImproves(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("http_methods", 200, len(okBody), okBody, "curl -X get"),
		row("http_methods", 200, len(okBody), okBody, "curl -X acl"),
		row("case_substitution", 200, len(okBody), okBody, "curl -X ReCords"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if tr.BaselineSource != analysis.BaselineDumbCheck {
		t.Errorf("BaselineSource = %q, want %q", tr.BaselineSource, analysis.BaselineDumbCheck)
	}
	if tr.BaselineStatus != 403 {
		t.Errorf("BaselineStatus = %d, want 403", tr.BaselineStatus)
	}

	bypasses := clustersOfClass(tr, analysis.ClassBypass)
	if len(bypasses) != 1 {
		t.Fatalf("want exactly 1 BYPASS cluster, got %d (%+v)", len(bypasses), tr.Clusters)
	}
	if bypasses[0].Count != 3 {
		t.Errorf("BYPASS count = %d, want 3", bypasses[0].Count)
	}
	if !containsCurl(bypasses[0], "curl -X get") {
		t.Errorf("BYPASS cluster must contain the -X get member")
	}
	if n := len(clustersOfClass(tr, analysis.ClassVariant)); n != 0 {
		t.Errorf("want 0 VARIANT clusters, got %d", n)
	}
}

func TestClassifyDistinctBodySameStatusIsVariant(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("end_paths", 403, len(altBody1), altBody1, "curl --path-as-is"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if got := len(clustersOfClass(tr, analysis.ClassVariant)); got != 1 {
		t.Errorf("want 1 VARIANT cluster, got %d", got)
	}
	if got := len(clustersOfClass(tr, analysis.ClassBypass)); got != 0 {
		t.Errorf("a 403 with a different body must not be a BYPASS (got %d)", got)
	}
}

func TestClassifyIdenticalToBaselineIsDup(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("end_paths", 403, len(forbidden), forbidden, "curl --path-as-is"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	dups := clustersOfClass(tr, analysis.ClassDup)
	if len(dups) != 1 {
		t.Fatalf("want 1 DUP cluster, got %d (%+v)", len(dups), tr.Clusters)
	}
	if dups[0].Count != 2 {
		t.Errorf("DUP count = %d, want 2 (baseline + identical module row)", dups[0].Count)
	}
}

func TestClassifyAsciiWhitespaceOnlyBody(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("mid_paths", 403, 0, "", "curl empty403"),
		row("mid_paths", 200, 0, "", "curl empty200"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if got := len(clustersOfClass(tr, analysis.ClassNoise)); got != 1 {
		t.Errorf("want 1 NOISE cluster (empty 403), got %d", got)
	}
	bypasses := clustersOfClass(tr, analysis.ClassBypass)
	if len(bypasses) != 1 {
		t.Fatalf("want 1 BYPASS (empty 200 still improves), got %d", len(bypasses))
	}
	if bypasses[0].Fingerprint.Status != 200 {
		t.Errorf("empty-200 BYPASS status = %d, want 200", bypasses[0].Fingerprint.Status)
	}
}

func TestClassifyModalBaselineFallbackWithoutDumbCheck(t *testing.T) {
	rows := []analysis.Row{
		row("end_paths", 403, len(forbidden), forbidden, "curl a"),
		row("mid_paths", 403, len(forbidden), forbidden, "curl b"),
		row("char_encode", 200, len(okBody), okBody, "curl c"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if tr.BaselineSource != analysis.BaselineModal {
		t.Fatalf("BaselineSource = %q, want %q", tr.BaselineSource, analysis.BaselineModal)
	}
	if tr.BaselineStatus != 403 {
		t.Errorf("BaselineStatus = %d, want 403 (modal)", tr.BaselineStatus)
	}
	if got := len(clustersOfClass(tr, analysis.ClassBypass)); got != 1 {
		t.Errorf("want 1 BYPASS vs modal baseline, got %d", got)
	}
	if got := len(clustersOfClass(tr, analysis.ClassDup)); got != 1 {
		t.Errorf("want 1 DUP (the modal block page), got %d", got)
	}
}

func TestClassifyOrdering(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("mid_paths", 403, len(altBody1), altBody1, "curl v1a"),
		row("end_paths", 403, len(altBody1), altBody1, "curl v1b"),
		row("end_paths", 403, len(altBody2), altBody2, "curl v2"),
		row("http_methods", 200, len(okBody), okBody, "curl bypass"),
		row("mid_paths", 403, 0, "", "curl noise"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	wantClasses := []analysis.Class{
		analysis.ClassBypass, analysis.ClassVariant, analysis.ClassVariant,
		analysis.ClassDup, analysis.ClassNoise,
	}
	wantCounts := []int{1, 2, 1, 1, 1}

	if len(tr.Clusters) != len(wantClasses) {
		t.Fatalf("got %d clusters, want %d (%+v)", len(tr.Clusters), len(wantClasses), tr.Clusters)
	}
	for i := range wantClasses {
		if tr.Clusters[i].Class != wantClasses[i] {
			t.Errorf("cluster %d class = %v, want %v", i, tr.Clusters[i].Class, wantClasses[i])
		}
		if tr.Clusters[i].Count != wantCounts[i] {
			t.Errorf("cluster %d count = %d, want %d", i, tr.Clusters[i].Count, wantCounts[i])
		}
	}
}

func TestClassifyReportGroupsByTargetDeterministically(t *testing.T) {
	rows := []analysis.Row{
		{TargetURL: "https://b.example/x", BypassModule: "dumb_check", StatusCode: 403, ContentLength: 9, ResponseBodyPreview: forbidden, CurlCMD: "curl b"},
		{TargetURL: "https://a.example/x", BypassModule: "dumb_check", StatusCode: 403, ContentLength: 9, ResponseBodyPreview: forbidden, CurlCMD: "curl a"},
		{TargetURL: "https://a.example/x", BypassModule: "end_paths", StatusCode: 200, ContentLength: int64(len(okBody)), ResponseBodyPreview: okBody, CurlCMD: "curl a2"},
	}
	rep := analysis.ClassifyReport(rows)

	if len(rep.Targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(rep.Targets))
	}
	if rep.Targets[0].TargetURL != "https://a.example/x" {
		t.Errorf("targets must be sorted by URL; got %q first", rep.Targets[0].TargetURL)
	}
	if got := len(clustersOfClass(rep.Targets[0], analysis.ClassBypass)); got != 1 {
		t.Errorf("a.example should have 1 BYPASS, got %d", got)
	}
	if got := len(clustersOfClass(rep.Targets[1], analysis.ClassBypass)); got != 0 {
		t.Errorf("b.example should have 0 BYPASS, got %d", got)
	}
}
