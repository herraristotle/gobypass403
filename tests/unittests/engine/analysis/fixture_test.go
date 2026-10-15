package tests

// Task A5 (SPEC-unkover-gaps.md Addendum 5, Phase A): fixtures + parity
// regression.
//
// The curated real DB is a genuine unKover testbed run (see
// tests/testdata/README.md). These tests pin the headline outcomes the
// whole addendum exists for: a bypass surfaces WITHOUT the operator
// supplying -mc, and hundreds of near-identical responses collapse to a
// single cluster whose hidden members are announced.

import (
	"os"
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
)

const realSuffixFixture = "../../../testdata/unKover-suffix-findings.db"

// unKover's exact PoC curl, verbatim as gobypass403 emitted it.
const bareSuffixCurl = "curl -skgi --path-as-is 'https://403.brutelogic.net/access/nginx/suffix/'"

func mustAnalyze(t *testing.T, path string) analysis.Report {
	t.Helper()
	rep, err := analysis.Analyze(path)
	if err != nil {
		t.Fatalf("Analyze(%s): %v", path, err)
	}
	return rep
}

func TestRealSuffixFixtureYieldsSingleBypassCluster(t *testing.T) {
	rep := mustAnalyze(t, realSuffixFixture)
	if len(rep.Targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(rep.Targets))
	}
	tr := rep.Targets[0]

	if tr.BaselineSource != analysis.BaselineDumbCheck || tr.BaselineStatus != 403 {
		t.Errorf("baseline = %s/%d, want dumb_check/403", tr.BaselineSource, tr.BaselineStatus)
	}

	bypasses := clustersOfClass(tr, analysis.ClassBypass)
	if len(bypasses) != 1 {
		t.Fatalf("want exactly 1 BYPASS cluster, got %d (%+v)", len(bypasses), tr.Clusters)
	}
	b := bypasses[0]
	if b.Count != 453 || b.Fingerprint.Status != 200 || b.Fingerprint.Length != 40 {
		t.Errorf("BYPASS cluster = count %d, status %d, length %d; want 453/200/40",
			b.Count, b.Fingerprint.Status, b.Fingerprint.Length)
	}
	if !containsCurl(b, bareSuffixCurl) {
		t.Errorf("BYPASS cluster must contain unKover's exact bare /suffix/ PoC")
	}
}

func TestRealSuffixFixtureCollapseIsAnnounced(t *testing.T) {
	txt := mustAnalyze(t, realSuffixFixture).Text()
	// 453 members, 5 shown -> 448 collapsed (the same +448 that motivated
	// the findings-table display fix).
	if !strings.Contains(txt, "+448 more identical (first: ") {
		t.Errorf("report must announce the 448 collapsed members\n--- output ---\n%s", txt)
	}
	if !strings.Contains(txt, "=== https://403.brutelogic.net/access/nginx/suffix ===") {
		t.Errorf("report must name the real target\n--- output ---\n%s", txt)
	}
}

func TestRealSuffixFixtureIsReadOnly(t *testing.T) {
	before := sha256File(t, realSuffixFixture)

	if _, err := analysis.Analyze(realSuffixFixture); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if after := sha256File(t, realSuffixFixture); after != before {
		t.Errorf("curated fixture was modified: %s -> %s", before, after)
	}
	for _, sidecar := range []string{realSuffixFixture + "-wal", realSuffixFixture + "-shm"} {
		if _, err := os.Stat(sidecar); err == nil {
			t.Errorf("Analyze created sidecar %s", sidecar)
		}
	}
}

func TestSyntheticRecordsParityWithoutFilter(t *testing.T) {
	db, path := newFixtureDB(t)
	insertRows(t, db,
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("http_methods", 200, len(okBody), okBody,
			"curl -skgi -X get 'https://403.brutelogic.net/access/apache/records'"),
		row("end_paths", 403, len(altBody1), altBody1, "curl other"),
	)
	_ = db.Close()

	rep := mustAnalyze(t, path)
	bypasses := clustersOfClass(rep.Targets[0], analysis.ClassBypass)
	if len(bypasses) != 1 {
		t.Fatalf("want 1 BYPASS cluster, got %d (%+v)", len(bypasses), rep.Targets[0].Clusters)
	}
	if !strings.Contains(bypasses[0].Representative.CurlCMD, "-X get") {
		t.Errorf("representative = %q, want the -X get row", bypasses[0].Representative.CurlCMD)
	}
}
