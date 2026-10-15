/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Internal tests for the offline analysis mode (SPEC-unkover-gaps.md
Addendum 5, Phase A): -analyze <db> / -analyze-json <file> read an existing
findings DB, print the differential report and exit — no URL, no outdir,
no DB of our own, no network.
*/
package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realFixtureDB is the curated real unKover run committed for Phase A.
const realFixtureDB = "../../tests/testdata/unKover-suffix-findings.db"

func TestValidateAnalyzeModeRejectsScanInputs(t *testing.T) {
	cases := []struct {
		name string
		o    *CliOptions
	}{
		{"with -u", &CliOptions{AnalyzeDB: realFixtureDB, URL: "https://t.example"}},
		{"with -l", &CliOptions{AnalyzeDB: realFixtureDB, URLsFile: "urls.txt"}},
		{"with -shf", &CliOptions{AnalyzeDB: realFixtureDB, SubstituteHostsFile: "hosts.txt"}},
		{"with -r", &CliOptions{AnalyzeDB: realFixtureDB, ResendRequest: "sometoken"}},
		{"with -update-payloads", &CliOptions{AnalyzeDB: realFixtureDB, UpdatePayloads: true}},
	}
	for _, tc := range cases {
		if err := tc.o.validate(); err == nil {
			t.Errorf("-analyze %s: expected an error", tc.name)
		}
	}
}

func TestValidateAnalyzeJSONRequiresAnalyze(t *testing.T) {
	o := &CliOptions{AnalyzeJSON: filepath.Join(t.TempDir(), "out.json")}
	if err := o.validate(); err == nil {
		t.Fatalf("-analyze-json without -analyze must error")
	}
}

func TestValidateAnalyzeModeSetsUpNothing(t *testing.T) {
	o := &CliOptions{AnalyzeDB: realFixtureDB}
	if err := o.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if o.OutDir != "" || o.ResultsDBFile != "" {
		t.Errorf("analyze mode must not prepare an outdir/DB: outdir=%q db=%q",
			o.OutDir, o.ResultsDBFile)
	}
}

func TestValidateScanModeStillRequiresURL(t *testing.T) {
	o := &CliOptions{ScanProfile: "full"}
	if err := o.validate(); err == nil {
		t.Fatalf("a normal run without -u/-l must still error")
	}
}

func TestHandleAnalyzeWritesJSONReport(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.json")
	r := &Runner{RunnerOptions: &CliOptions{AnalyzeDB: realFixtureDB, AnalyzeJSON: out}}

	if err := r.handleAnalyze(); err != nil {
		t.Fatalf("handleAnalyze: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("JSON report not written: %v", err)
	}
	if !json.Valid(data) {
		t.Fatalf("report is not valid JSON:\n%s", data)
	}
	if !strings.Contains(string(data), `"class": "BYPASS"`) {
		t.Errorf("JSON report is missing the BYPASS cluster")
	}
}

func TestHandleAnalyzeMissingDBErrors(t *testing.T) {
	r := &Runner{RunnerOptions: &CliOptions{AnalyzeDB: filepath.Join(t.TempDir(), "nope.db")}}
	if err := r.handleAnalyze(); err == nil {
		t.Fatalf("expected an error for a missing database")
	}
}

// Regression: Initialize() handles analysis and returns, but main still
// calls Run(). Without the analyze guard, Run() fell through to a nil
// Scanner and panicked AFTER printing the report (exit 2).
func TestRunAfterAnalyzeModeIsANoOp(t *testing.T) {
	r := &Runner{RunnerOptions: &CliOptions{AnalyzeDB: realFixtureDB}}
	if err := r.Run(); err != nil {
		t.Fatalf("Run after analysis mode must be a no-op: %v", err)
	}
}
