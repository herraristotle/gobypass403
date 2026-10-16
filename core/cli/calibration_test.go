/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Internal tests for `-calibrate` module wiring (SPEC-unkover-gaps.md
Addendum 6): the negative-control module is injected right after the baseline
and stays out of every default/profile set.
*/
package cli

import (
	"slices"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
)

func TestCalibrateInjectsControlAfterBaseline(t *testing.T) {
	o := &CliOptions{Module: "headers_ip", moduleSet: true, Calibrate: true}
	got := resolveModuleList(t, o)
	want := []string{"dumb_check", analysis.CalibrationModule, "headers_ip"}
	if !slices.Equal(got, want) {
		t.Errorf("-calibrate injection mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestCalibrateInjectedOnlyOnceWithAll(t *testing.T) {
	o := &CliOptions{Calibrate: true}
	got := resolveModuleList(t, o)

	if n := countOf(got, analysis.CalibrationModule); n != 1 {
		t.Errorf("calibration module appears %d times, want exactly 1 (%v)", n, got)
	}
	if len(got) < 2 || got[0] != "dumb_check" || got[1] != analysis.CalibrationModule {
		t.Errorf("calibration must sit right after the baseline; got %v", got)
	}
}

func TestCalibrationStaysOutOfDefaultAndTriageSets(t *testing.T) {
	for _, o := range []*CliOptions{{}, {ScanProfile: "triage"}} {
		got := resolveModuleList(t, o)
		if slices.Contains(got, analysis.CalibrationModule) {
			t.Errorf("without -calibrate the control must not be scheduled; got %v", got)
		}
	}
}

func TestCalibrateRejectedWithAnalyze(t *testing.T) {
	o := &CliOptions{AnalyzeDB: "/tmp/x.db", Calibrate: true}
	if err := o.validateAnalyze(); err == nil {
		t.Fatalf("expected -analyze + -calibrate to be rejected")
	}
}

func countOf(list []string, v string) int {
	n := 0
	for _, m := range list {
		if m == v {
			n++
		}
	}
	return n
}
