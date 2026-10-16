/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Tests for the Phase C escalation decision: the deep families to run, and the
trigger (baseline 403 + a BYPASS cluster) that justifies running them.
*/
package adaptive

import (
	"fmt"
	"slices"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// report builds a target report whose clusters carry the given classes.
func report(baselineStatus int, classes ...analysis.Class) analysis.TargetReport {
	rep := analysis.TargetReport{BaselineStatus: baselineStatus}
	for i, c := range classes {
		rep.Clusters = append(rep.Clusters, analysis.Cluster{
			Class: c,
			Count: i + 1,
		})
	}
	return rep
}

func TestShouldEscalateOnlyOn403AndBypassCluster(t *testing.T) {
	cases := []struct {
		name string
		rep  analysis.TargetReport
		want bool
	}{
		{"403 + BYPASS", report(403, analysis.ClassBypass), true},
		{"403 + VARIANT only", report(403, analysis.ClassVariant), false},
		{"403 + DUP only", report(403, analysis.ClassDup), false},
		{"403 + NOISE only", report(403, analysis.ClassNoise), false},
		{"403 + no clusters", report(403), false},
		{"200 + BYPASS", report(200, analysis.ClassBypass), false},
		{"0 + BYPASS", report(0, analysis.ClassBypass), false},
		{"empty report", analysis.TargetReport{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldEscalate(tc.rep); got != tc.want {
				t.Fatalf("ShouldEscalate = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShouldEscalateScansEveryCluster(t *testing.T) {
	for _, pos := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("pos%d", pos), func(t *testing.T) {
			classes := []analysis.Class{
				analysis.ClassDup, analysis.ClassVariant,
				analysis.ClassNoise, analysis.ClassDup,
			}
			classes[pos] = analysis.ClassBypass
			if !ShouldEscalate(report(403, classes...)) {
				t.Fatalf("BYPASS cluster at position %d did not escalate", pos)
			}
		})
	}
}

func TestDeepModulesAreTheDeepFamilies(t *testing.T) {
	want := []string{
		"path_prefix",
		"unicode_path_normalization",
		"unicode_path_truncation",
		"unicode_path_experimental",
		"param_manipulation",
	}
	if got := DeepModules(); !slices.Equal(got, want) {
		t.Fatalf("DeepModules() = %v, want %v (registry order)", got, want)
	}
}

func TestDeepModulesAreAllRegistered(t *testing.T) {
	for _, m := range DeepModules() {
		if !slices.Contains(payload.BypassModulesRegistry, m) {
			t.Fatalf("deep module %q is not in payload.BypassModulesRegistry", m)
		}
	}
	// A shallow module must never be marked deep: the triage preset is
	// derived as registry - deep, so a wrong entry would silently stop it
	// from being scanned in a triage run.
	for _, m := range []string{"dumb_check", "end_paths", "mid_paths", "headers_ip", "http10"} {
		if slices.Contains(DeepModules(), m) {
			t.Fatalf("shallow module %q wrongly marked deep", m)
		}
	}
}
