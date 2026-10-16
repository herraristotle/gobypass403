/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Escalation for Addendum 5 Phase C (adaptive-order): which modules the triage
preset deliberately leaves out (the deep families, decision C.4), and the
evidence that justifies running them for one target.

The bar is deliberately high: a baseline that is not a confirmed 403 never
escalates, and neither does a triage pass that only produced same-status
variants. A novel cluster with an improved status class is the signal that the
full deep pass is worth its ~68k payloads.
*/
package adaptive

import (
	"net/http"
	"slices"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
)

// deepModules is the triage preset's complement (decision C.5): the families
// too expensive (and too narrow) to run against every target, in registry
// order. Keep in sync with payload.BypassModulesRegistry testing.
var deepModules = []string{
	"path_prefix",
	"unicode_path_normalization",
	"unicode_path_truncation",
	"unicode_path_experimental",
	"param_manipulation",
}

// DeepModules returns the deep families in registry order. Callers get a copy
// so the table cannot be mutated from outside.
func DeepModules() []string {
	return slices.Clone(deepModules)
}

// ShouldEscalate reports whether one target has earned the deep pass: its
// baseline is a confirmed 403 and at least one triage cluster improved on it
// (ClassBypass). A non-403 baseline, no clusters, or only VARIANT/DUP/NOISE
// clusters all mean no escalation.
func ShouldEscalate(rep analysis.TargetReport) bool {
	if rep.BaselineStatus != http.StatusForbidden {
		return false
	}
	for _, c := range rep.Clusters {
		if c.Class == analysis.ClassBypass {
			return true
		}
	}
	return false
}
