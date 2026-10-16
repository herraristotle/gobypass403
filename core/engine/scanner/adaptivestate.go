/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Adaptive state (SPEC-unkover-gaps.md Addendum 5, Phase C) — `-adaptive`.

One target's fingerprint and triage evidence: the baseline response's
Fingerprint decides the module order, and the observations of the modules that
ran decide whether the deep families have been earned. Both live here rather
than in package globals so `-tw > 1` keeps working (Phase D). Off by default:
with the flag off nothing here is read or written.
*/
package scanner

import (
	"github.com/slicingmelon/gobypass403/core/engine/adaptive"
	"github.com/slicingmelon/gobypass403/core/engine/analysis"
)

// adaptiveState is the per-target adaptive bookkeeping. Single-goroutine use,
// like the rest of targetState.
type adaptiveState struct {
	enabled bool

	// capture is set while the baseline module runs: the first response it
	// produces becomes the target's fingerprint.
	capture      bool
	haveBaseline bool
	baseline     adaptive.Fingerprint

	// obs are the observations of every module of the triage pass, baseline
	// included: the evidence ShouldEscalate judges.
	obs []analysis.Observation
}

// fingerprintRequest marks the next module's first response as the baseline
// fingerprint. Called before the baseline module runs.
func (a *adaptiveState) fingerprintRequest() {
	a.capture = true
}

// captureFingerprint stores the baseline response, once. It returns true when
// this call was the one that captured it.
func (a *adaptiveState) captureFingerprint(status int, server string, headerLines []string) bool {
	if !a.enabled || !a.capture || a.haveBaseline {
		return false
	}
	a.baseline = adaptive.NewFingerprint(status, server, headerLines)
	a.haveBaseline = true
	return true
}

// remember accumulates the module batch that just finished. The caller passes
// the batch the collector holds; the slice is appended to, so the next
// startBatch cannot drop evidence the escalation still needs.
func (a *adaptiveState) remember(batch []analysis.Observation) {
	if !a.enabled || len(batch) == 0 {
		return
	}
	a.obs = append(a.obs, batch...)
}

// order returns the module order for this target: the default order when no
// baseline was captured, otherwise the adaptive promotion of the modules still
// to run.
func (a *adaptiveState) order(remaining []string) []string {
	if !a.haveBaseline {
		return remaining
	}
	return adaptive.Order(remaining, a.baseline)
}
