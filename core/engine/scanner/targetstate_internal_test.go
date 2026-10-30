package scanner

// Task D5a (SPEC-unkover-gaps.md Addendum 5, Phase D): per-target state.
//
// Two pieces of state used to be scanner-global and merely reset per target:
// the seen-RawURI map and the expansion bookkeeping. They move into a
// targetState so two targets can be scanned at once (D5b's pool) without
// corrupting each other. This is a refactor: behaviour for a single target is
// unchanged, which the byte-identical check covers; what is new here is the
// isolation itself.

import (
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/analysis"
	"github.com/herraristotle/gobypass403/core/engine/expand"
	"github.com/herraristotle/gobypass403/core/engine/payload"
)

func TestTargetStatesDoNotShareSeenPayloads(t *testing.T) {
	shape := []payload.BypassPayload{{RawURI: "/admin", PayloadToken: "t1"}}

	a := newTargetState(false, false)
	b := newTargetState(false, false)

	if got := len(a.filterUniqueBypassPayloads(shape, "path_prefix")); got != 1 {
		t.Fatalf("first target kept %d payloads, want 1 (nothing seen before)", got)
	}

	// The same shape from another module is a repeat for A...
	if got := len(a.filterUniqueBypassPayloads(shape, "end_paths")); got != 0 {
		t.Errorf("first target kept %d payloads repeating a shape it already sent, want 0", got)
	}

	// ...but not for B, which has its own history.
	if got := len(b.filterUniqueBypassPayloads(shape, "end_paths")); got != 1 {
		t.Errorf("second target inherited the first target's history: kept %d payloads, want 1", got)
	}
}

func TestTargetStatesKeepTheirOwnExpansionState(t *testing.T) {
	a := newTargetState(true, false)
	b := newTargetState(true, false)

	a.expand.startTarget("https://a.example/admin")
	a.expand.budget = 3

	if b.expand.budget != expand.PerTarget {
		t.Errorf("second target budget = %d, want the untouched %d", b.expand.budget, expand.PerTarget)
	}
	if b.expand.target != "" {
		t.Errorf("second target picked up the first target's URL: %q", b.expand.target)
	}
}

// A module that is not in the filter list never looks at, or writes to, the
// seen map: the state must stay empty for those batches.
func TestTargetStateLeavesUnfilteredModulesAlone(t *testing.T) {
	shape := []payload.BypassPayload{{RawURI: "/admin", PayloadToken: "t1"}}

	ts := newTargetState(false, false)
	if got := len(ts.filterUniqueBypassPayloads(shape, "http_methods")); got != 1 {
		t.Fatalf("unfiltered module kept %d payloads, want 1", got)
	}
	if len(ts.seen) != 0 {
		t.Errorf("unfiltered module wrote %d entries into the seen map, want 0", len(ts.seen))
	}
}

// Task C3 (Addendum 5, Phase C): the fingerprint and the triage evidence are
// per target too, so -tw > 1 cannot let one target's Server header or clusters
// decide another target's module order.
func TestTargetStatesKeepTheirOwnAdaptiveState(t *testing.T) {
	a := newTargetState(false, true)
	b := newTargetState(false, true)

	a.adaptive.fingerprintRequest()
	if !a.adaptive.captureFingerprint(403, "cloudflare", []string{"Server: cloudflare"}) {
		t.Fatal("the first baseline response was not captured")
	}
	a.adaptive.remember([]analysis.Observation{{Module: "dumb_check"}})

	if b.adaptive.haveBaseline {
		t.Error("second target inherited the first target's baseline fingerprint")
	}
	if len(b.adaptive.obs) != 0 {
		t.Errorf("second target inherited %d observations", len(b.adaptive.obs))
	}
	if got := b.adaptive.order([]string{"http_methods", "headers_ip"}); got[0] != "http_methods" {
		t.Errorf("second target was reordered without a baseline: %v", got)
	}

	// An adaptive-off state never captures or reorders, even mid-run.
	off := newTargetState(false, false)
	off.adaptive.fingerprintRequest()
	if off.adaptive.captureFingerprint(403, "cloudflare", nil) {
		t.Error("a state with -adaptive off captured a fingerprint")
	}
	if got := off.adaptive.order([]string{"b", "a"}); got[0] != "b" {
		t.Errorf("a state with -adaptive off reordered: %v", got)
	}
}
