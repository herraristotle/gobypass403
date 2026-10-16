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

	"github.com/slicingmelon/gobypass403/core/engine/expand"
	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

func TestTargetStatesDoNotShareSeenPayloads(t *testing.T) {
	shape := []payload.BypassPayload{{RawURI: "/admin", PayloadToken: "t1"}}

	a := newTargetState(false)
	b := newTargetState(false)

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
	a := newTargetState(true)
	b := newTargetState(true)

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

	ts := newTargetState(false)
	if got := len(ts.filterUniqueBypassPayloads(shape, "http_methods")); got != 1 {
		t.Fatalf("unfiltered module kept %d payloads, want 1", got)
	}
	if len(ts.seen) != 0 {
		t.Errorf("unfiltered module wrote %d entries into the seen map, want 0", len(ts.seen))
	}
}
