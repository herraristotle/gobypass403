package tests

// Task D2 (SPEC-unkover-gaps.md Addendum 5, Phase D): -max-reqs is a hard stop.
//
// The board counts what actually arrived, so these tests assert the wire, not
// the tool's own accounting: with a budget the run sends exactly that many
// requests and then finishes (results kept, no burst to make up the rest);
// without one it sends the whole batch as before.

import (
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/scanner"
)

func TestMaxReqsIsAHardStopOnTheWire(t *testing.T) {
	board := startWireBoard(t, func(req string) bool { return false })
	target := board.url("/access")

	const limit = 10
	opts := wireOpts(false)
	opts.MaxReqs = limit

	s := scanner.NewScanner(opts, []string{target})
	s.RunBypassModule(wireModule, target)

	seen := board.seen()
	if len(seen) != limit {
		t.Errorf("board saw %d requests with -max-reqs %d, want exactly %d", len(seen), limit, limit)
	}
}

func TestMaxReqsLargerThanTheBatchSendsTheWholeBatch(t *testing.T) {
	board := startWireBoard(t, func(req string) bool { return false })
	target := board.url("/access")

	jobs := wireJobs(t, target)
	opts := wireOpts(false)
	opts.MaxReqs = len(jobs) + 1000

	s := scanner.NewScanner(opts, []string{target})
	s.RunBypassModule(wireModule, target)

	if seen := board.seen(); len(seen) != len(jobs) {
		t.Errorf("board saw %d requests, want the whole batch of %d", len(seen), len(jobs))
	}
}

func TestNoMaxReqsSendsTheWholeBatch(t *testing.T) {
	board := startWireBoard(t, func(req string) bool { return false })
	target := board.url("/access")

	jobs := wireJobs(t, target)

	s := scanner.NewScanner(wireOpts(false), []string{target})
	s.RunBypassModule(wireModule, target)

	if seen := board.seen(); len(seen) != len(jobs) {
		t.Errorf("board saw %d requests without a budget, want the whole batch of %d", len(seen), len(jobs))
	}
}
