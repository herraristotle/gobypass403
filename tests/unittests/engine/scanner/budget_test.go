package tests

// Task D1 (SPEC-unkover-gaps.md Addendum 5, Phase D): the request budget.
//
// The budget is what makes -max-reqs a hard stop. A batch reserves the number
// of requests it is about to submit and sends only what it was granted, so the
// total that reaches the wire is exactly the limit even when several target
// workers run at once. A nil budget means "no limit configured".

import (
	"sync"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/scanner"
)

func TestRequestBudgetNilIsUnlimited(t *testing.T) {
	var b *scanner.RequestBudget

	if got := b.Reserve(5); got != 5 {
		t.Errorf("nil budget granted %d, want 5", got)
	}
	if b.Exhausted() {
		t.Error("nil budget must never be exhausted")
	}
	if b.Limit() != 0 {
		t.Errorf("nil budget limit = %d, want 0 (no limit configured)", b.Limit())
	}
}

func TestRequestBudgetGrantsExactlyUpToTheLimit(t *testing.T) {
	b := scanner.NewRequestBudget(10)

	if got := b.Reserve(4); got != 4 {
		t.Fatalf("Reserve(4) granted %d, want 4", got)
	}
	if b.Used() != 4 || b.Remaining() != 6 {
		t.Errorf("after one reservation: used=%d remaining=%d, want 4/6", b.Used(), b.Remaining())
	}

	// Asking for more than is left must clamp, not overshoot.
	if got := b.Reserve(9); got != 6 {
		t.Errorf("Reserve(9) with 6 left granted %d, want 6", got)
	}
	if b.Used() != 10 || b.Remaining() != 0 || !b.Exhausted() {
		t.Errorf("exhausted budget: used=%d remaining=%d exhausted=%v, want 10/0/true",
			b.Used(), b.Remaining(), b.Exhausted())
	}

	if got := b.Reserve(1); got != 0 {
		t.Errorf("Reserve(1) on an exhausted budget granted %d, want 0", got)
	}
}

func TestRequestBudgetNonPositiveLimitIsUnlimited(t *testing.T) {
	for _, limit := range []int{0, -1} {
		b := scanner.NewRequestBudget(limit)
		if got := b.Reserve(3); got != 3 {
			t.Errorf("limit %d: Reserve(3) granted %d, want 3", limit, got)
		}
		if b.Exhausted() {
			t.Errorf("limit %d: budget reported exhausted", limit)
		}
	}
}

func TestRequestBudgetIgnoresNonPositiveRequests(t *testing.T) {
	b := scanner.NewRequestBudget(5)

	if got := b.Reserve(0); got != 0 {
		t.Errorf("Reserve(0) granted %d, want 0", got)
	}
	if got := b.Reserve(-3); got != 0 {
		t.Errorf("Reserve(-3) granted %d, want 0", got)
	}
	if b.Used() != 0 {
		t.Errorf("used %d after non-positive reservations, want 0", b.Used())
	}
}

func TestRequestBudgetConcurrentReserveNeverOverGrants(t *testing.T) {
	const limit = 1000
	b := scanner.NewRequestBudget(limit)

	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				n := b.Reserve(3)
				mu.Lock()
				granted += n
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if granted != limit {
		t.Errorf("concurrent reservations granted %d, want exactly %d", granted, limit)
	}
	if b.Used() != limit {
		t.Errorf("used %d, want %d", b.Used(), limit)
	}
	if !b.Exhausted() {
		t.Error("budget should be exhausted after granting its whole limit")
	}
}
