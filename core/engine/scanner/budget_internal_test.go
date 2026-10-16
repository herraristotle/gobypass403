package scanner

// Task D2 (SPEC-unkover-gaps.md Addendum 5, Phase D): the exhaustion notice is
// announced once per run, not once per truncated batch. Internal test because
// it pins a scanner-internal guard (the log line itself goes to the logger,
// which tests do not capture).

import (
	"sync"
	"testing"
)

func TestBudgetExhaustionIsAnnouncedOnce(t *testing.T) {
	s := &Scanner{}

	if !s.reportBudgetExhausted() {
		t.Error("first report should announce the stop")
	}
	if s.reportBudgetExhausted() {
		t.Error("second report should stay quiet")
	}

	// Concurrent reporters: exactly one wins.
	s2 := &Scanner{}
	var wg sync.WaitGroup
	wins := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wins <- s2.reportBudgetExhausted()
		}()
	}
	wg.Wait()
	close(wins)

	n := 0
	for w := range wins {
		if w {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d concurrent reporters announced the stop, want exactly 1", n)
	}
}
