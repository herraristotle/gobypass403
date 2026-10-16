/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import "sync/atomic"

// RequestBudget is a hard cap on how many requests a run may send, shared by
// every target worker. A batch reserves the number of requests it is about to
// submit and sends only what it was granted, so the total that reaches the
// wire is exactly the limit no matter how many targets run at once.
//
// A nil *RequestBudget means "no limit configured": every request is granted
// and the run behaves exactly as it did before -max-reqs existed, which is why
// the accessor methods are nil-safe. A non-positive limit has the same meaning.
//
// Retries of an already reserved job are not charged again: they are part of
// the request that was granted, and stay bounded by -max-retries.
type RequestBudget struct {
	limit int64
	used  atomic.Int64
}

// NewRequestBudget returns a budget that allows at most limit requests. A
// non-positive limit means unlimited (see RequestBudget).
func NewRequestBudget(limit int) *RequestBudget {
	return &RequestBudget{limit: int64(limit)}
}

// Reserve grants up to n requests, clamped to what is left, and records the
// grant. It returns the number of requests the caller may send: 0 means the
// budget is exhausted. n <= 0 grants nothing.
func (b *RequestBudget) Reserve(n int) int {
	if n <= 0 {
		return 0
	}
	if b == nil || b.limit <= 0 {
		if b != nil {
			b.used.Add(int64(n))
		}
		return n
	}

	for {
		used := b.used.Load()
		left := b.limit - used
		if left <= 0 {
			return 0
		}
		grant := int64(n)
		if grant > left {
			grant = left
		}
		if b.used.CompareAndSwap(used, used+grant) {
			return int(grant)
		}
	}
}

// Used reports how many requests have been granted so far.
func (b *RequestBudget) Used() int {
	if b == nil {
		return 0
	}
	return int(b.used.Load())
}

// Remaining reports how many requests may still be granted. It is meaningless
// for an unlimited budget, where Limit reports 0.
func (b *RequestBudget) Remaining() int {
	if b == nil || b.limit <= 0 {
		return 0
	}
	left := b.limit - b.used.Load()
	if left < 0 {
		return 0
	}
	return int(left)
}

// Limit reports the configured cap, or 0 when the budget is unlimited.
func (b *RequestBudget) Limit() int {
	if b == nil {
		return 0
	}
	return int(b.limit)
}

// Exhausted reports whether the budget has granted everything it allows. An
// unlimited budget is never exhausted.
func (b *RequestBudget) Exhausted() bool {
	if b == nil || b.limit <= 0 {
		return false
	}
	return b.used.Load() >= b.limit
}

// reportBudgetExhausted records that the hard stop was announced, returning
// true only the first time so a run logs it once instead of once per batch.
func (s *Scanner) reportBudgetExhausted() bool {
	return s.budgetAnnounced.CompareAndSwap(false, true)
}
