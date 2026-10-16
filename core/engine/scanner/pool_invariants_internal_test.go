package scanner

// Task D5c (SPEC-unkover-gaps.md Addendum 5, Phase D): the -tw invariants.
//
// Four targets over two loopback boards (two hosts, two paths each) are scanned
// twice: once one at a time and once through the pool with -tw 4. The pooled run
// must produce exactly the rows of the four single runs, the boards must never
// see two requests at once, and the shared -max-reqs budget must stop on the
// exact number. ConcurrentRequests is 1 so "one target per host" is directly
// visible on the wire: with a per-target pool depth above one, a single target
// would already put several requests in flight and the invariant would be
// untestable.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	invariantsDBOnce sync.Once
	invariantsDBPath string
)

// initInvariantsDB points the process-wide findings DB at a directory of its
// own. This package's tests never call Close(), so the DB stays usable for the
// whole internal test process.
func initInvariantsDB(t *testing.T) {
	t.Helper()

	invariantsDBOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gb403-pool-invariants")
		if err != nil {
			t.Fatalf("tempdir: %v", err)
		}
		invariantsDBPath = filepath.Join(dir, "results.db")
		if err := InitDB(invariantsDBPath, 1); err != nil {
			t.Fatalf("InitDB: %v", err)
		}
	})
}

// concurrencyBoard answers 403 to everything and records how many requests were
// in flight at once.
type concurrencyBoard struct {
	mu       sync.Mutex
	inFlight int
	maxSeen  int
	paths    []string
}

func (b *concurrencyBoard) board() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.inFlight++
		if b.inFlight > b.maxSeen {
			b.maxSeen = b.inFlight
		}
		b.paths = append(b.paths, r.URL.Path)
		b.mu.Unlock()

		// Widen the window so a second request would overlap even on a fast box.
		time.Sleep(time.Millisecond)

		b.mu.Lock()
		b.inFlight--
		b.mu.Unlock()

		w.WriteHeader(http.StatusForbidden)
	}
}

func (b *concurrencyBoard) stats() (maxInFlight, requests int, paths []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxSeen, len(b.paths), append([]string(nil), b.paths...)
}

func poolInvariantOpts(workers, maxReqs int) *ScannerOpts {
	o := poolOpts(workers)
	o.BypassModule = "http_methods"
	o.ConcurrentRequests = 1
	o.MatchStatusCodes = nil // store the 403s: the rows are the evidence
	o.MaxReqs = maxReqs
	return o
}

// twoBoards builds two hosts, two paths each: four targets.
func twoBoards(t *testing.T) (*concurrencyBoard, *concurrencyBoard, []string) {
	t.Helper()

	b1, b2 := &concurrencyBoard{}, &concurrencyBoard{}
	s1 := httptest.NewServer(b1.board())
	t.Cleanup(s1.Close)
	s2 := httptest.NewServer(b2.board())
	t.Cleanup(s2.Close)

	return b1, b2, []string{s1.URL + "/access", s1.URL + "/admin", s2.URL + "/access", s2.URL + "/admin"}
}

// rowFingerprint is the multiset of stored rows for one target, keyed by the
// fields that identify a batch's output.
func rowFingerprint(t *testing.T, target string) map[string]int {
	t.Helper()

	db, err := sql.Open("sqlite3", "file:"+invariantsDBPath+"?_busy_timeout=10000")
	if err != nil {
		t.Fatalf("open findings db: %v", err)
	}
	defer db.Close()

	rows, err := db.Query(
		`SELECT bypass_module, status_code, curl_cmd, COUNT(*) FROM scan_results
		 WHERE target_url = ? GROUP BY 1, 2, 3`, target)
	if err != nil {
		t.Fatalf("fingerprint %s: %v", target, err)
	}
	defer rows.Close()

	fp := map[string]int{}
	for rows.Next() {
		var module, curl string
		var status, n int
		if err := rows.Scan(&module, &status, &curl, &n); err != nil {
			t.Fatalf("scan fingerprint row: %v", err)
		}
		fp[module+"|"+strconv.Itoa(status)+"|"+curl] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("fingerprint rows: %v", err)
	}
	return fp
}

func dropRows(t *testing.T, targets []string) {
	t.Helper()

	db, err := sql.Open("sqlite3", "file:"+invariantsDBPath+"?_busy_timeout=10000")
	if err != nil {
		t.Fatalf("open findings db: %v", err)
	}
	defer db.Close()

	for _, target := range targets {
		if _, err := db.Exec("DELETE FROM scan_results WHERE target_url = ?", target); err != nil {
			t.Fatalf("clear rows for %s: %v", target, err)
		}
	}
}

func TestPoolProducesExactlyTheRowsOfTheSequentialRuns(t *testing.T) {
	initInvariantsDB(t)

	b1, b2, urls := twoBoards(t)

	// Single runs, the known-good rows for each target.
	single := make([]*Scanner, len(urls))
	want := make([]map[string]int, len(urls))
	for i, u := range urls {
		single[i] = NewScanner(poolInvariantOpts(1, 0), []string{u})
		single[i].scanTarget(u, func(string, int) {})
		want[i] = rowFingerprint(t, u)
		if len(want[i]) == 0 {
			t.Fatalf("single run of %s stored no rows, nothing to compare against", u)
		}
	}
	dropRows(t, urls)

	// The same four targets through the pool.
	pooled := NewScanner(poolInvariantOpts(4, 0), urls)
	pooled.runTargetPool(func(string, int) {})

	for i, u := range urls {
		got := rowFingerprint(t, u)
		if len(got) != len(want[i]) {
			t.Errorf("%s: pooled run stored %d distinct rows, single run %d", u, len(got), len(want[i]))
			continue
		}
		for key, n := range want[i] {
			if got[key] != n {
				t.Errorf("%s: row %q stored %d times instead of %d", u, key, got[key], n)
			}
		}
	}

	for name, b := range map[string]*concurrencyBoard{"H1": b1, "H2": b2} {
		maxInFlight, _, _ := b.stats()
		if maxInFlight > 1 {
			t.Errorf("%s saw %d requests in flight at once, want at most 1", name, maxInFlight)
		}
	}
}

func TestPoolSharesTheRequestBudgetAcrossWorkers(t *testing.T) {
	initInvariantsDB(t)

	b1, b2, urls := twoBoards(t)
	const budget = 50

	s := NewScanner(poolInvariantOpts(4, budget), urls)
	s.runTargetPool(func(string, int) {})

	_, req1, _ := b1.stats()
	_, req2, _ := b2.stats()
	if total := req1 + req2; total != budget {
		t.Errorf("boards saw %d requests in total, want exactly the %d budget", total, budget)
	}
}
