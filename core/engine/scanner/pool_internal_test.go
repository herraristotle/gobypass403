package scanner

// Task D5b (SPEC-unkover-gaps.md Addendum 5, Phase D): the -tw target pool.
//
// These are wire tests against loopback httptest servers, so "at most one
// target per host at once" and "completion-order reporting" are observed as
// they actually happen, not by inspecting the pool's internals. No findings are
// stored (only 200s would be kept and the boards answer 403), so the shared
// findings DB is not touched by this file.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func poolOpts(workers int) *ScannerOpts {
	return &ScannerOpts{
		BypassModule:             "dumb_check",
		Timeout:                  5000,
		ConcurrentRequests:       5,
		ResponseBodyPreviewSize:  3096,
		DisableProgressBar:       true,
		MaxRetries:               0,
		MaxConsecutiveFailedReqs: 1000,
		Method:                   "GET",
		MatchStatusCodes:         []int{200},
		ConcurrentTargets:        workers,
	}
}

// gate is a loopback board that parks every request until it is released, so a
// test can see which targets are in flight right now.
type gate struct {
	mu      sync.Mutex
	entered []string
	release chan struct{}
}

func newGate() *gate { return &gate{release: make(chan struct{})} }

func (g *gate) board() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.entered = append(g.entered, r.URL.Path)
		g.mu.Unlock()

		<-g.release // held until the test says so
		w.WriteHeader(http.StatusForbidden)
	}
}

func (g *gate) seen() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.entered...)
}

func TestGroupTargetsByHostKeepsBucketsInFirstSeenOrder(t *testing.T) {
	urls := []string{
		"http://a.example/app",
		"http://b.example/app",
		"http://a.example/admin",
		"http://b.example:8443/app",
		"http://a.example/other",
	}

	got := groupTargetsByHost(urls)

	want := [][]string{
		{"http://a.example/app", "http://a.example/admin", "http://a.example/other"},
		{"http://b.example/app"},
		{"http://b.example:8443/app"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d buckets, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if strings.Join(got[i], " ") != strings.Join(want[i], " ") {
			t.Errorf("bucket %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestGroupTargetsByHostKeepsUnparseableTargetsAlone(t *testing.T) {
	got := groupTargetsByHost([]string{"http://a.example/x", "::not a url::", "http://a.example/y"})

	if len(got) != 2 {
		t.Fatalf("got %d buckets, want 2: %v", len(got), got)
	}
	if len(got[1]) != 1 || got[1][0] != "::not a url::" {
		t.Errorf("an unparseable target must be its own bucket, got %v", got[1])
	}
}

func TestTargetPoolScansOneTargetPerHostAtOnce(t *testing.T) {
	h1, h2 := newGate(), newGate()

	srv1 := httptest.NewServer(h1.board())
	defer srv1.Close()
	srv2 := httptest.NewServer(h2.board())
	defer srv2.Close()

	// Registered last so it runs first: a failing assertion must unblock the
	// parked requests before the servers are closed, or Close would wait on them.
	var once sync.Once
	release := func() { once.Do(func() { close(h1.release); close(h2.release) }) }
	defer release()

	urls := []string{srv1.URL + "/a", srv1.URL + "/b", srv2.URL + "/c", srv2.URL + "/d"}
	s := NewScanner(poolOpts(4), urls)

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runTargetPool(func(string, int) {})
	}()

	// Both hosts must be in flight at the same time: a pool that ran targets
	// one after another (or bucketed both loopback ports as one host) never
	// gets here.
	deadline := time.After(15 * time.Second)
	for len(h1.seen()) == 0 || len(h2.seen()) == 0 {
		select {
		case <-deadline:
			t.Fatalf("hosts never ran together: H1=%v H2=%v", h1.seen(), h2.seen())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// ...but the second target of a host must wait its turn.
	time.Sleep(300 * time.Millisecond)
	if got := h1.seen(); len(got) != 1 {
		t.Errorf("H1 had %d targets in flight at once, want 1: %v", len(got), got)
	}

	release()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the pool did not finish after the boards were released")
	}

	for name, g := range map[string]*gate{"H1": h1, "H2": h2} {
		if got := len(g.seen()); got != 2 {
			t.Errorf("%s scanned %d targets, want 2: %v", name, got, g.seen())
		}
	}
}

func TestTargetPoolReportsInCompletionOrder(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer slow.Close()

	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer fast.Close()

	slowTarget := slow.URL + "/slow"
	urls := []string{slowTarget, fast.URL + "/f1", fast.URL + "/f2", fast.URL + "/f3"}

	var reported []string
	s := NewScanner(poolOpts(4), urls)
	s.runTargetPool(func(url string, _ int) { reported = append(reported, url) })

	if len(reported) != len(urls) {
		t.Fatalf("reported %d targets, want %d: %v", len(reported), len(urls), reported)
	}
	if reported[len(reported)-1] != slowTarget {
		t.Errorf("last reported target = %q, want the slow one %q (completion order)", reported[len(reported)-1], slowTarget)
	}
}

func TestTargetPoolNeverInterleavesReportedTargets(t *testing.T) {
	board := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer board.Close()

	urls := []string{board.URL + "/1", board.URL + "/2", board.URL + "/3", board.URL + "/4"}

	// Two hosts, so two workers: without a print lock these blocks interleave.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer other.Close()
	urls = append(urls, other.URL+"/1", other.URL+"/2", other.URL+"/3", other.URL+"/4")

	// Only the pool's report path writes here; the test never locks it.
	var out strings.Builder
	s := NewScanner(poolOpts(4), urls)
	s.runTargetPool(func(url string, _ int) {
		fmt.Fprintf(&out, "BEGIN %s\n", url)
		time.Sleep(10 * time.Millisecond)
		fmt.Fprintf(&out, "END %s\n", url)
	})

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2*len(urls) {
		t.Fatalf("got %d report lines, want %d:\n%s", len(lines), 2*len(urls), out.String())
	}
	for i := 0; i < len(lines); i += 2 {
		begin, end := lines[i], lines[i+1]
		if !strings.HasPrefix(begin, "BEGIN ") || !strings.HasPrefix(end, "END ") {
			t.Fatalf("report lines interleaved:\n%s", out.String())
		}
		if strings.TrimPrefix(begin, "BEGIN ") != strings.TrimPrefix(end, "END ") {
			t.Fatalf("begin/end pair mismatch (%q / %q):\n%s", begin, end, out.String())
		}
	}
}

func TestScannerDisablesTheBarForParallelTargets(t *testing.T) {
	parallel := poolOpts(4)
	parallel.DisableProgressBar = false
	if NewScanner(parallel, nil).progressBarEnabled.Load() {
		t.Error("a single progress bar cannot describe -tw 4: want it off")
	}

	serial := poolOpts(1)
	serial.DisableProgressBar = false
	if !NewScanner(serial, nil).progressBarEnabled.Load() {
		t.Error("single-target runs keep the progress bar")
	}
}
