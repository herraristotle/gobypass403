package tests

// Task C3 (SPEC-unkover-gaps.md Addendum 5, Phase C): -adaptive on the wire.
//
// The raw wire board records what actually left the process, so these tests
// pin the three claims the phase makes:
//
//   * with -adaptive the baseline (dumb_check) runs first and the modules the
//     fingerprint promotes run before the rest — and the promoted order is the
//     same on a second run;
//   * without -adaptive the default order is untouched;
//   * the deep families run only after a 403 baseline plus a BYPASS cluster,
//     and never past -max-reqs.
//
// The board's Server header is the fingerprint under test, which is why the
// board takes it as a parameter (default board advertises wireboard/1.0).

import (
	"slices"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/scanner"
)

// adaptiveServer is a Server header the nginx rule matches.
const adaptiveServer = "nginx/1.24.0"

// adaptiveOpts is a plain wire run with the module list and -adaptive under
// test.
func adaptiveOpts(modules string, adaptive bool) *scanner.ScannerOpts {
	opts := wireOpts(false)
	opts.BypassModule = modules
	opts.Adaptive = adaptive
	return opts
}

// moduleRequests is the request set a module will send for a target.
func moduleRequests(t *testing.T, module, target string) map[string]bool {
	t.Helper()

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    target,
		BypassModule: module,
		Method:       "GET",
	})
	jobs := pg.Generate()
	if len(jobs) == 0 {
		t.Fatalf("module %s generated no payloads for %s", module, target)
	}
	return requestSet(jobs)
}

// moduleSet names one module's requests.
type moduleSet struct {
	name string
	reqs map[string]bool
}

// labelled reduces the wire trace to the sequence of modules that owned it:
// a request that belongs to exactly one of the given modules is attributed to
// it, an ambiguous one (the baseline's GET /access is also an http_methods
// payload) is dropped, and consecutive repeats are collapsed. Batches are
// sequential, so the result is deterministic even with concurrent requests
// inside a batch.
func labelled(seen []string, sets []moduleSet) []string {
	var out []string
	for _, r := range seen {
		label := ""
		ambiguous := false
		for _, s := range sets {
			if !s.reqs[r] {
				continue
			}
			if label != "" {
				ambiguous = true
				break
			}
			label = s.name
		}
		if ambiguous || label == "" {
			continue
		}
		if len(out) > 0 && out[len(out)-1] == label {
			continue
		}
		out = append(out, label)
	}
	return out
}

// adaptiveModules is the module list the ordering tests use: two cheap
// modules whose requests the label helper can tell apart.
const adaptiveModules = "dumb_check,http_methods,case_substitution"

func adaptiveModuleSets(t *testing.T, target string) []moduleSet {
	t.Helper()
	return []moduleSet{
		{"dumb_check", moduleRequests(t, "dumb_check", target)},
		{"http_methods", moduleRequests(t, "http_methods", target)},
		{"case_substitution", moduleRequests(t, "case_substitution", target)},
	}
}

func TestAdaptiveRunsTheBaselineThenThePromotedModule(t *testing.T) {
	initWireDB(t)

	board := startWireBoardWithServer(t, adaptiveServer, func(string) bool { return false })
	target := board.url("/access")
	sets := adaptiveModuleSets(t, target)

	s := scanner.NewScanner(adaptiveOpts(adaptiveModules, true), []string{target})
	s.RunAllBypasses(target)

	seen := board.seen()
	wantTotal := 0
	for _, s := range sets {
		wantTotal += len(s.reqs)
	}
	if len(seen) != wantTotal {
		t.Errorf("board saw %d requests, want one per payload (%d)", len(seen), wantTotal)
	}

	// The nginx fingerprint promotes case_substitution ahead of http_methods.
	if got, want := labelled(seen, sets), []string{"case_substitution", "http_methods"}; !slices.Equal(got, want) {
		t.Errorf("adaptive module order = %v, want %v", got, want)
	}
}

func TestAdaptiveOrderIsStableOnTheWire(t *testing.T) {
	initWireDB(t)

	run := func() []string {
		board := startWireBoardWithServer(t, adaptiveServer, func(string) bool { return false })
		target := board.url("/access")
		s := scanner.NewScanner(adaptiveOpts(adaptiveModules, true), []string{target})
		s.RunAllBypasses(target)
		return labelled(board.seen(), adaptiveModuleSets(t, target))
	}

	first, second := run(), run()
	if !slices.Equal(first, second) {
		t.Errorf("adaptive order is not stable: %v then %v", first, second)
	}
}

func TestNoAdaptiveLeavesTheRunUntouched(t *testing.T) {
	initWireDB(t)

	board := startWireBoardWithServer(t, adaptiveServer, func(string) bool { return false })
	target := board.url("/access")
	sets := adaptiveModuleSets(t, target)

	s := scanner.NewScanner(adaptiveOpts(adaptiveModules, false), []string{target})
	s.RunAllBypasses(target)

	seen := board.seen()
	wantTotal := 0
	for _, s := range sets {
		wantTotal += len(s.reqs)
	}
	if len(seen) != wantTotal {
		t.Errorf("board saw %d requests without -adaptive, want %d", len(seen), wantTotal)
	}

	// Default order: the module list order, http_methods before
	// case_substitution, even though the board advertises nginx.
	if got, want := labelled(seen, sets), []string{"http_methods", "case_substitution"}; !slices.Equal(got, want) {
		t.Errorf("default module order = %v, want %v", got, want)
	}
}

func TestAdaptiveDoesNotEscalateWithoutABypassCluster(t *testing.T) {
	initWireDB(t)

	// Every response is the same 403: triage produces DUP clusters only, so
	// the deep families must not run.
	board := startWireBoardWithServer(t, adaptiveServer, func(string) bool { return false })
	target := board.url("/access")

	modules := "dumb_check,http_methods"
	httpReqs := moduleRequests(t, "http_methods", target)

	s := scanner.NewScanner(adaptiveOpts(modules, true), []string{target})
	s.RunAllBypasses(target)

	seen := board.seen()
	if want := 1 + len(httpReqs); len(seen) != want {
		t.Errorf("board saw %d requests, want the baseline plus http_methods (%d): something escalated", len(seen), want)
	}
	for _, r := range seen {
		if !httpReqs[r] {
			t.Errorf("request outside the triage modules was sent: %q", r)
		}
	}
}

// escalateSetup runs an adaptive scan whose http_methods batch contains a
// BYPASS (the baseline 403 versus the winning method's 200), bounded by
// maxReqs.
func escalateSetup(t *testing.T, maxReqs int) (*wireBoard, []string) {
	t.Helper()

	winner := wireWinner(t)
	accept := wireAccept(winner)
	board := startWireBoardWithServer(t, adaptiveServer, func(req string) bool { return accept[req] })
	target := board.url("/access")

	opts := adaptiveOpts("dumb_check,http_methods", true)
	opts.MaxReqs = maxReqs
	s := scanner.NewScanner(opts, []string{target})
	s.RunAllBypasses(target)

	return board, board.seen()
}

func TestAdaptiveEscalatesAfter403AndBypassCluster(t *testing.T) {
	initWireDB(t)

	// Budget the triage exactly, plus 20 deep requests.
	probe := startWireBoardWithServer(t, adaptiveServer, func(string) bool { return false })
	triageTarget := probe.url("/access")
	triage := 1 + len(moduleRequests(t, "http_methods", triageTarget))

	board, seen := escalateSetup(t, triage+20)
	realTarget := board.url("/access")

	if len(seen) != triage+20 {
		t.Fatalf("board saw %d requests, want exactly the %d-request budget", len(seen), triage+20)
	}

	// path_prefix is the first deep module: every request past triage must be
	// one of its payloads (the batch is truncated to the remaining budget).
	pathReqs := moduleRequests(t, "path_prefix", realTarget)
	tail := seen[triage:]
	if len(tail) == 0 {
		t.Fatal("no deep requests after a 403 baseline plus a BYPASS cluster: escalation did not run")
	}
	for _, r := range tail {
		if !pathReqs[r] {
			t.Errorf("escalated request is not a path_prefix payload: %q", r)
		}
	}
}

func TestAdaptiveEscalationRespectsTheBudget(t *testing.T) {
	initWireDB(t)

	probe := startWireBoardWithServer(t, adaptiveServer, func(string) bool { return false })
	triage := 1 + len(moduleRequests(t, "http_methods", probe.url("/access")))

	for _, extra := range []int{0, 1, 20} {
		_, seen := escalateSetup(t, triage+extra)
		if len(seen) != triage+extra {
			t.Errorf("with a %d-request budget the board saw %d requests", triage+extra, len(seen))
		}
	}
}
