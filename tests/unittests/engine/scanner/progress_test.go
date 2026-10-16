package tests

// Task D3 (SPEC-unkover-gaps.md Addendum 5, Phase D): the resume checkpoint.
//
// scan.progress.json in the outdir records the (target_url, module) pairs that
// finished, so a restarted run can skip them. It must never be the reason a
// scan fails: a missing file is a first run, an unreadable one is reported and
// replaced by a fresh start.

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/scanner"
)

func TestProgressPathLivesInTheOutDir(t *testing.T) {
	if got, want := scanner.ProgressPath("/tmp/scan"), filepath.Join("/tmp/scan", "scan.progress.json"); got != want {
		t.Errorf("ProgressPath = %q, want %q", got, want)
	}
}

func TestProgressMissingFileIsAFirstRun(t *testing.T) {
	p, err := scanner.LoadProgress(filepath.Join(t.TempDir(), "scan.progress.json"))
	if err != nil {
		t.Fatalf("missing checkpoint must not be an error, got %v", err)
	}
	if p.Count() != 0 {
		t.Errorf("fresh checkpoint has %d pairs, want 0", p.Count())
	}
	if p.Has("https://t.example/admin", "dumb_check") {
		t.Error("fresh checkpoint reports a completed pair")
	}
}

func TestProgressEmptyFileIsAFirstRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.progress.json")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	p, err := scanner.LoadProgress(path)
	if err != nil {
		t.Fatalf("empty checkpoint must not be an error, got %v", err)
	}
	if p.Count() != 0 {
		t.Errorf("empty checkpoint has %d pairs, want 0", p.Count())
	}
}

func TestProgressUnreadableFileIsReportedAndStartsFresh(t *testing.T) {
	cases := map[string]string{
		"garbage":       "not json at all",
		"wrong version": `{"version":2,"completed":[{"target_url":"https://t.example","module":"dumb_check"}]}`,
		"truncated":     `{"version":1,"completed":[{"target_url":`,
	}

	for name, body := range cases {
		path := filepath.Join(t.TempDir(), "scan.progress.json")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}

		p, err := scanner.LoadProgress(path)
		if err == nil {
			t.Errorf("%s: expected the checkpoint to be reported as unusable", name)
		}
		if p == nil {
			t.Fatalf("%s: expected a usable (empty) checkpoint", name)
		}
		if p.Count() != 0 {
			t.Errorf("%s: recovered %d pairs from an unusable file, want 0", name, p.Count())
		}
	}
}

func TestProgressRoundTripsPairs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.progress.json")

	p, err := scanner.LoadProgress(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p.Mark("https://b.example/admin", "headers_ip")
	p.Mark("https://a.example/admin", "dumb_check")
	p.Mark("https://a.example/admin", "dumb_check") // idempotent
	if err := p.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	reloaded, err := scanner.LoadProgress(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Count() != 2 {
		t.Fatalf("reloaded %d pairs, want 2", reloaded.Count())
	}
	for _, want := range [][2]string{
		{"https://a.example/admin", "dumb_check"},
		{"https://b.example/admin", "headers_ip"},
	} {
		if !reloaded.Has(want[0], want[1]) {
			t.Errorf("pair %v did not round-trip", want)
		}
	}
	if reloaded.Has("https://a.example/admin", "headers_ip") {
		t.Error("pairs must be keyed by target *and* module")
	}
	if reloaded.Has("https://a.example/admin/", "dumb_check") {
		t.Error("pair keys must be exact, not prefix/case folded")
	}
}

func TestProgressSaveIsIdempotentAndLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.progress.json")

	p, err := scanner.LoadProgress(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p.Mark("https://a.example/admin", "dumb_check")
	if err := p.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if err := p.Save(); err != nil {
		t.Fatalf("second save: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("saving twice changed the file:\n%s\n---\n%s", first, second)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "scan.progress.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only the checkpoint file", names)
	}

	if strings.Contains(string(first), "timestamp") || strings.Contains(string(first), "time\"") {
		t.Errorf("checkpoint should stay reproducible, no timestamps:\n%s", first)
	}
}

func TestProgressConcurrentMarkLosesNoPair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.progress.json")

	p, err := scanner.LoadProgress(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				target := "https://host" + string(rune('a'+i)) + ".example/admin"
				p.Mark(target, "dumb_check")
				p.Mark(target, "headers_ip")
			}
		}(i)
	}
	wg.Wait()

	if err := p.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	reloaded, err := scanner.LoadProgress(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Count() != 64 {
		t.Errorf("reloaded %d pairs, want 64 (32 targets x 2 modules)", reloaded.Count())
	}
}

func TestProgressNilIsSafe(t *testing.T) {
	var p *scanner.Progress

	if p.Has("https://a.example/admin", "dumb_check") {
		t.Error("nil checkpoint reports a completed pair")
	}
	p.Mark("https://a.example/admin", "dumb_check")
	if err := p.Save(); err != nil {
		t.Errorf("nil checkpoint save: %v", err)
	}
	if p.Count() != 0 {
		t.Errorf("nil checkpoint count = %d, want 0", p.Count())
	}
}
