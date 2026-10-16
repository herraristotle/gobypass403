package cli

// Task W2 (SPEC-unkover-gaps.md Addendum 7): the -warn-wildcard opt-in.
//
// Internal tests for the flag itself: it must exist, be a plain boolean bound
// to CliOptions.WarnWildcard, default to off, and -- unlike -expand, -adaptive
// and -calibrate -- stay legal in -analyze mode, because the report is exactly
// where the catch-all shape should be named. The scanner side of the hint is
// covered by the wire test.

import (
	"strings"
	"testing"
)

func TestWarnWildcardFlagIsARegisteredBool(t *testing.T) {
	opts := &CliOptions{}

	var found bool
	for _, f := range flagDefinitions(opts) {
		for _, name := range strings.Split(f.name, ",") {
			if strings.TrimSpace(name) != "warn-wildcard" {
				continue
			}
			found = true
			v, ok := f.value.(*bool)
			if !ok {
				t.Fatalf("-warn-wildcard value is %T, want *bool", f.value)
			}
			if v != &opts.WarnWildcard {
				t.Error("-warn-wildcard is not bound to CliOptions.WarnWildcard")
			}
			if f.defVal != false {
				t.Errorf("-warn-wildcard default is %v, want false", f.defVal)
			}
		}
	}
	if !found {
		t.Fatal("-warn-wildcard is not registered")
	}
}

func TestWarnWildcardDefaultsOff(t *testing.T) {
	if (&CliOptions{}).WarnWildcard {
		t.Error("the hint must be off unless asked for: default output is protected")
	}
}

func TestWarnWildcardHelpNamesTheRemedy(t *testing.T) {
	var usage string
	for _, f := range flagDefinitions(&CliOptions{}) {
		for _, name := range strings.Split(f.name, ",") {
			if strings.TrimSpace(name) == "warn-wildcard" {
				usage = f.usage
			}
		}
	}
	if usage == "" {
		t.Fatal("-warn-wildcard is not registered")
	}
	if !strings.Contains(usage, "-calibrate") {
		t.Errorf("usage must name the remedy (-calibrate): %q", usage)
	}
	if !strings.Contains(usage, "off by default") {
		t.Errorf("usage must state the default: %q", usage)
	}
}

func TestWarnWildcardIsAllowedWithAnalyze(t *testing.T) {
	// The offline report is where an operator looks after the fact, so the
	// hint must not be rejected there (it performs no request).
	o := &CliOptions{AnalyzeDB: "/tmp/results.db", WarnWildcard: true}
	if err := o.validateAnalyze(); err != nil {
		t.Fatalf("-analyze + -warn-wildcard must be accepted; got %v", err)
	}
}
