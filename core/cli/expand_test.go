package cli

// Task B5 (SPEC-unkover-gaps.md Addendum 5, Phase B): the -expand opt-in.
//
// Internal tests for the flag itself: it must exist, be a plain boolean bound
// to CliOptions.Expand, default to off, and be rejected where it makes no sense
// (offline analysis performs no requests). The end-to-end behaviour of an
// expansion pass is covered by the scanner wire test.

import (
	"strings"
	"testing"
)

func TestExpandFlagIsARegisteredBool(t *testing.T) {
	opts := &CliOptions{}

	var found bool
	for _, f := range flagDefinitions(opts) {
		for _, name := range strings.Split(f.name, ",") {
			if strings.TrimSpace(name) != "expand" {
				continue
			}
			found = true
			v, ok := f.value.(*bool)
			if !ok {
				t.Fatalf("-expand value is %T, want *bool", f.value)
			}
			if v != &opts.Expand {
				t.Error("-expand is not bound to CliOptions.Expand")
			}
		}
	}
	if !found {
		t.Fatal("-expand is not registered")
	}
}

func TestExpandDefaultsOff(t *testing.T) {
	if (&CliOptions{}).Expand {
		t.Error("expansion must default off")
	}
}

func TestExpandIsRejectedInAnalyzeMode(t *testing.T) {
	o := &CliOptions{AnalyzeDB: "/tmp/results.db", Expand: true}

	err := o.validateAnalyze()
	if err == nil {
		t.Fatal("expected -analyze with -expand to be rejected")
	}
	if !strings.Contains(err.Error(), "expand") {
		t.Errorf("error %q should name -expand", err)
	}
}
