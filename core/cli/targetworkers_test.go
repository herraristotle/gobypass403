package cli

// Task D5b (SPEC-unkover-gaps.md Addendum 5, Phase D): the -tw flag.

import (
	"strings"
	"testing"
)

func TestTargetWorkersFlagIsARegisteredInt(t *testing.T) {
	opts := &CliOptions{}

	var found bool
	for _, f := range flagDefinitions(opts) {
		for _, name := range strings.Split(f.name, ",") {
			if strings.TrimSpace(name) != "tw" {
				continue
			}
			found = true
			v, ok := f.value.(*int)
			if !ok {
				t.Fatalf("-tw value is %T, want *int", f.value)
			}
			if v != &opts.TargetWorkers {
				t.Error("-tw is not bound to CliOptions.TargetWorkers")
			}
			if f.defVal != 1 {
				t.Errorf("-tw default is %v, want 1 (sequential)", f.defVal)
			}
		}
	}
	if !found {
		t.Fatal("-tw is not registered")
	}
}

func TestTargetWorkersRejectsNonPositiveValues(t *testing.T) {
	for _, n := range []int{-2, -1, 0} {
		o := &CliOptions{TargetWorkers: n}

		err := o.validateTargetWorkers()
		if err == nil {
			t.Errorf("-tw %d must be rejected", n)
			continue
		}
		if !strings.Contains(err.Error(), "tw") {
			t.Errorf("error %q should name -tw", err)
		}
	}

	if err := (&CliOptions{TargetWorkers: 1}).validateTargetWorkers(); err != nil {
		t.Errorf("-tw 1 is the default and must be accepted: %v", err)
	}
}
