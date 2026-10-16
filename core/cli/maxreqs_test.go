package cli

// Task D2 (SPEC-unkover-gaps.md Addendum 5, Phase D): the -max-reqs flag.

import (
	"strings"
	"testing"
)

func TestMaxReqsFlagIsARegisteredInt(t *testing.T) {
	opts := &CliOptions{}

	var found bool
	for _, f := range flagDefinitions(opts) {
		for _, name := range strings.Split(f.name, ",") {
			if strings.TrimSpace(name) != "max-reqs" {
				continue
			}
			found = true
			v, ok := f.value.(*int)
			if !ok {
				t.Fatalf("-max-reqs value is %T, want *int", f.value)
			}
			if v != &opts.MaxReqs {
				t.Error("-max-reqs is not bound to CliOptions.MaxReqs")
			}
			if f.defVal != 0 {
				t.Errorf("-max-reqs default is %v, want 0 (unlimited)", f.defVal)
			}
		}
	}
	if !found {
		t.Fatal("-max-reqs is not registered")
	}
}

func TestMaxReqsDefaultsToUnlimited(t *testing.T) {
	if (&CliOptions{}).MaxReqs != 0 {
		t.Error("no budget must be configured by default")
	}
}

func TestMaxReqsRejectsNegativeValues(t *testing.T) {
	o := &CliOptions{MaxReqs: -1}

	err := o.validateRequestBudget()
	if err == nil {
		t.Fatal("expected a negative -max-reqs to be rejected")
	}
	if !strings.Contains(err.Error(), "max-reqs") {
		t.Errorf("error %q should name -max-reqs", err)
	}
}
