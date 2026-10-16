package cli

// Task C4 (SPEC-unkover-gaps.md Addendum 5, Phase C): the -adaptive flag.

import (
	"strings"
	"testing"
)

func TestAdaptiveFlagIsARegisteredBool(t *testing.T) {
	opts := &CliOptions{}

	var found bool
	for _, f := range flagDefinitions(opts) {
		for _, name := range strings.Split(f.name, ",") {
			if strings.TrimSpace(name) != "adaptive" {
				continue
			}
			found = true
			v, ok := f.value.(*bool)
			if !ok {
				t.Fatalf("-adaptive value is %T, want *bool", f.value)
			}
			if v != &opts.Adaptive {
				t.Error("-adaptive is not bound to CliOptions.Adaptive")
			}
			if f.defVal != false {
				t.Errorf("-adaptive default is %v, want false", f.defVal)
			}
			if !strings.Contains(f.usage, "off by default") {
				t.Errorf("-adaptive usage %q should state it is opt-in", f.usage)
			}
		}
	}
	if !found {
		t.Fatal("-adaptive is not registered")
	}
}

func TestAdaptiveDefaultsToOff(t *testing.T) {
	if (&CliOptions{}).Adaptive {
		t.Error("adaptive ordering must be opt-in")
	}
}

func TestAnalyzeRejectsAdaptive(t *testing.T) {
	o := &CliOptions{AnalyzeDB: "results.db", Adaptive: true}

	err := o.validateAnalyze()
	if err == nil {
		t.Fatal("expected -analyze with -adaptive to be rejected")
	}
	if !strings.Contains(err.Error(), "adaptive") {
		t.Errorf("error %q should name -adaptive", err)
	}
}
