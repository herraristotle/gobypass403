package cli

// Task D4 (SPEC-unkover-gaps.md Addendum 5, Phase D): the -resume flag.

import (
	"strings"
	"testing"
)

func TestResumeFlagIsARegisteredBool(t *testing.T) {
	opts := &CliOptions{}

	var found bool
	for _, f := range flagDefinitions(opts) {
		for _, name := range strings.Split(f.name, ",") {
			if strings.TrimSpace(name) != "resume" {
				continue
			}
			found = true
			v, ok := f.value.(*bool)
			if !ok {
				t.Fatalf("-resume value is %T, want *bool", f.value)
			}
			if v != &opts.Resume {
				t.Error("-resume is not bound to CliOptions.Resume")
			}
			if f.defVal != false {
				t.Errorf("-resume default is %v, want false", f.defVal)
			}
		}
	}
	if !found {
		t.Fatal("-resume is not registered")
	}
}

func TestResumeDefaultsToOff(t *testing.T) {
	if (&CliOptions{}).Resume {
		t.Error("resuming must be opt-in")
	}
}

func TestAnalyzeRejectsResume(t *testing.T) {
	o := &CliOptions{AnalyzeDB: "results.db", Resume: true}

	err := o.validateAnalyze()
	if err == nil {
		t.Fatal("expected -analyze with -resume to be rejected")
	}
	if !strings.Contains(err.Error(), "resume") {
		t.Errorf("error %q should name -resume", err)
	}
}
