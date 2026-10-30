/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Internal tests for the -scan-profile preset (SPEC-unkover-gaps.md
Addendum 4): triage-first workflow — a curated high-signal module set
for first-pass scans, full enumeration only on confirmed targets.
*/
package cli

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
)

// profileTriageWant is the Addendum-4 triage set in BypassModulesRegistry
// order: every registry module except the deep families (path_prefix,
// unicode_path_*, param_manipulation).
var profileTriageWant = []string{
	"dumb_check",
	"mid_paths",
	"end_paths",
	"http_methods",
	"case_substitution",
	"char_encode",
	"nginx_bypasses",
	"haproxy_bypasses",
	"headers_scheme",
	"headers_ip",
	"headers_port",
	"headers_url",
	"headers_host",
	"headers_hop_by_hop",
	"api_versions",
	"http10",
	"headers_method",
	"user_agent",
}

// resolveModuleList runs the same setDefaults+validateModule pipeline
// parseFlags uses, and returns the final module list.
func resolveModuleList(t *testing.T, o *CliOptions) []string {
	t.Helper()
	o.setDefaults()
	if err := o.validateModule(); err != nil {
		t.Fatalf("validateModule: %v", err)
	}
	return strings.Split(o.Module, ",")
}

func TestScanProfileTriageResolvesRegistryOrderedSet(t *testing.T) {
	o := &CliOptions{ScanProfile: "triage"}
	got := resolveModuleList(t, o)
	if !slices.Equal(got, profileTriageWant) {
		t.Errorf("triage module set mismatch\n got: %v\nwant: %v", got, profileTriageWant)
	}
}

func TestScanProfileDefaultKeepsFullBehavior(t *testing.T) {
	// No -scan-profile, no -m: must resolve to every registry module
	// (default behavior byte-identical to before the flag existed).
	// "all" expands via map iteration, so compare as sets.
	o := &CliOptions{}
	got := resolveModuleList(t, o)
	want := slices.Clone(payload.BypassModulesRegistry)
	slices.Sort(got)
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("default module set mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestScanProfileExplicitModuleWinsOverTriage(t *testing.T) {
	// moduleSet mimics parseFlags' flag.Visit recording of -m.
	o := &CliOptions{ScanProfile: "triage", Module: "headers_ip", moduleSet: true}
	got := resolveModuleList(t, o)
	want := []string{"dumb_check", "headers_ip"}
	if !slices.Equal(got, want) {
		t.Errorf("explicit -m must win over profile\n got: %v\nwant: %v", got, want)
	}
}

func TestScanProfileExcludeSubtractsFromTriage(t *testing.T) {
	o := &CliOptions{ScanProfile: "triage", ExcludeModule: "char_encode"}
	got := resolveModuleList(t, o)
	want := slices.Clone(profileTriageWant)
	want = slices.DeleteFunc(want, func(m string) bool { return m == "char_encode" })
	if !slices.Equal(got, want) {
		t.Errorf("-em must subtract from the profile set\n got: %v\nwant: %v", got, want)
	}
}

func TestScanProfileRejectsUnknownValue(t *testing.T) {
	o := &CliOptions{ScanProfile: "quick"}
	o.setDefaults()
	if err := o.validate(); err == nil {
		t.Fatalf("expected error for -scan-profile quick, got nil")
	} else if !strings.Contains(err.Error(), "scan-profile") {
		t.Errorf("error should mention the flag: %v", err)
	}
}

func TestScanProfileTriageExcludesDeepFamilies(t *testing.T) {
	o := &CliOptions{ScanProfile: "triage"}
	got := resolveModuleList(t, o)
	for _, deep := range []string{
		"path_prefix",
		"unicode_path_normalization",
		"unicode_path_truncation",
		"unicode_path_experimental",
		"param_manipulation",
	} {
		if slices.Contains(got, deep) {
			t.Errorf("triage set must defer deep family %q", deep)
		}
	}
}
