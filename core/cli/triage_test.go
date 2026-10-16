package cli

// Task C5 (SPEC-unkover-gaps.md Addendum 5, Phase C): the -scan-profile triage
// preset is the registry minus the deep families, derived rather than
// hand-kept so the two lists cannot drift. These tests pin the derivation and
// the exact 18-module order the preset had before the refactor.

import (
	"slices"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/adaptive"
	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

func TestTriagePresetIsRegistryMinusDeep(t *testing.T) {
	want := make([]string, 0, len(payload.BypassModulesRegistry))
	for _, m := range payload.BypassModulesRegistry {
		if slices.Contains(adaptive.DeepModules(), m) {
			continue
		}
		want = append(want, m)
	}

	if !slices.Equal(profileTriageModules, want) {
		t.Errorf("triage preset =\n %v\nwant registry minus deep =\n %v", profileTriageModules, want)
	}
}

func TestTriagePresetExcludesDeepFamilies(t *testing.T) {
	for _, m := range adaptive.DeepModules() {
		if slices.Contains(profileTriageModules, m) {
			t.Errorf("deep family %q is in the triage preset", m)
		}
	}
	for _, m := range profileTriageModules {
		if !slices.Contains(payload.BypassModulesRegistry, m) {
			t.Errorf("triage module %q is not in the registry", m)
		}
	}
}

// TestTriagePresetOrderIsUnchanged pins the pre-Phase-C literal: 18 modules,
// dumb_check first, the five appended modules last (registry order).
func TestTriagePresetOrderIsUnchanged(t *testing.T) {
	want := []string{
		"dumb_check", "mid_paths", "end_paths", "http_methods",
		"case_substitution", "char_encode", "nginx_bypasses", "haproxy_bypasses",
		"headers_scheme", "headers_ip", "headers_port", "headers_url",
		"headers_host", "headers_hop_by_hop", "api_versions", "http10",
		"headers_method", "user_agent",
	}
	if !slices.Equal(profileTriageModules, want) {
		t.Errorf("triage preset order changed:\n got  %v\n want %v", profileTriageModules, want)
	}
}
