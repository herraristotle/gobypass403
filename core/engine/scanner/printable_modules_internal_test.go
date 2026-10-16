package scanner

// Addendum 6 gap: the printed results table must not show the negative-control
// rows. They are stored for the offline analyzer but are not findings.

import (
	"slices"
	"testing"
)

func TestPrintableModulesDropsTheControlOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"control is dropped", "dumb_check,calibration,http_methods", []string{"dumb_check", "http_methods"}},
		{"a plain list is untouched", "dumb_check,http_methods", []string{"dumb_check", "http_methods"}},
		{"control only has nothing to print", "calibration", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := printableModules(tc.in); !slices.Equal(got, tc.want) {
				t.Errorf("printableModules(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
