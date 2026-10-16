/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Task C6 (SPEC-unkover-gaps.md Addendum 5, Phase C): the README has to document
the heuristic table, its evidence and its opt-in nature. A table in the docs
rots silently when the code is extended, so this test reads the README section
and asserts every rule — its markers, its promoted modules — and every deep
family is named there. It fails when a rule is added to the code without
documenting it.
*/
package adaptive

import (
	"os"
	"strings"
	"testing"
)

// readmeAdaptiveSection returns the README part that documents -adaptive: from
// its heading to the next top-level heading.
func readmeAdaptiveSection(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile("../../../README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readme := string(raw)

	start := strings.Index(readme, "## Adaptive ordering")
	if start < 0 {
		t.Fatal("README.md has no '## Adaptive ordering' section")
	}
	rest := readme[start:]
	if end := strings.Index(rest[1:], "\n## "); end >= 0 {
		return rest[:end+1]
	}
	return rest
}

func TestReadmeDocumentsEveryRule(t *testing.T) {
	section := readmeAdaptiveSection(t)

	if len(Rules) == 0 {
		t.Fatal("Rules is empty")
	}
	for _, r := range Rules {
		if !strings.Contains(section, r.Name) {
			t.Errorf("README does not name the %q rule", r.Name)
		}
		for _, marker := range r.Markers {
			if !strings.Contains(section, marker) {
				t.Errorf("README does not document marker %q of rule %q", marker, r.Name)
			}
		}
		for _, module := range r.Promotes {
			if !strings.Contains(section, module) {
				t.Errorf("README does not document promoted module %q of rule %q", module, r.Name)
			}
		}
	}

	for _, module := range DeepModules() {
		if !strings.Contains(section, module) {
			t.Errorf("README does not document deep family %q", module)
		}
	}
}

func TestReadmeStatesTheOptInNature(t *testing.T) {
	section := readmeAdaptiveSection(t)

	for _, want := range []string{"403", "BYPASS", "Opt-in", "no extra request"} {
		if !strings.Contains(section, want) {
			t.Errorf("README adaptive section does not state %q", want)
		}
	}
}
