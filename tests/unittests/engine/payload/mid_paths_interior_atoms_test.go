package tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
)

// Addendum 7 (interior control/delimiter atoms).
//
// end_paths already carries the ASCII control range and the delimiters, but it
// only appends them to the tail of the path. mid_paths inserts its corpus at
// every interior position (segment-start fused, segment-end fused, after each
// slash), so the gap is the *interior* insertion of those atoms — the shape a
// gateway and an application disagree about when they read a whitespace byte, a
// ';' or a '\' inside the path.

// interiorAtomDomain is the atom set from SPEC Addendum 7: ASCII controls
// %00-%1F, the ASCII punctuation/symbol set (isSpecialCharASCII), space %20 and
// DEL %7F — 66 atoms, percent-encoded uppercase.
func interiorAtomDomain() []string {
	atoms := make([]string, 0, 66)
	for b := 0x00; b <= 0x1F; b++ {
		atoms = append(atoms, fmt.Sprintf("%%%02X", b))
	}
	for _, ch := range "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" {
		atoms = append(atoms, fmt.Sprintf("%%%02X", ch))
	}
	atoms = append(atoms, "%20", "%7F")
	return atoms
}

// escapeKey canonicalises the hex of every %XX escape, because %2f and %2F
// denote the same byte and the corpus carries both spellings. Dedup against
// internal_midpaths.lst is done on this key.
func escapeKey(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			b.WriteByte('%')
			b.WriteString(strings.ToUpper(s[i+1 : i+3]))
			i += 3
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// TestMidPathsInteriorControlAtoms pins that the folded-in atoms reach the wire
// at interior positions. For /admin/config, %00 must appear fused to the end of
// the first segment and after its slash (interior), and fused to the start.
// Atoms chosen span the categories: controls %00/%01/%08, delimiters %22/'%3C',
// punctuation %7E, and DEL %7F.
func TestMidPathsInteriorControlAtoms(t *testing.T) {
	jobs := generateModule(t, "mid_paths", "https://example.com/admin/config")

	has := make(map[string]bool, len(jobs))
	for _, j := range jobs {
		has[j.RawURI] = true
	}

	for _, atom := range []string{"%00", "%01", "%08", "%22", "%3C", "%7E", "%7F"} {
		for _, want := range []string{
			"/admin" + atom + "/config",  // fused to the segment end
			"/admin/" + atom + "/config", // after the segment's slash
			"/" + atom + "admin/config",  // fused to the segment start
		} {
			if !has[want] {
				t.Errorf("mid_paths missing interior shape %q for atom %s", want, atom)
			}
		}
	}
}

// TestMidPathsAtomDomainCoveredAndDeduped enforces the "dedup against
// internal_midpaths.lst" contract on the committed corpus itself, read from the
// embedded FS so it does not depend on a user's overridable local copy: every
// atom in the 66-atom domain is present, and no line is duplicated. 49 atoms
// were appended (532 -> 581 lines).
func TestMidPathsAtomDomainCoveredAndDeduped(t *testing.T) {
	data, err := payload.DefaultPayloadsDir.ReadFile("payloads/internal_midpaths.lst")
	if err != nil {
		t.Fatalf("read embedded internal_midpaths.lst: %v", err)
	}

	covered := make(map[string]bool) // escapeKey -> a matching line exists
	exact := make(map[string]bool)   // exact line -> duplicate guard
	lines := 0
	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lines++
		if exact[line] {
			t.Errorf("internal_midpaths.lst has a duplicate line %q", line)
		}
		exact[line] = true
		covered[escapeKey(line)] = true
	}

	if lines != 581 {
		t.Errorf("internal_midpaths.lst has %d lines, want 581 (532 + 49 added atoms)", lines)
	}
	for _, atom := range interiorAtomDomain() {
		if !covered[escapeKey(atom)] {
			t.Errorf("atom %s is not inserted at any interior position", atom)
		}
	}
}

// TestMidPathsAtomsDoNotGrowUnicodeExperimental guards the no-collateral claim:
// unicode_path_experimental reads the same corpus, but its
// countSubstitutablePositions skips percent-encoded sequences and every added
// atom is a bare %XX, so the append contributes zero payloads. The pinned
// count is the module's output for /admin/config.
func TestMidPathsAtomsDoNotGrowUnicodeExperimental(t *testing.T) {
	jobs := generateModule(t, "unicode_path_experimental", "https://example.com/admin/config")
	if len(jobs) != 50101 {
		t.Errorf("unicode_path_experimental generated %d payloads, want 50101 — Addendum 7 must add none", len(jobs))
	}
}
