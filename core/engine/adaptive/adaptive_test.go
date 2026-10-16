/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Tests for the Phase C (adaptive-order) heuristic table: Order is a
promotion-only, deterministic permutation, and the table only names modules
that actually exist.
*/
package adaptive

import (
	"fmt"
	"slices"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// registry returns a copy of the real module registry: the order Order has to
// preserve.
func registry() []string {
	return slices.Clone(payload.BypassModulesRegistry)
}

func cloudflareFP() Fingerprint {
	return Fingerprint{
		Status:  403,
		Server:  "cloudflare",
		Headers: []string{"CF-Ray: 8f3c1a2b9d7e1234-LHR", "CF-Cache-Status: DYNAMIC"},
		Cookies: []string{"__cf_bm=abc123"},
	}
}

func TestOrderIsDeterministicForAFixedFingerprint(t *testing.T) {
	fp := cloudflareFP()

	first := Order(registry(), fp)
	second := Order(registry(), fp)
	third := Order(registry(), cloudflareFP())

	if !slices.Equal(first, second) || !slices.Equal(first, third) {
		t.Fatalf("Order is not deterministic:\n first  = %v\n second = %v\n third  = %v", first, second, third)
	}
}

func TestOrderNeverAddsOrDropsModules(t *testing.T) {
	fps := []Fingerprint{
		{},
		cloudflareFP(),
		{Server: "nginx/1.24.0"},
		{Server: "AkamaiGHost", Headers: []string{"X-Akamai-Transformed: 9"}},
		{Server: "cloudflare", Headers: []string{"X-Served-By: cache-lhr1234"}, Cookies: []string{"BIGipServerpool=1.2.3.4.80"}},
	}

	for i, fp := range fps {
		t.Run(fmt.Sprintf("fp%d", i), func(t *testing.T) {
			in := registry()
			got := Order(in, fp)
			if len(got) != len(in) {
				t.Fatalf("Order changed the module count: got %d, want %d", len(got), len(in))
			}
			if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(in))) {
				t.Fatalf("Order is not a permutation of its input:\n got  = %v\n want = %v", got, in)
			}
		})
	}
}

func TestOrderKeepsUnmatchedModulesInDefaultOrder(t *testing.T) {
	in := registry()
	got := Order(in, Fingerprint{Status: 403, Server: "totally-unknown-server/0.1"})

	if !slices.Equal(got, in) {
		t.Fatalf("unknown fingerprint changed the order:\n got  = %v\n want = %v", got, in)
	}
}

func TestOrderWithoutFingerprintIsTheDefaultOrder(t *testing.T) {
	in := registry()
	if got := Order(in, Fingerprint{}); !slices.Equal(got, in) {
		t.Fatalf("empty fingerprint changed the order:\n got  = %v\n want = %v", got, in)
	}
}

func TestOrderPromotesCloudflareModules(t *testing.T) {
	want := promoted(ruleCloudflare, registry())
	got := Order(registry(), cloudflareFP())

	if len(want) == 0 {
		t.Fatal("cloudflare rule promotes nothing: table regression")
	}
	if !slices.Equal(got[:len(want)], want) {
		t.Fatalf("cloudflare modules were not promoted to the front:\n got  = %v\n want = %v", got[:len(want)], want)
	}
	// The promoted modules must be strictly ahead of every unpromoted one.
	if idx := indexOf(got, "http_methods"); idx < len(want) {
		t.Fatalf("unmatched module http_methods moved to index %d, before the promoted block of %d", idx, len(want))
	}
}

func TestOrderPromotesNginxAndHaproxyModules(t *testing.T) {
	nginx := Order(registry(), Fingerprint{Status: 403, Server: "nginx/1.24.0"})
	wantNginx := promoted(ruleNginx, registry())
	if got := nginx[:len(wantNginx)]; !slices.Equal(got, wantNginx) {
		t.Fatalf("nginx modules were not promoted:\n got  = %v\n want = %v", got, wantNginx)
	}

	haproxy := Order(registry(), Fingerprint{Status: 403, Server: "HAProxy"})
	wantHaproxy := promoted(ruleHaproxy, registry())
	if got := haproxy[:len(wantHaproxy)]; !slices.Equal(got, wantHaproxy) {
		t.Fatalf("haproxy modules were not promoted (marker match is case-insensitive?):\n got  = %v\n want = %v", got, wantHaproxy)
	}
}

func TestOrderMatchesServerHeaderAndCookieMarkers(t *testing.T) {
	cases := []struct {
		name string
		fp   Fingerprint
		rule Rule
	}{
		{"server header", Fingerprint{Status: 403, Server: "cloudflare"}, ruleCloudflare},
		{"raw header line", Fingerprint{Status: 403, Headers: []string{"X-Served-By: cache-lhr1234"}}, ruleVarnish},
		{"cookie", Fingerprint{Status: 403, Cookies: []string{"BIGipServerpool=1.2.3.4.80"}}, ruleF5},
		{"server case-insensitive", Fingerprint{Status: 403, Server: "MICROSOFT-IIS/10.0"}, ruleIIS},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := promoted(tc.rule, registry())
			if len(want) == 0 {
				t.Fatalf("%s rule promotes nothing: table regression", tc.rule.Name)
			}
			got := Order(registry(), tc.fp)
			if !slices.Equal(got[:len(want)], want) {
				t.Fatalf("%s marker did not promote %v:\n got  = %v\n want = %v", tc.name, tc.rule.Name, got[:len(want)], want)
			}
		})
	}
}

func TestOrderUsesRuleOrderForMultipleMatches(t *testing.T) {
	// Two rules match: Cloudflare (via cf-ray) and nginx (via Server). The
	// earlier rule's block must come first, and a module promoted by both
	// rules must appear exactly once.
	fp := Fingerprint{
		Status:  403,
		Server:  "nginx",
		Headers: []string{"cf-ray: 8f3c1a2b9d7e1234-LHR"},
	}
	got := Order(registry(), fp)
	wantPrefix := append(promoted(ruleCloudflare, registry()), promotedNotIn(ruleCloudflare, ruleNginx, registry())...)

	if !slices.Equal(got[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("promotion did not follow rule order:\n got  = %v\n want = %v", got[:len(wantPrefix)], wantPrefix)
	}
	if n := countOf(got, "end_paths"); n != 1 {
		t.Fatalf("shared promoted module appeared %d times, want exactly 1", n)
	}
}

func TestRulesOnlyNameKnownModules(t *testing.T) {
	if len(Rules) == 0 {
		t.Fatal("Rules table is empty")
	}
	seen := map[string]bool{}
	for _, r := range Rules {
		if r.Name == "" {
			t.Fatal("rule with empty name")
		}
		if seen[r.Name] {
			t.Fatalf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true
		if len(r.Markers) == 0 {
			t.Fatalf("rule %q has no markers", r.Name)
		}
		if len(r.Promotes) == 0 {
			t.Fatalf("rule %q promotes nothing", r.Name)
		}
		for _, m := range r.Promotes {
			if !slices.Contains(payload.BypassModulesRegistry, m) {
				t.Fatalf("rule %q promotes unknown module %q", r.Name, m)
			}
		}
	}
}

// --- helpers ---

// promoted returns the modules a rule promotes, in rule order, filtered to
// those present in in.
func promoted(r Rule, in []string) []string {
	out := make([]string, 0, len(r.Promotes))
	for _, m := range r.Promotes {
		if slices.Contains(in, m) {
			out = append(out, m)
		}
	}
	return out
}

// promotedNotIn returns the modules second promotes that first does not.
func promotedNotIn(first, second Rule, in []string) []string {
	out := make([]string, 0, len(second.Promotes))
	for _, m := range second.Promotes {
		if slices.Contains(first.Promotes, m) {
			continue
		}
		if slices.Contains(in, m) {
			out = append(out, m)
		}
	}
	return out
}

func indexOf(mods []string, want string) int {
	for i, m := range mods {
		if m == want {
			return i
		}
	}
	return -1
}

func countOf(mods []string, want string) int {
	n := 0
	for _, m := range mods {
		if m == want {
			n++
		}
	}
	return n
}
