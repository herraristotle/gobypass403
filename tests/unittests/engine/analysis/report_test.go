package tests

// Task A3 (SPEC-unkover-gaps.md Addendum 5, Phase A): report rendering.
//
// Text() must be deterministic and useful: targets sorted, clusters in
// class order, member curls collapsed ("+N more identical (first: ...)"),
// and an honest footer about preview-derived fingerprints.
// JSON() must be valid, stable-fielded and machine-readable, with the
// class as a human-readable string.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
)

func TestClassString(t *testing.T) {
	cases := map[analysis.Class]string{
		analysis.ClassBypass:  "BYPASS",
		analysis.ClassVariant: "VARIANT",
		analysis.ClassDup:     "DUP",
		analysis.ClassNoise:   "NOISE",
	}
	for c, want := range cases {
		if got := c.String(); got != want {
			t.Errorf("Class(%d).String() = %q, want %q", int(c), got, want)
		}
	}
}

// reportFixture returns a one-target report: baseline 403, a 6-member
// BYPASS cluster (so collapsing is exercised), and one VARIANT.
func reportFixture() analysis.Report {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("http_methods", 200, len(okBody), okBody, "curl m1"),
		row("http_methods", 200, len(okBody), okBody, "curl m2"),
		row("http_methods", 200, len(okBody), okBody, "curl m3"),
		row("http_methods", 200, len(okBody), okBody, "curl m4"),
		row("http_methods", 200, len(okBody), okBody, "curl m5"),
		row("http_methods", 200, len(okBody), okBody, "curl m6"),
		row("end_paths", 403, len(altBody1), altBody1, "curl variant"),
	}
	return analysis.ClassifyReport(rows)
}

func TestReportTextFormatting(t *testing.T) {
	txt := reportFixture().Text()

	for _, want := range []string{
		"=== https://t.example/access ===",
		"baseline: dumb_check (status 403)",
		"x6",
		"+1 more identical (first: curl m6)",
		"preview",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("Text() missing %q\n--- output ---\n%s", want, txt)
		}
	}

	iBypass := strings.Index(txt, "BYPASS")
	iVariant := strings.Index(txt, "VARIANT")
	if iBypass < 0 || iVariant < 0 || iBypass > iVariant {
		t.Errorf("BYPASS must be rendered before VARIANT (bypass=%d variant=%d)\n%s", iBypass, iVariant, txt)
	}
	if strings.Count(txt, "=== ") != 1 {
		t.Errorf("expected exactly one target heading\n%s", txt)
	}
}

func TestReportJSONStableAndValid(t *testing.T) {
	data, err := reportFixture().JSON()
	if err != nil {
		t.Fatalf("JSON(): %v", err)
	}
	if !json.Valid(data) {
		t.Fatalf("JSON() produced invalid JSON:\n%s", data)
	}
	for _, want := range []string{`"class": "BYPASS"`, `"target_url"`, `"fingerprint"`, `"members"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("JSON() missing %q\n%s", want, data)
		}
	}

	var decoded struct {
		Targets []struct {
			TargetURL string `json:"target_url"`
			Clusters  []struct {
				Class string `json:"class"`
				Count int    `json:"count"`
			} `json:"clusters"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if len(decoded.Targets) != 1 || decoded.Targets[0].TargetURL != "https://t.example/access" {
		t.Fatalf("unexpected decoded targets: %+v", decoded.Targets)
	}
	if got := decoded.Targets[0].Clusters[0]; got.Class != "BYPASS" || got.Count != 6 {
		t.Errorf("first cluster = %+v, want BYPASS x6", got)
	}
}

func TestReportTextIsDeterministic(t *testing.T) {
	if a, b := reportFixture().Text(), reportFixture().Text(); a != b {
		t.Errorf("Text() is not deterministic")
	}
}
