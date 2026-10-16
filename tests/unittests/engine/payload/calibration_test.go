package tests

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// TestCalibrationProbesAreUniqueSiblings pins the `-calibrate` negative-control
// generator (SPEC-unkover-gaps.md Addendum 6): a small constant batch of
// requests whose final path segment is a random non-existent sibling of the
// target's own segment, so the responses can only be the server's default.
func TestCalibrationProbesAreUniqueSiblings(t *testing.T) {
	const target = "http://example.com/admin/.env"
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    target,
		BypassModule: analysis.CalibrationModule,
	})

	jobs := pg.Generate()
	if len(jobs) < 2 {
		t.Fatalf("want several calibration probes, got %d", len(jobs))
	}

	seen := make(map[string]bool)
	for _, j := range jobs {
		if j.BypassModule != analysis.CalibrationModule {
			t.Errorf("probe module = %q, want %q", j.BypassModule, analysis.CalibrationModule)
		}
		if !strings.HasPrefix(j.RawURI, "/admin/") {
			t.Errorf("probe %q must be a sibling of the target's directory /admin/", j.RawURI)
		}
		if j.RawURI == "/admin/.env" {
			t.Errorf("probe must not re-request the target itself")
		}
		token := strings.TrimPrefix(j.RawURI, "/admin/")
		if token == "" || strings.ContainsAny(token, "/.?") {
			t.Errorf("probe %q must end in a plain random token", j.RawURI)
		}
		if seen[j.RawURI] {
			t.Errorf("probe %q repeated; tokens must be unique", j.RawURI)
		}
		seen[j.RawURI] = true
		if j.Scheme != "http" || j.Host != "example.com" {
			t.Errorf("probe scheme/host not preserved: %q %q", j.Scheme, j.Host)
		}
	}
}

// TestCalibrationProbeDirectoryRoot covers paths with no directory component:
// the probe belongs at the root, not nested under the file name.
func TestCalibrationProbeDirectoryRoot(t *testing.T) {
	for _, target := range []string{"http://example.com/.env", "http://example.com/a", "http://example.com/"} {
		pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
			TargetURL:    target,
			BypassModule: analysis.CalibrationModule,
		})
		for _, j := range pg.Generate() {
			if strings.Count(j.RawURI, "/") != 1 || !strings.HasPrefix(j.RawURI, "/") {
				t.Errorf("%s: probe %q must be a single segment at the root", target, j.RawURI)
			}
		}
	}
}
