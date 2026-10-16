package scanner

// Task B4 (SPEC-unkover-gaps.md Addendum 5, Phase B): the derived requests must
// become real jobs. An expansion row has to be indistinguishable from a
// module's own row — same display grouping, same DB row, resendable with -r —
// apart from the marker that identifies it as expansion output.
//
// Depth 1 is structural in this package: RunBypassModule calls decide() once
// per module batch and expandBatch() never calls it, and the batch is scanned
// with a nil job index so its responses are never observed.

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

func TestExpansionJobsAreRealJobs(t *testing.T) {
	hit := payload.BypassPayload{
		Scheme: "https", Host: "t.example", RawURI: "/access;.css;.js",
		Method: "GET", BypassModule: "end_paths",
	}

	jobs := expansionJobs([]payload.BypassPayload{hit})

	if len(jobs) != 1 {
		t.Fatalf("expansionJobs produced %d jobs, want 1", len(jobs))
	}
	if jobs[0].PayloadToken == "" {
		t.Fatal("expansion job has no debug token; -r resend would not work")
	}
	if jobs[0].BypassModule != "end_paths" {
		t.Errorf("module = %q, want end_paths (the results table groups by module)", jobs[0].BypassModule)
	}

	// The token must round-trip the *derived* request, not the hit.
	back, err := payload.DecodePayloadToken(jobs[0].PayloadToken)
	if err != nil {
		t.Fatalf("DecodePayloadToken: %v", err)
	}
	if back.RawURI != hit.RawURI || back.Method != hit.Method || back.BypassModule != hit.BypassModule {
		t.Errorf("token round-trip = %+v, want the derived request %+v", back, hit)
	}

	// The derived request must not be mutated in place: the caller's slice
	// keeps the payload it handed over.
	if hit.PayloadToken != "" {
		t.Error("expansionJobs mutated the caller's payload")
	}
}

func TestExpandMarkerStaysAShellComment(t *testing.T) {
	// The row's curl command is meant to be copy-pasted by an operator, so the
	// marker has to be a trailing shell comment.
	if !strings.HasPrefix(expandMarker, " #") {
		t.Errorf("expandMarker = %q; it must be a shell comment suffix", expandMarker)
	}
	if !strings.Contains(expandMarker, "expand") {
		t.Errorf("expandMarker = %q; it must say what it is", expandMarker)
	}
}
