package tests

// Task B3 (SPEC-unkover-gaps.md Addendum 5, Phase B): which confirmed hit gets
// expanded.
//
// The decision must be:
//   * scoped to the module batch that just finished (an earlier module's hit
//     is never expanded twice, and a baseline-only cluster never expands);
//   * the top BYPASS cluster in Phase A's deterministic order, derived from
//     its representative;
//   * "nothing" for an unsupported module, a batch with no BYPASS, or an
//     out-of-range ref.

import (
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/analysis"
	"github.com/herraristotle/gobypass403/core/engine/expand"
	"github.com/herraristotle/gobypass403/core/engine/payload"
)

const decideTarget = "https://t.example/access"

const (
	decideDenyBody    = "<html>403 forbidden</html>"
	decideOKBody      = "<html>200 dashboard</html>"
	decideVariantBody = "<html>403 but a different page</html>"
)

func decideObs(status int, body, module, curl string, ref int) analysis.Observation {
	return analysis.Observation{
		Fingerprint: analysis.FingerprintFrom(status, "text/html", []byte(body),
			int64(len(body)), len(body)),
		Module:  module,
		CurlCMD: curl,
		Ref:     ref,
	}
}

// decideFixture: dumb_check denies (403), an http_methods batch finds three
// identical 200s (one BYPASS cluster, refs 1-3), an end_paths batch finds a
// 403 with a different body (VARIANT, ref 4).
func decideFixture() ([]analysis.Observation, []payload.BypassPayload) {
	obs := []analysis.Observation{
		decideObs(403, decideDenyBody, "dumb_check", "curl dumb", 0),
		decideObs(200, decideOKBody, "http_methods", "curl zz", 1),
		decideObs(200, decideOKBody, "http_methods", "curl aa", 2),
		decideObs(200, decideOKBody, "http_methods", "curl mm", 3),
		decideObs(403, decideVariantBody, "end_paths", "curl vv", 4),
	}
	uris := []string{"/access", "/access?m=1", "/access?m=2", "/access?m=3", "/access;.css"}
	reqs := make([]payload.BypassPayload, 0, len(uris))
	for i, uri := range uris {
		reqs = append(reqs, payload.BypassPayload{
			Scheme: "https", Host: "t.example", RawURI: uri,
			Method: "GET", BypassModule: obs[i].Module,
		})
	}
	return obs, reqs
}

func TestDecidePicksTopBypassFromTheCurrentBatch(t *testing.T) {
	obs, reqs := decideFixture()
	report := analysis.ClassifyObservations(decideTarget, obs)

	hit, ok := expand.Decide(expand.ModuleHTTPMethods, report, reqs, 1)
	if !ok {
		t.Fatalf("expected a hit for the http_methods batch")
	}
	// Representative is the lexicographically smallest curl ("curl aa"), so
	// the derived shape is the request with ref 2.
	if hit.RawURI != "/access?m=2" {
		t.Errorf("hit RawURI = %q, want /access?m=2", hit.RawURI)
	}
	if hit.BypassModule != expand.ModuleHTTPMethods {
		t.Errorf("hit module = %q, want %q", hit.BypassModule, expand.ModuleHTTPMethods)
	}
}

func TestDecideIgnoresHitsFromEarlierBatches(t *testing.T) {
	obs, reqs := decideFixture()
	report := analysis.ClassifyObservations(decideTarget, obs)

	// The end_paths batch (refs >= 4) has no BYPASS member: the http_methods
	// hit must not be expanded a second time.
	if _, ok := expand.Decide(expand.ModuleEndPaths, report, reqs, 4); ok {
		t.Error("a batch without its own BYPASS must not expand")
	}
}

func TestDecideNothingWhenNoBypassOrUnsupportedModule(t *testing.T) {
	obs, reqs := decideFixture()
	report := analysis.ClassifyObservations(decideTarget, obs)

	if _, ok := expand.Decide("param_manipulation", report, reqs, 1); ok {
		t.Error("unsupported module must not expand")
	}

	// VARIANT-only batch: same 403 class, different body.
	variantOnly := []analysis.Observation{
		decideObs(403, decideDenyBody, "dumb_check", "curl dumb", 0),
		decideObs(403, decideVariantBody, "end_paths", "curl v", 1),
	}
	variantReqs := []payload.BypassPayload{
		{Scheme: "https", Host: "t.example", RawURI: "/access", Method: "GET", BypassModule: "dumb_check"},
		{Scheme: "https", Host: "t.example", RawURI: "/access;.css", Method: "GET", BypassModule: "end_paths"},
	}
	variantReport := analysis.ClassifyObservations(decideTarget, variantOnly)
	if _, ok := expand.Decide(expand.ModuleEndPaths, variantReport, variantReqs, 1); ok {
		t.Error("a VARIANT-only batch must not expand")
	}

	// Out-of-range representative ref (caller passed a short refs slice).
	if _, ok := expand.Decide(expand.ModuleHTTPMethods, report, reqs[:1], 1); ok {
		t.Error("an out-of-range ref must not expand")
	}
}
