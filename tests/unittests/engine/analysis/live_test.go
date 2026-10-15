package tests

// Task B1 (SPEC-unkover-gaps.md Addendum 5, Phase B): live-scan entry points.
//
// A live scan cannot retain response bodies (a param_manipulation batch is
// ~6.5k responses), so the classifier must accept already-computed
// fingerprints. These tests pin that:
//
//   * FingerprintFrom is the single hashing path (NewFingerprint delegates);
//   * ClassifyObservations produces the same classes, counts, fingerprints and
//     ordering as Classify for equivalent input (one shared core);
//   * observation-built clusters carry Refs (caller-side indices) instead of
//     duplicating members as Rows.

import (
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
)

func TestFingerprintFromMatchesRowFingerprint(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl a"),
		row("end_paths", 200, len(okBody), okBody, "curl b"),
		row("mid_paths", 403, 0, "", "curl c"),
		{ // content_length unknown -> falls back to response_body_bytes
			TargetURL: "https://t.example/access", BypassModule: "char_encode",
			StatusCode: 200, ContentLength: -1, ContentType: "Text/HTML; charset=UTF-8",
			ResponseBodyPreview: okBody, ResponseBodyBytes: len(okBody), CurlCMD: "curl d",
		},
		{ // non-UTF8 bytes must survive byte-safe normalisation
			TargetURL: "https://t.example/access", BypassModule: "char_encode",
			StatusCode: 500, ContentLength: 3, ContentType: "",
			ResponseBodyPreview: string([]byte{0xff, 0x00, 0xfe}), ResponseBodyBytes: 3, CurlCMD: "curl e",
		},
	}

	for i, r := range rows {
		got := analysis.FingerprintFrom(
			r.StatusCode, r.ContentType, []byte(r.ResponseBodyPreview),
			r.ContentLength, r.ResponseBodyBytes,
		)
		want := analysis.NewFingerprint(r)
		if got != want {
			t.Errorf("row %d: FingerprintFrom = %+v, NewFingerprint = %+v", i, got, want)
		}
	}
}

// obsFrom mirrors what the scanner will do: fingerprint each response, then
// discard the body.
func obsFrom(rows []analysis.Row) []analysis.Observation {
	obs := make([]analysis.Observation, 0, len(rows))
	for i, r := range rows {
		obs = append(obs, analysis.Observation{
			Fingerprint: analysis.FingerprintFrom(
				r.StatusCode, r.ContentType, []byte(r.ResponseBodyPreview),
				r.ContentLength, r.ResponseBodyBytes,
			),
			Module:  r.BypassModule,
			CurlCMD: r.CurlCMD,
			Ref:     i,
		})
	}
	return obs
}

func TestClassifyObservationsMatchesRowClassification(t *testing.T) {
	// Mixed batch: baseline, a 3-member BYPASS, one VARIANT, one DUP, one NOISE.
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("http_methods", 200, len(okBody), okBody, "curl m1"),
		row("http_methods", 200, len(okBody), okBody, "curl m2"),
		row("case_substitution", 200, len(okBody), okBody, "curl m3"),
		row("end_paths", 403, len(altBody1), altBody1, "curl variant"),
		row("mid_paths", 403, len(forbidden), forbidden, "curl dup"),
		row("mid_paths", 403, 0, "", "curl noise"),
	}
	const target = "https://t.example/access"

	want := analysis.Classify(target, rows)
	got := analysis.ClassifyObservations(target, obsFrom(rows))

	if got.TargetURL != want.TargetURL || got.Rows != want.Rows {
		t.Errorf("target/rows = %q/%d, want %q/%d", got.TargetURL, got.Rows, want.TargetURL, want.Rows)
	}
	if got.BaselineSource != want.BaselineSource || got.BaselineStatus != want.BaselineStatus {
		t.Errorf("baseline = %s/%d, want %s/%d",
			got.BaselineSource, got.BaselineStatus, want.BaselineSource, want.BaselineStatus)
	}
	if len(got.Clusters) != len(want.Clusters) {
		t.Fatalf("got %d clusters, want %d", len(got.Clusters), len(want.Clusters))
	}
	for i := range want.Clusters {
		w, g := want.Clusters[i], got.Clusters[i]
		if g.Class != w.Class || g.Count != w.Count || g.Fingerprint.Key() != w.Fingerprint.Key() {
			t.Errorf("cluster %d = %s/%d/%s, want %s/%d/%s",
				i, g.Class, g.Count, g.Fingerprint.Key(), w.Class, w.Count, w.Fingerprint.Key())
		}
		if g.Representative.CurlCMD != w.Representative.CurlCMD ||
			g.Representative.BypassModule != w.Representative.BypassModule {
			t.Errorf("cluster %d representative = %q/%q, want %q/%q",
				i, g.Representative.CurlCMD, g.Representative.BypassModule,
				w.Representative.CurlCMD, w.Representative.BypassModule)
		}
		if g.Representative.StatusCode != w.Representative.StatusCode {
			t.Errorf("cluster %d representative status = %d, want %d",
				i, g.Representative.StatusCode, w.Representative.StatusCode)
		}
		if len(g.Members) != 0 {
			t.Errorf("cluster %d: observation clusters must not duplicate members as Rows (got %d)", i, len(g.Members))
		}
		if len(g.Refs) != g.Count {
			t.Errorf("cluster %d: %d refs for %d members", i, len(g.Refs), g.Count)
		}
	}
}

func TestClassifyObservationsRefsPointAtMembers(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
		row("http_methods", 200, len(okBody), okBody, "curl zzz"),
		row("http_methods", 200, len(okBody), okBody, "curl aaa"),
		row("http_methods", 200, len(okBody), okBody, "curl mmm"),
	}
	got := analysis.ClassifyObservations("https://t.example/access", obsFrom(rows))

	bypasses := clustersOfClass(got, analysis.ClassBypass)
	if len(bypasses) != 1 {
		t.Fatalf("want 1 BYPASS cluster, got %d", len(bypasses))
	}
	b := bypasses[0]
	if b.Count != 3 || len(b.Refs) != 3 {
		t.Fatalf("BYPASS = %d members, %d refs; want 3/3", b.Count, len(b.Refs))
	}
	// Refs follow member (insertion) order: the three 200s are rows 1,2,3.
	if b.Refs[0] != 1 || b.Refs[1] != 2 || b.Refs[2] != 3 {
		t.Errorf("refs = %v, want [1 2 3]", b.Refs)
	}
	// Representative is the lexicographically smallest curl.
	if b.Representative.CurlCMD != "curl aaa" {
		t.Errorf("representative = %q, want %q", b.Representative.CurlCMD, "curl aaa")
	}
	if b.Representative.BypassModule != "http_methods" {
		t.Errorf("representative module = %q, want http_methods", b.Representative.BypassModule)
	}
}
