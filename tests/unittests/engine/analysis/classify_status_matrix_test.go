package tests

// Status-matrix coverage for the differential classifier.
//
// Why this file exists: `statusImproves` (classify.go) is the single rule that
// decides BYPASS. Its redirect branch (`status/100 == 3`) had no test at all,
// and a live run proved it generates false positives: Cloudflare answers
// `http://<origin-ip>/.env` with a 301 to `https://billpoint.co/.env`, which
// then 403s. The classifier saw "403 baseline -> 301" and reported BYPASS.
//
// Contract pinned here:
//   * a 2xx is a confirmed BYPASS on a 4xx/5xx baseline;
//   * a 3xx is NOT a confirmed BYPASS -- a redirect is not proof of access.
//     It stays visible in the report as a VARIANT (with its curl PoC) so the
//     operator can follow it, but it is never auto-promoted to BYPASS;
//   * 4xx/5xx against a 4xx/5xx baseline is a VARIANT, never a BYPASS.

import (
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/analysis"
)

func TestClassifyStatusMatrixAgainstForbiddenBaseline(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   analysis.Class
	}{
		{"200 is a confirmed bypass", 200, "secret content served", analysis.ClassBypass},
		{"201 is a confirmed bypass", 201, "created", analysis.ClassBypass},
		{"204 empty is a confirmed bypass", 204, "", analysis.ClassBypass},
		{"301 redirect is not a confirmed bypass", 301, "", analysis.ClassVariant},
		{"302 redirect is not a confirmed bypass", 302, "", analysis.ClassVariant},
		{"307 redirect is not a confirmed bypass", 307, "", analysis.ClassVariant},
		{"404 is a denial, not a bypass", 404, "not found", analysis.ClassVariant},
		{"500 is a denial, not a bypass", 500, "server error", analysis.ClassVariant},
		{"403 different body is a variant", 403, "a different block page", analysis.ClassVariant},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows := []analysis.Row{
				row("dumb_check", 403, len(forbidden), forbidden, "curl dumb"),
				row("headers_host", tc.status, len(tc.body), tc.body, "curl probe"),
			}
			tr := analysis.Classify("https://t.example/access", rows)

			bypasses := clustersOfClass(tr, analysis.ClassBypass)
			gotBypass := len(bypasses) == 1
			wantBypass := tc.want == analysis.ClassBypass
			if gotBypass != wantBypass {
				t.Fatalf("status %d: BYPASS present = %v, want %v (clusters: %+v)",
					tc.status, gotBypass, wantBypass, tr.Clusters)
			}
			if !wantBypass {
				// It must still be surfaced somewhere, not silently dropped.
				if len(tr.Clusters) != 2 {
					t.Fatalf("status %d: want the probe kept as a 2nd cluster, got %d (%+v)",
						tc.status, len(tr.Clusters), tr.Clusters)
				}
			}
		})
	}
}

// The exact shape observed live on billpoint.co: the "bypass" is only a
// scheme redirect that lands back on the same protected resource and 403s.
// The classifier cannot follow the redirect offline, so it must not assert
// access -- it may only surface it for the operator to check.
func TestClassifySchemeRedirectBackToSameResourceIsNotBypass(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 403, len(forbidden), forbidden,
			"curl 'https://billpoint.co/.env'"),
		// http://<cf-ip>/.env  ->  301 Location: https://billpoint.co/.env
		row("headers_host", 301, 167, "301 Moved Permanently",
			"curl -H 'Host: billpoint.co' 'http://104.26.12.201/.env'"),
	}
	tr := analysis.Classify("https://billpoint.co/.env", rows)

	if got := len(clustersOfClass(tr, analysis.ClassBypass)); got != 0 {
		t.Fatalf("a scheme redirect must not be a confirmed BYPASS (got %d): %+v",
			got, clustersOfClass(tr, analysis.ClassBypass))
	}

	// The redirect must remain findable, with its PoC intact.
	variants := clustersOfClass(tr, analysis.ClassVariant)
	if len(variants) != 1 {
		t.Fatalf("want the redirect surfaced as exactly 1 VARIANT, got %d", len(variants))
	}
	if !containsCurl(variants[0], "curl -H 'Host: billpoint.co' 'http://104.26.12.201/.env'") {
		t.Errorf("redirect VARIANT must keep its curl PoC for manual follow-up")
	}
}

// Guards the direction of the fix: a success body served from a 5xx baseline
// (a broken-but-open backend) is still a bypass.
func TestClassifySuccessOverServerErrorBaselineIsBypass(t *testing.T) {
	rows := []analysis.Row{
		row("dumb_check", 503, len(forbidden), "503 unavailable", "curl dumb"),
		row("path_prefix", 200, len(okBody), okBody, "curl probe"),
	}
	tr := analysis.Classify("https://t.example/access", rows)

	if got := len(clustersOfClass(tr, analysis.ClassBypass)); got != 1 {
		t.Fatalf("2xx over a 5xx baseline must be a BYPASS, got %d (%+v)", got, tr.Clusters)
	}
}
