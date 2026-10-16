/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Tests for the scanner-facing helpers of Phase C: building a Fingerprint from a
scanned baseline response, and planning which deep modules an escalation still
has to run.
*/
package adaptive

import (
	"slices"
	"testing"
)

func TestNewFingerprintExtractsStatusServerHeadersAndCookies(t *testing.T) {
	fp := NewFingerprint(403, "cloudflare", []string{
		"Server: cloudflare",
		"",
		"Set-Cookie: __cf_bm=abc123; Path=/; HttpOnly; Secure",
		"CF-Ray: 8f3c1a2b9d7e1234-LHR",
	})

	if fp.Status != 403 {
		t.Errorf("Status = %d, want 403", fp.Status)
	}
	if fp.Server != "cloudflare" {
		t.Errorf("Server = %q, want cloudflare", fp.Server)
	}
	if len(fp.Headers) != 3 {
		t.Errorf("Headers = %v, want the three non-empty lines", fp.Headers)
	}
	if !slices.Contains(fp.Cookies, "__cf_bm=abc123") {
		t.Errorf("Cookies = %v, want __cf_bm=abc123 (value up to the first ;)", fp.Cookies)
	}

	// The built fingerprint must be usable by the table as-is.
	if got := Order([]string{"http_methods", "headers_ip"}, fp); got[0] != "headers_ip" {
		t.Errorf("fingerprint from a cloudflare response ordered %v, want headers_ip first", got)
	}
}

func TestNewFingerprintWithoutHeaders(t *testing.T) {
	fp := NewFingerprint(200, "", nil)
	if fp.Status != 200 || fp.Server != "" || len(fp.Headers) != 0 || len(fp.Cookies) != 0 {
		t.Errorf("empty response produced %+v, want a zero-value fingerprint with status 200", fp)
	}
	if got := Order([]string{"b_module", "a_module"}, fp); got[0] != "b_module" {
		t.Errorf("empty fingerprint reordered %v", got)
	}
}

func TestDeepModulesExceptSkipsScanned(t *testing.T) {
	if got := DeepModulesExcept(nil); !slices.Equal(got, DeepModules()) {
		t.Errorf("DeepModulesExcept(nil) = %v, want every deep module %v", got, DeepModules())
	}

	got := DeepModulesExcept([]string{"dumb_check", "path_prefix", "param_manipulation"})
	want := []string{
		"unicode_path_normalization",
		"unicode_path_truncation",
		"unicode_path_experimental",
	}
	if !slices.Equal(got, want) {
		t.Errorf("DeepModulesExcept = %v, want %v", got, want)
	}

	if got := DeepModulesExcept(DeepModules()); len(got) != 0 {
		t.Errorf("DeepModulesExcept(deep) = %v, want nothing left to run", got)
	}
}
