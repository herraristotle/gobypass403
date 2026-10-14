/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Internal tests for CLI request flags helpers (-X/--request, --data).
*/
package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateMethodAcceptsValidHTTPTokens(t *testing.T) {
	valid := []string{"", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "M-SEARCH", "PATCH1"}
	for _, m := range valid {
		if err := validateMethod(m); err != nil {
			t.Errorf("validateMethod(%q) = unexpected error: %v", m, err)
		}
	}
}

func TestValidateMethodRejectsInvalidMethods(t *testing.T) {
	invalid := []string{
		"GE T",            // space
		"PO\nST",          // LF
		"GET\r\nX: y",     // CRLF header injection
		"GET /admin",      // request-line smuggling attempt
		"PO;ST",           // semicolon not a tchar
		"GÉT",         // non-ASCII
		"POST\t",          // tab
	}
	for _, m := range invalid {
		if err := validateMethod(m); err == nil {
			t.Errorf("validateMethod(%q) = expected error, got nil", m)
		}
	}
}

func TestResolveRequestBodyReturnsInlineDataVerbatim(t *testing.T) {
	for _, in := range []string{"", "user=admin&role=root", "line1\nline2", "{\"json\":true}"} {
		got, err := resolveRequestBody(in)
		if err != nil {
			t.Fatalf("resolveRequestBody(%q) unexpected error: %v", in, err)
		}
		if got != in {
			t.Errorf("resolveRequestBody(%q) = %q, want verbatim %q", in, got, in)
		}
	}
}

func TestResolveRequestBodyReadsFileWhenPrefixedWithAt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "body.json")
	content := `{"user":"admin","role":"root"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := resolveRequestBody("@" + path)
	if err != nil {
		t.Fatalf("resolveRequestBody(@file) unexpected error: %v", err)
	}
	if got != content {
		t.Errorf("resolveRequestBody(@file) = %q, want file contents %q", got, content)
	}
}

func TestResolveRequestBodyErrorsOnMissingFile(t *testing.T) {
	if _, err := resolveRequestBody("@/nonexistent/definitely/missing.body"); err == nil {
		t.Error("resolveRequestBody(@missing-file) = expected error, got nil")
	}
	if _, err := resolveRequestBody("@"); err == nil {
		t.Error("resolveRequestBody(@) with empty path = expected error, got nil")
	}
}

// TestNewModulesRegistered pins unKover-gap module registration so a dropped
// map entry fails loudly (SPEC-unkover-gaps.md).
func TestNewModulesRegistered(t *testing.T) {
	for _, module := range []string{"headers_hop_by_hop"} {
		if !AvailableModules[module] {
			t.Errorf("module %q not registered in AvailableModules", module)
		}
	}
}
