/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Fidelity tests (issue #2, phase 2, Task 6): an imported request's headers
and body must survive into the curl POC (-H/-d/-X) and the debug-token
round-trip used by -r resends. Tests only - both paths were wired in
phase 1; these pin them for imported (payload-level) headers.
*/
package tests

import (
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
)

// importedPayload mirrors what RunBypassModule produces for a --request-file
// scan: module headers first, imported request headers appended.
func importedPayload() payload.BypassPayload {
	return payload.BypassPayload{
		OriginalURL: "https://example.com/admin/config/users?debug=1",
		Method:      "POST",
		Scheme:      "https",
		Host:        "example.com",
		RawURI:      "/admin/config/users?debug=1",
		Body:        `{"user":"admin","role":"root"}`,
		Headers: []payload.Headers{
			{Header: "X-Request-Source", Value: "burp"},
			{Header: "Content-Type", Value: "application/json"},
		},
		BypassModule: "mid_paths",
	}
}

// TestCurlPOCIncludesImportedHeaders: the findings-table POC must reproduce
// an imported-request finding: -X, -d, and -H for every imported header.
func TestCurlPOCIncludesImportedHeaders(t *testing.T) {
	cmd := string(rawhttp.BuildCurlCommandPoc(importedPayload(), nil))

	if !strings.Contains(cmd, "-X POST") {
		t.Errorf("curl POC missing -X POST: %s", cmd)
	}
	if !strings.Contains(cmd, "-H 'X-Request-Source: burp'") {
		t.Errorf("curl POC missing imported -H X-Request-Source: %s", cmd)
	}
	if !strings.Contains(cmd, "-H 'Content-Type: application/json'") {
		t.Errorf("curl POC missing imported -H Content-Type: %s", cmd)
	}
	if !strings.Contains(cmd, `-d '{"user":"admin","role":"root"}'`) {
		t.Errorf("curl POC missing -d body: %s", cmd)
	}
	if !strings.Contains(cmd, "'https://example.com/admin/config/users?debug=1'") {
		t.Errorf("curl POC missing URL with file's path+query: %s", cmd)
	}
}

// TestDebugTokenRoundTripPreservesImportedHeaders: -r resends must see the
// imported headers and body - the token is the wire-of-truth for findings.
func TestDebugTokenRoundTripPreservesImportedHeaders(t *testing.T) {
	bp := importedPayload()

	token := payload.GeneratePayloadToken(bp)
	decoded, err := payload.DecodePayloadToken(token)
	if err != nil {
		t.Fatalf("DecodePayloadToken failed: %v", err)
	}

	if decoded.Method != "POST" {
		t.Errorf("Method = %q, want POST", decoded.Method)
	}
	if decoded.Body != bp.Body {
		t.Errorf("Body = %q, want %q", decoded.Body, bp.Body)
	}
	if decoded.RawURI != bp.RawURI {
		t.Errorf("RawURI = %q, want %q", decoded.RawURI, bp.RawURI)
	}
	if len(decoded.Headers) != len(bp.Headers) {
		t.Fatalf("decoded %d headers, want %d: %+v", len(decoded.Headers), len(bp.Headers), decoded.Headers)
	}
	for i, h := range bp.Headers {
		if decoded.Headers[i].Header != h.Header || decoded.Headers[i].Value != h.Value {
			t.Errorf("header %d = %+v, want %+v", i, decoded.Headers[i], h)
		}
	}
}
