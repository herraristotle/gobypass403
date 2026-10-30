package tests

import (
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
)

// methodOverrideValues is the researched method-override value set from
// research-acquisition-report.md §4.1 (bup http_headers_method: GET POST
// PUT PATCH; nomore403 simpleheaders + HackTricks add DELETE HEAD OPTIONS).
var methodOverrideValues = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
}

var methodOverrideHeaders = []string{
	"X-HTTP-Method",
	"X-HTTP-Method-Override",
	"X-Method-Override",
	"X-Original-HTTP-Command",
}

// TestHeadersMethodGeneration pins the headers_method module (addendum 3,
// Phase A): every override header × every researched method value, sent on
// the ORIGINAL request-target, no other payloads.
func TestHeadersMethodGeneration(t *testing.T) {
	moduleName := "headers_method"
	targetURL := "https://example.com/admin/login?x=1"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.Generate()
	if len(jobs) == 0 {
		t.Fatal("headers_method generated no payloads")
	}

	wantCount := len(methodOverrideHeaders) * len(methodOverrideValues) // 28
	if len(jobs) != wantCount {
		t.Errorf("generated %d payloads, want %d (4 headers × 7 methods)", len(jobs), wantCount)
	}

	seen := make(map[string]bool)
	for _, j := range jobs {
		if j.BypassModule != moduleName {
			t.Errorf("payload BypassModule = %q, want %q", j.BypassModule, moduleName)
		}
		if j.RawURI != "/admin/login?x=1" {
			t.Errorf("payload RawURI = %q, want original request-target /admin/login?x=1", j.RawURI)
		}
		if len(j.Headers) != 1 {
			t.Errorf("payload has %d headers, want exactly 1 override header", len(j.Headers))
			continue
		}
		h, v := j.Headers[0].Header, j.Headers[0].Value
		isKnownHeader := false
		for _, kh := range methodOverrideHeaders {
			if h == kh {
				isKnownHeader = true
			}
		}
		if !isKnownHeader {
			t.Errorf("unexpected override header %q", h)
		}
		if !methodOverrideValues[v] {
			t.Errorf("unexpected method value %q", v)
		}
		seen[h+" "+v] = true
	}
	for _, h := range methodOverrideHeaders {
		for v := range methodOverrideValues {
			if !seen[h+" "+v] {
				t.Errorf("missing payload %s: %s", h, v)
			}
		}
	}
}

// TestHeadersMethodRegistered pins registration (append-only registry:
// after http10; later modules may append after it).
func TestHeadersMethodRegistered(t *testing.T) {
	idx := -1
	h10Idx := -1
	for i, m := range payload.BypassModulesRegistry {
		if m == "headers_method" {
			idx = i
		}
		if m == "http10" {
			h10Idx = i
		}
	}
	if idx == -1 {
		t.Fatal("module \"headers_method\" not in payload.BypassModulesRegistry")
	}
	if idx < h10Idx {
		t.Errorf("headers_method index %d must come after http10 (append-only), got http10 at %d", idx, h10Idx)
	}
}
