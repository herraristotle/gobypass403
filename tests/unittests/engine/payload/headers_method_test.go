package tests

import (
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
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

	wantCount := len(methodOverrideHeaders) * len(methodOverrideValues) // 21
	if len(jobs) != wantCount {
		t.Errorf("generated %d payloads, want %d (3 headers × 7 methods)", len(jobs), wantCount)
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

// TestHeadersMethodRegistered pins registration (append-only registry).
func TestHeadersMethodRegistered(t *testing.T) {
	last := ""
	for _, m := range payload.BypassModulesRegistry {
		last = m
	}
	if last != "headers_method" {
		t.Errorf("last registry entry = %q, want headers_method appended after http10", last)
	}
}
