package tests

import (
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
)

// TestHopByHopPayloads pins the unKover `hop_by_hop` parity: for each of the
// five well-known auth headers, one payload pairing "<h>: bypass" with
// "Connection: <h>" (SPEC-unkover-gaps.md task 2).
func TestHopByHopPayloads(t *testing.T) {
	moduleName := "headers_hop_by_hop"
	targetURL := "http://example.com/admin/panel?x=1"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.GenerateHeadersHopByHopPayloads(targetURL, moduleName)

	expectedHeaders := []string{"Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "X-Access-Token"}

	if len(jobs) != len(expectedHeaders) {
		t.Fatalf("Expected %d payloads, got %d", len(expectedHeaders), len(jobs))
	}

	tokens := make(map[string]struct{})
	for i, j := range jobs {
		h := expectedHeaders[i]

		if j.RawURI != "/admin/panel?x=1" {
			t.Errorf("Payload %s: RawURI = %q, want original path+query", h, j.RawURI)
		}
		if j.Scheme != "http" || j.Host != "example.com" {
			t.Errorf("Payload %s: scheme/host not preserved: %q %q", h, j.Scheme, j.Host)
		}
		if j.BypassModule != moduleName {
			t.Errorf("Payload %s: BypassModule = %q", h, j.BypassModule)
		}
		if j.Method != "GET" {
			t.Errorf("Payload %s: Method = %q, want base method (GET)", h, j.Method)
		}

		if len(j.Headers) != 2 {
			t.Fatalf("Payload %s: expected exactly 2 headers, got %+v", h, j.Headers)
		}
		if j.Headers[0].Header != h || j.Headers[0].Value != "bypass" {
			t.Errorf("Payload %s: first header = %+v, want {%s bypass}", h, j.Headers[0], h)
		}
		if j.Headers[1].Header != "Connection" || j.Headers[1].Value != h {
			t.Errorf("Payload %s: second header = %+v, want {Connection %s}", h, j.Headers[1], h)
		}

		if _, dup := tokens[j.PayloadToken]; dup {
			t.Errorf("Duplicate payload token for %s", h)
		}
		tokens[j.PayloadToken] = struct{}{}
	}
}

// TestHopByHopDispatch pins module dispatch through the Generate() switch.
func TestHopByHopDispatch(t *testing.T) {
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    "http://example.com/admin",
		BypassModule: "headers_hop_by_hop",
	})
	if jobs := pg.Generate(); len(jobs) != 5 {
		t.Errorf("Generate() dispatch for headers_hop_by_hop returned %d jobs, want 5", len(jobs))
	}
}
