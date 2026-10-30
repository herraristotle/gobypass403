package tests

import (
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
)

// TestDebugTokenRoundTripPreservesBody is a regression guard: the debug token
// format must carry request bodies so -r resends reproduce POST findings.
func TestDebugTokenRoundTripPreservesBody(t *testing.T) {
	cases := []struct {
		name   string
		method string
		body   string
	}{
		{"POST with form body", "POST", "user=admin&role=root"},
		{"POST with JSON body", "POST", `{"user":"admin"}`},
		{"PUT with empty body", "PUT", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bp := payload.BypassPayload{
				OriginalURL: "https://example.com/admin",
				Method:      tc.method,
				Scheme:      "https",
				Host:        "example.com",
				RawURI:      "/admin",
				Body:        tc.body,
				Headers:     []payload.Headers{{Header: "X-Test", Value: "1"}},
				BypassModule: "dumb_check",
			}

			token := payload.GeneratePayloadToken(bp)
			decoded, err := payload.DecodePayloadToken(token)
			if err != nil {
				t.Fatalf("DecodePayloadToken failed: %v", err)
			}

			if decoded.Method != tc.method {
				t.Errorf("Method = %q, want %q", decoded.Method, tc.method)
			}
			if decoded.Body != tc.body {
				t.Errorf("Body = %q, want %q", decoded.Body, tc.body)
			}
			if decoded.RawURI != bp.RawURI {
				t.Errorf("RawURI = %q, want %q", decoded.RawURI, bp.RawURI)
			}
		})
	}
}
