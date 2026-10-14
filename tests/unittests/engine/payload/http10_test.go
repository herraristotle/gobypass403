package tests

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
)

// TestHTTP10ModuleGeneration pins the http10 module (spec addendum 2B):
// it must generate payloads carrying an explicit HTTP/1.0 request-line
// version, including an optional Connection: close variant.
func TestHTTP10ModuleGeneration(t *testing.T) {
	moduleName := "http10"
	targetURL := "http://403.brutelogic.net:8081/access/rproxy/protocol10"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.Generate()
	if len(jobs) == 0 {
		t.Fatal("http10 module generated no payloads")
	}

	plain, closeVariant := false, false
	for _, j := range jobs {
		if j.BypassModule != moduleName {
			t.Errorf("payload BypassModule = %q, want %q", j.BypassModule, moduleName)
		}
		if j.RawURI != "/access/rproxy/protocol10" {
			t.Errorf("payload RawURI = %q, want /access/rproxy/protocol10", j.RawURI)
		}
		if j.HTTPVersion != "HTTP/1.0" {
			t.Errorf("payload HTTPVersion = %q, want HTTP/1.0", j.HTTPVersion)
		}
		if len(j.Headers) == 0 {
			plain = true
		}
		for _, h := range j.Headers {
			if h.Header == "Connection" && strings.EqualFold(h.Value, "close") {
				closeVariant = true
			}
		}
	}
	if !plain {
		t.Error("missing plain HTTP/1.0 payload (no headers)")
	}
	if !closeVariant {
		t.Error("missing HTTP/1.0 + Connection: close variant")
	}
}

// TestHTTP10RawRequestLineWire pins the bytes BuildRawRequest puts on the
// wire: the request line must terminate with HTTP/1.0, not the hardcoded
// HTTP/1.1 default.
func TestHTTP10RawRequestLineWire(t *testing.T) {
	moduleName := "http10"
	targetURL := "http://example.com/access/rproxy/protocol10"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.Generate()
	if len(jobs) == 0 {
		t.Fatal("http10 module generated no payloads")
	}

	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())
	for _, bp := range jobs {
		bb, _ := rawhttp.BuildRawRequest(client, bp)
		raw := string(bb.B)
		firstLine := raw[:strings.Index(raw, "\r\n")]
		if !strings.HasSuffix(firstLine, " HTTP/1.0") {
			t.Errorf("request line = %q, want suffix \" HTTP/1.0\"", firstLine)
		}
	}
}

// TestDefaultModulePayloadsRemainHTTP11 pins that only the http10 module
// sets HTTPVersion: every other module's payloads keep the empty version
// so BuildRawRequest's HTTP/1.1 default is untouched.
func TestDefaultModulePayloadsRemainHTTP11(t *testing.T) {
	for _, moduleName := range []string{"end_paths", "headers_ip", "http_methods"} {
		pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
			TargetURL:    "http://example.com/admin",
			BypassModule: moduleName,
		})
		jobs := pg.Generate()
		if len(jobs) == 0 {
			t.Fatalf("%s generated no payloads", moduleName)
		}
		for _, j := range jobs {
			if j.HTTPVersion != "" {
				t.Errorf("%s payload has HTTPVersion %q, want empty (HTTP/1.1 default)", moduleName, j.HTTPVersion)
			}
		}
	}
}

// TestHTTP10TokenRoundTrip pins debug-token fidelity for the new optional
// field: HTTPVersion must survive encode/decode for -r resend, and tokens
// without it must decode to empty (backward compatible).
func TestHTTP10TokenRoundTrip(t *testing.T) {
	withVersion := payload.BypassPayload{
		OriginalURL:  "http://example.com/x",
		Scheme:       "http",
		Host:         "example.com",
		Method:       "GET",
		RawURI:       "/x",
		BypassModule: "http10",
		HTTPVersion:  "HTTP/1.0",
		Headers:      []payload.Headers{{Header: "Connection", Value: "close"}},
	}
	withVersion.PayloadToken = payload.GeneratePayloadToken(withVersion)
	decoded, err := payload.DecodePayloadToken(withVersion.PayloadToken)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.HTTPVersion != "HTTP/1.0" {
		t.Errorf("decoded HTTPVersion = %q, want HTTP/1.0", decoded.HTTPVersion)
	}
	if decoded.RawURI != "/x" || decoded.Method != "GET" || len(decoded.Headers) != 1 {
		t.Errorf("decoded payload corrupted: %+v", decoded)
	}

	withoutVersion := payload.BypassPayload{
		Scheme:       "http",
		Host:         "example.com",
		Method:       "GET",
		RawURI:       "/y",
		BypassModule: "end_paths",
	}
	withoutVersion.PayloadToken = payload.GeneratePayloadToken(withoutVersion)
	decoded2, err := payload.DecodePayloadToken(withoutVersion.PayloadToken)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded2.HTTPVersion != "" {
		t.Errorf("decoded HTTPVersion = %q for default payload, want empty", decoded2.HTTPVersion)
	}
}

// TestHTTP10CurlPOC pins that the rendered curl reproduction carries
// --http1.0 so a human (or -r tooling) replays the exact protocol.
func TestHTTP10CurlPOC(t *testing.T) {
	bp := payload.BypassPayload{
		Method:       "GET",
		RawURI:       "/access/rproxy/protocol10",
		BypassModule: "http10",
		HTTPVersion:  "HTTP/1.0",
	}
	cmd := string(rawhttp.BuildCurlCommandPoc(bp, nil))
	if !strings.Contains(cmd, "--http1.0") {
		t.Errorf("curl POC missing --http1.0: %s", cmd)
	}
	// default payload must NOT get the flag
	bp2 := payload.BypassPayload{Method: "GET", RawURI: "/x", BypassModule: "end_paths"}
	cmd2 := string(rawhttp.BuildCurlCommandPoc(bp2, nil))
	if strings.Contains(cmd2, "--http1.0") {
		t.Errorf("default curl POC must not carry --http1.0: %s", cmd2)
	}
}

// TestHTTP10Registered pins registration in BypassModulesRegistry (append
// only — registry order is baked into debug-token module bytes).
func TestHTTP10Registered(t *testing.T) {
	found := false
	lastNonDefault := ""
	for _, m := range payload.BypassModulesRegistry {
		if m == "http10" {
			found = true
		}
		lastNonDefault = m
	}
	if !found {
		t.Fatal("module \"http10\" not in payload.BypassModulesRegistry")
	}
	if lastNonDefault != "http10" {
		t.Errorf("http10 must be appended last in registry, last entry = %q", lastNonDefault)
	}
}
