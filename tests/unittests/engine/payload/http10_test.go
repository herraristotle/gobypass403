package tests

import (
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
)

// http10Versions is the researched text-version set (addendum 3 Phase D,
// item 9: HackTricks protocol-version diff + bup CURL_HTTP_VERSIONS
// constrained to text request-line variants — real h2/h2c transport is
// infeasible with the HTTP/1.x-only client). Probed against the testbed:
// HTTP/1.0 (unKover parity), HTTP/2.0 accepted where 1.1 is accepted,
// HTTP/0.9 yields a version-parsing differential (400 vs 403 on nginx).
var http10Versions = []string{"HTTP/1.0", "HTTP/0.9", "HTTP/2.0"}

// TestHTTP10ModuleGeneration pins the http10 module: explicit non-default
// request-line versions (HTTP/1.0 / HTTP/0.9 / HTTP/2.0), each as a plain
// payload and a Connection: close companion (3 × 2 = 6 payloads).
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
	if len(jobs) != len(http10Versions)*2 {
		t.Errorf("generated %d payloads, want %d (3 versions × plain/conn-close)", len(jobs), len(http10Versions)*2)
	}

	seen := make(map[string]int)
	for _, j := range jobs {
		if j.BypassModule != moduleName {
			t.Errorf("payload BypassModule = %q, want %q", j.BypassModule, moduleName)
		}
		if j.RawURI != "/access/rproxy/protocol10" {
			t.Errorf("payload RawURI = %q, want /access/rproxy/protocol10", j.RawURI)
		}
		wantVersion := false
		for _, v := range http10Versions {
			if j.HTTPVersion == v {
				wantVersion = true
			}
		}
		if !wantVersion {
			t.Errorf("payload HTTPVersion = %q, want one of %v", j.HTTPVersion, http10Versions)
		}
		seen[j.HTTPVersion]++
		if len(j.Headers) == 0 {
			continue
		}
		for _, h := range j.Headers {
			if h.Header == "Connection" && strings.EqualFold(h.Value, "close") {
				seen[j.HTTPVersion+" close"]++
			}
		}
	}
	for _, v := range http10Versions {
		if seen[v] != 2 {
			t.Errorf("version %s: %d payloads, want 2 (plain + conn-close)", v, seen[v])
		}
		if seen[v+" close"] != 1 {
			t.Errorf("version %s: %d conn-close variants, want 1", v, seen[v+" close"])
		}
	}
}

// TestHTTP10CurlVersionMapping pins curl PoC flag mapping for the text
// versions: 1.0 → --http1.0 (exact), 0.9 → --http0.9, 2.0 → --http2
// (curl's closest transport flag — text-2.0 request lines are not
// reproducible in curl; -r debug-token resends are byte-exact).
func TestHTTP10CurlVersionMapping(t *testing.T) {
	for _, tc := range []struct{ version, flag string }{
		{"HTTP/1.0", "--http1.0"},
		{"HTTP/0.9", "--http0.9"},
		{"HTTP/2.0", "--http2"},
	} {
		job := payload.BypassPayload{
			Method: "GET", Scheme: "http", Host: "example.com",
			RawURI: "/admin", BypassModule: "http10", HTTPVersion: tc.version,
		}
		poc := string(rawhttp.BuildCurlCommandPoc(job, nil))
		if !strings.Contains(poc, tc.flag) {
			t.Errorf("version %s: PoC %q missing flag %q", tc.version, poc, tc.flag)
		}
		if strings.Contains(poc, "--http2.0") {
			t.Errorf("version %s: PoC %q must not contain invalid flag --http2.0", tc.version, poc)
		}
	}
}

// TestHTTP10RawRequestLineWire pins the bytes BuildRawRequest puts on the
// wire: every request line must terminate with the payload's own text
// version (HTTP/1.0 / HTTP/0.9 / HTTP/2.0), never the hardcoded HTTP/1.1
// default.
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
		if !strings.HasSuffix(firstLine, " "+bp.HTTPVersion) {
			t.Errorf("request line = %q, want suffix %q", firstLine, " "+bp.HTTPVersion)
		}
		if strings.Contains(firstLine, "HTTP/1.1") {
			t.Errorf("request line = %q, must not fall back to HTTP/1.1 default", firstLine)
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
// only — registry order is baked into debug-token module bytes: http10
// must sit after all pre-existing modules, though later modules may append
// after it).
func TestHTTP10Registered(t *testing.T) {
	idx := -1
	apiIdx := -1
	for i, m := range payload.BypassModulesRegistry {
		if m == "http10" {
			idx = i
		}
		if m == "api_versions" {
			apiIdx = i
		}
	}
	if idx == -1 {
		t.Fatal("module \"http10\" not in payload.BypassModulesRegistry")
	}
	if idx < apiIdx {
		t.Errorf("http10 index %d must come after api_versions (append-only), got api_versions at %d", idx, apiIdx)
	}
}
