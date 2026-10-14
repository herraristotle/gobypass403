package tests

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// wordlist mirror for expectations (spec: /v1../v9, /api, /api/v1../v4)
var expectedVersionPrefixes = []string{
	"/v1", "/v2", "/v3", "/v4", "/v5", "/v6", "/v7", "/v8", "/v9",
	"/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
}

// TestAPIVersionsPrefixPayloads pins the prefix-injection sub-technique.
func TestAPIVersionsPrefixPayloads(t *testing.T) {
	moduleName := "api_versions"
	targetURL := "http://example.com/admin/panel?x=1"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.GenerateAPIVersionPayloads(targetURL, moduleName)

	if len(jobs) != len(expectedVersionPrefixes) {
		t.Fatalf("Expected %d prefix payloads, got %d", len(expectedVersionPrefixes), len(jobs))
	}

	tokens := make(map[string]struct{})
	rawURIs := make(map[string]struct{})
	for _, j := range jobs {
		rawURIs[j.RawURI] = struct{}{}
		if _, dup := tokens[j.PayloadToken]; dup {
			t.Errorf("Duplicate token for RawURI %q", j.RawURI)
		}
		tokens[j.PayloadToken] = struct{}{}
		if j.Scheme != "http" || j.Host != "example.com" {
			t.Errorf("Payload %q: scheme/host not preserved: %q %q", j.RawURI, j.Scheme, j.Host)
		}
		if j.BypassModule != moduleName {
			t.Errorf("Payload %q: BypassModule = %q", j.RawURI, j.BypassModule)
		}
	}
	for _, p := range expectedVersionPrefixes {
		want := p + "/admin/panel?x=1"
		if _, ok := rawURIs[want]; !ok {
			t.Errorf("Missing prefix payload RawURI %q", want)
		}
	}
}

// TestAPIVersionsSwapPayloads pins the version-swap sub-technique and its
// identity-skip behavior.
func TestAPIVersionsSwapPayloads(t *testing.T) {
	moduleName := "api_versions"
	targetURL := "http://example.com/api/v1/users?token=abc"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.GenerateAPIVersionPayloads(targetURL, moduleName)

	// 14 prefixes + 10 swaps (v2..v9, v1.1, v2.0; v1 skipped as identity).
	if want := len(expectedVersionPrefixes) + 10; len(jobs) != want {
		t.Fatalf("Expected %d payloads, got %d", want, len(jobs))
	}

	rawURIs := make(map[string]struct{})
	for _, j := range jobs {
		rawURIs[j.RawURI] = struct{}{}
	}
	for _, sv := range []string{"v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v1.1", "v2.0"} {
		want := "/api/" + sv + "/users?token=abc"
		if _, ok := rawURIs[want]; !ok {
			t.Errorf("Missing swap payload RawURI %q", want)
		}
	}
	if _, ok := rawURIs["/api/v1/users?token=abc"]; ok {
		t.Error("Identity swap (/v1/ -> v1) should be skipped")
	}
}

// TestAPIVersionsNoSwapWithoutVersionSegment: no /vN/ in path -> no swap payloads.
func TestAPIVersionsNoSwapWithoutVersionSegment(t *testing.T) {
	moduleName := "api_versions"
	targetURL := "http://example.com/admin/settings"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.GenerateAPIVersionPayloads(targetURL, moduleName)

	if len(jobs) != len(expectedVersionPrefixes) {
		t.Errorf("Expected exactly %d payloads (prefix-only), got %d", len(expectedVersionPrefixes), len(jobs))
	}
	for _, j := range jobs {
		if !strings.HasPrefix(j.RawURI, "/v") && !strings.HasPrefix(j.RawURI, "/api/") {
			t.Errorf("Unexpected non-prefix RawURI %q", j.RawURI)
		}
	}
}

// TestAPIVersionsSpoofPrefix pins custom prefix injection + normalization.
func TestAPIVersionsSpoofPrefix(t *testing.T) {
	moduleName := "api_versions"
	targetURL := "http://example.com/admin"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
		SpoofPrefix:  "/internal,/x/,bad*prefix",
	})
	jobs := pg.GenerateAPIVersionPayloads(targetURL, moduleName)

	// 14 wordlist + 2 valid custom ("bad*prefix" has invalid chars -> dropped).
	if want := len(expectedVersionPrefixes) + 2; len(jobs) != want {
		t.Fatalf("Expected %d payloads, got %d", want, len(jobs))
	}

	rawURIs := make(map[string]struct{})
	for _, j := range jobs {
		rawURIs[j.RawURI] = struct{}{}
	}
	for _, want := range []string{"/internal/admin", "/x/admin"} {
		if _, ok := rawURIs[want]; !ok {
			t.Errorf("Missing custom prefix RawURI %q", want)
		}
	}
	for uri := range rawURIs {
		if strings.Contains(uri, "bad") {
			t.Errorf("Invalid custom prefix leaked into RawURI %q", uri)
		}
		if strings.Contains(uri, "//") {
			t.Errorf("Double slash in RawURI %q (normalization failed)", uri)
		}
	}
}

// TestAPIVersionsDispatch pins Generate() dispatch.
func TestAPIVersionsDispatch(t *testing.T) {
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    "http://example.com/admin",
		BypassModule: "api_versions",
	})
	if jobs := pg.Generate(); len(jobs) == 0 {
		t.Error("Generate() dispatch for api_versions returned no jobs")
	}
}
