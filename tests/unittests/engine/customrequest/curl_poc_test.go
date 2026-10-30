package tests

import (
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
)

// TestCurlPOCIncludesMethodAndBody verifies the findings-table curl POC
// reproduces a POST finding: -X for non-GET methods and -d for bodies.
func TestCurlPOCIncludesMethodAndBody(t *testing.T) {
	bp := payload.BypassPayload{
		OriginalURL: "https://example.com/admin",
		Method:      "POST",
		Scheme:      "https",
		Host:        "example.com",
		RawURI:      "/admin",
		Body:        "user=admin&role=root",
		Headers:     []payload.Headers{{Header: "X-Test", Value: "1"}},
	}

	cmd := string(rawhttp.BuildCurlCommandPoc(bp, nil))

	if !strings.Contains(cmd, "-X POST") {
		t.Errorf("curl POC missing -X POST: %s", cmd)
	}
	if !strings.Contains(cmd, "-d 'user=admin&role=root'") {
		t.Errorf("curl POC missing -d body: %s", cmd)
	}
	if !strings.Contains(cmd, "-H 'X-Test: 1'") {
		t.Errorf("curl POC missing -H header: %s", cmd)
	}
	if !strings.Contains(cmd, "'https://example.com/admin'") {
		t.Errorf("curl POC missing URL: %s", cmd)
	}
}

// TestCurlPOCEscapesSingleQuotesInBody verifies single quotes in the body are
// escaped for safe shell copy-paste.
func TestCurlPOCEscapesSingleQuotesInBody(t *testing.T) {
	bp := payload.BypassPayload{
		Method: "POST",
		Scheme: "https",
		Host:   "example.com",
		RawURI: "/admin",
		Body:   "it's valid",
	}

	cmd := string(rawhttp.BuildCurlCommandPoc(bp, nil))

	if !strings.Contains(cmd, `-d 'it'\''s valid'`) {
		t.Errorf("curl POC body quotes not escaped: %s", cmd)
	}
}

// TestCurlPOCUnchangedForGETWithoutBody verifies default GET requests get no
// -X and no -d flags (no-flag behavior identical to previous releases).
func TestCurlPOCUnchangedForGETWithoutBody(t *testing.T) {
	bp := payload.BypassPayload{
		Method: "GET",
		Scheme: "https",
		Host:   "example.com",
		RawURI: "/admin",
	}

	cmd := string(rawhttp.BuildCurlCommandPoc(bp, nil))

	if strings.Contains(cmd, "-X") {
		t.Errorf("curl POC for GET should not contain -X: %s", cmd)
	}
	if strings.Contains(cmd, "-d") {
		t.Errorf("curl POC without body should not contain -d: %s", cmd)
	}
}
