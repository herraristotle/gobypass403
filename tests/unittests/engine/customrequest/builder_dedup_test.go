/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Builder dedup guards (issue #2, phase 2, Task 5): payload-level (imported)
Host/Connection/Content-Length headers must not produce duplicate lines
alongside the builder's auto-added ones. The guard pre-exists for the
headers_host module; these tests pin it for --request-file imported headers.
*/
package tests

import (
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
)

// buildRaw builds a raw request for the payload and returns it as a string.
func buildRaw(t *testing.T, bp payload.BypassPayload) string {
	t.Helper()
	httpClient := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())
	bb, _ := rawhttp.BuildRawRequest(httpClient, bp)
	return string(bb.B)
}

// TestBuilderDedupImportedConnection: an imported Connection header must be
// emitted exactly once - no auto keep-alive/close line next to it.
func TestBuilderDedupImportedConnection(t *testing.T) {
	for _, connValue := range []string{"close", "keep-alive"} {
		bp := payload.BypassPayload{
			Method: "POST",
			Scheme: "https",
			Host:   "example.com",
			RawURI: "/admin",
			Body:   "a=b",
			Headers: []payload.Headers{
				{Header: "X-Imported", Value: "1"},
				{Header: "Connection", Value: connValue},
			},
		}
		raw := buildRaw(t, bp)

		if c := strings.Count(raw, "Connection: "+connValue); c != 1 {
			t.Errorf("Connection %q appears %d times, want 1:\n%s", connValue, c, raw)
		}
		if connValue == "close" && strings.Contains(raw, "Connection: keep-alive") {
			t.Errorf("auto keep-alive emitted next to imported close:\n%s", raw)
		}
		if connValue == "keep-alive" && strings.Contains(raw, "Connection: close") {
			t.Errorf("auto close emitted next to imported keep-alive:\n%s", raw)
		}
		if !strings.Contains(raw, "X-Imported: 1\r\n") {
			t.Errorf("imported header missing:\n%s", raw)
		}
		if !strings.Contains(raw, "Content-Length: 3\r\n") {
			t.Errorf("auto Content-Length missing:\n%s", raw)
		}
	}
}

// TestBuilderDedupPayloadLevelHost: a payload-level Host header (as generated
// by headers_host and carried by imported requests) suppresses the auto Host.
func TestBuilderDedupPayloadLevelHost(t *testing.T) {
	bp := payload.BypassPayload{
		Method: "GET",
		Scheme: "https",
		Host:   "example.com",
		RawURI: "/admin",
		Headers: []payload.Headers{
			{Header: "Host", Value: "spoofed.example"},
		},
	}
	raw := buildRaw(t, bp)

	if c := strings.Count(raw, "Host: "); c != 1 {
		t.Errorf("Host line appears %d times, want 1:\n%s", c, raw)
	}
	if !strings.Contains(raw, "Host: spoofed.example\r\n") {
		t.Errorf("payload-level Host value lost:\n%s", raw)
	}
	if strings.Contains(raw, "Host: example.com") {
		t.Errorf("auto Host emitted next to payload-level Host:\n%s", raw)
	}
}

// TestBuilderDedupImportedContentLengthIsDroppedAtParse simulates the parse
// contract: imported Content-Length never reaches the builder (dropped at
// parse time), so auto CL from the body is always the single source.
// If a Content-Length payload header does reach the builder (e.g. module-
// generated), it must appear exactly once with no auto duplicate.
func TestBuilderDedupImportedContentLengthIsDroppedAtParse(t *testing.T) {
	bp := payload.BypassPayload{
		Method: "POST",
		Scheme: "https",
		Host:   "example.com",
		RawURI: "/upload",
		Body:   "hello",
		Headers: []payload.Headers{
			{Header: "Content-Length", Value: "999"},
		},
	}
	raw := buildRaw(t, bp)

	if c := strings.Count(raw, "Content-Length: "); c != 1 {
		t.Errorf("Content-Length appears %d times, want 1:\n%s", c, raw)
	}
	if !strings.Contains(raw, "Content-Length: 999\r\n") {
		t.Errorf("payload-level Content-Length value lost:\n%s", raw)
	}
	if strings.Contains(raw, "Content-Length: 5") {
		t.Errorf("auto CL emitted next to payload-level CL:\n%s", raw)
	}
}
