/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Internal tests for the raw request file parser (--request-file).
*/
package cli

import (
	"strings"
	"testing"
)

const crlfRequest = "POST /admin/config/users?debug=1 HTTP/1.1\r\n" +
	"Host: backend.internal.example\r\n" +
	"X-Request-Source: burp\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 31\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	`{"user":"admin","role":"root"}`

func TestParseRawRequestFullRequest(t *testing.T) {
	pr, err := parseRawRequest(crlfRequest)
	if err != nil {
		t.Fatalf("parseRawRequest failed: %v", err)
	}

	if pr.Method != "POST" {
		t.Errorf("Method = %q, want POST", pr.Method)
	}
	if pr.RawURI != "/admin/config/users?debug=1" {
		t.Errorf("RawURI = %q, want /admin/config/users?debug=1", pr.RawURI)
	}
	if pr.Host != "backend.internal.example" {
		t.Errorf("Host = %q, want backend.internal.example", pr.Host)
	}
	if pr.Body != `{"user":"admin","role":"root"}` {
		t.Errorf("Body = %q, want JSON body", pr.Body)
	}

	got := map[string]string{}
	for _, h := range pr.Headers {
		got[h.Header] = h.Value
	}
	if got["X-Request-Source"] != "burp" {
		t.Errorf("X-Request-Source = %q, want burp", got["X-Request-Source"])
	}
	if got["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got["Content-Type"])
	}
	if got["Connection"] != "close" {
		t.Errorf("Connection = %q, want close (kept as imported header)", got["Connection"])
	}
	if _, ok := got["Host"]; ok {
		t.Error("Host must not appear in imported headers")
	}
	if _, ok := got["Content-Length"]; ok {
		t.Error("Content-Length must be dropped (recomputed by builder)")
	}
	if len(got) != 3 {
		t.Errorf("imported headers = %v, want exactly 3", got)
	}
}

func TestParseRawRequestLFOnlyParsesIdentically(t *testing.T) {
	lf := strings.ReplaceAll(crlfRequest, "\r\n", "\n")
	pr, err := parseRawRequest(lf)
	if err != nil {
		t.Fatalf("parseRawRequest(LF) failed: %v", err)
	}
	if pr.Method != "POST" || pr.Host != "backend.internal.example" ||
		pr.Body != `{"user":"admin","role":"root"}` || len(pr.Headers) != 3 {
		t.Errorf("LF parse differs from CRLF parse: %+v", pr)
	}
}

func TestParseRawRequestMinimalRequestLineOnly(t *testing.T) {
	pr, err := parseRawRequest("GET /index.html HTTP/1.1")
	if err != nil {
		t.Fatalf("parseRawRequest(minimal) failed: %v", err)
	}
	if pr.Method != "GET" || pr.RawURI != "/index.html" {
		t.Errorf("Method/RawURI = %q/%q", pr.Method, pr.RawURI)
	}
	if pr.Host != "" || pr.Body != "" || len(pr.Headers) != 0 {
		t.Errorf("expected empty host/body/headers, got %+v", pr)
	}
}

func TestParseRawRequestBodyKeptVerbatim(t *testing.T) {
	body := "line1\r\nline2 with spaces\r\n\r\ntrailing-newline\n"
	req := "POST /upload HTTP/1.1\r\nHost: h\r\n\r\n" + body
	pr, err := parseRawRequest(req)
	if err != nil {
		t.Fatalf("parseRawRequest failed: %v", err)
	}
	if pr.Body != body {
		t.Errorf("Body = %q, want verbatim %q", pr.Body, body)
	}
}

func TestParseRawRequestRejectsInvalidInputs(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"absolute-form target", "POST http://evil.com/admin HTTP/1.1\r\nHost: h\r\n\r\nbody"},
		{"method with tab", "GE\tT /x HTTP/1.1"},
		{"garbage first line", "this is not a request"},
		{"empty file", ""},
		{"header line without colon", "GET /x HTTP/1.1\r\nBadHeaderLine\r\n\r\n"},
		{"no HTTP version", "GET /x"},
		{"empty method", " /x HTTP/1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRawRequest(tc.input); err == nil {
				t.Errorf("parseRawRequest(%q) = expected error, got nil", tc.input)
			}
		})
	}
}

func TestParseRawRequestHostHeaderCaseInsensitive(t *testing.T) {
	for _, line := range []string{"HOST: example.com", "host: example.com", "Host: example.com"} {
		pr, err := parseRawRequest("GET / HTTP/1.1\r\n" + line + "\r\n\r\n")
		if err != nil {
			t.Fatalf("parseRawRequest failed: %v", err)
		}
		if pr.Host != "example.com" {
			t.Errorf("line %q: Host = %q, want example.com", line, pr.Host)
		}
		if len(pr.Headers) != 0 {
			t.Errorf("line %q: Host leaked into headers: %v", line, pr.Headers)
		}
	}
}
