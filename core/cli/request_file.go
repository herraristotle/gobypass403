/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package cli

import (
	"fmt"
	"strings"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
)

// parseRawRequest parses a raw HTTP request captured from a proxy or editor
// (Burp, curl -v, mitmproxy). Both CRLF and LF line endings are accepted.
// The body is kept verbatim; the request-target must be origin-form
// (leading /) - host and scheme come from -u/--url.
// Returns *rawhttp.ParsedRequest so the scanner can consume it without an
// import cycle (core/cli already imports core/engine/scanner).
func parseRawRequest(content string) (*rawhttp.ParsedRequest, error) {
	if strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("request file is empty")
	}

	// Split header section from body at the first blank line (CRLF or LF).
	headerEnd, bodyStart := -1, -1
	if i := strings.Index(content, "\r\n\r\n"); i != -1 {
		headerEnd, bodyStart = i, i+4
	}
	if j := strings.Index(content, "\n\n"); j != -1 && (headerEnd == -1 || j < headerEnd) {
		headerEnd, bodyStart = j, j+2
	}

	headerSection, body := content, ""
	if headerEnd != -1 {
		headerSection = content[:headerEnd]
		body = content[bodyStart:]
	}

	// Normalize CRLF to LF for line-based parsing of the header section only.
	lines := strings.Split(strings.ReplaceAll(headerSection, "\r\n", "\n"), "\n")
	requestLine := strings.TrimRight(lines[0], "\r")
	if strings.TrimSpace(requestLine) == "" {
		return nil, fmt.Errorf("request file has no request line")
	}

	parts := strings.Split(requestLine, " ")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed request line %q: want \"METHOD /path HTTP/x.y\"", requestLine)
	}
	method, target, version := parts[0], parts[1], parts[2]
	if method == "" {
		return nil, fmt.Errorf("malformed request line %q: empty method", requestLine)
	}
	if err := validateMethod(method); err != nil {
		return nil, fmt.Errorf("malformed request line: %v", err)
	}
	if !strings.HasPrefix(target, "/") {
		return nil, fmt.Errorf("unsupported request-target %q: only origin-form paths (starting with /) are supported, use -u to specify the host", target)
	}
	if !strings.HasPrefix(version, "HTTP/") {
		return nil, fmt.Errorf("malformed request line %q: bad HTTP version %q", requestLine, version)
	}

	pr := &rawhttp.ParsedRequest{Method: method, RawURI: target, Body: body}

	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		colon := strings.Index(line, ":")
		if colon == -1 {
			return nil, fmt.Errorf("malformed header line %q: want \"Name: value\"", line)
		}
		name := strings.TrimSpace(line[:colon])
		if name == "" {
			return nil, fmt.Errorf("malformed header line %q: empty header name", line)
		}
		value := strings.TrimSpace(line[colon+1:])
		switch {
		case strings.EqualFold(name, "Host"):
			pr.Host = value
		case strings.EqualFold(name, "Content-Length"):
			// Dropped: the request builder recomputes Content-Length from the body.
		default:
			pr.Headers = append(pr.Headers, payload.Headers{Header: name, Value: value})
		}
	}

	return pr, nil
}
