package tests

// Minimal raw HTTP server helpers for the rawhttp request-builder tests.
//
// The vendored fasthttp fork (pkg/fasthttp-client-1.64.0) is client-only: it
// provides fasthttp.Request/Response and fasthttputil.InmemoryListener but no
// fasthttp.Server/fasthttp.RequestCtx. The tests in this package originally
// ran echo/canned-response servers on the upstream Server API, which left the
// whole package unable to compile. These helpers restore that capability with
// a small raw-socket server: requests are read byte-exactly off the wire and
// responses are written as raw bytes, which is strictly better for tests that
// assert byte-level request fidelity (no server-side normalization at all).

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/herraristotle/fasthttp/fasthttputil"
)

// rawRequest is a minimal parse of one HTTP/1.x request read off the wire.
type rawRequest struct {
	raw        []byte            // the full raw request (head + body) as received
	method     string            // request-line method
	target     string            // request-line request-target, exactly as sent
	version    string            // request-line protocol version
	requestURI string            // path+query portion of target (absolute-form stripped)
	headers    map[string]string // lower-cased header name -> value (first occurrence wins)
	body       []byte            // request body (per Content-Length)
}

// header returns the first value for a lower-cased header name.
func (r *rawRequest) header(name string) string {
	return r.headers[name]
}

// readRawRequest reads exactly one full HTTP request (head terminated by a
// blank line, then Content-Length bytes of body, if any) from br.
func readRawRequest(br *bufio.Reader) (*rawRequest, error) {
	var raw bytes.Buffer

	// Read the head line by line until the terminating blank line.
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		raw.Write(line)
		b := raw.Bytes()
		if len(b) >= 4 && bytes.HasSuffix(b, []byte("\r\n\r\n")) {
			break
		}
		if len(b) >= 2 && b[len(b)-2] == '\n' && b[len(b)-1] == '\n' {
			break
		}
	}

	head := raw.Bytes()

	// Request line: METHOD SP TARGET SP VERSION.
	lineEnd := bytes.IndexByte(head, '\n')
	if lineEnd < 0 {
		return nil, fmt.Errorf("malformed request: no request line")
	}
	requestLine := strings.TrimRight(string(head[:lineEnd]), "\r\n")
	fields := strings.SplitN(requestLine, " ", 3)
	if len(fields) < 2 {
		return nil, fmt.Errorf("malformed request line: %q", requestLine)
	}
	req := &rawRequest{
		raw:     head,
		method:  fields[0],
		target:  fields[1],
		headers: make(map[string]string),
	}
	if len(fields) == 3 {
		req.version = fields[2]
	}

	// Headers.
	rest := head[lineEnd+1:]
	for len(rest) > 0 {
		var line []byte
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line = rest[:i+1]
			rest = rest[i+1:]
		} else {
			line = rest
			rest = nil
		}
		trimmed := strings.TrimRight(string(line), "\r\n")
		if trimmed == "" {
			break
		}
		if i := strings.IndexByte(trimmed, ':'); i > 0 {
			name := strings.ToLower(strings.TrimSpace(trimmed[:i]))
			value := strings.TrimSpace(trimmed[i+1:])
			if _, exists := req.headers[name]; !exists {
				req.headers[name] = value
			}
		}
	}

	// Body, per Content-Length.
	if cl := req.header("content-length"); cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad Content-Length: %q", cl)
		}
		if n > 0 {
			body := make([]byte, n)
			if _, err := io.ReadFull(br, body); err != nil {
				return nil, err
			}
			req.body = body
			raw.Write(body)
			req.raw = raw.Bytes()
		}
	}

	// requestURI: strip scheme://authority from absolute-form targets.
	req.requestURI = req.target
	if strings.HasPrefix(req.target, "http://") || strings.HasPrefix(req.target, "https://") {
		schemeEnd := strings.Index(req.target, "://")
		after := req.target[schemeEnd+3:]
		if slash := strings.IndexByte(after, '/'); slash >= 0 {
			req.requestURI = after[slash:]
		} else {
			req.requestURI = "/"
		}
	}

	return req, nil
}

// respFn produces the raw response bytes for one parsed request.
type respFn func(*rawRequest) []byte

// serveInmemory starts a raw HTTP server on an InmemoryListener. Every
// connection may carry multiple keep-alive requests; each request is answered
// with respFn's bytes. Only unexpected accept-loop errors are reported on the
// returned channel — normal listener shutdown is silent.
func serveInmemory(ln *fasthttputil.InmemoryListener, fn respFn) chan error {
	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "closed") {
					select {
					case errCh <- err:
					default:
					}
				}
				return
			}
			go serveConn(conn, fn)
		}
	}()
	return errCh
}

// serveConn reads requests from conn until EOF/timeout and answers each with
// fn's response bytes.
func serveConn(conn net.Conn, fn respFn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		req, err := readRawRequest(br)
		if err != nil {
			return // EOF, deadline or listener shutdown — all expected
		}
		if _, err := conn.Write(fn(req)); err != nil {
			return
		}
	}
}

// rawResponse builds a well-formed HTTP/1.1 200 response.
func rawResponse(contentType, body string) []byte {
	return []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
		contentType, len(body), body))
}

// echoRespFn answers with a diagnostic echo of the raw request as received —
// the contract the request-builder tests were written against (raw request
// dump + requestURI/body summary).
func echoRespFn(req *rawRequest) []byte {
	body := fmt.Sprintf("Raw request is:\n==>\n%s\n<==\nrequestURI=%s, body=%s",
		req.raw, req.requestURI, req.body)
	return rawResponse("text/html", body)
}

// cannedRespFn serves the fixed responses TestResponseProcessingWithSpacedHeaders
// asserts against, selected by the X-Test-Case request header — the same
// responses the original fasthttp.Server handler produced, now as raw bytes.
func cannedRespFn(req *rawRequest) []byte {
	switch req.header("x-test-case") {
	case "content-disposition":
		body := "PDF content with special chars: áéíóú"
		return []byte(fmt.Sprintf(
			"HTTP/1.1 200 OK\r\n"+
				"Content-Disposition: attachment; filename=\"test file.pdf\"\r\n"+
				"Content-Type: application/pdf\r\n"+
				"Content-Length: %d\r\n\r\n%s",
			len(body), body))
	case "csp-header":
		body := "<html><head><title>Test Page</title></head><body>Test content with spaces and special chars: áéíóú</body></html>"
		return []byte(fmt.Sprintf(
			"HTTP/1.1 200 OK\r\n"+
				"Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://example.com\r\n"+
				"Content-Type: text/html; charset=utf-8\r\n"+
				"Content-Length: %d\r\n\r\n%s",
			len(body), body))
	case "malformed-response":
		// Deliberately unparseable: no status line, no headers.
		return []byte("nction() {\n\treturn this.href")
	default:
		return rawResponse("text/plain", "")
	}
}
