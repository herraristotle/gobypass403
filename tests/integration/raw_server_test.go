package tests

// Raw in-memory HTTP/1.1 server helpers for integration tests.
//
// The vendored fasthttp fork (pkg/fasthttp-client-1.64.0, wired via the
// go.mod replace) is intentionally client-only: it has no Server, no
// RequestCtx and no Serve. Historical integration tests were written against
// a full fasthttp server and have not compiled since the fork was adopted.
//
// These helpers restore them without touching the fork: each test's original
// handler logic becomes a func(*rawRequest) that receives the exact bytes the
// client sent (zero re-encoding, so raw-line/header-case fidelity assertions
// keep working) and returns a raw response to write back.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

// rawRequest is one client request as received on the wire.
type rawRequest struct {
	Method  string   // e.g. "GET"
	Target  string   // request-target exactly as received (path, abs-uri or authority)
	Proto   string   // e.g. "HTTP/1.1"
	Headers [][2]string
	Body    []byte
	Raw     []byte // full bytes: request line + headers + body
}

// Header returns the value of the first header with the given name
// (case-insensitive), or "" if absent.
func (r *rawRequest) Header(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

// HeaderAll returns every value for the given header name, in wire order.
func (r *rawRequest) HeaderAll(name string) []string {
	var out []string
	for _, h := range r.Headers {
		if strings.EqualFold(h[0], name) {
			out = append(out, h[1])
		}
	}
	return out
}

// readRawRequest parses one HTTP/1.x message from br, preserving the raw
// bytes it consumed.
func readRawRequest(br *bufio.Reader) (*rawRequest, error) {
	line, err := readRawLine(br)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed request line %q", line)
	}
	req := &rawRequest{
		Method: parts[0],
		Target: parts[1],
		Proto:  parts[2],
		Raw:    []byte(line),
	}
	for {
		h, err := readRawLine(br)
		if err != nil {
			return nil, err
		}
		req.Raw = append(req.Raw, h...)
		trimmed := strings.TrimRight(h, "\r\n")
		if trimmed == "" {
			break
		}
		kv := strings.SplitN(trimmed, ":", 2)
		if len(kv) != 2 {
			continue // tolerate malformed header lines; they stay in Raw
		}
		req.Headers = append(req.Headers, [2]string{kv[0], strings.TrimSpace(kv[1])})
	}

	// Body, if any.
	if strings.EqualFold(req.Header("Transfer-Encoding"), "chunked") {
		for {
			cl, err := readRawLine(br)
			if err != nil {
				return nil, err
			}
			req.Raw = append(req.Raw, cl...)
			n, err := strconv.ParseInt(strings.TrimSpace(cl), 16, 64)
			if err != nil {
				return nil, fmt.Errorf("bad chunk size %q", cl)
			}
			if n == 0 {
				// Trailer section up to blank line.
				for {
					t, err := readRawLine(br)
					if err != nil {
						return nil, err
					}
					req.Raw = append(req.Raw, t...)
					if strings.TrimRight(t, "\r\n") == "" {
						break
					}
				}
				break
			}
			buf := make([]byte, n+2) // data + CRLF
			if _, err := io.ReadFull(br, buf); err != nil {
				return nil, err
			}
			req.Raw = append(req.Raw, buf...)
			req.Body = append(req.Body, buf[:n]...)
		}
	} else if cl := req.Header("Content-Length"); cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad Content-Length %q", cl)
		}
		if n > 0 {
			body := make([]byte, n)
			if _, err := io.ReadFull(br, body); err != nil {
				return nil, err
			}
			req.Body = body
			req.Raw = append(req.Raw, body...)
		}
	}
	return req, nil
}

func readRawLine(br *bufio.Reader) (string, error) {
	s, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return s, nil
}

// rawResult is one response plus whether the server should close the
// connection after writing it.
type rawResult struct {
	Data  []byte
	Close bool
}

// rawServer reports the lifecycle of a serveRaw loop.
type rawServer struct {
	// Errs receives at most one unexpected accept-loop error. A closed
	// listener ends the loop silently, never via Errs.
	Errs <-chan error
	// Done closes when the accept loop has exited (listener closed).
	Done <-chan struct{}
}

// serveRaw serves fn on ln until ln is closed, keeping connections alive
// across requests. fn must be safe for concurrent use. ln may be a
// fasthttputil.InmemoryListener or any real net.Listener.
func serveRaw(ln net.Listener, fn func(*rawRequest) []byte) *rawServer {
	return serveRawResult(ln, func(req *rawRequest) rawResult {
		return rawResult{Data: fn(req)}
	})
}

// serveRawResult is serveRaw with per-response connection-close control.
func serveRawResult(ln net.Listener, fn func(*rawRequest) rawResult) *rawServer {
	errs := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed: normal shutdown
			}
			go serveRawConn(conn, fn, errs)
		}
	}()
	return &rawServer{Errs: errs, Done: done}
}

func serveRawConn(conn net.Conn, fn func(*rawRequest) rawResult, errs chan error) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := readRawRequest(br)
		if err != nil {
			return // client went away or listener closed
		}
		// Honor Expect: 100-continue before reading is impossible (body
		// already read), but clients in this suite do not use it; kept
		// out of scope deliberately.
		res := fn(req)
		if len(res.Data) > 0 {
			if _, err := conn.Write(res.Data); err != nil {
				return
			}
		}
		if res.Close || strings.EqualFold(req.Header("Connection"), "close") {
			return
		}
	}
}

var statusTexts = map[int]string{
	100: "Continue",
	101: "Switching Protocols",
	200: "OK",
	201: "Created",
	202: "Accepted",
	204: "No Content",
	206: "Partial Content",
	301: "Moved Permanently",
	302: "Found",
	303: "See Other",
	304: "Not Modified",
	307: "Temporary Redirect",
	308: "Permanent Redirect",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	406: "Not Acceptable",
	408: "Request Timeout",
	409: "Conflict",
	410: "Gone",
	418: "I'm a teapot",
	422: "Unprocessable Entity",
	429: "Too Many Requests",
	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
}

// rawResp builds a well-formed HTTP/1.1 response. Content-Length is added
// automatically unless headers already carry one.
func rawResp(status int, headers [][2]string, body string) []byte {
	var b strings.Builder
	reason := statusTexts[status]
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, reason)
	hasCL := false
	for _, h := range headers {
		if strings.EqualFold(h[0], "Content-Length") {
			hasCL = true
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	if !hasCL {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// rawStatus builds a bodyless response with no extra headers.
func rawStatus(status int) []byte {
	return rawResp(status, nil, "")
}

// guardedCounter is a request counter for stateful canned handlers.
type guardedCounter struct {
	mu sync.Mutex
	n  int
}

// next increments the counter and returns the new value under the lock.
func (c *guardedCounter) next() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return c.n
}
