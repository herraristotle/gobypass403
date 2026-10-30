package tests

// Raw canned-response server for benchmarks. The vendored fasthttp fork
// (pkg/fasthttp-client-1.64.0) is client-only: fasthttp.Server /
// fasthttp.RequestCtx / fasthttp.Serve do not exist, which left this package
// unable to compile. Same pattern as
// tests/unittests/engine/rawhttp/echo_server_test.go — requests are read
// byte-exactly, responses are raw bytes.

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

// rawBenchResp builds a canned HTTP/1.1 response with an exact Content-Length.
func rawBenchResp(status, contentType, body string) []byte {
	return []byte(fmt.Sprintf(
		"HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
		status, contentType, len(body), body))
}

// serveBench serves fn()'s response bytes for every request arriving on ln,
// one response per request, until the listener is closed. Only unexpected
// accept-loop errors are reported (non-blocking, capacity 1).
func serveBench(ln *fasthttputil.InmemoryListener, fn func() []byte) chan error {
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
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
					if err := readBenchRequest(br); err != nil {
						return
					}
					if _, err := c.Write(fn()); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return errCh
}

// benchServer is a minimal stand-in for fasthttp.Server at the benchmark call
// sites: Shutdown() closes the listener, which stops the accept loop.
type benchServer struct {
	ln   *fasthttputil.InmemoryListener
	stop func()
}

// Shutdown closes the listener and stops serving.
func (s *benchServer) Shutdown() { s.stop() }

// readBenchRequest reads exactly one full HTTP request (head terminated by a
// blank line, then Content-Length bytes of body, if any).
func readBenchRequest(br *bufio.Reader) error {
	var raw bytes.Buffer
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return err
		}
		raw.Write(line)
		b := raw.Bytes()
		if bytes.HasSuffix(b, []byte("\r\n\r\n")) {
			break
		}
		if len(b) >= 2 && b[len(b)-1] == '\n' && b[len(b)-2] == '\n' {
			break
		}
	}

	head := raw.Bytes()
	contentLength := 0
	for _, line := range bytes.Split(head, []byte("\n")) {
		l := strings.ToLower(strings.TrimSpace(string(line)))
		if strings.HasPrefix(l, "content-length:") {
			if v, err := strconv.Atoi(strings.TrimSpace(l[len("content-length:"):])); err == nil && v > 0 {
				contentLength = v
			}
		}
	}
	if contentLength > 0 {
		body := make([]byte, contentLength)
		if _, err := io.ReadFull(br, body); err != nil {
			return err
		}
	}
	return nil
}
