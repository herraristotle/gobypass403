/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Wire round-trip tests for --request-file (issue #2, phase 2):
a ParsedRequest must drive Scanner.RunBypassModule end-to-end - file
method/headers/body/Host on the wire, variants from the file's path,
and the -u URL losing to the file on both host and path.
*/
package tests

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
	"github.com/herraristotle/gobypass403/core/engine/scanner"
)

// wireRequest is a raw request captured by startWireServer.
type wireRequest struct {
	URI         string
	FullRequest string
}

// startWireServer accepts TCP connections, records raw requests, and replies
// with a minimal 200 OK so the client does not hang.
func startWireServer(t *testing.T, ch chan<- wireRequest) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start wire server: %v", err)
	}
	serverAddr := listener.Addr().String()

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil || strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				handleWireConnection(t, c, ch)
			}(conn)
		}
	}()

	stop := func() {
		cancel()
		wg.Wait()
	}
	return serverAddr, stop
}

func handleWireConnection(t *testing.T, conn net.Conn, ch chan<- wireRequest) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)

	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	var sb strings.Builder
	sb.WriteString(requestLine)

	uri := ""
	if parts := strings.Split(strings.TrimSpace(requestLine), " "); len(parts) >= 2 {
		uri = parts[1]
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return
		}
		sb.WriteString(line)
		if line == "\r\n" || line == "\n" || err == io.EOF {
			break
		}
	}

	// Small body read; sufficient for these tests.
	bodyBuf := make([]byte, 8192)
	if n, _ := reader.Read(bodyBuf); n > 0 {
		sb.Write(bodyBuf[:n])
	}

	select {
	case ch <- wireRequest{URI: uri, FullRequest: sb.String()}:
	case <-time.After(100 * time.Millisecond):
	}

	conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
}

func drainWire(ch <-chan wireRequest) []wireRequest {
	var out []wireRequest
	for rd := range ch {
		out = append(out, rd)
	}
	return out
}

// newRequestFileScanner builds a Scanner wired like a real run but without DB
// writes (MatchStatusCodes matches nothing) and without a progress bar.
func newRequestFileScanner(pr *rawhttp.ParsedRequest, tmpDir string) *scanner.Scanner {
	return scanner.NewScanner(&scanner.ScannerOpts{
		Timeout:                 3000,
		ConcurrentRequests:      25,
		MaxRetries:              0,
		RetryDelay:              0,
		MaxConsecutiveFailedReqs: 10000,
		MatchStatusCodes:        []int{599}, // no response matches -> no DB writes
		DisableProgressBar:      true,
		ResponseBodyPreviewSize: 512,
		OutDir:                  tmpDir,
		ParsedRequest:           pr,
	}, nil)
}

// TestRequestFileDrivesFullScanOnWire runs a real RunBypassModule (dumb_check,
// 1 job) driven purely by a ParsedRequest. The -u URL host and path are both
// deliberately wrong: the file must win on host (dial target), path, method,
// headers and body.
func TestRequestFileDrivesFullScanOnWire(t *testing.T) {
	received := make(chan wireRequest, 16)
	serverAddr, stop := startWireServer(t, received)
	defer stop()

	body := `{"user":"admin","role":"root"}`
	pr := &rawhttp.ParsedRequest{
		Method: "POST",
		RawURI: "/admin/config/users?debug=1",
		Host:   serverAddr,
		Headers: []payload.Headers{
			{Header: "X-Request-Source", Value: "burp"},
			{Header: "Content-Type", Value: "application/json"},
			{Header: "Connection", Value: "close"},
		},
		Body: body,
	}

	s := newRequestFileScanner(pr, t.TempDir())
	s.RunBypassModule("dumb_check", "http://127.0.0.1:1/original/path")

	stop()
	close(received)
	got := drainWire(received)

	if len(got) != 1 {
		t.Fatalf("server received %d requests, want 1 (file host must win over -u)", len(got))
	}
	full := got[0].FullRequest

	if !strings.HasPrefix(full, "POST /admin/config/users?debug=1 HTTP/1.1") {
		t.Errorf("request line not from file: %q", firstReqLine(full))
	}
	if got[0].URI != "/admin/config/users?debug=1" {
		t.Errorf("URI = %q, want file's request-target", got[0].URI)
	}
	if !strings.Contains(full, "Host: "+serverAddr+"\r\n") {
		t.Errorf("Host header not file's host (%s):\n%s", serverAddr, full)
	}
	if c := strings.Count(full, "\r\nHost: "); c != 1 {
		t.Errorf("want exactly 1 Host header, got %d:\n%s", c, full)
	}
	if !strings.Contains(full, "X-Request-Source: burp\r\n") {
		t.Errorf("imported header missing:\n%s", full)
	}
	if !strings.Contains(full, "Content-Type: application/json\r\n") {
		t.Errorf("imported Content-Type missing:\n%s", full)
	}
	if c := strings.Count(full, "Connection: close\r\n"); c != 1 {
		t.Errorf("want exactly 1 Connection line (no builder duplicate), got %d:\n%s", c, full)
	}
	if strings.Contains(full, "Connection: keep-alive") {
		t.Errorf("builder added keep-alive alongside imported Connection:\n%s", full)
	}
	cl := fmt.Sprintf("Content-Length: %d\r\n", len(body))
	if !strings.Contains(full, cl) {
		t.Errorf("auto Content-Length %q missing:\n%s", cl, full)
	}
	if !strings.HasSuffix(full, body) {
		t.Errorf("body not verbatim at end of request:\n%s", full)
	}
}

// TestRequestFileMidPathsVariantsDeriveFromFilePath verifies path modules build
// variants from the file's request-target (not -u's) and that every generated
// request carries the imported method/header/body.
func TestRequestFileMidPathsVariantsDeriveFromFilePath(t *testing.T) {
	received := make(chan wireRequest, 16384)
	serverAddr, stop := startWireServer(t, received)
	defer stop()

	pr := &rawhttp.ParsedRequest{
		Method: "POST",
		RawURI: "/x",
		Host:   serverAddr,
		Headers: []payload.Headers{
			{Header: "X-Request-Source", Value: "burp"},
		},
		Body: "a=b",
	}

	s := newRequestFileScanner(pr, t.TempDir())
	s.RunBypassModule("mid_paths", "http://127.0.0.1:1/original/path")

	stop()
	close(received)
	got := drainWire(received)

	if len(got) == 0 {
		t.Fatal("server received no requests (file host must win over -u)")
	}

	for i, rd := range got {
		if !strings.HasPrefix(rd.FullRequest, "POST ") {
			t.Errorf("request %d: method not from file: %q", i, firstReqLine(rd.FullRequest))
		}
		if strings.Contains(rd.URI, "original") {
			t.Errorf("request %d: URI derived from -u path, not file path: %q", i, rd.URI)
		}
		if !strings.Contains(rd.FullRequest, "X-Request-Source: burp\r\n") {
			t.Errorf("request %d: imported header missing:\n%s", i, rd.FullRequest)
		}
		if !strings.HasSuffix(rd.FullRequest, "a=b") {
			t.Errorf("request %d: body not verbatim:\n%s", i, rd.FullRequest)
		}
		if !strings.Contains(rd.FullRequest, "Content-Length: 3\r\n") {
			t.Errorf("request %d: auto Content-Length missing:\n%s", i, rd.FullRequest)
		}
	}
	if !strings.Contains(got[0].URI, "x") {
		t.Errorf("no URI derived from file path /x, first was %q", got[0].URI)
	}
}

func firstReqLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i != -1 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
