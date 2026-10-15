package tests

// Minimal HTTP CONNECT tunneling proxy for TestPathPrefixPayloadsWithProxy.
//
// The test previously hardcoded http://127.0.0.1:8080 and required a manually
// started external proxy; with none running it always failed on URI counts.
// rawhttp's proxy mode dials via fasthttpproxy.FasthttpHTTPDialerTimeout,
// which sends "CONNECT host:port HTTP/1.1" and expects a 200 before splicing
// raw bytes — so this helper implements exactly that contract: accept CONNECT,
// dial the target, reply 200, then splice bytes in both directions with zero
// parsing or re-encoding, which is precisely what the test's byte-exact URI
// fidelity assertions require.

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Proxy-side counters for diagnosing lost requests.
var (
	proxyCONNECTs     atomic.Int64
	proxyDialFails    atomic.Int64
	proxyBadHandshake atomic.Int64
)

// startConnectProxy starts a minimal HTTP CONNECT tunneling proxy on a free
// local port. It returns the proxy URL (http://127.0.0.1:port) and a stop
// function that tears down the listener and every open tunnel.
func startConnectProxy(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start proxy listener: %v", err)
	}

	var (
		mu    sync.Mutex
		conns = map[net.Conn]struct{}{}
		wg    sync.WaitGroup
		once  sync.Once
	)
	track := func(c net.Conn) {
		mu.Lock()
		conns[c] = struct{}{}
		mu.Unlock()
	}
	untrack := func(c net.Conn) {
		mu.Lock()
		delete(conns, c)
		mu.Unlock()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed by stop()
			}
			track(conn)
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer untrack(c)
				handleConnectProxyConn(c)
			}(conn)
		}
	}()

	stop := func() {
		once.Do(func() {
			_ = ln.Close()
			mu.Lock()
			for c := range conns {
				_ = c.Close()
			}
			mu.Unlock()
			wg.Wait()
			t.Logf("proxy stats: CONNECT=%d dial_fail=%d bad_handshake=%d",
				proxyCONNECTs.Load(), proxyDialFails.Load(), proxyBadHandshake.Load())
		})
	}

	return "http://" + ln.Addr().String(), stop
}

// handleConnectProxyConn performs one CONNECT handshake and then splices raw
// bytes between the client and the upstream target until either side closes.
func handleConnectProxyConn(client net.Conn) {
	defer client.Close()

	// Handshake deadline only; cleared once the tunnel is established.
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(client)

	// Read the CONNECT request head up to the blank line.
	var head []byte
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		head = append(head, line...)
		if bytes.HasSuffix(head, []byte("\r\n\r\n")) {
			break
		}
	}

	lineEnd := bytes.IndexByte(head, '\n')
	firstLine := strings.TrimSpace(string(head[:lineEnd]))
	fields := strings.SplitN(firstLine, " ", 3)
	if len(fields) < 3 || fields[0] != "CONNECT" {
		proxyBadHandshake.Add(1)
		_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	target := fields[1]
	proxyCONNECTs.Add(1)

	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		proxyDialFails.Add(1)
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer upstream.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Tunnel may now live for the whole test — clear the handshake deadline.
	_ = client.SetDeadline(time.Time{})

	// Splice raw bytes both ways. No parsing, no re-encoding: tunneled
	// payloads reach the origin byte-exact.
	go func() {
		_, _ = io.Copy(upstream, br)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(client, upstream)
}
