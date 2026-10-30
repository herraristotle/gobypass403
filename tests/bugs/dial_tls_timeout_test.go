package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/herraristotle/fasthttp"
)

// startLocalTLSEndpoints starts two hermetic stand-ins for github.com:443
// and github.com:80 on 127.0.0.1 ephemeral ports:
//
//   - a TLS endpoint: raw TLS handshakes succeed, plaintext HTTP probes are
//     rejected by the handshake and close without an HTTP response;
//   - a plain HTTP endpoint: raw HTTP probes get an "HTTP/1.1" response,
//     TLS handshakes fail.
//
// The original tests dialed the real github.com, which fails in offline or
// sandboxed environments with "lookup github.com: no such host". The probe
// semantics under test — detecting TLS vs plain-HTTP endpoints — are fully
// reproduced locally.
func startLocalTLSEndpoints(t *testing.T) (tlsAddr, httpAddr string) {
	t.Helper()

	cert := newTestTLSCertificate(t)

	// Plain HTTP endpoint (github.com:80 equivalent).
	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { plainLn.Close() })
	go serveProbeEndpoint(plainLn)

	// TLS endpoint (github.com:443 equivalent).
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { rawLn.Close() })
	tlsLn := tls.NewListener(rawLn, &tls.Config{Certificates: []tls.Certificate{cert}})
	go serveProbeEndpoint(tlsLn)

	return tlsLn.Addr().String(), plainLn.Addr().String()
}

// serveProbeEndpoint accepts connections until the listener closes. Each
// connection reads one chunk of input and, only if that read succeeds,
// replies with a minimal HTTP response — whether a probe therefore "sees
// HTTP" depends solely on how the endpoint wraps its connections.
func serveProbeEndpoint(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 1024)
			if _, err := conn.Read(buf); err != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		}(conn)
	}
}

// newTestTLSCertificate generates a short-lived self-signed certificate for
// 127.0.0.1 so the local TLS endpoint can handshake without any external
// certificate material.
func newTestTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gobypass403-local-tls-endpoint"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
}

func TestTLSDialing(t *testing.T) {
	tlsAddr, httpAddr := startLocalTLSEndpoints(t)

	// Test configuration
	testCases := []struct {
		name     string
		addr     string
		wantTLS  bool
		wantHTTP bool
	}{
		{
			name:     "TLS endpoint (local 443 equivalent)",
			addr:     tlsAddr,
			wantTLS:  true,
			wantHTTP: false,
		},
		{
			name:     "Plain HTTP endpoint (local 80 equivalent)",
			addr:     httpAddr,
			wantTLS:  false,
			wantHTTP: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new fasthttp dialer
			dialer := &fasthttp.TCPDialer{
				Concurrency:      2048,
				DNSCacheDuration: 10 * time.Minute,
			}

			// Test TLS connection
			tlsOK := testTLSHandshake(t, dialer, tc.addr)
			assert.Equal(t, tc.wantTLS, tlsOK, "TLS handshake result mismatch")

			// Test HTTP connection
			httpOK := testHTTPConnection(t, dialer, tc.addr)
			assert.Equal(t, tc.wantHTTP, httpOK, "HTTP connection result mismatch")
		})
	}
}

func TestTLSDialing_IP(t *testing.T) {
	tlsAddr, httpAddr := startLocalTLSEndpoints(t)

	testCases := []struct {
		name     string
		ip       string // numeric target: resolves without DNS, keeping the resolve-then-dial flow
		addr     string // local endpoint providing the port
		wantTLS  bool
		wantHTTP bool
	}{
		{
			name:     "TLS endpoint (local 443 equivalent)",
			ip:       "127.0.0.1",
			addr:     tlsAddr,
			wantTLS:  true,
			wantHTTP: false,
		},
		{
			name:     "Plain HTTP endpoint (local 80 equivalent)",
			ip:       "127.0.0.1",
			addr:     httpAddr,
			wantTLS:  false,
			wantHTTP: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Resolve IP first
			ips, err := net.LookupIP(tc.ip)
			require.NoError(t, err, "IP lookup failed")
			require.NotEmpty(t, ips, "No IPs resolved")

			_, port, err := net.SplitHostPort(tc.addr)
			require.NoError(t, err)

			// Create dialer
			dialer := &fasthttp.TCPDialer{
				Concurrency:      2048,
				DNSCacheDuration: 10 * time.Minute,
			}

			// Test first resolved IP
			ip := ips[0].String()
			addr := net.JoinHostPort(ip, port)
			t.Logf("Testing IP: %s", addr)

			// Test TLS connection
			tlsOK := testTLSHandshake(t, dialer, addr)
			require.Equal(t, tc.wantTLS, tlsOK, "TLS handshake result mismatch")

			// Test HTTP connection
			httpOK := testHTTPConnection(t, dialer, addr)
			require.Equal(t, tc.wantHTTP, httpOK, "HTTP connection result mismatch")
		})
	}
}

func testTLSHandshake(t *testing.T, dialer *fasthttp.TCPDialer, addr string) bool {
	t.Helper()

	// First establish TCP connection
	conn, err := dialer.Dial(addr)
	if err != nil {
		t.Logf("TCP dial error for %s: %v", addr, err)
		return false
	}
	defer conn.Close()

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	// Attempt TLS handshake
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Logf("TLS set deadline error for %s: %v", addr, err)
		return false
	}

	if err := tlsConn.Handshake(); err != nil {
		t.Logf("TLS handshake error for %s: %v", addr, err)
		return false
	}

	t.Logf("Successful TLS handshake with %s", addr)
	return true
}

func testHTTPConnection(t *testing.T, dialer *fasthttp.TCPDialer, addr string) bool {
	t.Helper()

	// Establish TCP connection
	conn, err := dialer.Dial(addr)
	if err != nil {
		t.Logf("HTTP dial error for %s: %v", addr, err)
		return false
	}
	defer conn.Close()

	// Set deadline for the entire operation
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send HTTP request
	_, err = fmt.Fprintf(conn, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr)
	if err != nil {
		t.Logf("HTTP write error for %s: %v", addr, err)
		return false
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Logf("HTTP read error for %s: %v", addr, err)
		return false
	}

	if n > 0 && string(buf[:n])[:4] == "HTTP" {
		t.Logf("Successful HTTP connection with %s", addr)
		return true
	}

	t.Logf("Invalid HTTP response from %s", addr)
	return false
}

// Optional: Add benchmark tests for connection performance
func BenchmarkTLSHandshake(b *testing.B) {
	dialer := &fasthttp.TCPDialer{
		Concurrency:      2048,
		DNSCacheDuration: 10 * time.Minute,
	}
	addr := "github.com:443"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := dialer.Dial(addr)
		if err != nil {
			b.Fatal(err)
		}

		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		})

		tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			b.Fatal(err)
		}

		tlsConn.Close()
	}
}
