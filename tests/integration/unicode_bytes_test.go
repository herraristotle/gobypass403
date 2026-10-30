package tests

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestUnicodeBytes(t *testing.T) {
	// Create a buffer to simulate writing a raw HTTP request
	buf := bytes.NewBuffer(nil)

	// Unicode string in the request line
	unicodePath := "/path/こんにちは" // Japanese "Hello"

	// Write the request line with Unicode
	buf.WriteString("GET ")
	buf.WriteString(unicodePath)
	buf.WriteString(" HTTP/1.1\r\n")

	// Write a Host header
	buf.WriteString("Host: evil.com\r\n")

	// Write a custom header with Unicode
	unicodeHeader := "X-Test-Header: こんにちは\r\n"
	buf.WriteString(unicodeHeader)

	// End of headers
	buf.WriteString("\r\n")

	// Print the raw request bytes for inspection
	rawBytes := buf.Bytes()
	fmt.Printf("Raw request bytes (hex): %x\n", rawBytes)
	fmt.Printf("Raw request bytes (string): %s\n", rawBytes)

	// Verify the raw bytes contain the expected UTF-8 sequences
	expectedPathBytes := []byte(unicodePath)
	if !bytes.Contains(rawBytes, expectedPathBytes) {
		t.Errorf("Expected raw bytes to contain UTF-8 encoded path: %x", expectedPathBytes)
	}

	expectedHeaderBytes := []byte(unicodeHeader)
	if !bytes.Contains(rawBytes, expectedHeaderBytes) {
		t.Errorf("Expected raw bytes to contain UTF-8 encoded header: %x", expectedHeaderBytes)
	}
}

func TestRawHTTPClientBuildAndSendRequest(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup server handler
	serverHandler := func(req *rawRequest) []byte {
		t.Logf("Received request:")
		t.Logf("Request line: %s %s %s", req.Method, req.Target, req.Proto)
		t.Logf("Host header: %s", req.Header("Host"))
		t.Logf("X-Test-Header: %s", req.Header("X-Test-Header"))
		t.Logf("Full request:\n%s", req.Raw)

		// Verify the request line
		if req.Target != "/path/こんにちは" {
			t.Errorf("Expected request line to be 'GET /path/こんにちは HTTP/1.1', but got '%s %s %s'",
				req.Method, req.Target, req.Proto)
		}

		// Simulate response
		return rawResp(200, nil, "Request received")
	}

	// Start raw in-memory server
	serveRaw(ln, serverHandler)

	// Create rawhttp.HTTPClient. The dialer must route to the in-memory
	// listener; historically it was missing and the test dialed real :80.
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}
	client := rawhttp.NewHTTPClient(opts)

	// Create a PayloadJob with Unicode in the path and headers
	job := payload.BypassPayload{
		Method: "GET",
		Scheme: "http",
		Host:   "localhost:80",
		RawURI: "/path/こんにちは", // Unicode path
		Headers: []payload.Headers{
			{Header: "Host", Value: "evil.com"},       // Spoofed Host header
			{Header: "X-Test-Header", Value: "こんにちは"}, // Unicode header
		},
		PayloadToken: "debug-token-123",
	}

	// Create fasthttp.Request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Build the raw HTTP request
	err := rawhttp.BuildRawHTTPRequest(client, req, job)
	assert.NoError(t, err, "Failed to build raw HTTP request")

	// Log the request details
	t.Logf("Sending request to: http://localhost")
	t.Logf("Request line: %s %s %s", req.Header.Method(), req.URI().Path(), req.Header.Protocol())
	t.Logf("Using Host header: %s", string(req.Header.Peek("Host")))
	t.Logf("Request headers:\n%s", req.Header.String())

	// Send request using the in-memory listener
	_, err = client.DoRequest(req, resp, payload.BypassPayload{})
	assert.NoError(t, err, "Failed to send request")

	// Verify response
	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
	assert.Equal(t, "Request received", string(resp.Body()))

	// Verify the Host header was set correctly
	assert.Equal(t, "evil.com", string(req.Header.Peek("Host")))
	assert.Equal(t, "こんにちは", string(req.Header.Peek("X-Test-Header")))
}

func TestRawHTTPClientBuildAndSendRequestDirectLocalhost(t *testing.T) {
	// Hermetic replacement for the historical assumption of a server already
	// running on localhost:80: a real TCP listener on an ephemeral port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serveRaw(ln, func(req *rawRequest) []byte {
		if req.Target != "/path/こんにちは" {
			t.Errorf("Expected request line to be 'GET /path/こんにちは HTTP/1.1', but got '%s %s %s'",
				req.Method, req.Target, req.Proto)
		}
		return rawResp(200, nil, "Request received")
	})

	opts := rawhttp.DefaultHTTPClientOptions()
	opts.Dialer = rawhttp.CreateHTTPClientDialer(opts.DialTimeout, opts.ProxyURL)

	// Create rawhttp.HTTPClient with default options
	client := rawhttp.NewHTTPClient(opts)

	// Create a PayloadJob with Unicode in the path and headers
	job := payload.BypassPayload{
		Method:  "GET",
		Scheme:  "http",
		Host:    ln.Addr().String(), // Target the hermetic test server
		RawURI:  "/path/こんにちは",    // Unicode path
		Headers: []payload.Headers{
			{Header: "Host", Value: "evil.com"},        // Spoofed Host header
			{Header: "X-Test-Header", Value: "こんにちは"}, // Unicode header
		},
		PayloadToken: "debug-token-123",
	}

	// Create fasthttp.Request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Build the raw HTTP request
	err = rawhttp.BuildRawHTTPRequest(client, req, job)
	assert.NoError(t, err, "Failed to build raw HTTP request")

	// Log the request details
	t.Logf("Sending request to: %s", job.Host)
	t.Logf("Request line: %s %s %s", req.Header.Method(), req.URI().Path(), req.Header.Protocol())
	t.Logf("Using Host header: %s", string(req.Header.Peek("Host")))
	t.Logf("Request headers:\n%s", req.Header.String())

	// Send request to the real server
	_, err = client.DoRequest(req, resp, payload.BypassPayload{})
	assert.NoError(t, err, "Failed to send request")

	// Verify response
	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
	assert.Equal(t, "Request received", string(resp.Body()))

	// Verify the Host header was set correctly
	assert.Equal(t, "evil.com", string(req.Header.Peek("Host")))
	assert.Equal(t, "こんにちは", string(req.Header.Peek("X-Test-Header")))
}
