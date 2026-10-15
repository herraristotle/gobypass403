package tests

import (
	"net"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestHostHeaderInjection(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup server handler
	serverHandler := func(req *rawRequest) []byte {
		host := req.Header("Host")

		// Log received request details for debugging
		t.Logf("Received request:")
		t.Logf("Host header: %s", host)
		t.Logf("RequestURI: %s", req.Target)
		t.Logf("Full request:\n%s", req.Raw)

		// Simulate host header based redirection vulnerability
		if host == "evil.com:1337" {
			return rawResp(302, [][2]string{{"Location", "https://evil.com/pwned"}}, "")
		}

		return rawResp(200, nil, "Normal response")
	}

	// Start raw in-memory server
	serveRaw(ln, serverHandler)

	// Create client with mock listener. The dialer must be set before
	// construction: NewHTTPClient bakes opts.Dialer into the underlying
	// fasthttp client, so post-construction mutation was a no-op that sent
	// this test to the real internet.
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}
	client := rawhttp.NewHTTPClient(clientOpts)

	// Test cases
	testCases := []struct {
		name         string
		targetURL    string
		hostHeader   string
		expectedCode int
	}{
		{
			name: "Normal request",
			// http: the in-memory listener is plaintext; https would force a
			// TLS handshake against a plain server.
			targetURL:    "http://example.com/path",
			hostHeader:   "example.com",
			expectedCode: 200,
		},
		{
			name:         "Host header injection attempt",
			targetURL:    "http://example.com/path",
			hostHeader:   "evil.com:1337",
			expectedCode: 302,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Setup payload job. Host must be a bare hostname: directDial
			// parses host:port from it and chokes on a full URL.
			job := payload.BypassPayload{
				Scheme: "http",
				Host:   "example.com",
				RawURI: "/path",
				Method: "GET",
				Headers: []payload.Headers{
					{
						Header: "Host",
						Value:  tc.hostHeader,
					},
				},
			}

			// Build and send request
			err := rawhttp.BuildRawHTTPRequest(client, req, job)
			//req.UseHostHeader = true
			assert.NoError(t, err)

			_, err = client.DoRequest(req, resp, payload.BypassPayload{})
			assert.NoError(t, err)

			// Verify response
			assert.Equal(t, tc.expectedCode, resp.StatusCode())
		})
	}
}

func TestHostHeaderInjection2(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup server handler: host-based routing with openresty-style responses.
	serverHandler := func(req *rawRequest) []byte {
		host := req.Header("Host")

		// Log received request details for debugging
		t.Logf("Received request:")
		t.Logf("Host header: %s", host)
		t.Logf("RequestURI: %s", req.Target)
		t.Logf("Full request:\n%s", req.Raw)

		if host != "example.com" {
			// Openresty-style redirect for unknown hosts
			return rawResp(301, [][2]string{
				{"Server", "openresty"},
				{"Content-Type", "text/html"},
				{"Location", "https://example.com/"},
			}, "<html>\n<head><title>301 Moved Permanently</title></head>\n<body>\n<center><h1>301 Moved Permanently</h1></center>\n<hr><center>openresty</center>\n</body>\n</html>")
		}

		// Normal response for matching host
		return rawResp(301, [][2]string{
			{"Location", "https://www.example.com/"},
			{"Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"},
		}, "")
	}

	// Start raw in-memory server
	serveRaw(ln, serverHandler)

	// Create client with mock listener. The dialer was historically commented
	// out — and even uncommented post-construction it would have been a no-op
	// (NewHTTPClient bakes opts.Dialer in), which sent this test to the real
	// internet. Set it before construction.
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}
	client := rawhttp.NewHTTPClient(clientOpts)

	// Test cases remain the same
	testCases := []struct {
		name             string
		targetURL        string
		hostHeader       string
		expectedCode     int
		expectedLocation string
		expectedServer   string
	}{
		{
			name:             "Normal request with matching host",
			targetURL:        "http://example.com/",
			hostHeader:       "example.com",
			expectedCode:     301,
			expectedLocation: "https://www.example.com/",
			expectedServer:   "",
		},
		{
			name:             "Request with different host header",
			targetURL:        "http://example.com/",
			hostHeader:       "google.com",
			expectedCode:     301,
			expectedLocation: "https://example.com/",
			expectedServer:   "openresty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Build the request directly (the original called the commented-out
			// BuildRawHTTPRequest and never set the per-case Host header);
			// UseHostHeader routes the custom Host onto the wire.
			req.SetRequestURI("http://example.com/")

			req.UseHostHeader = true
			req.Header.SetHost(tc.hostHeader)
			req.URI().SetScheme("http")
			// Log the actual request being sent
			t.Logf("Sending request with headers:\n%s", req.Header.String())

			_, err := client.DoRequest(req, resp, payload.BypassPayload{})
			assert.NoError(t, err)

			// Log the response received
			t.Logf("Received response:\nStatus: %d\nHeaders:\n%s\nBody: %s\n",
				resp.StatusCode(),
				resp.Header.String(),
				resp.Body())

			// Verify response
			assert.Equal(t, tc.expectedCode, resp.StatusCode())
			assert.Equal(t, tc.expectedLocation, string(resp.Header.Peek("Location")))

			if tc.expectedServer != "" {
				assert.Equal(t, tc.expectedServer, string(resp.Header.Peek("Server")))
			}

			// Verify the Host header was set correctly
			assert.Equal(t, tc.hostHeader, string(req.Header.Peek("Host")))
		})
	}
}

func TestManualHostHeaderInjection(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup server handler
	serverHandler := func(req *rawRequest) []byte {
		host := req.Header("Host")

		t.Logf("Received request:")
		t.Logf("Host header: %s", host)
		t.Logf("RequestURI: %s", req.Target)
		t.Logf("Full request:\n%s", req.Raw)

		// Simulate different behavior based on host header
		switch host {
		case "evil.com":
			return rawResp(302, [][2]string{{"Location", "https://evil.com/pwned"}}, "")
		case "admin.internal":
			return rawResp(200, nil, "Admin panel accessed")
		default:
			return rawStatus(403)
		}
	}

	// Start raw in-memory server
	serveRaw(ln, serverHandler)

	// Create client with mock listener. The dialer must be set before
	// construction: post-construction mutation of opts.Dialer is a no-op
	// (NewHTTPClient bakes it into the fasthttp client) and the test would
	// hit the real internet.
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}
	client := rawhttp.NewHTTPClient(clientOpts)

	// Test cases
	testCases := []struct {
		name         string
		targetHost   string
		path         string
		hostHeader   string
		expectedCode int
		expectedBody string
	}{
		{
			name:         "Normal request",
			targetHost:   "example.com",
			path:         "/",
			hostHeader:   "example.com",
			expectedCode: 403,
		},
		{
			name:         "Host header injection - evil.com",
			targetHost:   "example.com",
			path:         "/",
			hostHeader:   "evil.com",
			expectedCode: 302,
		},
		{
			name:         "Host header injection - admin.internal",
			targetHost:   "example.com",
			path:         "/admin",
			hostHeader:   "admin.internal",
			expectedCode: 200,
			expectedBody: "Admin panel accessed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Manually set up the request. http, not https: the in-memory
			// listener is plaintext (https made the client TLS-handshake the
			// raw server and always failed).
			req.SetRequestURI(tc.path)
			req.URI().SetScheme("http")
			req.URI().SetHost(tc.targetHost)

			// Enable custom host header
			req.UseHostHeader = true
			req.Header.SetHost(tc.hostHeader)

			// Log the request details
			t.Logf("Sending request to: http://%s%s", tc.targetHost, tc.path)
			t.Logf("Using Host header: %s", tc.hostHeader)
			t.Logf("Request headers:\n%s", req.Header.String())

			// Send request
			_, err := client.DoRequest(req, resp, payload.BypassPayload{})
			assert.NoError(t, err)

			// Verify response
			assert.Equal(t, tc.expectedCode, resp.StatusCode())
			if tc.expectedBody != "" {
				assert.Equal(t, tc.expectedBody, string(resp.Body()))
			}

			// Verify the Host header was set correctly
			assert.Equal(t, tc.hostHeader, string(req.Header.Peek("Host")))
		})
	}
}

func TestManualHostHeaderInjection2(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup server handler
	serverHandler := func(req *rawRequest) []byte {
		host := req.Header("Host")

		t.Logf("Received request:")
		t.Logf("Host header: %s", host)
		t.Logf("RequestURI: %s", req.Target)
		t.Logf("Full request:\n%s", req.Raw)

		// Simulate different behavior based on host header
		switch host {
		case "evil.com":
			return rawResp(302, [][2]string{{"Location", "https://evil.com/pwned"}}, "")
		case "admin.internal":
			return rawResp(200, nil, "Admin panel accessed")
		default:
			return rawStatus(403)
		}
	}

	// Start raw in-memory server
	serveRaw(ln, serverHandler)

	// Create client with mock listener
	client := &fasthttp.Client{
		Dial: func(addr string) (net.Conn, error) {
			return ln.Dial()
		},
	}

	// Test cases
	testCases := []struct {
		name         string
		targetHost   string
		path         string
		hostHeader   string
		expectedCode int
		expectedBody string
	}{
		{
			name:         "Normal request",
			targetHost:   "example.com",
			path:         "/",
			hostHeader:   "example.com",
			expectedCode: 403,
		},
		{
			name:         "Host header injection - evil.com",
			targetHost:   "example.com",
			path:         "/",
			hostHeader:   "evil.com",
			expectedCode: 302,
		},
		{
			name:         "Host header injection - admin.internal",
			targetHost:   "example.com",
			path:         "/admin",
			hostHeader:   "admin.internal",
			expectedCode: 200,
			expectedBody: "Admin panel accessed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Manually set up the request
			req.SetRequestURI(tc.path)
			req.URI().SetScheme("http") // Use http for in-memory listener
			req.URI().SetHost(tc.targetHost)

			// Enable custom host header
			req.UseHostHeader = true
			req.Header.SetHost(tc.hostHeader)

			// Log the request details
			t.Logf("Sending request to: http://%s%s", tc.targetHost, tc.path)
			t.Logf("Using Host header: %s", tc.hostHeader)
			t.Logf("Request headers:\n%s", req.Header.String())

			// Send request
			err := client.Do(req, resp)
			assert.NoError(t, err)

			// Verify response
			assert.Equal(t, tc.expectedCode, resp.StatusCode())
			if tc.expectedBody != "" {
				assert.Equal(t, tc.expectedBody, string(resp.Body()))
			}

			// Verify the Host header was set correctly
			assert.Equal(t, tc.hostHeader, string(req.Header.Peek("Host")))
		})
	}
}
