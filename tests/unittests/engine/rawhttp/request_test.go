package tests

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"

	GB403Logger "github.com/herraristotle/gobypass403/core/utils/logger"
	"github.com/herraristotle/fasthttp"
	"github.com/herraristotle/fasthttp/fasthttputil"
)

func TestRequestBuilderViaEchoServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Create listener with context for cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Raw echo server. The vendored fasthttp fork is client-only (no
	// fasthttp.Server), so the echo behavior lives in echo_server_test.go.
	serverErr := serveInmemory(ln, echoRespFn)

	// Create test client with custom dialer
	clientoptions := rawhttp.DefaultHTTPClientOptions()
	clientoptions.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}
	client := rawhttp.NewHTTPClient(clientoptions)

	// Test cases using real payload generators
	testCases := []struct {
		name         string
		targetURL    string
		bypassModule string
	}{
		{
			name:         "HeaderIP Payloads",
			targetURL:    "http://example.com/test",
			bypassModule: "headers_ip",
		},
		{
			name:         "MidPaths Payloads",
			targetURL:    "http://example.com/test/path",
			bypassModule: "mid_paths",
		},
		{
			name:         "HeaderScheme Payloads",
			targetURL:    "http://example.com/admin",
			bypassModule: "headers_scheme",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			select {
			case err := <-serverErr:
				t.Fatalf("Server error: %v", err)
			default:
			}

			// Create the payload generator with options
			pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
				TargetURL:    tc.targetURL,
				BypassModule: tc.bypassModule,
			})

			// Use the centralized Generate method
			jobs := pg.Generate()

			if len(jobs) == 0 {
				t.Fatalf("No payloads generated for %s", tc.name)
			}

			// Rest of your test code remains the same
			for i, job := range jobs {
				select {
				case <-ctx.Done():
					t.Fatal("Test timeout")
				default:
				}

				GB403Logger.DefaultLogger.EnableDebug()
				GB403Logger.DefaultLogger.EnableVerbose()

				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				rawhttp.BuildRawHTTPRequest(client, req, job)

				// Build virtual request
				GB403Logger.PrintYellow("[GB403Logger] Sending request :\n%s", req)

				// Send request and let server handle the comparison printing
				_, err := client.DoRequest(req, resp, payload.BypassPayload{})
				if err != nil {
					t.Fatalf("Job %d failed: %v", i, err)
				}
				// StreamResponseBody is on by default: the pooled connection is
				// released only once the body stream is drained. resp.Body()
				// consumes it — without this the pool exhausts at
				// MaxConnsPerHost (128) with ErrNoFreeConns.
				_ = resp.Body()

				// // Log only on failure to reduce output
				// if !bytes.Contains(echoedRequest, []byte(job.Method+" "+job.RawURI)) {
				// 	t.Logf("\nPayload %d Raw Request:\n%s", i, string(echoedRequest))
				// 	t.Errorf("Request line mismatch for job %d", i)
				// }

				// // Verify all headers are present
				// for _, header := range job.Headers {
				// 	expectedHeader := fmt.Sprintf("%s: %s", header.Header, header.Value)
				// 	if !bytes.Contains(echoedRequest, []byte(expectedHeader)) {
				// 		// Print more debug info
				// 		fmt.Printf("\nExpected header not found: %s\n", expectedHeader)
				// 		fmt.Printf("Headers in request:\n%s\n", string(echoedRequest))
				// 		t.Errorf("Missing header in job %d: %s", i, expectedHeader)
				// 	}
				// }

				// // Verify debug header
				// if !bytes.Contains(echoedRequest, []byte("X-GB403-Debug: "+job.PayloadSeed)) {
				// 	t.Errorf("Missing or incorrect debug header in job %d", i)

			}
		})
	}
}

func TestRequestBuilderMidPathsPayloads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Create listener with context for cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Raw echo server (see echo_server_test.go).
	serverErr := serveInmemory(ln, echoRespFn)

	// Create test client with custom dialer
	clientoptions := rawhttp.DefaultHTTPClientOptions()
	clientoptions.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}
	client := rawhttp.NewHTTPClient(clientoptions)

	// Test cases using real payload generators
	testCases := []struct {
		name         string
		targetURL    string
		bypassModule string
	}{
		{
			name:         "MidPaths Payloads",
			targetURL:    "http://example.com/admin",
			bypassModule: "mid_paths",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			select {
			case err := <-serverErr:
				t.Fatalf("Server error: %v", err)
			default:
			}

			// Create the payload generator with options
			pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
				TargetURL:    tc.targetURL,
				BypassModule: tc.bypassModule,
			})

			// Use the centralized Generate method
			jobs := pg.Generate()
			if len(jobs) == 0 {
				t.Fatalf("No payloads generated for %s", tc.name)
			}

			for i, job := range jobs {
				select {
				case <-ctx.Done():
					t.Fatal("Test timeout")
				default:
				}

				GB403Logger.DefaultLogger.EnableDebug()
				GB403Logger.DefaultLogger.EnableVerbose()

				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				rawhttp.BuildRawHTTPRequest(client, req, job)

				// Build virtual request
				GB403Logger.PrintGreen("[GB403Logger][RequestBuilder] [X-GB403-Token: %s] Sending request: %s\n================>\n%s<================\n", job.PayloadToken, payload.BypassPayloadToFullURL(job), req)

				// Send request and let server handle the comparison printing
				if _, err := client.DoRequest(req, resp, job); err != nil {
					t.Fatalf("Job %d failed: %v", i, err)
				}

				GB403Logger.PrintYellow("[GB403Logger] [X-GB403-Token: %s] Response received for: %s\n%s", job.PayloadToken, payload.BypassPayloadToFullURL(job), resp.Body())
			}
		})
	}
}

func TestRequestBuilderHostHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Hermetic raw echo server: the Host override is asserted against the
	// bytes the server actually received, instead of dialing the public
	// internet with a malformed URL (the old test set RawURI to an absolute
	// URL, yielding "http://google.comhttps://example.com").
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()
	serveInmemory(ln, echoRespFn)

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}
	client := rawhttp.NewHTTPClient(clientOpts)

	testCases := []struct {
		name string
	}{
		{
			name: "Host Header Override",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			// Create minimal payload job with just Method and FullURL
			job := payload.BypassPayload{
				Method: "GET",
				Host:   "example.com",
				RawURI: "/admin",
				Headers: []payload.Headers{
					{Header: "Host", Value: "yahoo.com"},
				},
			}
			req.UseHostHeader = false
			req.Header.SetMethod(job.Method)
			req.SetRequestURI(payload.BypassPayloadToFullURL(job))
			req.URI().DisablePathNormalizing = true
			req.Header.DisableNormalizing()
			req.Header.SetNoDefaultContentType(true)

			for _, h := range job.Headers {
				if h.Header == "Host" {
					req.UseHostHeader = true
					req.Header.Set(h.Header, h.Value)
				}
			}

			GB403Logger.PrintGreen("\n=== Sending Request ===")
			GB403Logger.PrintYellow("Test Case: %s", tc.name)
			GB403Logger.PrintYellow("Request URI: %s", req.URI().FullURI())
			GB403Logger.PrintYellow("===================\n")

			if _, err := client.DoRequest(req, resp, job); err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			// Drain the streamed body (releases the pooled connection) and
			// verify the server saw both a 200 and the overridden Host.
			body := resp.Body()
			if resp.StatusCode() != 200 {
				t.Errorf("Expected status 200 from echo server, got %d", resp.StatusCode())
			}
			if !bytes.Contains(body, []byte("Host: yahoo.com")) {
				t.Errorf("Overridden Host header not received by server; body:\n%s", body)
			}
		})
	}
}

func TestResponseProcessingWithSpacedHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Canned-response server (see echo_server_test.go) — serves the fixed
	// Content-Disposition / CSP / malformed responses selected by X-Test-Case.
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	serveInmemory(ln, cannedRespFn)

	clientoptions := rawhttp.DefaultHTTPClientOptions()
	clientoptions.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientoptions)

	testCases := []struct {
		name           string
		testCaseID     string
		expectedResp   map[string]string
		expectedBody   string
		expectError    bool
		expectedStatus int
	}{
		{
			name:       "Content-Disposition with spaces",
			testCaseID: "content-disposition",
			expectedResp: map[string]string{
				"Content-Disposition": "attachment; filename=\"test file.pdf\"",
				"Content-Type":        "application/pdf",
			},
			expectedBody:   "PDF content with special chars: áéíóú",
			expectError:    false,
			expectedStatus: 200,
		},
		{
			name:       "CSP Header with spaces",
			testCaseID: "csp-header",
			expectedResp: map[string]string{
				"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://example.com",
				"Content-Type":            "text/html; charset=utf-8",
			},
			expectedBody:   "<html><head><title>Test Page</title></head><body>Test content with spaces and special chars: áéíóú</body></html>",
			expectError:    false,
			expectedStatus: 200,
		},
		{
			name:           "Malformed Response",
			testCaseID:     "malformed-response",
			expectedResp:   map[string]string{},
			expectedBody:   "nction() {\n\treturn this.href",
			expectError:    true,
			expectedStatus: 0, // Status code will be 0 for malformed responses
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			req.SetRequestURI("http://testserver/test")
			req.Header.SetMethod("GET")
			req.Header.Set("X-Test-Case", tc.testCaseID)

			respTime, err := client.DoRequest(req, resp, payload.BypassPayload{})
			if err != nil && !tc.expectError {
				t.Fatalf("Unexpected request error: %v", err)
			}

			// Get response headers
			headers := rawhttp.GetResponseHeaders(&resp.Header, resp.StatusCode(), []byte{})

			// Log response details for debugging
			GB403Logger.Info().Msgf("\n=== Response Details for %s ===\n", tc.name)
			GB403Logger.Info().Msgf("Response Time: %dms", respTime)
			GB403Logger.Info().Msgf("Status Code: %d", resp.StatusCode())
			GB403Logger.Info().Msgf("Headers:\n%s", string(headers))
			GB403Logger.Info().Msgf("Body:\n%s", string(resp.Body()))
			GB403Logger.Info().Msgf("================\n")

			if !tc.expectError {
				// Verify headers
				for header, expectedValue := range tc.expectedResp {
					if !bytes.Contains(headers, []byte(header+": "+expectedValue)) {
						t.Errorf("Header %s not found or incorrect\nExpected: %s\nGot: %s",
							header, expectedValue, string(headers))
					}
				}

				// Verify body
				if !bytes.Equal(resp.Body(), []byte(tc.expectedBody)) {
					t.Errorf("Body mismatch\nExpected: %s\nGot: %s",
						tc.expectedBody, string(resp.Body()))
				}

				if resp.StatusCode() != tc.expectedStatus {
					t.Errorf("Expected status code %d, got %d", tc.expectedStatus, resp.StatusCode())
				}
			}

		})
	}
}

// TestBuildRawHTTPRequestPreservesMethodCase pins the exact request-line
// method bytes: fasthttp's request-line parse must not canonicalize the
// http_methods module's lowercase twins ("get" vs "GET"). Verbatim wire
// behavior was verified against the unKover testbed (local capture shows
// "get /x HTTP/1.1" intact; the engine's results DB records -X get -> 200
// on /access/apache/records in every run — the findings TABLE's 5-row
// group cap is what hid it, not the transport).
func TestBuildRawHTTPRequestPreservesMethodCase(t *testing.T) {
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	job := payload.BypassPayload{
		Method: "get",
		Host:   "example.com",
		RawURI: "/records",
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	if err := rawhttp.BuildRawHTTPRequest(client, req, job); err != nil {
		t.Fatalf("BuildRawHTTPRequest failed: %v", err)
	}
	if got := string(req.Header.Method()); got != "get" {
		t.Errorf("request-line method = %q, want %q (lowercase twins must survive the parse)", got, "get")
	}
}
