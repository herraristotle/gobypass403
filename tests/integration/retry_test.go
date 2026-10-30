package tests

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
	GB403ErrorHandler "github.com/herraristotle/gobypass403/core/utils/error"
	GB403Logger "github.com/herraristotle/gobypass403/core/utils/logger"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestRetryOnEOF(t *testing.T) {
	GB403Logger.DefaultLogger.EnableDebug()

	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Track connection attempts
	connectionAttempts := atomic.Int32{}

	// Start server: first two requests get a malformed response followed by
	// EOF; subsequent requests get a proper response.
	serveRawResult(ln, func(*rawRequest) rawResult {
		attempts := connectionAttempts.Add(1)
		t.Logf("Server handling attempt %d", attempts)

		if attempts <= 2 {
			// Send completely malformed response, then EOF
			t.Logf("Server sending malformed response for attempt %d", attempts)
			return rawResult{
				Data:  []byte("   200 OK\r\nContent-Length: 5\r\n\r\nhello"),
				Close: true,
			}
		}
		// Send proper response
		t.Logf("Server sending proper response for attempt %d", attempts)
		return rawResult{Data: rawResp(200, nil, "success"), Close: true}
	})

	// Create client options
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.MaxRetries = 4
	opts.Timeout = 20 * time.Second
	opts.RetryDelay = 100 * time.Millisecond
	opts.DisableKeepAlive = false

	// Use broken connection for first two attempts. The dialer counts dials
	// itself: the original read the server-side request counter, which cannot
	// distinguish "two failed attempts" from "the third attempt in flight".
	dialCount := atomic.Int32{}
	opts.Dialer = func(addr string) (net.Conn, error) {
		conn, err := ln.Dial()
		if err != nil {
			return nil, err
		}

		currentAttempt := dialCount.Add(1)
		t.Logf("Dialer creating connection for attempt %d", currentAttempt)

		if currentAttempt <= 2 {
			return &brokenConn{
				Conn:       conn,
				breakAfter: 10, // Break after just 10 bytes
				t:          t,
			}, nil
		}
		return conn, nil
	}

	// Create client with error handler that logs errors
	client := rawhttp.NewHTTPClient(opts)

	// Prepare request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://test.local/test")

	// Execute request and capture each error
	_, err := client.DoRequest(req, resp, payload.BypassPayload{})
	t.Logf("DoRequest returned error: %v", err)

	// Log for debugging
	t.Logf("Final error: %v", err)
	t.Logf("Retry attempts: %d", client.GetPerReqRetryAttempts())
	t.Logf("Connection attempts: %d", connectionAttempts.Load())

	// Assertions. Retry ownership here lives in the fasthttp fork's internal
	// idempotent-request retry loop (DefaultMaxIdemponentCallAttempts=5):
	// rawhttp's GetPerReqRetryAttempts only counts handleRetries-driven
	// retries, which never fire when the fork recovers internally. The
	// observable contract: 2 malformed responses tolerated, 3rd succeeds.
	assert.NoError(t, err, "Expected successful request after retries")
	assert.Equal(t, "success", string(resp.Body()), "Expected success response")
	assert.Equal(t, int32(3), connectionAttempts.Load(), "Expected exactly 3 connection attempts (1 + 2 tolerated failures)")

	client.Close()
}

// brokenConn simulates a connection that breaks after N bytes
type brokenConn struct {
	net.Conn
	bytesRead  int
	breakAfter int
	t          *testing.T
}

func (c *brokenConn) Read(b []byte) (n int, err error) {
	if c.bytesRead >= c.breakAfter {
		c.t.Logf("brokenConn: forcing immediate EOF after %d bytes", c.bytesRead)
		return 0, io.EOF
	}

	// Only read up to breakAfter bytes
	if c.bytesRead+len(b) > c.breakAfter {
		n = c.breakAfter - c.bytesRead
		copy(b[:n], make([]byte, n))
		c.bytesRead += n
		c.t.Logf("brokenConn: partial read %d bytes (total: %d), returning EOF", n, c.bytesRead)
		return n, io.EOF
	}

	n = len(b)
	copy(b, make([]byte, n))
	c.bytesRead += n
	c.t.Logf("brokenConn: read %d bytes (total: %d)", n, c.bytesRead)
	return n, nil
}

func TestRetryWithPayloads(t *testing.T) {
	// Hermetic in-memory server (the original pointed at the dead external
	// domain cmsrestrictedpagexx.com; DNS timeouts made the result-collection
	// window nondeterministic offline).
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	serveRaw(ln, func(*rawRequest) []byte {
		return rawStatus(200)
	})

	// Create base client options
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.MaxRetries = 2
	opts.Timeout = 20 * time.Second
	opts.RetryDelay = 100 * time.Millisecond
	//opts.DisableKeepAlive = true
	opts.MaxConnsPerHost = 100
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(opts)
	defer client.Close()

	baseURL := "http://cmsrestrictedpagexx.com/test"
	payloads := []string{
		"/.;",
		"/.;/",
		"/.;//",
		"/..",
		"/..;/",
		"/..;/;/",
		"/..;/;/..;/",
		"/..;/..;/",
		"/..;/../",
		"/..;//",
		"/..;//..;/",
		"/..;//../",
		"/..;%2f",
		"/..;%2f..;%2f",
		"/..;%2f..;%2f..;%2f",
		"/../",
		"/../;/",
		"/../;/../",
		"/../.;/../",
		"/../..;/",
		"/../../",
		"/../../../",
		"/../../..//",
		"/../..//",
		"/../..//../",
		"/.././../",
		"/..//",
		"/..//..;/",
		"/..//../",
		"/..//../../",
		"/..%2f",
		"/..%2f..%2f",
		"/..%2f..%2f..%2f",
		"/./",
		"/.//",
		"/.%00",
		"/.%00/",
		"/.randomstring",
		"/../",
		"/../;/",
		"/../;/../",
		"/../.;/../",
		"/../..;/",
		"/../../",
		"/../../../",
		"/../../..//",
		"/../..//",
		"/../..//../",
		"/.././../",
		"/..//",
		"/..//..;/",
		"/..//../",
		"/..//../../",
		"/..%2f",
		"/..%2f..%2f",
		"/..%2f..%2f..%2f",
		"/./",
		"/.//",
		"/.%00",
		"/.%00/",
		"/.randomstring",
		"/../",
		"/../;/",
		"/../;/../",
		"/../.;/../",
		"/../..;/",
		"/../../",
		"/../../../",
		"/../../..//",
		"/../..//",
		"/../..//../",
		"/.././../",
		"/..//",
		"/..//..;/",
		"/..//../",
		"/..//../../",
		"/..%2f",
		"/..%2f..%2f",
		"/..%2f..%2f..%2f",
		"/./",
		"/.//",
		"/.%00",
		"/.%00/",
		"/.randomstring",
	}

	results := make(chan struct {
		payload string
		retries int32
		err     error
	}, len(payloads))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent requests

	// Launch goroutine to process payloads
	for i, _payload := range payloads {
		wg.Add(1)
		go func(p string, idx int) {
			defer wg.Done()

			// Acquire semaphore
			t.Logf("Goroutine %d: Waiting for semaphore", idx)
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			t.Logf("Goroutine %d: Got semaphore, processing payload: %s", idx, p)

			// Each goroutine gets its own request/response objects
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			fullURL := baseURL + p
			req.SetRequestURI(fullURL)
			t.Logf("Goroutine %d: Sending request to %s", idx, fullURL)

			_, err := client.DoRequest(req, resp, payload.BypassPayload{})
			t.Logf("Goroutine %d: Got response with error: %v", idx, err)

			results <- struct {
				payload string
				retries int32
				err     error
			}{
				payload: p,
				retries: client.GetPerReqRetryAttempts(),
				err:     err,
			}
			t.Logf("Goroutine %d: Sent result to channel", idx)
		}(_payload, i)
	}

	t.Log("All goroutines launched, waiting for completion")

	// Start a goroutine to close results channel when all work is done
	go func() {
		t.Log("Waiting for all goroutines to complete")
		wg.Wait()
		t.Log("All goroutines completed, closing results channel")
		close(results)
	}()

	// Collect results with a timeout
	timeout := time.After(25 * time.Second)
	resultCount := 0

	t.Log("Starting to collect results")
	for resultCount < len(payloads) {
		select {
		case result, ok := <-results:
			if !ok {
				t.Log("Results channel closed")
				return
			}
			t.Logf("Got result %d/%d", resultCount+1, len(payloads))
			t.Logf("Payload: %s", result.payload)
			t.Logf("  Retries: %d", result.retries)
			t.Logf("  Error: %v", result.err)
			t.Logf("---")
			resultCount++
		case <-timeout:
			t.Fatal("Test timed out waiting for results")
			return
		}
	}

	t.Log("All results collected")
}

var requestCount int32

func TestRetryWithLargeResponse(t *testing.T) {
	requestCount = 0

	// Create response body that exceeds the client's response-body limit.
	// NewHTTPClient clamps MaxResponseBodySize up to at least
	// headers+preview+padding (8192+1024+1024 = 10240), so the declared
	// Content-Length must exceed 10240 for the limit to trip at all.
	largeBody := make([]byte, 20000)
	for i := range largeBody {
		largeBody[i] = 'A'
	}

	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Start raw server: 200 with a Content-Length larger than the client's
	// effective MaxResponseBodySize (10240 after clamping) -> ErrBodyTooLarge
	// once the headers have already been parsed.
	serveRaw(ln, func(*rawRequest) []byte {
		count := atomic.AddInt32(&requestCount, 1)
		t.Logf("Server: handling request attempt %d", count)
		t.Logf("Server: sent large response for attempt %d", count)
		return rawResp(200, [][2]string{{"Content-Length", "20000"}}, string(largeBody))
	})

	// Create client options with small max response size
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.MaxRetries = 2
	opts.Timeout = 500 * time.Millisecond
	opts.RetryDelay = 100 * time.Millisecond
	opts.MaxResponseBodySize = 1030
	opts.MaxConnsPerHost = 100
	//opts.ReadBufferSize = 1030
	//opts.WriteBufferSize = 1030
	opts.StreamResponseBody = false

	// Set up the dialer to use our in-memory listener
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(opts)
	defer client.Close()

	// Test with a single request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://localhost/test") // The actual URL doesn't matter with our custom dialer
	t.Log("Sending request...")

	_, err := client.DoRequest(req, resp, payload.BypassPayload{})
	t.Logf("Request completed with error: %v", err)

	// Contract for oversized responses: ErrBodyTooLarge is whitelisted in
	// defaultWhitelistedErrorsStr, and ReadLimitBody parses the status line
	// and headers before rejecting the body. DoRequest therefore reports
	// success with the status code intact, and no retry loop fires (the fork
	// explicitly does not retry ErrBodyTooLarge, and the rawhttp whitelist
	// converts it to a handled success).
	if err != nil {
		t.Errorf("Oversized response should be accepted (status only), got error: %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Errorf("Expected status 200 despite oversized body, got %d", resp.StatusCode())
	}
	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Errorf("Expected exactly 1 request to the server (no retries), got %d", got)
	}
}

func TestRetryWithConcurrentRequests(t *testing.T) {
	const (
		concurrentRequests = 500
		requestDuration    = 5 * time.Second
	)

	requestCount := atomic.Int32{}
	retryCount := atomic.Int32{}
	errorCount := atomic.Int32{}

	// Create server
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	serveRaw(ln, func(*rawRequest) []byte {
		requestCount.Add(1)
		// Content-Length 20000 exceeds the client's effective
		// MaxResponseBodySize (10240 after NewHTTPClient clamping) ->
		// ErrBodyTooLarge after the headers are parsed.
		return rawResp(200, [][2]string{{"Content-Length", "20000"}}, string(make([]byte, 20000)))
	})

	// Create client
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.MaxRetries = 2
	opts.Timeout = 500 * time.Millisecond
	opts.RetryDelay = 20 * time.Millisecond // Shorter delay for stress test
	opts.MaxResponseBodySize = 1030
	opts.MaxConnsPerHost = 100
	//opts.ReadBufferSize = 1030
	//opts.WriteBufferSize = 1030
	opts.StreamResponseBody = false
	opts.MaxConnsPerHost = 1000 // Allow many concurrent connections
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(opts)
	defer client.Close()

	// Start concurrent requests
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(num int) {
			defer wg.Done()

			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			req.SetRequestURI("http://localhost/test")
			_, err := client.DoRequest(req, resp, payload.BypassPayload{})

			if err != nil {
				errorCount.Add(1)
				if errors.Is(err, fasthttp.ErrBodyTooLarge) {
					retryCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	t.Logf("Completed %d requests in %v", concurrentRequests, duration)
	t.Logf("Total requests to server: %d", requestCount.Load())
	t.Logf("Requests that saw oversized-body marker: %d", retryCount.Load())
	t.Logf("Total errors: %d", errorCount.Load())

	// Oversized responses are whitelisted successes (status code delivered,
	// body rejected, no retries): every request completes without error and
	// hits the server exactly once.
	if errorCount.Load() != 0 {
		t.Errorf("Expected no errors (whitelisted oversized responses), got %d", errorCount.Load())
	}
	if requestCount.Load() != concurrentRequests {
		t.Errorf("Expected exactly %d server hits (no retries), got %d", concurrentRequests, requestCount.Load())
	}
}

func TestRetryWhitespaceFirstLine(t *testing.T) {
	GB403Logger.DefaultLogger.EnableDebug()

	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Track connection attempts
	connectionAttempts := atomic.Int32{}

	// Start server that sends a malformed response on the first attempt,
	// then a proper one
	serveRawResult(ln, func(*rawRequest) rawResult {
		attempts := connectionAttempts.Add(1)
		t.Logf("Server handling attempt %d", attempts)

		if attempts == 1 {
			// First attempt: send malformed response, then EOF
			t.Logf("Server sending malformed response")
			return rawResult{Data: []byte("TRaILeR:,\n\n"), Close: true}
		}
		// Subsequent attempts: send proper response
		t.Logf("Server sending proper response")
		return rawResult{Data: rawResp(200, nil, "success"), Close: true}
	})

	// Create client options
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.MaxRetries = 4
	opts.Timeout = 2 * time.Second
	opts.RetryDelay = 100 * time.Millisecond

	// Set up the dialer to use our in-memory listener
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(opts)
	defer client.Close()

	// Prepare request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://localhost/test")

	// Execute request
	_, err := client.DoRequest(req, resp, payload.BypassPayload{})
	t.Logf("DoRequest returned error: %v", err)

	// Log for debugging
	t.Logf("Final error: %v", err)
	t.Logf("Retry attempts: %d", client.GetPerReqRetryAttempts())
	t.Logf("Connection attempts: %d", connectionAttempts.Load())

	// Assertions. Retry ownership here lives in the fasthttp fork's internal
	// idempotent retry loop (DefaultMaxIdemponentCallAttempts=5); rawhttp's
	// GetPerReqRetryAttempts only counts handleRetries-driven retries, which
	// never fire when the fork recovers internally. Observable contract: the
	// first malformed line is tolerated, the second attempt succeeds.
	assert.NoError(t, err, "Expected successful request after retries")
	assert.Equal(t, "success", string(resp.Body()), "Expected success response")
	assert.Equal(t, int32(2), connectionAttempts.Load(), "Expected exactly 2 connection attempts")

	GB403ErrorHandler.GetErrorHandler().PrintErrorStats()
}
