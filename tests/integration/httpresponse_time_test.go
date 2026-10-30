package tests

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
	"github.com/herraristotle/fasthttp"
	"github.com/herraristotle/fasthttp/fasthttputil"
)

// simpleDelayedResp emulates the original fasthttp handler: 200 with body
// and a 50 ms processing delay.
func simpleDelayedResp(*rawRequest) []byte {
	// Simulate some processing delay.
	time.Sleep(50 * time.Millisecond)
	return rawResp(200, nil, "Hello, world!")
}

func TestClientResponseTimeSequential(t *testing.T) {
	// Create an in-memory listener for the server.
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Start the raw in-memory server with our canned handler.
	serveRaw(ln, simpleDelayedResp)

	// Create custom dialer that uses the in-memory listener.
	dialer := func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create HTTP client options; assign the custom dialer.
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.Dialer = dialer
	// Make sure no extra client-level delay is applied.
	opts.RequestDelay = 0

	// For testing, we pass nil for the error handler.
	client := rawhttp.NewHTTPClient(opts)

	// Acquire request and response instances from the client.
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod("GET")
	// The URL here is not used by the dialer (it always dials on ln) but still needs to be set.
	req.SetRequestURI("http://example.com/")

	// Perform the request.
	directResponseTime, err := client.DoRequest(req, resp, payload.BypassPayload{})
	if err != nil {
		t.Fatalf("DoRequest error: %v", err)
	}

	// Get response time via getter
	getterResponseTime := client.GetLastResponseTime()

	// Log both times for comparison
	t.Logf("Direct Response Time: %d ms", directResponseTime)
	t.Logf("Getter Response Time: %d ms", getterResponseTime)

	// Verify they match
	if directResponseTime != getterResponseTime {
		t.Errorf("Response time mismatch: direct=%d ms, getter=%d ms",
			directResponseTime, getterResponseTime)
	}

	// Additionally, check the status code.
	if status := resp.StatusCode(); status != fasthttp.StatusOK {
		t.Errorf("Expected status %d but got %d", fasthttp.StatusOK, status)
	}
}

// TestClientResponseTimeConcurrent spins up multiple concurrent requests
// using the same client instance and then prints the response time captured
// in the shared client field.
// Note: Because the client field is shared across all goroutines, the retrieved
// response time may not accurately reflect each individual request.
func TestClientResponseTimeConcurrent(t *testing.T) {
	// Create an in-memory listener.
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Start the raw in-memory server with our canned handler.
	serveRaw(ln, simpleDelayedResp)

	dialer := func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	opts := rawhttp.DefaultHTTPClientOptions()
	opts.Dialer = dialer
	opts.RequestDelay = 0

	client := rawhttp.NewHTTPClient(opts)
	const numRequests = 50

	// Define result structure
	type requestResult struct {
		index              int
		directResponseTime int64
		getterResponseTime int64
		error              error
	}

	// Create buffered channel for results
	results := make(chan requestResult, numRequests)
	var wg sync.WaitGroup

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			req.Header.SetMethod("GET")
			req.SetRequestURI("http://example.com/")

			// Get direct response time from DoRequest
			directRT, err := client.DoRequest(req, resp, payload.BypassPayload{})
			// Get response time via getter
			getterRT := client.GetLastResponseTime()

			// Send results to channel
			results <- requestResult{
				index:              idx,
				directResponseTime: directRT,
				getterResponseTime: getterRT,
				error:              err,
			}
		}(i)
	}

	// Close results channel after all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and analyze results
	var totalDirect, totalGetter int64
	var count int
	mismatchCount := 0

	// Process results as they come in
	for result := range results {
		if result.error != nil {
			t.Errorf("Request %d failed: %v", result.index, result.error)
			continue
		}

		t.Logf("Request %d - Direct RT: %d ms, Getter RT: %d ms",
			result.index, result.directResponseTime, result.getterResponseTime)

		if result.directResponseTime != result.getterResponseTime {
			mismatchCount++
		}

		totalDirect += result.directResponseTime
		totalGetter += result.getterResponseTime
		count++
	}

	// Print summary statistics
	t.Logf("Summary:")
	t.Logf("Total Requests: %d", count)
	t.Logf("Average Direct RT: %d ms", totalDirect/int64(count))
	t.Logf("Average Getter RT: %d ms", totalGetter/int64(count))
	t.Logf("Number of RT mismatches: %d", mismatchCount)
}
