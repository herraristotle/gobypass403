package tests

import (
	"net"
	"testing"
	"time"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
	"github.com/stretchr/testify/assert"
	"github.com/herraristotle/fasthttp"
	"github.com/herraristotle/fasthttp/fasthttputil"
)

func TestRequestWorkerPoolThrottle(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Canned handler: 429, 429 (with delay), then 200 — emulates the original
	// stateful fasthttp handler. The guarded counter preserves the original
	// requestCount++ semantics without the data race.
	counter := &guardedCounter{}
	srv := serveRaw(ln, func(*rawRequest) []byte {
		n := counter.next()

		// Add artificial delay to better observe throttling
		switch n {
		case 1:
			t.Logf("Server: Request %d - Returning 429", n)
			return rawStatus(429)
		case 2:
			t.Logf("Server: Request %d - Returning 429", n)
			time.Sleep(100 * time.Millisecond) // Add delay
			return rawStatus(429)
		default:
			t.Logf("Server: Request %d - Returning 200", n)
			return rawStatus(200)
		}
	})

	// Create client options with custom dialer. AutoThrottle must be enabled:
	// the throttler is nil otherwise, so the third request would race ahead
	// of the delayed second 429 instead of being throttled behind it, and
	// this test's completion-order contract ([429, 429, 200]) depends on the
	// 200ms+ throttle delay landing after the server's 100ms sleep.
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.AutoThrottle = true
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool with smaller worker count
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 2) // Reduced workers
	defer pool.Close()

	// Log initial pool stats
	t.Logf("Initial pool stats - Active workers: %d, Submitted tasks: %d",
		pool.GetReqWPActiveWorkers(),
		pool.GetReqWPSubmittedTasks())

	// Create test jobs (Method is required: BuildRawHTTPRequest round-trips
	// the raw line through the fork's parser, which rejects an empty method)
	jobs := []payload.BypassPayload{
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test1",
			Method:       "GET",
			BypassModule: "test-throttle",
		},
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test2",
			Method:       "GET",
			BypassModule: "test-throttle",
		},
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test3",
			Method:       "GET",
			BypassModule: "test-throttle",
		},
	}

	start := time.Now()
	resultsChan := pool.ProcessRequests(jobs)
	var results []*rawhttp.RawHTTPResponseDetails

	// Monitor pool stats during processing
	statsDone := make(chan bool)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.Logf("Pool stats - Active Workers: %d, Submitted: %d, Waiting: %d, Completed: %d",
					pool.GetReqWPActiveWorkers(),
					pool.GetReqWPSubmittedTasks(),
					pool.GetReqWPWaitingTasks(),
					pool.GetReqWPCompletedTasks())
			case <-statsDone:
				return
			}
		}
	}()

	// Collect results with timeout
	timeout := time.After(5 * time.Second)
	done := make(chan bool)

	go func() {
		for result := range resultsChan {
			if result != nil {
				t.Logf("Received result - Status: %d, Time since start: %v",
					result.StatusCode,
					time.Since(start))
				results = append(results, result)
			}
			if len(results) == len(jobs) {
				done <- true
				return
			}
		}
		done <- false
	}()

	// Wait for completion or timeout
	select {
	case success := <-done:
		if !success {
			t.Fatal("Not all results received")
		}
	case <-timeout:
		t.Fatal("Test timed out")
	}

	close(statsDone)

	// Log final stats
	t.Logf("Final pool stats - Active Workers: %d, Submitted: %d, Completed: %d",
		pool.GetReqWPActiveWorkers(),
		pool.GetReqWPSubmittedTasks(),
		pool.GetReqWPCompletedTasks())

	// Verify results
	if len(results) != len(jobs) {
		t.Fatalf("Expected %d results, got %d", len(jobs), len(results))
	}

	// Verify status codes and timing
	for i, result := range results {
		t.Logf("Result %d - Status: %d", i+1, result.StatusCode)
	}

	assert.Equal(t, fasthttp.StatusTooManyRequests, results[0].StatusCode, "First request should be 429")
	assert.Equal(t, fasthttp.StatusTooManyRequests, results[1].StatusCode, "Second request should be 429")
	assert.Equal(t, fasthttp.StatusOK, results[2].StatusCode, "Third request should be 200")

	// Clean up
	ln.Close()
	<-srv.Done
}
