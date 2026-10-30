package tests

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
	GB403Logger "github.com/herraristotle/gobypass403/core/utils/logger"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestClient301RedirectInmemory(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup redirect handler
	redirectHandler := func(*rawRequest) []byte {
		return rawResp(301, [][2]string{{"Location", "https://redirected.com/newpath"}}, "")
	}

	// Start raw in-memory server
	srv := serveRaw(ln, redirectHandler)

	// Create client options with custom dialer
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 10)

	// Create test payload
	jobs := []payload.BypassPayload{
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test",
			Method:       "GET",
			BypassModule: "test-redirect",
			Headers:      []payload.Headers{},
			PayloadToken: "test-token",
		},
	}

	// Process request and get results channel
	resultsChan := pool.ProcessRequests(jobs)

	// Read result
	var result *rawhttp.RawHTTPResponseDetails
	select {
	case result = <-resultsChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}

	// Verify results
	if result == nil {
		t.Fatal("no result received")
	}

	GB403Logger.PrintGreen("Result Status Code: %v\n", result.StatusCode)
	GB403Logger.PrintGreen("Result Redirect URL: %s\n", string(result.RedirectURL))
	GB403Logger.PrintGreen("Result Response Headers: %s\n", string(result.ResponseHeaders))

	// Check status code
	if result.StatusCode != fasthttp.StatusMovedPermanently {
		t.Errorf("unexpected status code: got %d, want %d",
			result.StatusCode, fasthttp.StatusMovedPermanently)
	}

	// Check redirect URL
	expectedLocation := "https://redirected.com/newpath"
	if string(result.RedirectURL) != expectedLocation {
		t.Errorf("unexpected location: got %q, want %q",
			string(result.RedirectURL), expectedLocation)
	}

	GB403Logger.Info().Msgf("Location: %s\n", string(result.RedirectURL))

	// Cleanup
	ln.Close()

	// Wait for server shutdown
	select {
	case <-srv.Done:
	case <-time.After(time.Second):
		t.Fatal("server shutdown timeout")
	}
}

func TestClient302RedirectCaseInsensitive(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Raw server: lowercase 'location' header preserved byte-for-byte.
	serveRaw(ln, func(*rawRequest) []byte {
		return rawResp(302, [][2]string{{"location", "https://redirected.com/newpath"}}, "")
	})

	// Create client options with custom dialer
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 10)

	// Create test payload
	jobs := []payload.BypassPayload{
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test",
			Method:       "GET",
			BypassModule: "test-redirect",
			Headers:      []payload.Headers{},
			PayloadToken: "test-token",
		},
	}

	// Process request and get results
	resultsChan := pool.ProcessRequests(jobs)

	// Read result
	var result *rawhttp.RawHTTPResponseDetails
	select {
	case result = <-resultsChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}

	// Verify results
	if result == nil {
		t.Fatal("no result received")
	}

	GB403Logger.PrintGreen("Result Status Code: %v\n", result.StatusCode)
	GB403Logger.PrintGreen("Result Redirect URL: %s\n", string(result.RedirectURL))
	GB403Logger.PrintGreen("Result Response Headers: %s\n", string(result.ResponseHeaders))

	expectedLocation := "https://redirected.com/newpath"
	if string(result.RedirectURL) != expectedLocation {
		t.Errorf("unexpected location: got %q, want %q",
			string(result.RedirectURL), expectedLocation)
	}
}

func TestRequestDelay(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Track request timestamps
	var requestTimes []time.Time
	var mu sync.Mutex

	// Setup handler that records request times
	handler := func(*rawRequest) []byte {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()
		return rawStatus(200)
	}

	// Start raw in-memory server
	srv := serveRaw(ln, handler)

	// Create client options with delay
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.RequestDelay = 3 * time.Second
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool with a single worker: the3s RequestDelay is applied
	// per request inside DoRequest, so only serial execution produces the
	// ~3s intervals this test asserts (10 workers would sleep in parallel).
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 1)

	// Create test payloads
	jobs := []payload.BypassPayload{
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test1",
			Method:       "GET",
			BypassModule: "test-delay",
			Headers:      []payload.Headers{},
			PayloadToken: "test-token-1",
		},
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test2",
			Method:       "GET",
			BypassModule: "test-delay",
			Headers:      []payload.Headers{},
			PayloadToken: "test-token-2",
		},
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test3",
			Method:       "GET",
			BypassModule: "test-delay",
			Headers:      []payload.Headers{},
			PayloadToken: "test-token-3",
		},
	}

	// Process requests
	resultsChan := pool.ProcessRequests(jobs)

	// Collect results
	var results []*rawhttp.RawHTTPResponseDetails
	for result := range resultsChan {
		results = append(results, result)
	}

	// Verify results count
	if len(results) != len(jobs) {
		t.Errorf("expected %d results, got %d", len(jobs), len(results))
	}

	// Verify delays between requests
	mu.Lock()
	if len(requestTimes) < 2 {
		mu.Unlock()
		t.Fatal("not enough requests recorded")
	}

	// Check intervals
	for i := 1; i < len(requestTimes); i++ {
		interval := requestTimes[i].Sub(requestTimes[i-1])
		if interval < 2800*time.Millisecond || interval > 3200*time.Millisecond {
			t.Errorf("unexpected interval between requests %d and %d: got %v, want ~3s",
				i-1, i, interval)
		}
	}
	mu.Unlock()

	// Cleanup
	ln.Close()
	<-srv.Done
}

// go.exe test -timeout 30s -run ^TestRequestDelayWithMultipleWorkers$ github.com/herraristotle/gobypass403/tests/integration -v
// === RUN   TestRequestDelayWithMultipleWorkers
// --- PASS: TestRequestDelayWithMultipleWorkers (6.00s)
// PASS
// ok  	github.com/herraristotle/gobypass403/tests/integration	7.525s
func TestRequestDelayWithMultipleWorkers(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Just track request timestamps
	var timestamps []time.Time
	var mu sync.Mutex

	// Simple handler that just records timestamps
	handler := func(*rawRequest) []byte {
		mu.Lock()
		timestamps = append(timestamps, time.Now())
		mu.Unlock()
		return rawStatus(200)
	}

	// Start raw in-memory server
	srv := serveRaw(ln, handler)

	// Create client with 3s delay
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.RequestDelay = 3 * time.Second
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create pool with 3 workers
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 3)

	// Create 6 test jobs
	jobs := []payload.BypassPayload{
		{Scheme: "http", Host: "example.com", RawURI: "/test1", Method: "GET"},
		{Scheme: "http", Host: "example.com", RawURI: "/test2", Method: "GET"},
		{Scheme: "http", Host: "example.com", RawURI: "/test3", Method: "GET"},
		{Scheme: "http", Host: "example.com", RawURI: "/test4", Method: "GET"},
		{Scheme: "http", Host: "example.com", RawURI: "/test5", Method: "GET"},
		{Scheme: "http", Host: "example.com", RawURI: "/test6", Method: "GET"},
	}

	// Process requests and collect results
	start := time.Now()
	resultsChan := pool.ProcessRequests(jobs)
	var results []*rawhttp.RawHTTPResponseDetails
	for result := range resultsChan {
		results = append(results, result)
	}

	// Total time should be ~6s (2 requests per worker with 3s delay)
	totalTime := time.Since(start)
	if totalTime > 7*time.Second {
		t.Errorf("Requests took too long: %v", totalTime)
	}
	if totalTime < 5*time.Second {
		t.Errorf("Requests too fast, delay not working: %v", totalTime)
	}

	// Verify we got all results
	if len(results) != len(jobs) {
		t.Errorf("expected %d results, got %d", len(jobs), len(results))
	}

	// Cleanup
	ln.Close()
	<-srv.Done
}
