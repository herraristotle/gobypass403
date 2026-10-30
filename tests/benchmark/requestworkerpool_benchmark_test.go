package tests

import (
	"fmt"
	"net"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
	"github.com/herraristotle/fasthttp"
	"github.com/herraristotle/fasthttp/fasthttputil"
)

func BenchmarkProcessRequests(b *testing.B) {
	// Create pool with all dependencies properly initialized
	pool := rawhttp.NewRequestWorkerPool(rawhttp.DefaultHTTPClientOptions(), 10)

	// Create test response
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Setup response data
	resp.SetStatusCode(200)
	resp.SetBody([]byte("<!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>"))
	resp.Header.SetContentType("text/html")
	resp.Header.Set("Server", "test-server")

	// Setup test job
	job := payload.BypassPayload{
		Scheme:       "http",
		Host:         "example.com",
		RawURI:       "/test",
		Method:       "GET",
		Headers:      []payload.Headers{{Header: "Accept", Value: "*/*"}},
		BypassModule: "test-mode",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.ProcessRequests([]payload.BypassPayload{job})
		}
	})
}

func BenchmarkProcessRequests2(b *testing.B) {
	pool := rawhttp.NewRequestWorkerPool(rawhttp.DefaultHTTPClientOptions(), 10)

	baseJob := payload.BypassPayload{
		Scheme:       "http",
		Host:         "example.com",
		RawURI:       "/test",
		Method:       "GET",
		Headers:      []payload.Headers{{Header: "Accept", Value: "*/*"}},
		BypassModule: "test-mode",
	}

	jobs := make([]payload.BypassPayload, 2000)
	for i := range jobs {
		jobs[i] = baseJob
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			count := 0
			for range pool.ProcessRequests(jobs) {
				count++
			}
			// Optionally verify count if needed
			// if count == 0 {
			//     b.Fatal("No results received")
			// }
		}
	})
}

func BenchmarkProcessRequests3(b *testing.B) {
	// Setup mock server
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Start mock server: raw canned response (the vendored fasthttp fork is
	// client-only — fasthttp.Serve/fasthttp.RequestCtx don't exist).
	body := "<!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>"
	respBytes := []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: test-server\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body))
	serveBench(ln, func() []byte { return respBytes })

	// Create custom client options with mock dialer
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	pool := rawhttp.NewRequestWorkerPool(opts, 10)
	defer pool.Close()

	baseJob := payload.BypassPayload{
		Scheme:       "http",
		Host:         "example.com",
		RawURI:       "/test",
		Method:       "GET",
		Headers:      []payload.Headers{{Header: "Accept", Value: "*/*"}},
		BypassModule: "test-mode",
	}

	jobs := make([]payload.BypassPayload, 2000)
	for i := range jobs {
		jobs[i] = baseJob
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			count := 0
			for result := range pool.ProcessRequests(jobs) {
				if result != nil {
					count++
				}
			}
			if count == 0 {
				b.Error("No results received")
			}
		}
	})
}
