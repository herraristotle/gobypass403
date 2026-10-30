package tests

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
	GB403ErrorHandler "github.com/herraristotle/gobypass403/core/utils/error"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

// setupInMemoryServer starts a raw canned-response server (200 "OK") on an
// in-memory listener. The vendored fasthttp fork is client-only — there is no
// fasthttp.Server — so the returned stand-in's Shutdown() just closes the
// listener, which stops the accept loop (see bench_server_test.go).
func setupInMemoryServer() (*benchServer, *fasthttputil.InmemoryListener) {
	ln := fasthttputil.NewInmemoryListener()
	resp := rawBenchResp("200 OK", "text/plain", "OK")
	serveBench(ln, func() []byte { return resp })
	return &benchServer{ln: ln, stop: func() { _ = ln.Close() }}, ln
}

// BenchmarkDoRequest benchmarks the DoRequest function with different payload sizes
func BenchmarkDoRequest(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	// Benchmarks disable response streaming: with the fork's streaming default
	// the pooled conn is only released once the body is drained, and these
	// benchmarks never read bodies (they would exhaust MaxConnsPerHost).
	clientOpts.StreamResponseBody = false
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	tests := []struct {
		name    string
		payload []byte
	}{
		{"SmallPayload", []byte("small payload")},
		{"MediumPayload", make([]byte, 1024)},     // 1KB
		{"LargePayload", make([]byte, 1024*1024)}, // 1MB
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			bypassPayload := payload.BypassPayload{}

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				// Each goroutine gets its own request and response
				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				req.SetRequestURI("http://localhost")
				req.SetBody(tt.payload)

				for pb.Next() {
					_, err := client.DoRequest(req, resp, bypassPayload)
					if err != nil {
						b.Fatal(err)
					}
					resp.Reset() // Reset response for reuse
				}
			})
		})
	}
}

func BenchmarkDoRequestAllocs(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	// Benchmarks disable response streaming: with the fork's streaming default
	// the pooled conn is only released once the body is drained, and these
	// benchmarks never read bodies (they would exhaust MaxConnsPerHost).
	clientOpts.StreamResponseBody = false
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://localhost")
	req.SetBody([]byte("test"))

	bypassPayload := payload.BypassPayload{}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := client.DoRequest(req, resp, bypassPayload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDoRequestAllocsDetailed(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	// Benchmarks disable response streaming: with the fork's streaming default
	// the pooled conn is only released once the body is drained, and these
	// benchmarks never read bodies (they would exhaust MaxConnsPerHost).
	clientOpts.StreamResponseBody = false
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	// Track individual components with ReportAllocs
	b.Run("setup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			req.SetRequestURI("http://localhost")
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		}
	})

	b.Run("payload", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = payload.BypassPayload{}
		}
	})

	// Full request with tracing
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("http://localhost")
	bypassPayload := payload.BypassPayload{}

	b.Run("full_request", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := client.DoRequest(req, resp, bypassPayload)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRequestComponents(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	// Benchmarks disable response streaming: with the fork's streaming default
	// the pooled conn is only released once the body is drained, and these
	// benchmarks never read bodies (they would exhaust MaxConnsPerHost).
	clientOpts.StreamResponseBody = false
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("http://localhost")
	bypassPayload := payload.BypassPayload{}

	b.Run("just_request_copy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reqCopy := fasthttp.AcquireRequest()
			rawhttp.ReqCopyToWithSettings(req, reqCopy)
			fasthttp.ReleaseRequest(reqCopy)
		}
	})

	b.Run("just_do_request", func(b *testing.B) {
		b.ReportAllocs()
		reqCopy := fasthttp.AcquireRequest()
		rawhttp.ReqCopyToWithSettings(req, reqCopy)
		for i := 0; i < b.N; i++ {
			_, err := client.DoRequest(reqCopy, resp, bypassPayload)
			if err != nil {
				b.Fatal(err)
			}
		}
		fasthttp.ReleaseRequest(reqCopy)
	})

	b.Run("error_context_with_handler", func(b *testing.B) {
		b.ReportAllocs()
		testErr := fmt.Errorf("test error")
		for i := 0; i < b.N; i++ {
			errCtx := GB403ErrorHandler.ErrorContext{
				ErrorSource:  "execFunc",
				Host:         payload.BypassPayloadToBaseURL(bypassPayload),
				BypassModule: bypassPayload.BypassModule,
				DebugToken:   bypassPayload.PayloadToken,
			}
			_ = GB403ErrorHandler.GetErrorHandler().HandleError(testErr, errCtx)
		}
	})
}

// BenchmarkDoRequestWithRetry benchmarks DoRequest with retry mechanism
func BenchmarkDoRequestWithRetry(b *testing.B) {
	var failCount int32
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Same cadence as the old fasthttp.Server handler: every 3rd request 503.
	resp503 := rawBenchResp("503 Service Unavailable", "text/plain", "")
	resp200 := rawBenchResp("200 OK", "text/plain", "OK")
	serveBench(ln, func() []byte {
		if atomic.AddInt32(&failCount, 1)%3 == 0 {
			return resp503
		}
		return resp200
	})

	clientOpts := &rawhttp.HTTPClientOptions{
		Timeout:    5 * time.Second,
		MaxRetries: 3,
		RetryDelay: 100 * time.Millisecond,
		// See the StreamResponseBody note above: keep pooled conns reusable
		// for benchmarks that never drain response bodies.
		StreamResponseBody: false,
		Dialer: func(addr string) (net.Conn, error) {
			return ln.Dial()
		},
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	bypassPayload := payload.BypassPayload{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := fasthttp.AcquireRequest()
		req.SetRequestURI("http://localhost")

		_, err := client.DoRequest(req, nil, bypassPayload)
		if err != nil {
			b.Fatal(err)
		}

		fasthttp.ReleaseRequest(req)
	}
}

// BenchmarkDoRequestWithDifferentMethods benchmarks different HTTP methods
func BenchmarkDoRequestWithDifferentMethods(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	// Benchmarks disable response streaming: with the fork's streaming default
	// the pooled conn is only released once the body is drained, and these
	// benchmarks never read bodies (they would exhaust MaxConnsPerHost).
	clientOpts.StreamResponseBody = false
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}
	bypassPayload := payload.BypassPayload{}

	//rawhttp.BuildRawHTTPRequest(client, req, bypassPayload)

	for _, method := range methods {
		b.Run(method, func(b *testing.B) {
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			req.SetRequestURI("http://localhost")
			req.Header.SetMethod(method)

			if method == "POST" || method == "PUT" {
				req.SetBody([]byte("test body"))
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := client.DoRequest(req, resp, bypassPayload) // Use resp instead of nil
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDoRequestWithHeaders benchmarks requests with different header sizes
func BenchmarkDoRequestWithHeaders(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())
	defer client.Close()

	tests := []struct {
		name         string
		headerCount  int
		headerLength int
	}{
		{"SmallHeaders", 5, 10},
		{"MediumHeaders", 20, 50},
		{"LargeHeaders", 50, 100},
	}

	bypassPayload := payload.BypassPayload{}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)

			req.SetRequestURI("http://localhost")

			// Add headers
			for i := 0; i < tt.headerCount; i++ {
				headerValue := make([]byte, tt.headerLength)
				req.Header.Set(fmt.Sprintf("Header-%d", i), string(headerValue))
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := client.DoRequest(req, nil, bypassPayload)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
