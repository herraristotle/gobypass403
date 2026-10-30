package tests

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/rawhttp"
)

// collectAndSendPayloads sends generated payloads to a raw TCP test server and
// returns everything the server received. Payload count must be small: this is
// a wire-format round-trip check, not a payload-generation test.
func collectAndSendPayloads(t *testing.T, generatedPayloads []payload.BypassPayload) []RequestData {
	t.Helper()

	numPayloads := len(generatedPayloads)
	if numPayloads == 0 {
		t.Fatalf("No payloads to send")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	serverAddr := listener.Addr().String()

	// Patch payload destinations to the actual test server
	for i := range generatedPayloads {
		generatedPayloads[i].Scheme = "http"
		generatedPayloads[i].Host = serverAddr
	}

	receivedDataChan := make(chan RequestData, numPayloads)
	stopServer := startRawTestServerWithListener(t, listener, receivedDataChan)
	defer stopServer()

	var collectedRequests []RequestData
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for reqData := range receivedDataChan {
			collectedRequests = append(collectedRequests, reqData)
		}
	}()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 3 * time.Second
	clientOpts.MaxRetries = 0
	clientOpts.MaxConsecutiveFailedReqs = numPayloads + 10

	wp := rawhttp.NewRequestWorkerPool(clientOpts, 25)
	defer wp.Close()

	resultsChan := wp.ProcessRequests(generatedPayloads)
	responseCount := 0
	for range resultsChan {
		responseCount++
	}
	if responseCount != numPayloads {
		t.Errorf("Client processed %d responses out of %d payloads", responseCount, numPayloads)
	}

	stopServer()
	close(receivedDataChan)
	collectWg.Wait()

	return collectedRequests
}

// TestPOSTBodyReachesWireVerbatim verifies that a user-specified method and
// body (-X POST --data) flow through payload generation into the raw requests
// actually sent on the wire, including an auto-computed Content-Length.
func TestPOSTBodyReachesWireVerbatim(t *testing.T) {
	body := "user=admin&role=root"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    "http://127.0.0.1/admin/config/users",
		BypassModule: "mid_paths",
		Method:       "POST",
		Body:         body,
	})
	allPayloads := pg.GenerateMidPathsPayloads("http://127.0.0.1/admin/config/users", "mid_paths")
	if len(allPayloads) == 0 {
		t.Fatal("No payloads generated for mid_paths")
	}

	// Wire-format check: a small subset is enough
	if len(allPayloads) > 25 {
		allPayloads = allPayloads[:25]
	}

	collected := collectAndSendPayloads(t, allPayloads)
	if len(collected) == 0 {
		t.Fatal("Server received no requests")
	}

	expectedCL := fmt.Sprintf("Content-Length: %d", len(body))
	for i, req := range collected {
		if !strings.HasPrefix(req.FullRequest, "POST ") {
			t.Errorf("request %d: request line is not POST: %q", i, firstLine(req.FullRequest))
		}
		if !strings.Contains(req.FullRequest, expectedCL) {
			t.Errorf("request %d: missing %s header in:\n%s", i, expectedCL, req.FullRequest)
		}
		parts := strings.SplitN(req.FullRequest, "\r\n\r\n", 2)
		if len(parts) != 2 {
			t.Errorf("request %d: no header/body separator in:\n%s", i, req.FullRequest)
			continue
		}
		if parts[1] != body {
			t.Errorf("request %d: body = %q, want %q", i, parts[1], body)
		}
	}
}

// TestCustomMethodReachesWire verifies a non-standard user method (-X PUT)
// reaches the wire verbatim together with the body.
func TestCustomMethodReachesWire(t *testing.T) {
	body := `{"probe":true}`

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    "http://127.0.0.1/admin/config/users",
		BypassModule: "dumb_check",
		Method:       "PUT",
		Body:         body,
	})
	payloads := pg.GenerateDumbCheckPayload("http://127.0.0.1/admin/config/users", "dumb_check")
	if len(payloads) != 1 {
		t.Fatalf("dumb_check generated %d payloads, want 1", len(payloads))
	}

	collected := collectAndSendPayloads(t, payloads)
	if len(collected) != 1 {
		t.Fatalf("Server received %d requests, want 1", len(collected))
	}

	req := collected[0].FullRequest
	if !strings.HasPrefix(req, "PUT ") {
		t.Errorf("request line is not PUT: %q", firstLine(req))
	}
	parts := strings.SplitN(req, "\r\n\r\n", 2)
	if len(parts) != 2 || parts[1] != body {
		t.Errorf("body not received verbatim in:\n%s", req)
	}
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx != -1 {
		return s[:idx]
	}
	return s
}
