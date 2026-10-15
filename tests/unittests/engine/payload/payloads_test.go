package tests

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// RequestData holds both the URI and full raw HTTP request received by the test server
type RequestData struct {
	URI         string // The URI portion of the request
	FullRequest string // The complete raw HTTP request (including request line, headers, body)
	HexEncoded  string // Hex-encoded raw request for precise comparison
}

// Helper function to start a raw TCP test server using an existing listener
func startRawTestServerWithListener(t *testing.T, listener net.Listener, receivedDataChan chan<- RequestData) func() {
	t.Helper()
	serverAddr := listener.Addr().String() // Get address for logging, though caller knows it
	t.Logf("Test server (with listener) starting on: %s", serverAddr)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	// Goroutine to close the listener when context is cancelled
	go func() {
		<-ctx.Done() // Wait for cancellation signal
		listener.Close()
		t.Logf("Test server listener on %s closed.", serverAddr)
	}()

	wg.Add(1) // Add to WaitGroup for the accept loop goroutine
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Check if the error is due to the listener being closed.
				if ctx.Err() != nil || strings.Contains(err.Error(), "use of closed network connection") {
					t.Logf("Test server accept loop on %s stopped.", serverAddr)
					return // Expected error when listener is closed
				}
				t.Errorf("Test server accept error on %s: %v", serverAddr, err)
				return // Unexpected error
			}

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				handleRawTestConnection(t, c, receivedDataChan)
			}(conn)
		}
	}()

	// Teardown function
	stopServer := func() {
		cancel()  // Signal goroutines to stop
		wg.Wait() // Wait for all connection handlers and accept loop to finish
		t.Logf("Test server on %s stopped gracefully.", serverAddr)
	}

	return stopServer
}

// Helper function to start a raw TCP test server
func startRawTestServer(t *testing.T, receivedDataChan chan<- RequestData) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0") // Listen on random free port
	if err != nil {
		t.Fatalf("Failed to start test server listener: %v", err)
	}
	serverAddr := listener.Addr().String()
	// Note: Original t.Logf("Test server listening on: %s", serverAddr) is now in startRawTestServerWithListener

	// Pass the created listener to the new function
	stopServerFunc := startRawTestServerWithListener(t, listener, receivedDataChan)

	return serverAddr, stopServerFunc
}

// Handles a single raw connection for the test server
func handleRawTestConnection(t *testing.T, conn net.Conn, receivedDataChan chan<- RequestData) {
	t.Helper()

	// 2s instead of the original 100ms: under worker-pool bursts (especially
	// via the CONNECT tunnel proxy, where the origin handler starts before
	// the client has finished the handshake) first-byte gaps can exceed
	// 100ms, silently dropping requests and flaking URI-count assertions.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Instead of just reading the first line, read the entire request
	var requestBuffer strings.Builder
	reader := bufio.NewReader(conn)

	// Read request line first (still needed to extract URI for backward compatibility)
	requestLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		t.Logf("[origin-anomaly] first-line read failed: %v (partial line: %q)", err, requestLine)
		return
	}
	requestBuffer.WriteString(requestLine)

	// Extract URI for backward compatibility
	requestLineParts := strings.Split(strings.TrimSpace(requestLine), " ")
	var receivedURI string
	if len(requestLineParts) >= 2 {
		receivedURI = requestLineParts[1]
	} else {
		t.Logf("Received malformed request line: %s", requestLine)
		return
	}

	// Read headers until empty line, tracking Content-Length so the body read
	// below only happens when a body actually exists.
	emptyLineFound := false
	contentLength := 0
	for !emptyLineFound {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			t.Logf("[origin-anomaly] header read failed: %v (line so far: %q)", err, line)
			break
		}
		requestBuffer.WriteString(line)

		if lower := strings.ToLower(line); strings.HasPrefix(lower, "content-length:") {
			if v, cerr := strconv.Atoi(strings.TrimSpace(lower[len("content-length:"):])); cerr == nil && v > 0 {
				contentLength = v
			}
		}

		// Empty line (just "\r\n") indicates end of headers
		if line == "\r\n" || line == "\n" {
			emptyLineFound = true
		}

		// Break on EOF
		if err == io.EOF {
			break
		}
	}

	// Read the body only when the request declares one: a blind Read here
	// would block until the read deadline on every bodyless request (the
	// original 100ms deadline masked this by accident — it doubled as a pacer,
	// while a longer deadline makes each GET wait out the full timeout and
	// races the client's own 3s timeout).
	if contentLength > 0 {
		bodyBuf := make([]byte, contentLength)
		n, _ := io.ReadFull(reader, bodyBuf)
		if n > 0 {
			requestBuffer.Write(bodyBuf[:n])
		}
	}

	// Get the full raw request
	fullRequest := requestBuffer.String()

	// Convert to hex for precise comparison including invisible characters
	hexRequest := hex.EncodeToString([]byte(fullRequest))

	// Create RequestData struct
	requestData := RequestData{
		URI:         receivedURI,
		FullRequest: fullRequest,
		HexEncoded:  hexRequest,
	}

	// Send the request data. The channel is buffered to numPayloads and the
	// collector goroutine drains it continuously, so this send never blocks.
	// The original `select + time.After(10ms)` was a latent drop-machine: if
	// the goroutine was descheduled between timer creation and case
	// evaluation, both cases were "ready" and select picked randomly —
	// silently discarding records and flaking URI-count assertions.
	receivedDataChan <- requestData

	// Send a minimal valid HTTP response so the client doesn't error out
	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	_, err = conn.Write([]byte(response))
	if err != nil {
		if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "forcibly closed") {
			t.Logf("Test server write error: %v", err)
		}
	}

	// Debug logging for request details
	// t.Logf("Received request with URI: %s", receivedURI)
	// t.Logf("Full raw request length: %d bytes", len(fullRequest))
}
