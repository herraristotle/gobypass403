package tests

// Task B6 (SPEC-unkover-gaps.md Addendum 5, Phase B): the on-the-wire proof.
//
// A minimal raw board records every request line it receives, so these tests
// assert what actually left the process rather than what the tool logged:
//
//   * a simulated bypass (one method answers 200) triggers exactly one derived
//     batch, bounded by PerHit, every request a case/space sibling of the
//     method that worked — and nothing beyond it (depth 1);
//   * a board with no bypass triggers zero extra requests;
//   * the same board with -expand off triggers zero extra requests (default
//     behaviour is untouched);
//   * the expansion row lands in the findings table marked " # expanded" and
//     still grouped under its real module name.
//
// The board is a raw TCP listener (not net/http) so unusual methods, mixed case
// and trailing-space twins reach the test intact instead of being normalised or
// rejected by a Go HTTP server parser.
//
// NOTE: scanner.InitDB is sync.Once (one findings DB per test process, see
// results_test.go). This file initialises it first (files run in name order) in
// a directory that outlives the test, so the printer scenarios seeded by
// results_test.go land in the same database.

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/expand"
	"github.com/herraristotle/gobypass403/core/engine/payload"
	"github.com/herraristotle/gobypass403/core/engine/scanner"
)

const wireModule = "http_methods"

// wireBoard answers one request per connection and remembers every request
// line it saw as "<METHOD> <target>" (version stripped).
type wireBoard struct {
	ln     net.Listener
	bypass func(req string) bool
	server string // Server header value; empty means the default below

	mu       sync.Mutex
	requests []string
}

func startWireBoard(t *testing.T, bypass func(req string) bool) *wireBoard {
	t.Helper()
	return startWireBoardWithServer(t, "", bypass)
}

// startWireBoardWithServer is startWireBoard with a chosen Server header,
// which is the fingerprint -adaptive reads.
func startWireBoardWithServer(t *testing.T, server string, bypass func(req string) bool) *wireBoard {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &wireBoard{ln: ln, bypass: bypass, server: server}
	go b.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return b
}

func (b *wireBoard) url(path string) string {
	return "http://" + b.ln.Addr().String() + path
}

func (b *wireBoard) seen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.requests...)
}

func (b *wireBoard) serve() {
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.handle(conn)
	}
}

func (b *wireBoard) handle(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimRight(line, "\r\n")

	// The request line is "<method> <target> HTTP/1.x" and a derived method
	// twin may legitimately end in a space, so strip the version and keep the
	// method/target boundary exactly as requestSet builds it.
	req := strings.TrimSuffix(strings.TrimSuffix(line, " HTTP/1.1"), " HTTP/1.0")

	b.mu.Lock()
	b.requests = append(b.requests, req)
	b.mu.Unlock()

	length := 0
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			break
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		if name, value, ok := strings.Cut(h, ":"); ok &&
			strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			_, _ = fmt.Sscanf(strings.TrimSpace(value), "%d", &length)
		}
	}
	if length > 0 {
		_, _ = br.Discard(length)
	}

	body := "<html><head><title>denied</title></head><body>403 forbidden</body></html>"
	status := "403 Forbidden"
	if b.bypass(req) {
		body = "<html><head><title>dashboard</title></head><body>200 bypassed</body></html>"
		status = "200 OK"
	}
	server := b.server
	if server == "" {
		server = "wireboard/1.0"
	}
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 %s\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: %d\r\nServer: %s\r\nConnection: close\r\n\r\n%s",
		status, len(body), server, body)
}

var (
	wireDBOnce sync.Once
	wireDBDir  string
)

// initWireDB points the process-wide findings DB at a directory that is not
// removed when this test ends, because results_test.go shares it.
func initWireDB(t *testing.T) {
	t.Helper()
	wireDBOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gb403-expand-wire")
		if err != nil {
			t.Fatalf("tempdir: %v", err)
		}
		wireDBDir = dir
		if err := scanner.InitDB(filepath.Join(dir, "results.db"), 1); err != nil {
			t.Fatalf("InitDB: %v", err)
		}
	})
}

func wireOpts(expandOn bool) *scanner.ScannerOpts {
	return &scanner.ScannerOpts{
		BypassModule:             wireModule,
		Timeout:                  5000,
		ConcurrentRequests:       5,
		ResponseBodyPreviewSize:  3096,
		DisableProgressBar:       true,
		MaxRetries:               0,
		MaxConsecutiveFailedReqs: 1000,
		Method:                   "GET",
		// Only 200s are stored, so the findings table shows exactly the rows
		// this test cares about (the module's hit and the derived hit).
		MatchStatusCodes: []int{200},
		Expand:           expandOn,
	}
}

// wireJobs mirrors what RunBypassModule will send for this module and target.
func wireJobs(t *testing.T, target string) []payload.BypassPayload {
	t.Helper()
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    target,
		BypassModule: wireModule,
		Method:       "GET",
	})
	jobs := pg.Generate()
	if len(jobs) == 0 {
		t.Fatal("http_methods generated no payloads")
	}
	return jobs
}

// wireWinner picks the module method this test makes bypass: a non-GET method
// from the module's own list, so the board's 200 is a single-member BYPASS
// cluster against a modal 403 baseline (dumb_check does not run here).
func wireWinner(t *testing.T) string {
	t.Helper()
	for _, p := range wireJobs(t, "http://board.invalid/access") {
		if !strings.EqualFold(p.Method, "GET") && !strings.EqualFold(p.Method, "HEAD") {
			return p.Method
		}
	}
	t.Fatal("no non-GET method in the http_methods payloads")
	return ""
}

func requestSet(jobs []payload.BypassPayload) map[string]bool {
	out := make(map[string]bool, len(jobs))
	for _, p := range jobs {
		out[p.Method+" "+p.RawURI] = true
	}
	return out
}

func TestExpandWireSendsExactlyOneDerivedBatch(t *testing.T) {
	initWireDB(t)

	winner := wireWinner(t)
	// The board accepts the method that worked and its trailing-space twin —
	// a shape only the derived batch can produce, so its 200 row is proof the
	// expansion actually reached the wire.
	accept := wireAccept(winner)
	board := startWireBoard(t, func(req string) bool { return accept[req] })
	target := board.url("/access")

	s := scanner.NewScanner(wireOpts(true), []string{target})
	if got := s.RunBypassModule(wireModule, target); got == 0 {
		t.Fatalf("the board's %s 200 was not recorded as a finding", winner)
	}

	jobs := wireJobs(t, target)
	moduleSet := requestSet(jobs)

	var hit payload.BypassPayload
	for _, p := range jobs {
		if p.Method == winner {
			hit = p
			break
		}
	}
	if hit.RawURI == "" {
		t.Fatalf("the winning method %q is not in the module's payloads", winner)
	}

	sent := make([]string, 0, len(jobs))
	shapes := make([]string, 0, len(jobs))
	for _, p := range jobs {
		sent = append(sent, p.RawURI)
		shapes = append(shapes, expand.ShapeKey(p))
	}
	// Composer is unused for the method family, so nil is honest here.
	expected := expand.Mutate(expand.Request{
		Module:     wireModule,
		Payload:    hit,
		Sent:       sent,
		SentShapes: shapes,
	}, nil, expand.PerHit)
	if len(expected) == 0 {
		t.Fatal("no derived requests for the confirming method")
	}
	wantSet := requestSet(expected)

	seen := board.seen()
	var derived []string
	for _, r := range seen {
		if moduleSet[r] {
			continue
		}
		derived = append(derived, r)
	}

	// Depth 1: exactly one derived batch, no more and no less.
	if len(derived) != len(wantSet) {
		t.Errorf("board saw %d derived requests, want %d\ngot:  %v\nwant: %v",
			len(derived), len(wantSet), derived, expected)
	}
	for _, r := range derived {
		if !wantSet[r] {
			t.Errorf("unexpected request on the wire: %q", r)
		}
	}
	// Nothing the module already tried was sent a second time.
	if len(seen) != len(jobs)+len(derived) {
		t.Errorf("board saw %d requests for %d module + %d derived; something was re-sent",
			len(seen), len(jobs), len(derived))
	}
	if len(derived) > expand.PerHit {
		t.Errorf("derived batch is %d requests, cap is %d", len(derived), expand.PerHit)
	}

	// The derived row: marked, and still grouped under its real module.
	out := captureStdout(t, func() {
		if err := scanner.PrintResultsTableFromDB(target, wireModule); err != nil {
			t.Errorf("PrintResultsTableFromDB: %v", err)
		}
	})
	if !strings.Contains(out, " # expanded") {
		t.Errorf("expansion row is not marked in the findings table:\n%s", out)
	}
	if !strings.Contains(out, wireModule) {
		t.Errorf("expansion row lost its module name:\n%s", out)
	}
}

func TestExpandWireNoBypassSendsNothingExtra(t *testing.T) {
	board := startWireBoard(t, func(req string) bool { return false })
	target := board.url("/access")

	s := scanner.NewScanner(wireOpts(true), []string{target})
	s.RunBypassModule(wireModule, target)

	want := requestSet(wireJobs(t, target))
	seen := board.seen()
	if len(seen) != len(want) {
		t.Errorf("board saw %d requests, want exactly the module's %d", len(seen), len(want))
	}
	for _, r := range seen {
		if !want[r] {
			t.Errorf("unexpected request with no bypass on the board: %q", r)
		}
	}
}

func TestExpandWireDisabledSendsNothingExtra(t *testing.T) {
	winner := wireWinner(t)
	accept := wireAccept(winner)
	board := startWireBoard(t, func(req string) bool { return accept[req] })
	target := board.url("/access")

	s := scanner.NewScanner(wireOpts(false), []string{target})
	s.RunBypassModule(wireModule, target)

	want := requestSet(wireJobs(t, target))
	seen := board.seen()
	if len(seen) != len(want) {
		t.Errorf("board saw %d requests with -expand off, want exactly the module's %d", len(seen), len(want))
	}
	for _, r := range seen {
		if !want[r] {
			t.Errorf("unexpected request with -expand off: %q", r)
		}
	}
}

// wireAccept is the board rule: the method that worked, plus the one shape only
// the derived batch can produce (that method with a trailing space).
func wireAccept(winner string) map[string]bool {
	return map[string]bool{
		winner + " /access":  true,
		winner + "  /access": true,
	}
}
