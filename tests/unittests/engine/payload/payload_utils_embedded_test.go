package tests

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// TestReadPayloadsFromFileFallsBackToEmbedded pins ReadPayloadsFromFile's
// embedded fallback: on a host with no local payload copy the module must still
// load the embedded .lst. An isolated XDG_CONFIG_HOME simulates that host
// deterministically, whether or not the developer has a local copy.
//
// Before the fix the fallback opened `filename` instead of `payloads/filename`
// (the embed root is the payloads/ directory), so it always errored and every
// .lst-backed module returned zero payloads on a host with no local copy.
func TestReadPayloadsFromFileFallsBackToEmbedded(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no ~/.config/gobypass403/payloads

	lines, err := payload.ReadPayloadsFromFile("internal_midpaths.lst")
	if err != nil {
		t.Fatalf("ReadPayloadsFromFile with no local payload copy: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("embedded fallback returned zero payloads")
	}

	// The fallback must parse the embedded file exactly as the local path does:
	// every non-empty, trimmed line.
	data, err := payload.DefaultPayloadsDir.ReadFile("payloads/internal_midpaths.lst")
	if err != nil {
		t.Fatalf("read embedded internal_midpaths.lst: %v", err)
	}
	want := 0
	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(raw) != "" {
			want++
		}
	}
	if len(lines) != want {
		t.Errorf("embedded fallback parsed %d payloads, want %d", len(lines), want)
	}
}

// TestReadPayloadsFromFileStillErrorsOnMissingFile guards the fix from going too
// far: a file that is neither local nor embedded must still be an error, so a
// typo never silently scans zero payloads.
func TestReadPayloadsFromFileStillErrorsOnMissingFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, err := payload.ReadPayloadsFromFile("no-such-payload-file.lst"); err == nil {
		t.Error("ReadPayloadsFromFile on a truly missing file should return an error")
	}
}
