package cli

// Task W2 (SPEC-unkover-gaps.md Addendum 9): the -warn-wildcard opt-in.
//
// Internal tests for the flag itself: it must exist, be a plain boolean bound
// to CliOptions.WarnWildcard, default to off, and -- unlike -expand, -adaptive
// and -calibrate -- stay legal in -analyze mode, because the report is exactly
// where the catch-all shape should be named. The scanner side of the hint is
// covered by the wire test.

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// hintFixtureDB builds the reduced-column findings database the analyzer
// reads: one denied baseline plus six distinct requests answered with the same
// catch-all page (the wildcard shape).
func hintFixtureDB(t *testing.T, target string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "results.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE scan_results (
		target_url TEXT NOT NULL, bypass_module TEXT NOT NULL, status_code INTEGER,
		content_length INTEGER, content_type TEXT, response_body_preview TEXT,
		response_body_bytes INTEGER, curl_cmd TEXT)`); err != nil {
		t.Fatalf("create fixture schema: %v", err)
	}

	insert := func(module string, status int, body, curl string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO scan_results
			(target_url, bypass_module, status_code, content_length, content_type,
			 response_body_preview, response_body_bytes, curl_cmd)
			VALUES (?,?,?,?,?,?,?,?)`,
			target, module, status, len(body), "text/html", body, len(body), curl); err != nil {
			t.Fatalf("insert fixture row: %v", err)
		}
	}

	insert("dumb_check", 403, "Forbidden", "curl -skgi --path-as-is '"+target+"'")
	for i := 0; i < 6; i++ {
		insert("end_paths", 200, "catch-all page for everything",
			fmt.Sprintf("curl -skgi --path-as-is '%s/.js%d'", target, i))
	}
	return path
}

// captureOut captures os.Stdout (the analyze report uses fmt, not the logger).
func captureOut(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		_ = r.Close()
		done <- sb.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = old
	return <-done
}

func TestAnalyzeWildcardHintPrintsWithTheFlag(t *testing.T) {
	db := hintFixtureDB(t, "https://t.example/access")
	r := &Runner{RunnerOptions: &CliOptions{AnalyzeDB: db, WarnWildcard: true}}

	var err error
	out := captureOut(t, func() { err = r.handleAnalyze() })
	if err != nil {
		t.Fatalf("handleAnalyze: %v", err)
	}

	if !strings.Contains(out, "wildcard-shaped cluster") {
		t.Errorf("-analyze -warn-wildcard must name the catch-all; got:\n%s", out)
	}
	if !strings.Contains(out, "https://t.example/access") {
		t.Errorf("the hint must name its target; got:\n%s", out)
	}
	if !strings.Contains(out, "-calibrate") {
		t.Errorf("the hint must name the remedy; got:\n%s", out)
	}
}

func TestAnalyzeWildcardHintSilentWithoutTheFlag(t *testing.T) {
	db := hintFixtureDB(t, "https://t.example/access")
	r := &Runner{RunnerOptions: &CliOptions{AnalyzeDB: db}}

	var err error
	out := captureOut(t, func() { err = r.handleAnalyze() })
	if err != nil {
		t.Fatalf("handleAnalyze: %v", err)
	}

	if strings.Contains(out, "wildcard-shaped") {
		t.Errorf("the hint is opt-in; got:\n%s", out)
	}
}

func TestAnalyzeWildcardHintLeavesJSONAlone(t *testing.T) {
	db := hintFixtureDB(t, "https://t.example/access")
	jsonPath := filepath.Join(t.TempDir(), "report.json")
	r := &Runner{RunnerOptions: &CliOptions{AnalyzeDB: db, WarnWildcard: true, AnalyzeJSON: jsonPath}}

	if err := r.handleAnalyze(); err != nil {
		t.Fatalf("handleAnalyze: %v", err)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("JSON report not written: %v", err)
	}
	if strings.Contains(string(data), "wildcard") {
		t.Errorf("hints must not enter the JSON contract:\n%s", data)
	}
}

func TestWarnWildcardFlagIsARegisteredBool(t *testing.T) {
	opts := &CliOptions{}

	var found bool
	for _, f := range flagDefinitions(opts) {
		for _, name := range strings.Split(f.name, ",") {
			if strings.TrimSpace(name) != "warn-wildcard" {
				continue
			}
			found = true
			v, ok := f.value.(*bool)
			if !ok {
				t.Fatalf("-warn-wildcard value is %T, want *bool", f.value)
			}
			if v != &opts.WarnWildcard {
				t.Error("-warn-wildcard is not bound to CliOptions.WarnWildcard")
			}
			if f.defVal != false {
				t.Errorf("-warn-wildcard default is %v, want false", f.defVal)
			}
		}
	}
	if !found {
		t.Fatal("-warn-wildcard is not registered")
	}
}

func TestWarnWildcardDefaultsOff(t *testing.T) {
	if (&CliOptions{}).WarnWildcard {
		t.Error("the hint must be off unless asked for: default output is protected")
	}
}

func TestWarnWildcardHelpNamesTheRemedy(t *testing.T) {
	var usage string
	for _, f := range flagDefinitions(&CliOptions{}) {
		for _, name := range strings.Split(f.name, ",") {
			if strings.TrimSpace(name) == "warn-wildcard" {
				usage = f.usage
			}
		}
	}
	if usage == "" {
		t.Fatal("-warn-wildcard is not registered")
	}
	if !strings.Contains(usage, "-calibrate") {
		t.Errorf("usage must name the remedy (-calibrate): %q", usage)
	}
	if !strings.Contains(usage, "off by default") {
		t.Errorf("usage must state the default: %q", usage)
	}
}

func TestWarnWildcardIsAllowedWithAnalyze(t *testing.T) {
	// The offline report is where an operator looks after the fact, so the
	// hint must not be rejected there (it performs no request).
	o := &CliOptions{AnalyzeDB: "/tmp/results.db", WarnWildcard: true}
	if err := o.validateAnalyze(); err != nil {
		t.Fatalf("-analyze + -warn-wildcard must be accepted; got %v", err)
	}
}
