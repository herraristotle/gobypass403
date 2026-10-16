package tests

// Addendum 6 gap: the negative-control probes are evidence for the classifier,
// not findings. Their rows must still reach the database (the offline -analyze
// recognises the wildcard from them), but they must not be counted as results:
// SPEC says a calibrated cluster "is not a finding".

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/slicingmelon/gobypass403/core/engine/analysis"
	"github.com/slicingmelon/gobypass403/core/engine/scanner"
)

// wireRowCount counts the rows this target has in the shared findings DB,
// optionally for one module only.
func wireRowCount(t *testing.T, target, module string) int {
	t.Helper()

	db, err := sql.Open("sqlite3", "file:"+filepath.Join(wireDBDir, "results.db")+"?mode=ro")
	if err != nil {
		t.Fatalf("open findings db: %v", err)
	}
	defer db.Close()

	query := "SELECT COUNT(*) FROM scan_results WHERE target_url = ?"
	args := []any{target}
	if module != "" {
		query += " AND bypass_module = ?"
		args = append(args, module)
	}

	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}

func TestCalibrationControlsAreStoredButNotCountedAsFindings(t *testing.T) {
	initWireDB(t)

	board := startWireBoard(t, soft404Accept)
	target := board.url("/access")

	s := scanner.NewScanner(calibrationOpts(true, false), []string{target})
	got := s.RunAllBypasses(target)

	controls := wireRowCount(t, target, analysis.CalibrationModule)
	if controls != 3 {
		t.Fatalf("the 3 control probes must still be stored for -analyze, found %d rows", controls)
	}

	if total := wireRowCount(t, target, ""); got != total-controls {
		t.Errorf("Found %d results counts the %d control rows; want %d stored findings", got, controls, total-controls)
	}
}
