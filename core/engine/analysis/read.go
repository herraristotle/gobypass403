/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Read-only database access for the offline differential analyzer
(SPEC-unkover-gaps.md Addendum 5, Phase A).
*/
package analysis

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// selectRowsSQL is the projection the analyzer needs. Only these columns
// are read, so a reduced-column fixture is a faithful input.
const selectRowsSQL = `SELECT
	target_url, bypass_module, status_code, content_length, content_type,
	response_body_preview, response_body_bytes, curl_cmd
	FROM scan_results`

// Analyze reads an existing findings database read-only and returns the
// differential report.
//
// The input is never modified and never left with -shm/-wal sidecars: when
// there is no -wal file the connection is opened with immutable=1, so
// SQLite cannot create them either.
func Analyze(dbPath string) (Report, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return Report{}, fmt.Errorf("cannot read findings database %q: %w", dbPath, err)
	}

	db, err := sql.Open("sqlite3", readOnlyDSN(dbPath))
	if err != nil {
		return Report{}, fmt.Errorf("open findings database %q: %w", dbPath, err)
	}
	defer db.Close()

	rows, err := db.Query(selectRowsSQL)
	if err != nil {
		return Report{}, fmt.Errorf("read %q (is it a gobypass403 results.db?): %w", dbPath, err)
	}
	defer rows.Close()

	all, err := scanRows(rows, dbPath)
	if err != nil {
		return Report{}, err
	}

	return ClassifyReport(all), nil
}

// TargetRows reads the analyzer projection for one target_url. The live scan
// uses it once a target has finished, so the wildcard hint (Addendum 7) is
// computed from exactly the rows -analyze sees, with the same classifier.
func TargetRows(dbPath, targetURL string) ([]Row, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("cannot read findings database %q: %w", dbPath, err)
	}

	db, err := sql.Open("sqlite3", readOnlyDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open findings database %q: %w", dbPath, err)
	}
	defer db.Close()

	rows, err := db.Query(selectRowsSQL+" WHERE target_url = ?", targetURL)
	if err != nil {
		return nil, fmt.Errorf("read %q (is it a gobypass403 results.db?): %w", dbPath, err)
	}
	defer rows.Close()

	return scanRows(rows, dbPath)
}

// scanRows materialises the analyzer projection. Only the selected columns are
// read, so a reduced-column fixture stays a faithful input.
func scanRows(rows *sql.Rows, dbPath string) ([]Row, error) {
	var all []Row
	for rows.Next() {
		var (
			targetURL, module          string
			status, contentLength      sql.NullInt64
			contentType, preview, curl sql.NullString
			bodyBytes                  sql.NullInt64
		)
		if err := rows.Scan(
			&targetURL, &module, &status, &contentLength, &contentType,
			&preview, &bodyBytes, &curl,
		); err != nil {
			return nil, fmt.Errorf("scan row of %q: %w", dbPath, err)
		}
		all = append(all, Row{
			TargetURL:           targetURL,
			BypassModule:        module,
			StatusCode:          int(status.Int64),
			ContentLength:       contentLength.Int64,
			ContentType:         contentType.String,
			ResponseBodyPreview: preview.String,
			ResponseBodyBytes:   int(bodyBytes.Int64),
			CurlCMD:             curl.String,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate %q: %w", dbPath, err)
	}

	return all, nil
}

// readOnlyDSN opens the database read-only. journal-mode pragmas are
// deliberately omitted (unlike the printer's DSN): requesting them on a
// read-only connection can attempt a header write. immutable=1 is added
// when there is no WAL sidecar, so no -shm/-wal can be created.
func readOnlyDSN(dbPath string) string {
	if _, err := os.Stat(dbPath + "-wal"); err == nil {
		return "file:" + dbPath + "?mode=ro&_busy_timeout=10000"
	}
	return "file:" + dbPath + "?mode=ro&immutable=1&_busy_timeout=10000"
}
