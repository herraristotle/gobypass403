# Test data

## `unKover-suffix-findings.db`

Curated real-run fixture for the Addendum 5 Phase A parity regression
(`tests/unittests/engine/analysis/fixture_test.go`).

- **Source:** gobypass403 scan id `18deb4236606e6b9` (2026-10-15),
  `-m end_paths -cr 5 -sc -dpb` against Brute Logic's official unKover
  testbed board `https://403.brutelogic.net/access/nginx/suffix`.
- **Content:** 516 rows — 1 `dumb_check` baseline (403), 453 × 200 with an
  identical 40-byte body but 453 distinct curl commands (including
  unKover's exact bare `/suffix/` PoC), plus 403/404/400 responses.
- **Reduction:** only the eight columns the analyzer reads were kept
  (`target_url, bypass_module, status_code, content_length, content_type,
  response_body_preview, response_body_bytes, curl_cmd`). All 516 rows and
  every kept value are unchanged — verified by multiset equality against
  the source before committing. Journal mode is `DELETE`, so the file is a
  single artifact with no `-wal`/`-shm` sidecars.
- **Expected analysis:** one target; baseline `dumb_check` status 403; one
  BYPASS cluster (status 200, length 40, count 453) whose members include
  the exact bare `/suffix/` command; 448 members collapse in the text
  report.

Note: on this board `content_length` is `-1` for most rows, so the
analyzer's length falls back to `response_body_bytes` — deliberately
exercised by this fixture.
