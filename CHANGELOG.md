# Unreleased

- **Fixed payload loading on a host with no local payload copy** — `ReadPayloadsFromFile`'s embedded fallback opened `filename` instead of `payloads/filename`, and the embed root is the `payloads/` directory, so the path never resolved. When no user-config copy existed (`~/.config/gobypass403/payloads/`) it therefore always errored and every `.lst`-backed module — `mid_paths`, `end_paths`, `headers_*`, `http_methods`, `user_agent`, `param_manipulation`, `headers_hop_by_hop` — silently generated **zero** payloads. The binary itself never reaches the fallback — `main` calls `InitializePayloadsDir` first, and it copies every missing file into `~/.config/gobypass403/payloads/`, so a fresh install scans normally — but readers that skip it do: the unit/integration suite and any library or embedded consumer, which fail with `file does not exist` and produce zero payloads on the pre-fix commit (verified with an empty `XDG_CONFIG_HOME`) and pass after. One-line fix (the `payloads/` prefix, matching this file's five other embed reads and `ReadPayloadsFromJSONFile`), plus a regression test that isolates `XDG_CONFIG_HOME` and asserts the fallback parses the embedded corpus, and that a genuinely missing file still errors. Local-first precedence is unchanged. Addendum 8 of the unKover-gaps work.

- **Added interior control/delimiter atoms to `mid_paths` (HTTP parser-inconsistency class)** — the URL atoms that expose HTTP parser inconsistencies (Orange Tsai, *A New Era of SSRF*; Rafael da Costa Santos, *Exploiting HTTP Parsers Inconsistencies*) were already curated but only at the **tail** of the path: `end_paths` appends them, while `mid_paths` inserted its corpus at every *interior* position but its corpus lacked the atoms. 49 atoms are now appended to `internal_midpaths.lst` (532→581 lines) — the ASCII controls `%00`–`%1F` minus the nine already present, plus the missing ASCII punctuation/symbols (`%21 %22 %24 %25 %27 %28 … %7E`) and DEL `%7F`. So `%00` is sent as `/admin%00/config`, `/admin/%00/config` and `/%00admin/config`, not only the tail shape `/admin/config%00`. Dedup is case-insensitive (`%2f`≡`%2F`, since both denote the same byte), so the 17 atoms the corpus already carried are not re-added, and `uniquePaths` guarantees a shape is never sent twice. Atoms are percent-encoded — ordinary literal bytes on the raw request line; a bare `%0D%0A` pair is deliberately excluded as request-splitting, a different class. `mid_paths` grows ~10% for a typical path (`/admin/config` 3,934→4,326 payloads); `unicode_path_experimental` reads the same file but its `countSubstitutablePositions` skips percent-encoded sequences, so it is unchanged (50,101 payloads). Pinned by `TestMidPathsInteriorControlAtoms`, `TestMidPathsAtomDomainCoveredAndDeduped` and `TestMidPathsAtomsDoNotGrowUnicodeExperimental`. **Upgrading installations must run once with `--update-payloads`** to refresh the user-config copy of the wordlists (`~/.config/gobypass403/payloads/`). Addendum 7 of the unKover-gaps work.

- **Added wildcard calibration (`-calibrate`)** — opt-in negative control that kills the soft-404 false positive. A target that answers every unknown path with a success page (wildcard `200`, catch-all "not found" served as `200`, SPA fallback) makes a 403 baseline misread *any* payload `200` as a `BYPASS`, because the classifier compares status classes only. With `-calibrate`, the scan sends three probes to random non-existent siblings of the target's own path (`/admin/<random>`), records them as the synthetic `calibration` module (which is injected after `dumb_check` and is deliberately **not** in `-m all` or any `-scan-profile` set), and classifies any cluster matching a control as the new **`CALIBRATED`** class — never `BYPASS`. A cluster matches on the same status **and** media type plus either an identical body digest (an exact wildcard — stronger than unKover's size-only `is_wildcard`) or a length within ±50 bytes (an echoing soft-404, which resizes with the path it echoes). Control rows skip the display filters so they always reach the DB, and since `-expand`/`-adaptive` act only on `BYPASS`, a calibrated cluster is never expanded or escalated — proven end to end on a raw wildcard board. `-calibrate` is rejected with `-analyze`; without the flag there is no probe request, no new row and byte-identical output. Honest limits: the ±50-byte rule trusts the stored length, so with a small `-rbps` two distinct large bodies can both read as the preview cap and match (the digest-equal path stays exact). Addendum 6 of the unKover-gaps work.

- **Added adaptive ordering (`-adaptive`)** — opt-in, table-driven spending of the same requests in a better order. The baseline (`dumb_check`) response is the target's fingerprint (status, `Server` header, marker headers, cookies — read from a response the run already sends, so **zero extra requests**), and the modules that fingerprint points at are promoted to the front of the resolved module list; ordering is a **permutation only**, it never adds or removes a module. The heuristic table lives as data in the new pure `core/engine/adaptive` package (Cloudflare, nginx, haproxy, Akamai, CloudFront, Azure, Varnish/Fastly, IIS, Apache, F5 → their path/header/module families), pinned row by row by tests and documented in the README with its evidence. Escalation is the second half: when a target's triage pass has a **403 baseline** and produced at least one **`BYPASS` cluster**, the five deep families (`path_prefix`, `unicode_path_normalization/truncation/experimental`, `param_manipulation`) run once for that target through the normal pipeline, so `-max-reqs` caps them and `-resume` checkpoints them like any other `(target, module)` pair. The `-scan-profile triage` preset is now derived as the registry minus those deep families instead of a second hand-kept list, so the two cannot drift. Without the flag nothing is fingerprinted, reordered or escalated (no-flag output byte-identical to before); excluding `dumb_check` means no fingerprint and the default order with one warning; `-adaptive` is rejected with `-analyze`. Honest limits: the table is a heuristic (unknown front end or stripped `Server` keeps the default order), and escalation is all-or-nothing per target — one confirmed bypass can turn a triage run into a full deep pass (~46k payloads for a typical path). Phase C of the Addendum-5 dynamic-discovery work.

- **Added long-run plumbing (`-max-reqs`, `-resume`, `-tw`)** — three opt-in flags for long scans; a default run is byte-identical to before. `-max-reqs <n>` is a hard request budget shared by every module, target and expansion batch: running out **finishes** the run instead of aborting it (later batches reserve nothing and send nothing, findings already collected are kept, one warning line), and a retried request is not charged twice. `-resume` reads `scan.progress.json` from the output directory, skips the `(target, module)` pairs it already names, and records each pair as soon as its module finishes, so an interruption costs at most the module in flight and no rows are duplicated; without the flag no sidecar is read or written, a damaged or foreign one is reported and triggers a full rescan, and pairs are keyed by the target string as typed plus module name (use `-o`, since the default output directory is unique per run). `-tw <n>` (default `1` = today's sequential loop) scans up to `n` targets at once with **one target per host at a time** — work is distributed as one bucket of targets per host, so a worker owns a host until its targets are done; `-tw > 1` disables the progress bar (one warning) and prints each target's table as it finishes, tables never interleave, the budget stays shared and the findings DB keeps its single-writer discipline, so per-target row counts are exactly those of the sequential runs. Invalid values (`0`, negative) are rejected. Phase D of the Addendum-5 dynamic-discovery work; the per-target scan state (seen-RawURI filtering and expansion bookkeeping) is no longer process-global, which is what makes parallel targets safe.
- **Added feedback expansion (`-expand`)** — opt-in, bounded, depth-1 follow-up around a confirmed hit. After a module's batch finishes, Phase A's classifier looks at that batch alone; if a `BYPASS` cluster exists, up to **256** variations of *that exact request* are derived from the module's own atoms and scanned through the normal pipeline (same pool, same `-mc`/`-mct`/`-min-cl`/`-max-cl` filters, same findings table), capped at **1024** per target with only the top `BYPASS` cluster of a batch expanded. Three families expand — path modules (the module's own generator re-applied to the confirmed request-target), `http_methods`/`headers_method` (case permutations + trailing-space twin of the method that worked), `headers_ip` (other notations/neighbours of the IP that worked); every other module is unsupported and sends nothing. Expansion responses are never re-classified, so depth stays 1 and a derived hit cannot start another round. Rows keep their real module name (so the table still groups them) and their `curl` command carries a trailing ` # expanded` (a shell comment, so the copy-pasted PoC still runs). A shape the batch already sent is never re-sent. Without the flag there is no observation collection, no classification and no extra request; default output is unchanged. Honest limits: hits come from the same heuristic status-class rule as `-analyze` (exact-digest matching, no fuzzy matching) and most modules have no mutator. Phase B of the Addendum-5 dynamic-discovery work.

- **Added offline differential analysis (`-analyze`, `-analyze-json`)** — re-reads a finished scan's `results.db` **read-only** (no new requests, no output DB, no recon) and reports what actually departed from each target's baseline: `BYPASS` (status class improved, e.g. baseline `403` → `200`/`3xx`, different body), `VARIANT` (same status class, different body), `DUP` (identical to baseline), `NOISE` (empty non-improving artifact). Responses are clustered by exact `(status, media type, sha256(body), length)`, so hundreds of near-identical hits collapse into one line that announces the hidden member count (e.g. 453 identical `200`s render as `+448 more identical (first: ...)`). The baseline is the target's `dumb_check` response when present, otherwise the target's most common response shape — the report states which. `-analyze-json <file>` writes the same report as stable, machine-readable JSON (`class` as `"BYPASS"` etc.). Mixing `-analyze` with `-u`/`-l`/`-r`/`-update-payloads` is an error, and `-analyze-json` requires `-analyze`. Honest limits: fingerprints derive from the stored body preview (capture-time `-rbps` truncation), matching is exact-digest only, and `BYPASS` means "the response changed", not "exploitable" — each cluster prints its ready-to-run `curl` command. New pure `core/engine/analysis` package (no logger/CLI/DB coupling in the classifier) that the later dynamic-discovery phases reuse. Phase A of the Addendum-5 dynamic-discovery work.
- **Added `http10` module (HTTP/1.0 downgrade)** — the last technique from the official unKover testbed (https://403.brutelogic.net/access) that gobypass403 could not reproduce. The raw request builder hardcoded `HTTP/1.1`; payloads can now carry an optional request-line version (`BypassPayload.HTTPVersion`, token-encoded as an optional field 8 so existing debug tokens stay byte-identical). The new module ships two payloads: the plain `--http1.0` downgrade (unKover `test_http10` parity) and a `Connection: close` companion. Findings render `curl --http1.0`, `-r` resends preserve the version, and the module is enabled by default. Validated live: both payloads bypass `:8081/access/rproxy/protocol10` (200) — the same PoC unKover reports.
- **Verified `end_paths` covers the testbed's "Parser Confusion" target** — `/access/rproxy/profile` ("breaker + static ext", e.g. `/.js`, `/.html`, `/.json`) is found autonomously: 19 findings from a single `-m end_paths` run. No generator change was needed (the base-path/suffix separator already composes the shapes); a regression test now pins the composed `/.js`-class payloads against future separator-logic refactors. An earlier survey note claiming this target was uncovered was a test-methodology error, not a tool gap.
- **Added unKover technique parity** — four techniques from Brute Logic's unKover (audited against v1.3) that gobypass403 did not cover:
  - Lowercase HTTP method variants: the `http_methods` module now emits a lowercase twin for every method in its list (36 → 72 payloads, plus POST query-as-body variants on URLs with query strings), since some allowlists compare methods case-insensitively. This is the only payload-count change to an existing module.
  - New `headers_hop_by_hop` module (5 payloads): pairs well-known auth headers (`Authorization`, `Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-Access-Token`) with `Connection: <header>` per RFC 7230 hop-by-hop stripping semantics.
  - New `api_versions` module: prefix injection (`/v1`–`/v9`, `/api`, `/api/v1`–`/api/v4`) and version-swap (`v1`–`v9`, `v1.1`, `v2.0`) sub-techniques for API version routing discrepancies.
  - New `-spoof-prefix` flag: comma-separated custom path prefixes for `api_versions` (example: `-spoof-prefix /internal,/v2beta`), following the `-spoof-header`/`-spoof-ip` flag family.
  - Both new modules are enabled by default; select them individually with `-m headers_hop_by_hop` / `-m api_versions`.
  - Validated against the official unKover testbed (https://403.brutelogic.net/access, nginx/Apache/rproxy boards). Two `headers_url` payload-shape gaps found and fixed: override headers (e.g. `X-Original-URL`) are now also sent **on the original request-target** (not only on `/`), and referer-ish headers now include unKover's trusted-section `Referer: https://host/<admin|dashboard|internal>` shapes. This grows `headers_url` payloads (~2 per header + 3 per referer-ish header).
- **Added research-acquisition fold-ins, phase A** (from `tasks/research-acquisition-report.md`, validated against 16 external sources):
  - New `headers_method` module (21 payloads): wires up the previously **orphaned** embedded `header_http_methods.lst` — `X-HTTP-Method`, `X-HTTP-Method-Override`, `X-Method-Override` × 7 method values (GET POST PUT PATCH DELETE HEAD OPTIONS) on the original request-target (bup `http_headers_method` parity). Enabled by default.
  - `end_paths` +33 suffixes: static extensions (`.php .asp .aspx .jsp .xml .bak .orig .do .action .png .ico .svg .woff2 .jpg`), cache-deception breakers (`;.css`…`;.svg`), unKover `SUFFIXES` (`;x`, `%3B.json`, `%23.json`, `%3F.json`, `%00.json`), CRLF/double-encode atoms and jhaddix residuals. Composed `/.php`-style forms are generated automatically by the separator logic (pinned by `TestEndPathsComposedStaticExtShapes`).
  - **Upgrading installations must run once with `--update-payloads`** to refresh the user-config copy of the wordlists (`~/.config/gobypass403/payloads/`) — wordlists are user-overridable and only copied on first run, so new entries are invisible to older config dirs until refreshed.
- **Added research-acquisition fold-ins, phase B (P1 wordlist folds)** — counts: `headers_ip` values 14→22 IPs (hex/octal/short/IPv6 loopback notations: `0x7F000001`, `0177.0000.0000.0001`, `127.1`, `127.1.1.1`, `172.16.0.1`, `::1`, `[::1]`, `::ffff:127.0.0.1`) + `CF-Connecting_IP` header; `http_methods` 36→46 verbs (`ARBITRARY`, `BASELINE-CONTROL`, `DEBUG`, `MKACTIVITY`, `MKCALENDAR`, `MKREDIRECTREF`, `MKWORKSPACE`, `PURGE`, `UNBIND`, `UNLINK` — lowercase twins automatic, 72→92 payloads); `mid_paths` 519→532 atoms (backslash + double-encode family); `headers_url` + bare `Referrer` header; `headers_port` 15→16 ports (+`74443`). Sources: SecLists, nomore403, bup, unKover.
- **Added research-acquisition fold-ins, phase C — new `user_agent` module** (45 payloads): rotates `User-Agent` with `payloads/internal_user_agents.lst` (bup's seed: Googlebot/CCBot/DuckDuckBot crawlers, legacy browsers, `Go-http-client/1.1`, `Java/1.8.0_202`, mobile/library clients) — WAFs and IP ACLs often whitelist crawler/legacy agents. The UA rides a new optional `BypassPayload.UserAgent` field (debug-token field 9, absent for every other module so tokens stay byte-identical); rawhttp emits it in place of the default browser UA, and findings show `curl -A '<ua>'` PoCs. Enabled by default (`-m user_agent`).
- **Added research-acquisition fold-ins, phase D (P2/P3 technique gaps)**:
  - `http10` now probes **three text request-line versions** — `HTTP/1.0` (unchanged unKover parity), `HTTP/0.9`, `HTTP/2.0` — each plain + `Connection: close` (2→6 payloads). Testbed-verified: HTTP/2.0 accepted where 1.1 is (200/403), HTTP/0.9 forces a 400-vs-403 differential on nginx; protocol10 bypass still found (200/37 bytes). Curl PoCs map to `--http1.0`/`--http0.9`/`--http2`; real h2/h2c transport documented out of scope (HTTP/1.x-only client stack). Module keeps the `http10` name (registry append-only + CLI compat).
  - `headers_host` gains an unconditional **Host-removal** payload (token field 10 `OmitHost`; the client skips its default `Host:` emission) — HackTricks "remove the Host header"; curl PoC `-H 'Host:'`. Wire-verified: request arrives with UA/Accept but no `Host:` line; testbed probe → 400 vs 403 baseline (Host-keyed routing differential).
  - `headers_ip` Forwarded header gains the **quoted-pair** value shape `for="[..]"` (HackTricks WAF research) alongside plain `by=/for=/host=`.
  - **New `param_manipulation` module** (~6,460 payloads for a queryless target): mutate values to boundary set `-234/0/99999999` + numeric increment, remove each param, reverse order, and append `&<name>=true` for 6,452 names from `payloads/internal_param_names.lst` (seeded from Parallax `parameters.txt`). Raw query bytes are never re-encoded. Enabled by default.
- **Added research-acquisition fold-ins — Parallax headers.txt straggler fold (14 names)** — the full mechanical diff of Parallax `wordlists/headers.txt` (1,131 unique) against gobypass403's header registries (77 already covered) filtered to 14 conservative real-world names that fit an existing family: `header_proto_schemes.lst` + `Forwarded-Proto`, `X-Forwarded-Protocol`, `X-Forward-Proto`, `X-Originally-Forwarded-Proto`, `X-Https`, `X-Scheme` (10→16 headers; `X-Https` joins the `Front-End-Https`/`X-Forwarded-SSL` `on`-value class, `headers_scheme` 38→64 payloads); `header_urls.lst` + `Coming-From`, `X-Coming-From`, `X-XHR-Referer`, `X-Amz-Website-Redirect-Location` (57→61); `header_ip_hosts.lst` + `ClientIP`, `X-ClientIP`, `X-Amzn-Remapped-Host` (143→146); `header_http_methods.lst` + `X-Original-HTTP-Command` (`headers_method` 21→28 payloads). Pinned by `TestParallaxHeadersStragglerFold14`. **Upgrading installations must run once with `--update-payloads`** to refresh the user-config copy of the wordlists (same reason as phase A).
- **Added custom HTTP method and request body support** ([issue #2](https://github.com/slicingmelon/gobypass403/issues/2)) — new `-X/--request` and `--data` flags let you test POST (or any method) requests with a body. All bypass modules now use your method and body as the base request instead of hardcoded GET.
  - `-X POST` / `-X PUT` / any valid HTTP token; validated against RFC 7230 to block request-line smuggling.
  - `--data 'raw body'` or `--data @body.json` (body read verbatim from file). No Content-Type is added automatically — pass `-H "Content-Type: ..."` yourself, matching the tool's raw-request philosophy.
  - `Content-Length` is computed automatically; an explicitly provided `-H Content-Length` takes precedence.
  - Findings' curl PoC commands now include `-X <method>` (non-GET) and `-d '<body>'` with shell-safe quoting, so successful bypasses are copy-paste reproducible.
  - Fixed `-r` debug-token resend silently dropping request bodies — resending a POST finding now reproduces the original request byte-exact. The `-r` token info printout also shows the body.
  - Exceptions: the `http_methods` module keeps rotating methods (that is its purpose), and haproxy's CVE-2021-40346 smuggling job keeps its hardcoded POST and exploit body.
- **Added full raw request import** (issue #2, phase 2) — new `--request-file` flag scans a captured request straight from a text file (e.g. pasted from Burp, curl -v, mitmproxy).
  - The file supplies method, request-target, headers and body as the base request for every bypass module; path modules derive variants from the file's path, and the file's `Host` header (when present) wins over the `-u` host.
  - `-u` remains required and supplies scheme/port; both CRLF and LF line endings are accepted; the body is kept verbatim (no Content-Type added automatically).
  - Imported headers ride as payload headers, so they survive debug tokens and `-r` resends with full fidelity. `Content-Length` in the file is dropped and recomputed from the body.
  - `--request-file` cannot be combined with `-X/--request` or `--data` (the file already defines method and body); absolute-form request targets are rejected with a clear error.

# 0.8.8-2

- **Added Debian packaging** — Created standard `debian/` directory (control, copyright, changelog, rules) and a `build-deb` job in the release workflow. On each `v*` tag push, a `.deb` package is now built and attached to the GitHub release.

# 0.8.8

- **Improved curl command display in results table** — Rewrote multi-line formatting logic for the "Curl CMD" column in the findings summary table. Removed shell continuation characters (`` ` `` on Windows, `\` on Linux) and indentation from wrapped lines. Each line now starts at column 0 and is directly copyable. Flags that take arguments (`-H`, `--request-target`, etc.) are grouped with their values so they never split across lines. URLs always appear on a single line.

- **Fixed false "no results" error on multi-host scans** — When scanning multiple hosts, targets with no findings no longer return an error. Previously, `PrintResultsTableFromDB` would emit `"no results found for <url>"` as an error, causing noise in batch scans. Now returns `nil` silently so scanning continues cleanly.

- **Increased default response body preview size** — Changed the default for `-rbps` / `--response-body-preview-size` from 1024 to 3096 bytes, capturing more response body context by default.

- **Silenced fasthttp deprecated newline separator warning** — Patched the vendored fasthttp `headerScanner.next()` to suppress the `"Deprecated newline only separator found in header"` `slog.Error` messages that flooded terminal output during scans. The warning is irrelevant for raw HTTP response parsing and was drowning out useful scan progress.

# 0.8.7

- **Enhanced curl POC command generation** - Added `--request-target` flag support
  - Automatically detects when bypass payloads are placed before the leading `/` in the URI.
  - Uses curl's `--request-target` flag for non-standard request lines (e.g., `%e2%8a%a1/admin`).
  - Format: `curl -skgi --path-as-is --request-target 'payload' 'https://host'` when RawURI doesn't start with `/`.
  - Preserves standard format `curl -skgi --path-as-is 'https://host/path'` for normal requests.
  - Enables accurate reproduction of successful bypasses for manual verification and reporting.

- **Updated `unicode_path_experimental`** module - Advanced Unicode confusable-based WAF bypass
  - Exploits Unicode normalization vulnerabilities by systematically substituting ASCII characters with visually similar Unicode lookalikes (confusables).
  - Attack vector: WAF sees Unicode characters (e.g., `/admin․․/` using U+2024), backend normalizes to ASCII (e.g., `/admin../`), allowing bypass.
  - Generates ~75K payloads with `maxNormalizationsExperimental=2`, ~150K+ with `maxNormalizationsExperimental=5`.
  - One-character-at-a-time substitution strategy maximizes test coverage.
  - Doubles each variant: generates both raw Unicode and fully URL-encoded versions (`․.;` → raw + `%E2%80%A4.%3B`).
  - Byte-based UTF-8 processing using `utf8.DecodeRune`/`EncodeRune` for efficiency and correctness.
  - Preserves percent-encoded sequences (%XX) during substitution to avoid breaking existing encoding.
  - Integrates with `mid_paths` generation logic for comprehensive path manipulation techniques.
  - Uses `unicode_normalization_map.json` for ASCII→Unicode lookalike mappings.
  - Global deduplication prevents payload overlap with standard `mid_paths` module.

- **Fixed `end_paths`** module - Corrected alphanumeric detection for direct concatenation
  - Changed condition from `!isLetterASCII(payload[0])` to `!isAlphanumericASCII(payload[0])`.
  - Now properly prevents nonsensical concatenations for both words AND digits.
  - Prevents `/admin/login` + `0` → `/admin/login0` (nonsense).
  - Prevents `/admin/login` + `debug` → `/admin/logindebug` (nonsense).
  - Still allows `/admin/login` + `.css` → `/admin/login.css` (file extension bypass).
  - Ensures digits (`0`, `1`) are treated the same as words when appending to paths.
  - Added 20 new payloads to `internal_endpaths.lst`: encoded dots (`.%2e`, `%2e%2e%2f`), whitespace+slash combinations (`%09/`, `%20/`), and complex traversal patterns (`;%2f..%2f..%2f`, `..%3B/`).

- **Refactored `char_encode`** module - Consistent byte-wise iteration for URL encoding
  - Replaced mixed byte/rune iteration patterns with uniform byte-wise iteration throughout.
  - All encoding operations now use byte-level processing (`for i := 0; i < len(s); i++`) for ASCII letter detection.
  - Removed fragile rune-based range loops that could break with multi-byte UTF-8 (though current logic prevented this).
  - Changed `strings.Builder.WriteRune()` to `WriteByte()` for ASCII-only character handling.
  - Maintains identical functionality while improving code consistency and clarity.
  - Aligns with the tool's byte-oriented raw HTTP request architecture.
  
- **Performance optimization: `URLEncodeAll` function**
  - Refactored to use zero-copy string indexing instead of intermediate `[]byte` allocation.
  - Direct byte access via `s[i]` eliminates full string-to-byte-slice conversion overhead.
  - Pre-allocated exact buffer size (3 bytes per input byte) for optimal memory usage.
  - Removed repeated `append()` calls in favor of direct indexing (eliminates bounds checking overhead).
  - Properly handles UTF-8 characters by encoding each byte of their UTF-8 representation.

# 0.8.6

- Fixed critical deduplication bug in `nginx_bypasses` module where payloads with identical URIs but different headers were being dropped. Deduplication now uses composite key (RawURI + Headers) to preserve header variations, resulting in ~74% more test cases for comprehensive bypass testing.
  
# 0.8.5

- Added new CLI parameter `-strict-scheme` to perform testing only on the original scheme.
- Updated `headers_urls` payloads.
- The tool is now using a full, idependent, modified fasthttp client, completely stripped from any code unrelated to the client's comopnenets. 
- Also updated the internal fasthttp client to 1.64.0.
- New CLI option -em/-exclude-module.
- `-m` and `-em` now support glob patterns with *.
- Updated `internal_midpaths.lst` payloads.
- Updated internal tool `unicode_normalization_map.go`.
- Replaced internal `unicode_char_map.json` with `unicode_normalization_map.json`.
- Added a new tool `unicode_truncation_map.go`.
- Updated `unicode_path_normalization` module.
- Updated `char_encode` module.
- New bypass module `haproxy_bypasses`, two CVEs included:
  - CVE-2021-40346: HTTP Request Smuggling via Integer Overflow
  - CVE-2023-45539: URL Fragment ACL Bypass
- New bypass module `unicode_path_truncation`.
  - Targets applications that perform byte-level truncation (`char & 0xFF`) on Unicode characters.
  - Includes prebuilt `unicode_truncation_map.json` with comprehensive character mappings for all bytes (0x00-0xFF).
    
# 0.8.3-0.8.4

- Updated Github Actions workflow, linux static builds are done in Alpine with musl. Fixing issue [#1](https://github.com/slicingmelon/gobypass403/issues/1).
- Updated default output dir to `/tmp/gobypass403_tmp/` instead of `/tmp/`.
- Pre-compiled release binaries now include the version in the filename.
- Updated .goreleaser.yml just for local dev/snapshot builds.
- Updated README.

# 0.8.2

- Updated README.
- Small refactoring.
 
# 0.8.1

- Updated go to 1.24.1.
- Increased TLS LRUSessionCache size.
- Now using custom go-bytesutil pkgs.
- Public repo from now on.

# 0.8.0

- Major update.
- New module haproxy_bypasses.
- Bypass attempts using request smuggling (haproxy CVE).
- Multiple code optimizations.
- Documentation updated on the main README.md file.

# 0.7.9

- Updated all unit tests.
- Each bypass module now has its own deduplication algorithm.
- Added a global deduplication component that filters bypass modules to ensure the same payload is not sent more than once across different modules.
- Refactored `mid_paths` module entirely - it now generates payloads more efficiently, bypass coverage increased as well. 
- Updated payloads lists for `mid_paths` and `end_paths` modules.
- Fixed a major bug when scanning a list of URLs using the `-l` CLI command.
- Updated SQLite DB schema and table organization for better performance.
- Updated GitHub workflow - Linux builds are now compatible with older libc versions.


# 0.7.8

- Updated internal HTTP client to fasthttp 1.62.0. All gobypass403 patches applied.
- Added CVE-2025-29927 bypass, via `x-middleware-subrequest`.
- Proper unit-tests for most of the bypass modules.
- Payload files version detection. Updated the `-update-payloads` CLI command.
- Important updates on the final output table. The results table now includes only a summary of the findings, up to 5 unique results, sorted per url -> bypass module -> status code -> number of bytes in the HTTP response. 
- New CLI options:
  - `-mct, -match-content-type` Filter results by content type(s) substring (example: -mct application/json,text/html)
  - `-min-cl, -min-content-length` Filter results by minimum Content-Length (example: -min-cl 100).
  - `-max-cl, -max-content-length`  Filter results by maximum Content-Length (example: -max-cl 5000).
- Modular bypass modules. Each bypass module has its own .go file. 
- New bypass modules: `nginx_bypasses`, `unicode_path_normalization`, `path_prefix`.
- All bypass modules generating unicode/reverse unicode normalization payloads now rely on a pre-built charmap available in the payloads directory.  
- Updated support for `Transfer-Encoding: identity` HTTP responses.
- Several code refactors, including performance updates.
- New, fully refactored, progressbar. 

# 27 March 2025

- Major release.

# 14 February 2025

- Implemented retry attempts on failed requests, using linear backoff algorithm to increase the delay between retries.
- Autothrottler, throttles the requests exponentially based on known status codes.
- Option to resend the exact request at any time using the debug token.
- Refactored most of the core engine/rawhttp modules to improve performance and reduce allocations.
- Plus way more improvements...

# 09 January 2025

- Refactored the entire codebase. Everything will be documented separately. 

# 05 November 2024

- First official release- **Fixed silent findings truncation in the results table** — the table renders at most 5 rows per (module, status, length) group, and the group separator used to be bare dots, so target-rich runs looked like they produced only a handful of findings with no hint that more existed (observed on the unKover testbed: 5 of 453 `end_paths` findings shown on the nginx/suffix board; the `-X get` → 200 row was present in every `apache/records` run's results DB yet never rendered). Truncated groups now append `+N more in this group (see results.db)` to their separator row, on both flush paths (mid-table group change and the final flush); groups under the cap render byte-identically to before. Storage and filtering are untouched — the results DB always held every row.
- **Added `-scan-profile` scan scope presets (triage-first workflow)** — new flag with values `full` (default, byte-identical to previous behavior) and `triage` (a curated ~9–13k-payload subset instead of full `-m all`'s 68,819 with scheme expansion). Triage is the registry minus the deep families (`path_prefix`, `unicode_*`, `param_manipulation`) — it covers every technique the unKover testbed exercises (headers_ip spoofing, `end_paths` suffix, `http_methods` case, `char_encode` url-encoding, `http10`, `api_versions`, hop-by-hop) plus the full header-matrix depth, so a first pass takes minutes per target; run full `-m all` only on confirmed-403 targets worth enumerating. Explicit `-m` always wins over the preset, `-em` subtracts from whatever base is active, and non-default profiles are announced at startup (`Scan profile: triage (18 modules …)`). Flag named `-scan-profile` because the existing `-profile` is the pprof switch. Pinned by 6 RED→GREEN tests in `core/cli/scanprofile_test.go`.
