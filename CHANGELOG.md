# Unreleased

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

- First official release