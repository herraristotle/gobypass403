# GoByPASS403

A powerful WAF (HTTP 403/401) and URL parser bypass tool developed in Go, designed to preserve exact URL paths and structures during testing. Unlike Go's standard libraries, the tool enables true raw HTTP requests without any encoding or normalization, ensuring complete control over the request structure. This functionality is powered by a full-stack HTTP client, independent of Go's internals, and a custom URL parser.

## Author <!-- omit in toc -->

**slicingmelon**<br><br>
[![GitHub](https://img.shields.io/badge/GitHub-slicingmelon-black?logo=github)](https://github.com/slicingmelon)<br>
[![X](https://img.shields.io/badge/X-@pedro__infosec-1DA1F2?logo=x)](https://x.com/pedro_infosec)

---

- [GoByPASS403](#gobypass403)
- [Features](#features)
- [Installation](#installation)
  - [Precompiled Binaries (Recommended)](#precompiled-binaries-recommended)
  - [Build Locally](#build-locally)
    - [Standard Build](#standard-build)
    - [GoReleaser](#goreleaser)
- [Usage](#usage)
  - [Standard WAF 403/401 Bypass](#standard-waf-403401-bypass)
  - [Find CDN Bypasses Using A List Of Hosts](#find-cdn-bypasses-using-a-list-of-hosts)
  - [Screenshots](#screenshots)
- [Bypass Modules](#bypass-modules)
  - [1. char\_encode](#1-char_encode)
  - [2. mid\_paths](#2-mid_paths)
  - [3. end\_paths](#3-end_paths)
  - [4. path\_prefix](#4-path_prefix)
  - [5. http\_methods](#5-http_methods)
  - [6. case\_substitution](#6-case_substitution)
  - [7. nginx\_bypasses](#7-nginx_bypasses)
  - [8. haproxy\_bypasses](#8-haproxy_bypasses)
    - [CVE-2021-40346: HTTP Request Smuggling via Integer Overflow](#cve-2021-40346-http-request-smuggling-via-integer-overflow)
    - [CVE-2023-45539: URL Fragment ACL Bypass](#cve-2023-45539-url-fragment-acl-bypass)
  - [9. unicode\_path\_normalization](#9-unicode_path_normalization)
  - [10. unicode\_path\_truncation](#10-unicode_path_truncation)
  - [11. headers\_scheme](#11-headers_scheme)
  - [12. headers\_ip](#12-headers_ip)
  - [13. headers\_port](#13-headers_port)
  - [14. headers\_url](#14-headers_url)
  - [15. headers\_host](#15-headers_host)
  - [16. headers\_hop\_by\_hop](#16-headers_hop_by_hop)
  - [17. api\_versions](#17-api_versions)
  - [18. http10](#18-http10)
  - [19. headers\_method](#19-headers_method)
  - [20. user\_agent](#20-user_agent)
  - [21. param\_manipulation](#21-param_manipulation)
- [Findings](#findings)
  - [Findings Summary](#findings-summary)
  - [Full Findings Database](#full-findings-database)
  - [Reproducing Findings](#reproducing-findings)
    - [Curl PoC Commands](#curl-poc-commands)
    - [Debug Token System](#debug-token-system)
      - [Token Structure](#token-structure)
      - [Debug Token Usage](#debug-token-usage)
      - [Token Storage and Access](#token-storage-and-access)
- [Changelog](#changelog)
- [Motivation](#motivation)
  - [Credits](#credits)

# Features

- **Raw URL Preservation**: Unlike other Go tools that use the standard `net/url` package which automatically normalizes and encodes URLs, GoBypass403 preserves the exact URL structure similar, even better than curl's `--path-as-is` or Burp Engine. This is crucial for WAF bypass attempts where path traversal and specific URL structures need to be maintained.

- **Custom URL Parser**: Implements a specialized URL parser that prevents Go's default security measures from interfering with bypass attempts. This allows for testing of edge cases and security boundaries that would otherwise be normalized away.

- **Multiple Bypass Techniques**: 
  - Path manipulation (mid-path, end-path)
  - Case substitution
  - Headers manipulation (IP, scheme, URL, port)
  - Character encoding variations
  - And more...

- **CDN Bypass Support**: Special features for testing CDN-based bypasses using host substitution

# Installation

## Precompiled Binaries (Recommended)

- Windows, Linux and MacOS builds available: https://github.com/herraristotle/gobypass403/releases/latest.

## Build Locally

### Standard Build

```bash
git clone https://github.com/herraristotle/gobypass403.git
go mod download
go build .\cmd\gobypass403\
```

### GoReleaser 

```bash
goreleaser build --snapshot --clean --single-target --output .
```

# Usage

```
GoByPASS403

Usage:
  -u, -url
        Target URL (example: https://cms.facebook.com/login)
  -l, -urls-file
        File containing list of target URLs (one per line)
  -shf, -substitute-hosts-file
        File containing a list of hosts to substitute target URL's hostname (mostly used in CDN bypasses by providing a list of CDNs)
  -m, -module
        Bypass module (all,path_prefix,mid_paths,end_paths,http_methods,case_substitution,char_encode,nginx_bypasses,haproxy_bypasses,unicode_path_normalization,unicode_path_truncation,headers_scheme,headers_ip,headers_port,headers_url,headers_host,headers_hop_by_hop,api_versions,http10,headers_method,user_agent,param_manipulation). Supports glob patterns with * (e.g., headers*,*bypass*) (Default: all)
  -em, -exclude-module
        Exclude specific bypass modules. Supports glob patterns with * (e.g., -em unicode*,*experimental). Takes precedence over -m
  -o, -outdir
        Output directory
  -cr, -concurrent-requests
        Number of max concurrent requests (Default: 15)
  -T, -timeout
        Total timeout (in milliseconds) (Default: 20000)
  -delay
        Delay between requests (in milliseconds) (0 means no delay) (Default: 0)
  -max-retries
        Maximum number of retries for failed requests (0 means no retries) (Default: 2)
  -retry-delay
        Delay between retries (in milliseconds) (Default: 500)
  -max-cfr, -max-consecutive-fails
        Maximum number of consecutive failed requests before cancelling the current bypass module (Default: 15)
  -at, -auto-throttle
        Enable automatic request throttling (on/off, 1/0) (Default: on)
  -v, -verbose
        Verbose output (Default: false)
  -d, -debug
        Debug mode with request canaries (Default: false)
  -mc, -match-status-code
        Filter results by HTTP status codes (example: -mc 200, 301, 5xx, all). Default: All status codes
  -mct, -match-content-type
        Filter results by content type(s) substring (example: -mct application/json,text/html)
  -min-cl, -min-content-length
        Filter results by minimum Content-Length (example: -min-cl 100)
  -max-cl, -max-content-length
        Filter results by maximum Content-Length (example: -max-cl 5000)
  -H, -header
        Custom HTTP header (example: -H "X-My-Header: value"), can be used multiple times
  -X, -request
        HTTP method used for base requests, applied by all bypass modules (example: -X POST) (Default: GET)
  -data
        Request body sent verbatim with base requests; a leading @ reads the body from a file (example: --data 'user=admin', --data @body.json). No Content-Type is added automatically, use -H
  -request-file
        File containing one raw HTTP request (request line, headers, body) used as the base request for all modules; cannot be combined with -X/--request or --data. -u still supplies scheme/port (example: --request-file captured.req)
  -sc, -strict-scheme
        Only test URLs with the original scheme from input (prevents auto-expansion to http/https) (Default: false)
  -http2
        Enable HTTP2 client (Default: false)
  -x, -proxy
        Proxy URL (format: http://proxy:port) (Example: -x http://127.0.0.1:8080)
  -spoof-header
        Add more headers used to spoof IPs (example: X-SecretIP-Header,X-GO-IP)
  -spoof-ip
        Add more spoof IPs (example: 10.10.20.20,172.16.30.10)
  -spoof-prefix
        Add more path prefixes tested by the api_versions module (example: /internal,/v2beta)
  -fr, -follow-redirects
        Follow HTTP redirects
  -rbps, -response-body-preview-size
        Maximum number of bytes to retrieve from response body (Default: 3096)
  -drbs, -disable-response-body-streaming
        Disables streaming of response body (default: False) (Default: false)
  -dpb, -disable-progress-bar
        Disable progress bar (Default: false)
  -r, -resend
        Resend the exact request using the debug token (example: -r xyzdebugtoken)
  -rn, -resend-num
        Number of times to resend the debugged request (Default: 1)
  -analyze
        Analyze an existing results database offline (read-only) and print the differential report, then exit (example: -analyze /tmp/scan/results.db)
  -analyze-json
        With -analyze: also write the report as JSON to this file (example: -analyze-json /tmp/report.json)
  -profile
        Enable pprof profiler (Default: false)
  -scan-profile
        Scan scope preset: full (all bypass modules) or triage (high-signal subset for first-pass triage; explicit -m wins, -em subtracts) (Default: full)
  -adaptive
        Order the modules by the baseline fingerprint and run the deep families once a confirmed 403 produced a novel cluster (off by default; the fingerprint costs no extra request) (Default: false)
  -calibrate
        Send a negative-control probe to a path that cannot exist and suppress any result matching it (kills wildcard/soft-404 false positives; off by default, costs 3 requests per target) (Default: false)
  -warn-wildcard
        With -calibrate off: report a BYPASS cluster whose many distinct requests share one response as wildcard-shaped and point at -calibrate (a hint only, it never suppresses or reclassifies anything; works with -analyze; off by default) (Default: false)
  -expand
        Expand around a confirmed hit: derive a bounded depth-1 batch from the request that worked (off by default; 256 extra requests per hit, 1024 per target) (Default: false)
  -max-reqs
        Hard stop after this many requests across the whole run (0 = unlimited). Counts every request sent, including expansion batches (Default: 0)
  -resume
        Continue an interrupted run: skip the (target, module) pairs scan.progress.json in the output dir already marks complete (Default: false)
  -tw
        Scan this many targets at once, at most one per host (1 = sequential, the default). Disables the progress bar and prints each target's table as it finishes (Default: 1)
  -update-payloads
        Update payload files to latest version (Default: false)
```

## Offline Analysis: what actually bypassed

A scan records *responses*, but not which of them actually differ from the
target's normal (blocked) response. `-analyze` re-reads a finished
`results.db` **offline and read-only** — no new requests, no output DB, no
recon — and classifies every response against that target's baseline:

| Class | Meaning |
|---|---|
| `BYPASS` | status improved on the baseline (e.g. baseline `403` → `200`/`3xx`) with a different body — the interesting case |
| `VARIANT` | same status class, different body (a different block page, a soft-404, …) |
| `DUP` | exactly the baseline response |
| `NOISE` | empty, non-improving artifact |
| `CALIBRATED` | matches the `-calibrate` negative control — the server's wildcard/soft-404 default, never a finding |

Responses are clustered by exact `(status, media type, sha256(body), length)`,
so hundreds of near-identical hits collapse into **one** line that states how
many members were hidden.

```bash
# Print the differential report for a finished scan (read-only, offline)
gobypass403 -analyze /tmp/gobypass403_tmp/gobypass403_<id>/results.db

# Same report as JSON for pipelines (stable snake_case field names)
gobypass403 -analyze /tmp/gobypass403_tmp/gobypass403_<id>/results.db \
  -analyze-json /tmp/report.json
```

Baseline: the target's `dumb_check` response when present (the plain request
with no bypass trick applied); otherwise the target's most common response
shape — the report says which one was used.

**Honest limits.** Fingerprints are derived from the stored body preview
(truncated at capture time by `-rbps`), so responses that differ only beyond
the preview are treated as identical; clustering is exact-digest only (no
fuzzy matching); and `BYPASS` means "the response changed", not "this is
exploitable" — every cluster prints its ready-to-run `curl` command so you
can confirm by hand.

## Wildcard calibration: killing the soft-404 false positive

Some servers answer **every** unknown path with a success page — a wildcard
`200`, a catch-all "not found" served as `200`, or an SPA fallback. A 403
baseline against such a server makes the classifier read *any* payload `200` as
a `BYPASS`, when the server served nothing. The fix is a **negative control**:
ask for a path that cannot exist and see what the server does with it.

```bash
gobypass403 -u "https://target.example/admin/.env" -calibrate
```

`-calibrate` sends three probes to random non-existent siblings of the target's
own path (e.g. `/admin/<random>`), records them as the synthetic `calibration`
module, and marks any cluster matching a control as **`CALIBRATED`** — never
`BYPASS`. A cluster matches when it has the same status and media type and
either an **identical body digest** (an exact wildcard) or a length within
**±50 bytes** (an echoing soft-404, which stamps the requested path and so
changes size but not shape). Control rows are stored even when `-mc`/`-mcl`
would drop them, so the offline `-analyze` report sees them too. `-expand` and
`-adaptive` act only on `BYPASS`, so a calibrated cluster is never expanded or
escalated.

- **Opt-in.** Without `-calibrate` there is no probe request and no new row;
  the scan and its report are byte-identical to today.
- **`-calibrate` is the driver, not a module.** It is injected after
  `dumb_check` and never appears in `-m all` or a `-scan-profile` set.
- **Honest limits.** Matching relies on the stored length: with a small `-rbps`
  two distinct large bodies can both read as the preview cap and match. The
  digest-equal path is exact; when in doubt, read the `curl` PoC in the report.

### Spotting a wildcard when you forgot `-calibrate`: `-warn-wildcard`

`-calibrate` is the fix; `-warn-wildcard` is the nudge that tells you it was
needed. With it on, the end of a live run (and the offline `-analyze` report)
adds one line per suspect cluster:

```
wildcard-shaped cluster: 6 requests returned the same 200 text/html 39B (http_methods)
```

It fires when a `BYPASS` cluster's members come from **many distinct requests**
(≥ 5) while sharing one response shape — the signature of a server that answers
every path the same way. It is a **hint only**: it never suppresses,
reclassifies, hides or rewrites a finding. It says "looks like", and it points
you at `-calibrate` to settle it. Runs that already used `-calibrate` are
skipped entirely — the control already answered the question — and the flag
appears in `-analyze` too, so you can re-read an old `results.db`. Without the
flag, output is byte-identical to today.

- **Needs the baseline row.** The hint reads the run's baseline (the
  `dumb_check` row). A run whose `-mc` filter drops the baseline `403` stores
  the wildcard `200` as the modal baseline instead, the cluster classifies as a
  duplicate, and the hint stays silent. On a target you suspect of a catch-all,
  widen `-mc` (or just use `-calibrate`).
- **Not in `-analyze-json`.** The hint is operator-facing text; the JSON report
  is unchanged.

## Feedback Expansion: expand around a confirmed hit

A scan is normally one-way: each module sends its payload set and reports what
came back. `-expand` adds one bounded follow-up pass. When a module's batch
finishes, the same classifier that powers `-analyze` looks at that batch, and
if something actually bypassed, a **depth-1** batch of variations around *that
exact request* is derived and scanned through the normal pipeline (same
request pool, same filters, same findings table).

```bash
# find bypasses, then feel around the first one that works
gobypass403 -u "https://go-test-webapp.com/admin" -mc "200" -expand
```

Only three families expand; every other module reports itself unsupported and
sends nothing extra:

| Confirmed hit | Derived variations |
|---|---|
| path modules (`path_prefix`, `mid_paths`, `end_paths`, `char_encode`, `case_substitution`, …) | the module's own generator, re-applied to the confirmed request-target |
| `http_methods`, `headers_method` | case permutations and a trailing-space twin of the method that worked |
| `headers_ip` | other notations and neighbours of the IP value that worked |

Guardrails:

- **Opt-in.** Without `-expand` there is no observation collection, no
  classification and no extra request — a default run is unchanged.
- **Capped.** At most **256** derived requests per confirmed hit and **1024**
  per target; only the **top** `BYPASS` cluster of a batch is expanded.
- **Depth 1.** Expansion responses are never re-classified, so a derived hit
  cannot start another round and the batch cannot grow recursively.
- **Marked.** Expansion rows keep their real module name (the findings table
  still groups them) and their `curl` command ends in ` # expanded` — a shell
  comment, so a copy-pasted PoC still runs.
- **No repeats.** A shape the batch already sent is never re-sent (e.g.
  `http_methods` tests both `acl` and `ACL` itself, so a derived `acl` for a
  confirmed `ACL` is dropped).

**Honest limits.** A hit is judged by the same heuristic status-class rule as
`-analyze`: it means "this response differs from the baseline", not "this is
exploitable". Matching is exact-digest only (no fuzzy matching), expansion is
one round deep, and many modules have no mutator at all (most header families,
`param_manipulation`, `user_agent`, …), so they expand nothing.

## Adaptive ordering: fingerprint first, deep families last

`-adaptive` spends the same requests in a better order. Every scan already
starts with `dumb_check`, and its response is the target's **fingerprint** —
status, `Server` header, marker headers and cookies, all already in hand, so
the fingerprint costs **no extra request**. The modules that fingerprint points
at run first, and the expensive deep families run only when the triage pass
earned them.

```bash
# high-signal pass, in the order this front end wants to be probed
gobypass403 -u "https://target.example/admin" -scan-profile triage -adaptive
```

### The heuristic table

The table is data (`adaptive.Rules` in `core/engine/adaptive`), not vibes: each
rule matches markers in the baseline response and **promotes** the modules
listed, ahead of the rest, without ever adding or removing one — `-adaptive`
only reorders the module list you asked for.

| Front end (`Rule.Name`) | Fingerprint marker (`Server` header, header or cookie) | Promoted first |
|---|---|---|
| `cloudflare` | `cloudflare`, `cf-ray`, `cf-cache-status`, `cf-request-id`, `cf_clearance`, `__cf_bm`, `__cfduid` | `headers_ip`, `headers_host`, `end_paths`, `nginx_bypasses` |
| `nginx` | `nginx` | `nginx_bypasses`, `end_paths`, `mid_paths`, `case_substitution` |
| `haproxy` | `haproxy` | `haproxy_bypasses`, `end_paths`, `headers_url`, `case_substitution` |
| `akamai` | `akamaighost`, `x-akamai`, `akamai-grn`, `ak_bmsc`, `_abck`, `bm_sz` | `headers_host`, `headers_url`, `path_prefix`, `case_substitution` |
| `cloudfront` | `cloudfront`, `x-amz-cf-id`, `x-amz-cf-pop` | `headers_host`, `headers_url`, `headers_ip`, `end_paths` |
| `azure` | `azure`, `x-azure-ref`, `x-msedge-ref` | `headers_host`, `headers_url`, `case_substitution`, `end_paths` |
| `varnish` | `x-served-by`, `x-varnish`, `x-cache`, `x-fastly-request-id` | `headers_url`, `headers_host`, `char_encode`, `end_paths` |
| `iis` | `microsoft-iis`, `x-aspnet`, `x-powered-by: asp.net` | `headers_method`, `case_substitution`, `char_encode`, `end_paths` |
| `apache` | `apache` | `case_substitution`, `char_encode`, `end_paths`, `mid_paths` |
| `f5` | `bigipserver`, `x-wa-info`, `ts01` | `headers_url`, `headers_host`, `end_paths` |

Matching is a plain case-insensitive substring test over the baseline `Server`
value, the raw response header lines and the cookies, so a `Server: nginx/1.24.0`
or a `Set-Cookie: __cf_bm=…` promotes the same way. Each row encodes the module
family that front end is known to mishandle — the `x-forwarded-*`/`cf-*`
forwarding headers for Cloudflare, the path-normalisation quirks of
nginx/haproxy, the caching and header handling of Varnish/Fastly, Akamai,
CloudFront and F5. The table is pinned row by row in
`core/engine/adaptive/adaptive_test.go`, and promotion is exercised on the wire
on an `nginx` board in `tests/unittests/engine/scanner/adaptive_wire_test.go`.

### Escalation: the deep families only after evidence

The triage preset is the registry **minus the five deep families**
(`path_prefix`, `unicode_path_normalization`, `unicode_path_truncation`,
`unicode_path_experimental`, `param_manipulation`) — minutes per target instead
of tens of thousands of payloads. With `-adaptive`, when a target's triage pass

1. has a **403 baseline**, and
2. produced at least one **`BYPASS` cluster** — a response that improved on that
   baseline,

the five deep families run for that target, once, through the normal pipeline,
so `-max-reqs` still caps them and `-resume` checkpoints them like any other
`(target, module)` pair. No evidence, no deep pass: a 403 target whose
responses are all `DUP`/`VARIANT`, or a target that is not 403 at all, never
escalates.

Guardrails:

- **Opt-in.** Without `-adaptive` nothing is fingerprinted, reordered or
  escalated; the module order is exactly the `-m`/`-scan-profile` order and a
  default run is unchanged.
- **Promotion only.** Ordering never grows the module set; the only module
  `-adaptive` can add is a deep family, and only after 403 **plus** a novel
  cluster.
- **No extra request for the fingerprint.** It is read from `dumb_check`, which
  already runs first. Exclude it (`-em dumb_check`) and there is no fingerprint:
  the run keeps the default order and says so once.
- **Nothing already covered is repeated.** With `-m all` the deep families are
  in the list already, so escalation has nothing to add.

**Honest limits.** The table is a heuristic, not a fingerprint database: an
unknown front end (or a stripped `Server` header) simply keeps the default
order, and a wrong guess only changes *when* a module runs, never whether it
runs. Escalation is all-or-nothing per target — it runs the whole deep set, not
just the family that happened to match, so a single confirmed bypass can turn a
triage run into a full deep pass (~46k payloads for a typical path).

## Long runs: request budget, resume and parallel targets

Three flags make a long scan cheaper to run and cheaper to repeat. All three are
opt-in: without them a run is byte-identical to what it always was.

### `-max-reqs <n>` — stop after a fixed number of requests

```bash
# at most 2000 requests in total, then report what was found so far
gobypass403 -l targets.txt -max-reqs 2000
```

The budget is **shared by everything** the run sends — every module, every
target, expansion batches included — and `0` (the default) means unlimited.

**Exhaustion semantics.** Running out does *not* abort the scan. Later batches
reserve nothing and send nothing, the run finishes normally, and the findings
already collected are kept. You get **one** warning line saying the budget is
gone. A retried request is not charged twice, so with `-max-retry` above 0 the
wire may see slightly more than `n` attempts; the budget counts *requests
issued*, not retries of them.

### `-resume` — continue an interrupted run

```bash
# same outdir, same command, after a ctrl-c
gobypass403 -u https://target.example/admin -o /tmp/scan -resume
```

`-resume` reads `scan.progress.json` from the output directory, skips every
`(target, module)` pair already recorded there, and records each pair as soon as
its module finishes — so an interruption costs at most the module that was
running, never the whole run. Findings are not duplicated: skipped pairs send no
requests and store no rows.

```json
{
  "version": 1,
  "completed": [
    { "target_url": "https://target.example/admin", "module": "dumb_check" }
  ]
}
```

- **Without `-resume` there is no sidecar at all** — no file is read and none is
  written, which is why a plain run's output does not change.
- A **damaged or foreign** `scan.progress.json` is reported and ignored: the run
  rescans everything instead of failing.
- **Use `-o` with it.** The default output directory is unique per run
  (`/tmp/gobypass403_tmp/gobypass403_<id>/`), so `-resume` without `-o` finds no
  checkpoint and starts over — the `Resume: 0 completed (target, module) pairs
  will be skipped` line is your signal.
- **Honest limits.** A pair is keyed by the target string as you typed it and by
  **module name**: a target spelled differently is a different pair, and a module
  whose payload set changed since the interruption is still considered done.
  `-resume` cannot be combined with `-analyze`.

### `-tw <n>` — several targets at once

```bash
# four targets in flight, but never two at the same host
gobypass403 -l targets.txt -tw 4 -max-reqs 5000
```

`-tw` (default `1`, i.e. today's sequential loop) scans up to `n` targets
concurrently with **one target per host at a time**: work is distributed as one
bucket of targets per host, so a worker owns a host until its targets are done.
That is the politeness rule — `-tw` never lets the tool hit one host with two
different targets simultaneously, whatever `-cr` says within a target.

- With `-tw > 1` the **progress bar is disabled** (one warning line) because a
  single bar cannot describe several targets, and each target's table is printed
  **as that target finishes** — completion order, not input order.
- Result tables never interleave: each target still gets its own table and
  summary line.
- The request budget (`-max-reqs`) is shared across workers, so the total stays
  exact however many run at once, and the findings DB keeps its single-writer
  discipline, so per-target row counts are exactly those of the sequential runs.
- `-tw 1` keeps the sequential loop and input-order output, byte for byte.
- Invalid values (`0`, negative) are rejected.

## Standard WAF 403/401 Bypass

Standard command(s):
```bash
gobypass403 -u "https://go-test-webapp.com/admin" -mc "200"
gobypass403 -u "https://go-test-webapp.com/admin" -mc "200,500" -cr 10
gobypass403 -u "https://go-test-webapp.com/admin" -mc "mid_paths,nginx_bypasses,headers_ip" -cr 20 -mct "application/json,image/png"

# Test POST (or any method) requests with a body - all modules use your method/body
# as the base request. Add Content-Type yourself via -H if needed.
gobypass403 -u "https://go-test-webapp.com/admin" -X POST --data 'user=admin&role=root' -H "Content-Type: application/x-www-form-urlencoded" -mc "200"
gobypass403 -u "https://go-test-webapp.com/api/v1/users" -X POST --data @create_user.json -H "Content-Type: application/json" -mc "200"

# Or scan a full captured request (e.g. from Burp) straight from a file - method,
# path, headers and body all come from the file; -u only supplies scheme/port.
cat > captured.req <<'EOF'
POST /admin/config/users?debug=1 HTTP/1.1
Host: go-test-webapp.com
Content-Type: application/json

{"user":"admin","role":"root"}
EOF
gobypass403 -u "https://go-test-webapp.com:443/x" --request-file captured.req -mc "200"
```

Using a list of target URLs:
```bash
gobypass403 -l "targeturls.txt" 
```

## Find CDN Bypasses Using A List Of Hosts 

Sometimes you want to find bypasses in a long list of CDNs, and you know that the video path is always the same. Example when you want to bypass the hash check on a video or image.

// Redacted. Will update.

## Screenshots

Example Results 1
![Screenshot 1](images/1.jpg)

# Bypass Modules

The next section describes each bypass module in detail. Each module implements a distinct set of techniques designed to uncover specific vulnerabilities in WAFs, ACLs, reverse proxies, and web server misconfigurations.

## 1. char_encode

The `char_encode` module implements comprehensive character encoding techniques to bypass WAF pattern matching. It systematically generates payloads by applying URL encoding using five distinct strategies.

The module implements five core encoding techniques:

1. **Last Character Encoding:** Encodes the last character of the entire path.
2. **First Character Encoding:** Encodes the first character of the path (after any leading '/').
3. **Last Segment Character Encoding:** Encodes each character in the last path segment individually.
4. **Full Path Character Encoding:** Encodes each character in the entire path individually.
5. **Full Segment Encoding Variations:** Encodes all characters within complete path segments, creating fully URL-encoded versions of each segment.

For each technique, it generates three encoding variants:
- Single encoding: `%61` (standard percent encoding)
- Double encoding: `%2561` (encoding the percent sign itself)
- Triple encoding: `%252561` (encoding the percent sign twice)

Example payloads for `https://example.com/admin/test`:

```
# Individual character encoding
/admin/test → /admi%6e/test     # Last character encoded
/admin/test → /%61dmin/test     # First character encoded  
/admin/test → /admin/t%65st     # Character in last segment encoded

# Full segment encoding  
/admin/test → /%61%64%6d%69%6e/test           # Full "admin" segment encoded
/admin/test → /admin/%74%65%73%74             # Full "test" segment encoded
/admin/test → /%61%64%6d%69%6e/%74%65%73%74   # Both segments fully encoded
```

All variations preserve the original query string if present. Special characters like `?` and `#` are handled with proper percent-encoding to preserve query parameters.

## 2. mid_paths

The `mid_paths` module injects path traversal sequences and special character combinations using a predefined list of payloads (`internal_midpaths.lst`).

For a URL like `/a/b`, the module creates these variants:

1. Before path:
   - `PAYLOAD/a/b`
   - `/PAYLOAD/a/b`

2. At each segment:
   - `/PAYLOADa/b` (fused with first segment start)
   - `/aPAYLOAD/b` (fused with first segment end)
   - `/a/PAYLOADb` (fused with second segment start)
   - `/a/bPAYLOAD` (fused with second segment end)

3. After each slash:
   - `/a/PAYLOAD/b` (inserted after a slash)

Each variant is generated with appropriate path normalization handling. The module carefully manages special characters in path segments, generating additional variants with percent-encoded `?` and `#` characters when necessary.

The list also carries the **parser-inconsistency atoms** — the ASCII control range `%00`–`%1F`, the ASCII punctuation/symbol set, space `%20` and DEL `%7F` — so they are inserted *inside* the path (`/admin%00/config`, `/admin/%00/config`, `/%00admin/config`), not only at the end. That interior placement is what a front end and an application disagree about when they read a whitespace byte, a `;` or a `\` inside the path (Orange Tsai, *A New Era of SSRF*; Rafael da Costa Santos, *Exploiting HTTP Parsers Inconsistencies*). `end_paths` covers the same atoms at the tail only, so the two modules are complementary. Atoms are percent-encoded, never raw; a bare `%0D%0A` pair is deliberately excluded (that is request-splitting, a different class). They are deduped against the rest of the corpus (case-insensitively, since `%2f` and `%2F` denote the same byte), and `unicode_path_experimental` skips percent-encoded sequences, so the addition is a no-op for that module.

## 3. end_paths 

The `end_paths` module appends a variety of suffixes from a predefined list (`internal_endpaths.lst`) to the end of the URL path. This technique targets path normalization vulnerabilities and extension handling issues in WAFs.

For a URL like `https://example.com/admin`, the module generates:

1. Standard suffix variants:
   - `/admin/SUFFIX`
   - `/admin/SUFFIX/`

2. Direct append variants (when the base path isn't root `/` and suffix doesn't start with a letter):
   - `/adminSUFFIX`
   - `/adminSUFFIX/`

Common suffixes include:
- Path traversal sequences: `..;/`, `../`, `./`
- Special characters: `;`, `:`, `%20`
- Common extensions: `.json`, `.php~`, `.bak`

The module preserves the original query string and handles special characters with proper percent-encoding to maintain request integrity.

## 4. path_prefix

The `path_prefix` module manipulates path segments using specific byte patterns to bypass security checks. It systematically prefixes URL segments with ASCII control characters, special characters, and the literal 'x' character.

For each relevant byte value, the module creates three distinct variations:

1. Dummy Segment Prefix (Single Byte):
   - Adds a new first segment containing the byte value
   - Example: `/admin` → `/[b1]/admin` or `/%XX/admin`

2. Existing Segment Prefix (Single Byte):
   - Prepends the byte to each existing segment individually
   - Example: `/admin/login` → `/[b1]admin/login` or `/%XXadmin/login`

3. Existing Segment Prefix (Two Bytes):
   - Prepends byte pairs to each existing segment
   - Example: `/admin/login` → `/[b1b2]admin/login` or `/%XX%YYadmin/login`

Each byte value is applied both as a raw byte (when safe) and in percent-encoded form to ensure maximum coverage of potential bypass vectors.

## 5. http_methods 

The `http_methods` module tests various standard and non-standard HTTP methods loaded from a predefined list (`internal_http_methods.lst`). HTTP method switching is a well-known technique to bypass WAF rules that only filter specific methods.

For each method, it generates:

1. Base method variation:
   - Uses the specified method with the original URL's path and query string
   - Example: `OPTIONS /admin` instead of `GET /admin`

2. Content-Length handling:
   - For methods that typically expect a body (POST, PUT, PATCH, DELETE), adds `Content-Length: 0` header
   - Example: `GET /admin` with `Content-Length: 0`

3. Query parameter relocation (POST only):
   - For POST requests with query parameters, creates a variant where:
     - Query string is removed from URL
     - Parameters are moved to the request body
     - Proper content type headers are set
   - Example: `POST /admin?id=1` becomes `POST /admin` with body `id=1`

## 6. case_substitution 

The `case_substitution` module applies targeted case manipulations to bypass case-sensitive pattern matching in WAFs and ACLs.

It implements four distinct case manipulation strategies:

1. Terminal character case inversion:
   - Uppercases only the last letter of the path (if lowercase)
   - Example: `/admin` → `/admiN`

2. HTTP method case manipulation:
   - Uppercases the HTTP method (e.g., "GET", "POST")
   - Example: `get /admin` → `GET /admin`

3. Character-by-character case inversion:
   - Inverts the case of each letter in the path individually
   - Example: `/admin` → `/Admin`, `/aDmin`, `/adMin`, `/admIn`, etc.

4. Full path uppercase conversion:
   - Uppercases the entire path string
   - Example: `/admin` → `/ADMIN`

All original query parameters are preserved when applying these case manipulations.

## 7. nginx_bypasses

The `nginx_bypasses` module is a comprehensive collection of techniques targeting server-side parsing inconsistencies across multiple web frameworks and server types. While named for Nginx, it targets a broad spectrum of platforms including Flask, Spring Boot, and Node.js applications.

The module implements several specialized bypass vectors:

1. Framework-specific byte patterns:
   - Flask bypasses: Bad bytes used in payloads (`0x85, 0xA0, 0x1F, 0x1E, 0x1D, 0x1C, 0x0C, 0x0B`) that can trigger path normalization bypasses
   - Spring Boot bypasses: Leverages tab character (`0x09`) and semicolon (`;`) interpretation quirks
   - Node.js bypasses: Exploits specific characters (`0xA0, 0x09, 0x0C`) that Node.js processes differently

2. Strategic character insertion:
   - Inserts both raw and percent-encoded special bytes in key positions:
     - Path end: `/admin[char]`
     - After trailing slash: `/admin/[char]`
     - Path beginning: `/[char]admin`
     - After each segment: `/segment1[char]/segment2`
     - Before each segment: `/segment1/[char]segment2`
     - After first character: `/s[char]egment1`

3. Request splitting techniques:
   - HTTP protocol confusion with newlines: 
     - Injects `%0A` followed by HTTP version strings (`HTTP/1.1`, `HTTP/1.0`, `HTTP/2.0`, `HTTP/0.9`)
     - Example: `/admin%0AHTTP/1.1`

4. Routing manipulation attacks:
   - Complex request smuggling vectors:
     - Combines newlines, HTTP versions, and alternative URIs
     - Example: `/admin%0AHTTP/1.1%0Ahttp://localhost/admin`
   - Host variation:
     - Tests multiple alternative hosts: `localhost`, `127.0.0.1` with different port combinations
     - Combines with explicit Host header manipulation

5. Protocol handler exploitation:
   - Tests different URI schemes (`http://`, `https://`, `file://`, `gopher://`)
   - Targets proxy pass-through vulnerabilities and protocol handler misconfigurations

The module represents one of the most comprehensive path manipulation testing suites, targeting inconsistencies in:
- HTTP request parsing
- Proxy handling
- Framework-specific path normalization
- Reverse proxy configurations
- Load balancer behavior
- Server-side protocol handling

Each payload is carefully generated to preserve proper URL structure and ensure the original query parameters are correctly maintained.

The sample screenshots below show ambiguous requests generated by the nginx_bypasses module:

![431359279-d43321f1-5f02-4d40-b8dc-81db186b6a72](https://github.com/user-attachments/assets/448a4770-b0a1-4c38-9992-100719ed1aa6)

![431359726-45432421-cae0-40f9-be75-43f0d9c24022](https://github.com/user-attachments/assets/9594e5e2-a0c1-4ca1-bb38-c716eacc279b)

## 8. haproxy_bypasses

The `haproxy_bypasses` module targets specific vulnerabilities in HAProxy configurations, implementing exploitation techniques for two critical CVEs that affect different versions and functionalities of HAProxy.

### CVE-2021-40346: HTTP Request Smuggling via Integer Overflow

This vulnerability exploits an integer overflow in HAProxy's header parsing mechanism to achieve HTTP Request Smuggling, allowing attackers to bypass access controls and routing restrictions.

**Attack Mechanism:**
- Creates malformed `Content-Length` headers with 256+ character names (e.g., `Content-Length0aaa...`)
- Exploits integer overflow in header parsing to smuggle secondary HTTP requests
- Uses public endpoints as camouflage while targeting restricted paths in the smuggled request

**Payload Structure:**
```
POST /public HTTP/1.1
Host: target.com
Content-Length0aaaa...[252 more 'a' chars]: 
Content-Length: 89
Connection: close

GET /admin HTTP/1.1
h:GET /public HTTP/1.1
Host: target.com

```

**Key Features:**
- Tests multiple public endpoints (`/`, `/robots.txt`, `/favicon.ico`, etc.) as entry points
- Each payload is sent twice in sequence (required for smuggling to work)
- Targets backend servers that process smuggled requests differently than HAProxy

### CVE-2023-45539: URL Fragment ACL Bypass

This vulnerability exploits HAProxy's improper handling of URL fragments (`#`) in Access Control List (ACL) matching, allowing attackers to bypass `path_end`, `path_beg`, and `path_reg` rules.

**Attack Vectors:**

1. **Extension Bypass (`path_end` rules):**
   ```
   /admin#.png          # Bypasses path_end .png rules
   /restricted#.css     # Bypasses path_end .css rules
   /api/secret#.json    # Bypasses path_end .json rules
   ```

2. **Path Prefix Bypass (`path_beg` rules):**
   ```
   /admin#public        # Bypasses path_beg public rules
   /restricted#guest    # Bypasses path_beg guest rules
   /api/private#api     # Bypasses path_beg api rules
   ```

3. **Multi-level Fragment Injection:**
   ```
   /api/v1#.xml/users   # Fragment injection between path segments
   /admin#static/panel  # Complex routing manipulation
   ```

4. **Advanced Techniques:**
   - Double fragment bypass: `/admin#public#.png`
   - Query parameter interference: `/admin#.css?debug=true`
   - Path traversal combinations: `/admin#../file.txt`

**Vulnerability Context:**
According to the [HAProxy changelog](https://www.mail-archive.com/haproxy%40formilux.org/msg43861.html), this vulnerability was reported by Seth Manesse and Paul Plasil. The issue allows requests like `index.html#.png` to match ACL rules checking for `path_end .png`, leading to incorrect routing decisions.

**Impact:**
- Bypasses WAF filtering rules based on file extensions
- Circumvents routing logic that relies on path matching
- Exploits inconsistencies between HAProxy's path parsing and ACL evaluation

**References:**
- [CVE-2021-40346 Analysis](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/)
- [CVE-2023-45539 Technical Details](https://www.haproxy.com/blog/december-2023-cve-2023-45539-haproxy-accepts-as-part-of-the-uri-component-fixed)
- [HAProxy 2.8.2 Security Update](https://www.mail-archive.com/haproxy%40formilux.org/msg43861.html)
- [PoC Playground](https://github.com/slicingmelon/HAProxy-CVE-2023-45539-PoC)

The module generates comprehensive payloads for both vulnerabilities, with CVE-2021-40346 typically producing ~14 HTTP smuggling variations and CVE-2023-45539 generating 150+ fragment-based bypass attempts targeting different ACL patterns and injection points.

## 9. unicode_path_normalization 

The `unicode_path_normalization` module generates payloads using Unicode character variants that normalize to standard ASCII characters, targeting systems that perform Unicode normalization during request processing. The module uses `unicode_normalization_map.json` which contains mappings from ASCII to Unicode characters that normalize to the original ASCII character.

The module implements five core bypass techniques:

1. **Double Slash Variations:**
   - Inserts extra slashes at path separator positions (e.g., `/admin//login`)
   - Creates variants where all slashes are doubled (e.g., `//admin//login`)

2. **Full Path Character Variations:**
   - Replaces path characters with Unicode equivalents systematically
   - Tests single occurrence and all occurrence replacements
   - Generates three forms for each replacement:
     - Raw Unicode: `/admin/logＥn`
     - URL-encoded: `/admin/log%EF%BC%A5n` 
     - UTF-8 bytes: `/admin/log\\xEF\\xBC\\xA5n`

3. **Path Segment Character Variations:**
   - Targets individual path segments (e.g., `admin`, `login`)
   - Systematically replaces first and last characters in segments
   - Replaces each character in segments one by one (limited to prevent explosion)

4. **Unicode Slash Insertion:**
   - Uses Unicode equivalents of slash character (`/`)
   - Inserts them next to existing slashes: `/admin/（unicode_slash）login`
   - Tests raw Unicode, URL-encoded, and UTF-8 byte forms

5. **Full Segment Unicode Variations:**
   - Creates completely Unicode-fied versions of path segments
   - Example: `/admin` → `/ªᵈᵐᵢⁿ` (raw) or `/%C2%AA%E1%B5%88%E1%B5%90%E1%B5%A2%E2%81%BF` (encoded)
   - Generates payloads replacing individual segments and all segments at once

All variations preserve the original query string if present. This module is effective against systems where Unicode normalization occurs after initial WAF validation, allowing Unicode variants to bypass pattern matching before being normalized to their ASCII equivalents during processing.

## 10. unicode_path_truncation

The `unicode_path_truncation` module generates payloads using Unicode character variants that truncate to standard ASCII characters via byte truncation (`char & 0xFF`), targeting systems that perform byte-level truncation during request processing. The module uses `unicode_truncation_map.json` which contains mappings from ASCII to Unicode characters that truncate to the original ASCII character when their low byte is extracted.

**Key Differences from Normalization:**
- **Technique**: Byte truncation (`char & 0xFF`) instead of Unicode normalization
- **Target Range**: ALL bytes (0x00-0xFF) instead of ASCII printable only (0x20-0x7F)  
- **Vulnerability**: Applications that truncate Unicode characters to their low byte value
- **JSON Structure**: Uses `"form": "TRUNCATION"` instead of normalization forms like "NFKC"

The module implements the same five core bypass techniques as normalization:

1. **Double Slash Variations:**
   - Inserts extra slashes at path separator positions (e.g., `/admin//login`)
   - Creates variants where all slashes are doubled (e.g., `//admin//login`)

2. **Full Path Character Variations:**
   - Replaces path characters with Unicode equivalents that truncate to the original
   - Tests single occurrence and all occurrence replacements
   - Generates three forms for each replacement:
     - Raw Unicode: `/admin/logĀn` (where Ā truncates to 'a')
     - URL-encoded: `/admin/log%C4%80n`
     - UTF-8 bytes: `/admin/log\\xC4\\x80n`

3. **Path Segment Character Variations:**
   - Targets individual path segments (e.g., `admin`, `login`)
   - Systematically replaces first and last characters in segments
   - Replaces each character in segments one by one (limited to prevent explosion)

4. **Unicode Slash Insertion:**
   - Uses Unicode equivalents of slash character (`/`) that truncate to 0x2F
   - Inserts them next to existing slashes: `/admin/（unicode_slash）login`
   - Tests raw Unicode, URL-encoded, and UTF-8 byte forms

5. **Full Segment Unicode Variations:**
   - Creates completely Unicode-fied versions of path segments using truncation mappings
   - Example: `/admin` → `/Āďṁīṅ` (raw) or `/%C4%80%C4%8F%E1%B9%81%C4%AB%E1%B9%85` (encoded)
   - Generates payloads replacing individual segments and all segments at once

**Example Truncation Mappings:**
```json
{
  "ascii": 97,
  "char": "a", 
  "mappings": [
    {
      "unicode": "ā",        // U+0101 → 0x01 (truncates to 'a')
      "utf8_bytes": "\\xC4\\x81",
      "url_encoded": "%C4%81",
      "form": "TRUNCATION"
    }
  ]
}
```

**Target Systems:**
This technique is particularly effective against:
- Applications using legacy character handling that truncate Unicode to single bytes
- Systems with improper UTF-8 to ASCII conversion routines
- Web servers or frameworks that process Unicode characters through truncation
- Security controls that perform byte-level character validation after truncation

All variations preserve the original query string if present. This module targets a different class of vulnerabilities than normalization, focusing on byte-level truncation rather than Unicode standardization, making it complementary to the normalization module for comprehensive Unicode-based bypass testing.

## 11. headers_scheme 

The `headers_scheme` module tests protocol-based bypasses using custom HTTP headers that indicate the original protocol or request scheme. Many applications rely on these headers for internal routing decisions and security policies.

The module operates by:

1. Reading two predefined lists:
   - `header_proto_schemes.lst`: Common headers for protocol indication
   - `internal_proto_schemes.lst`: Various protocol schemes to test (http, https, etc.)

2. Generating scheme-based payloads in three categories:
   - Standard protocol indicators: Pairs most headers with each protocol scheme
   - HTTPS-specific flags: Sets headers like `Front-End-Https`, `X-Forwarded-HTTPS`, and `X-Forwarded-SSL` to `on`
   - Forwarded header (RFC 7239): Uses the standardized format `proto={scheme}`

These headers exploit common misconfigurations in:
- Reverse proxies that don't properly validate or sanitize forwarded scheme information
- Load balancers that trust scheme headers for SSL/TLS decisions
- Web applications that use scheme headers for conditional logic or URL construction

## 12. headers_ip

The `headers_ip` module is a powerful IP spoofing toolkit that exploits how servers trust client-reported IP addresses for access control decisions. This often-overlooked bypass technique can circumvent WAF restrictions by manipulating IP-based trust relationships.

Key capabilities include:

1. Comprehensive header coverage:
   - Tests all industry-standard IP reporting headers:
     - `X-Forwarded-For`: The de-facto standard for client IP behind proxies
     - `X-Real-IP`: Used by Nginx and many CDNs for original client IP
     - `X-Client-IP`: Common in enterprise environments
     - `X-Originating-IP`: Used by Microsoft products and services
     - Dozens of additional vendor-specific headers from `header_ip_hosts.lst`

2. Multi-source IP data collection:
   - Dynamic IP reconnaissance at runtime - automatically caches all resolved IPs, CNAMEs, and DNS records
   - Predefined IP address lists from `internal_ip_hosts.lst` targeting internal/trusted networks
   - Custom IP specification via `-spoof-ip` CLI flag (comma-separated values)
   - Focus on high-value targets: localhost, internal networks, cloud metadata IPs

3. Advanced header manipulation:
   - Custom header support via `-spoof-header` CLI flag for targeting specific environments
   - Tests both original and normalized (canonicalized) forms of headers
   - RFC 7239 Forwarded header with parameter variations: `by=`, `for=`, and `host=`
   - Special-case bypasses like `X-AppEngine-Trusted-IP-Request: 1`

This technique exploits fundamental architectural weaknesses in:
- Multi-tier architectures where trust is established between components
- IP-based access control lists (ACLs) for admin interfaces
- Cloud environments that trust specific internal IPs
- WAFs that exempt traffic from certain source addresses
- Load balancers that make routing decisions based on client IP

## 13. headers_port

The `headers_port` module manipulates port-related HTTP headers to bypass security controls that make routing or access decisions based on the originating port.

The module works by:

1. Key port-related headers:
   - `X-Forwarded-Port`: Most widely recognized port header
   - `X-Port`: Direct port specification
   - `Port`: Simple port header
   - CDN-specific variants like `Cdn-Server-Port` and `Cdn-Src-Port`
   - Additional headers from `header_ports.lst`

2. Strategic port values:
   - Standard web ports: `80`, `443`
   - Alternative web ports: `8080`, `8443`, `3000`
   - Less common service ports: `5000`, `5001`, `9080`, `9443`
   - All values loaded from `internal_ports.lst`

Example bypass combinations:
```
X-Forwarded-Port: 8080
X-Port: 443
Cdn-Src-Port: 9000
X-Protocol-Port: 80
```

This technique is particularly effective against:
- Web application firewalls with port-specific filtering rules
- Load balancers that route based on original client port
- Microservice architectures with port-based service routing
- Security controls that exempt traffic from specific trusted ports

## 14. headers_url

The `headers_url` module implements URL path injection techniques through custom headers, targeting web applications and proxies that use header values for internal routing decisions.

Critical headers exploited include:

1. Primary routing headers:
   - `X-Original-URL`: Used by many WAFs and proxies for URL rewriting
   - `X-Rewrite-URL`: Common in Nginx configurations
   - `X-Override-URL`: Used in various proxy setups
   - `X-Forwarded-URI`: Often trusted by load balancers
   - `Base-URL`: Used in some legacy applications

2. Strategic path injection techniques:
   - Root URI injection: Sets request path to `/` while placing actual target path in headers
   - Parent path traversal: Tests all parent directories of target path
   - Full URL injection: Supplies complete URLs in headers for URL-aware headers
   - Mixed URL/path formats: Creates variations with different formatting and encoding

3. CVE-2025-29927 exploitation:
   - Targets Next.js middleware bypass via the critical `x-middleware-subrequest` header
   - Generates values like `middleware`, `middleware:middleware:middleware`, etc.
   - Creates variations with `src/middleware` prefix

Example bypasses:
```
GET / HTTP/1.1
Host: example.com
X-Original-URL: /admin

GET / HTTP/1.1
Host: example.com
X-Rewrite-URL: /api/users

GET /api/public/data HTTP/1.1
Host: example.com
X-Override-URL: /api/private/data

GET /api/products HTTP/1.1
Host: example.com
x-middleware-subrequest: middleware:middleware:middleware
```

This technique is especially effective against:
- Misconfigured reverse proxies and API gateways
- Web application firewalls with URL-rewriting capabilities
- Cloud-based WAF solutions that process headers before routing requests
- Next.js applications vulnerable to middleware bypasses

## 15. headers_host

The `headers_host` module exploits discrepancies between URL hostname and Host header processing, leveraging real-time reconnaissance data to generate targeted bypass attempts.

Key features include:

1. Dynamic reconnaissance integration:
   - Utilizes the tool's built-in recon cache that collects IP addresses and CNAMEs for target hosts
   - Automatically generates payloads based on discovered network topology
   - Supports both IPv4 and IPv6 address variations

2. IPv4/IPv6 service variations:
   - For each discovered IP (with scheme and port):
     - Uses IP as URL host with original hostname in Host header
     - Uses original hostname in URL with IP in Host header
   - Handles port specifications appropriately (default ports vs. explicit ports)
   - Creates IPv6-specific variants with proper bracket notation ([IPv6]:port)

3. CNAME-based bypass techniques:
   - Uses discovered canonical names from DNS reconnaissance
   - Four strategic variations for each CNAME:
     - Original URL + CNAME in Host header
     - CNAME as URL host + original hostname in Host header
     - CNAME in both URL host and Host header
     - Recursive domain suffix testing (e.g., sub.domain.com → domain.com)

4. Host-header removal:
   - One unconditional payload (needs no recon data) that emits **no
     `Host:` header at all** (HackTricks "remove the Host header") — ACLs
     keyed on the Host header can misroute host-less requests
   - Reproduces in curl as `-H 'Host:'` (empty value omits the header)

This module is especially powerful for:
- Content Delivery Network (CDN) bypass attempts
- Virtual host confusion attacks
- DNS-based access control evasion
- Load balancer and reverse proxy misconfigurations

## 16. headers_hop_by_hop

The `headers_hop_by_hop` module tests the RFC 7230 hop-by-hop `Connection`
header trick: for each well-known auth header (`Authorization`, `Cookie`,
`X-Api-Key`, `X-Auth-Token`, `X-Access-Token`), it sends the header with the
value `bypass` while listing it in `Connection`. Proxies honoring Connection
list semantics strip the named header before forwarding, which can remove an
internal-only credential check or ACL-enforcing hop sitting between the
proxy and the origin.

The module sends exactly five payloads per target — the header pairing is
the technique, so the list is intentionally kept verbatim rather than
expanded.

## 17. api_versions

The `api_versions` module tests API version routing discrepancies with two
sub-techniques:

1. **Prefix injection** — prepends semantic path prefixes (`/v1`–`/v9`,
   `/api`, `/api/v1`–`/api/v4`) to the original path. Some servers protect
   `/admin` but route `/v2/admin` or `/api/admin` through different (often
   unprotected) middleware.
2. **Version swap** — when the path contains a version segment (e.g.
   `/api/v1/users`), replaces it with each alternative (`v1`–`v9`, `v1.1`,
   `v2.0`); identity swaps are skipped. A route registered under another
   API version may be unprotected.

Custom prefixes relevant to the target (e.g. an internal API namespace) can
be added with the `-spoof-prefix` flag:

```bash
./gobypass403 -u https://target.com/admin -m api_versions -spoof-prefix /internal,/v2beta
```

Values are comma-separated, normalized (leading slash ensured, trailing
slash stripped) and deduplicated against the built-in wordlist.

## 18. http10

The `http10` module tests request-line **version confusion**: it re-sends
the exact baseline request with a non-default version token — `HTTP/1.0`
(the classic `curl --http1.0` probe; reverse proxies in a chain sometimes
apply their ACL only to HTTP/1.1 parsing), `HTTP/0.9` and `HTTP/2.0`.
Probed against the official testbed: HTTP/1.0 bypasses
`:8081/access/rproxy/protocol10` (unKover parity, 200/37 bytes), HTTP/2.0
is accepted where HTTP/1.1 is (200/403 respectively), and HTTP/0.9 forces
a version-parsing differential (400 vs the 403 baseline on nginx).
Each version ships plain plus a `Connection: close` companion (6 payloads).

```bash
./gobypass403 -u http://target.internal:8081/admin -m http10
```

Findings render `--http1.0` / `--http0.9` / `--http2` in the PoC column
(curl has no text-`HTTP/2.0` request-line mode; `-r` debug-token resends
are byte-exact), and the version is preserved in debug tokens. The module
keeps its historical `http10` name — registry order is baked into token
bytes and `-m http10` is user-facing. Real HTTP/2/h2c transport probes are
out of scope: the client stack is HTTP/1.x-only (no HPACK/ALPN/framing).
The module is enabled by default.

## 19. headers_method

The `headers_method` module sends method-override headers on the original
request-target: `X-HTTP-Method`, `X-HTTP-Method-Override` and
`X-Method-Override`, each paired with one of seven method values
(`GET POST PUT PATCH DELETE HEAD OPTIONS`). Frameworks that honor these
headers run the request as the override method while the front proxy still
sees the original verb, slipping past method-based ACLs (bup
`http_headers_method` parity — 21 payloads per target).

```bash
./gobypass403 -u https://target.example/admin -m headers_method
```

## 20. user_agent

The `user_agent` module rotates the `User-Agent` header, sending one
payload per entry in `payloads/internal_user_agents.lst` (45 agents:
crawlers such as Googlebot/CCBot/DuckDuckBot, legacy browsers, mobile and
library clients like `Go-http-client/1.1` and `Java/1.8.0_202`). WAFs and
IP-based ACLs frequently whitelist crawler or legacy UAs. The UA travels
as a dedicated token field, so debug-token resends (`-r`) reproduce the
exact agent, and findings render with `curl -A '<ua>'` in the PoC column.

```bash
./gobypass403 -u https://target.example/admin -m user_agent
```

Run once with `--update-payloads` after upgrading to pick up wordlist
additions. The module is enabled by default.

## 21. param_manipulation

The `param_manipulation` module manipulates the target's query string —
pure query-layer, request-target only (HackTricks "Parameter
Manipulation"). For a target with a query it generates: **mutate** (each
value replaced by the boundary set `-234`, `0`, `99999999`, plus numeric
increment `id=123→124`), **remove** (each parameter dropped individually),
**reorder** (order reversed) and **add** (`&<name>=true` for every entry
in `payloads/internal_param_names.lst` — 6,452 names seeded from
Parallax's `parameters.txt`). Queryless targets get the add-variants as
`?<name>=true`. Query pairs are rebuilt from the raw bytes — never
re-encoded — so byte-level oddities in the original query survive into
every payload.

```bash
./gobypass403 -u 'https://target.example/admin?id=123' -m param_manipulation
```

Roughly 6,460 payloads for a queryless target — comparable to `path_prefix`
scale. Enabled by default.

# Findings

## Findings Summary

When GoBypass403 completes a scan, it displays a comprehensive summary table showing all successful bypass attempts. The results are intelligently grouped and organized for easy analysis:

- **Grouping Logic**: Results are grouped by bypass module → status code → content length
- **Result Limiting**: Maximum 5 results per group to maintain readability
- **Table Format**: Displays module name, curl command (truncated), HTTP status, content length, content type, page title, and server information
- **Visual Separation**: Groups are separated with dotted lines for better visual organization

The summary table provides a quick overview of successful bypasses, allowing security testers to immediately identify which techniques worked and prioritize further investigation.

## Full Findings Database

All scan results are stored in a local SQLite database containing detailed information about every bypass attempt:

**Stored Data Per Request**:
- **Target details**: Original URL, bypass module used, scan timestamp
- **Response metrics**: HTTP status code, content length, response time
- **Content analysis**: Response headers, body preview, content type, page title, server information
- **Reproduction data**: Curl PoC command and debug token
- **Redirect tracking**: Redirect URLs if applicable

**Why SQLite?** Given that comprehensive bypass testing can generate hundreds or thousands of requests, storing everything in a structured database allows for:
- Efficient querying and filtering of results
- Persistent storage of all attempt details
- Advanced analysis using SQL queries
- Integration with external tools and scripts

**Accessing Full Data**: Use any SQLite browser/GUI tool (like DB Browser for SQLite, DBeaver, or SQLiteStudio) to explore the complete dataset, run custom queries, and perform detailed analysis of all bypass attempts.

## Reproducing Findings

### Curl PoC Commands

Every successful bypass attempt includes a ready-to-use curl command that exactly replicates the request. Example below:

```bash
curl -X POST "https://target.com/admin" -H "X-Forwarded-For: 127.0.0.1"
```

These curl commands are:
- **Exact replicas** of the successful bypass requests
- **Immediately executable** for manual verification
- **Stored in both** the summary table and SQLite database
- **Properly escaped** and formatted for shell execution

### Debug Token System

GoBypass403 implements a custom, complex debug token system for precise request reproduction and analysis.

Each payload generates a unique debug token that serves as a compressed fingerprint of the entire request. The token generation process:

1. **Seed-Based Generation**: Every payload gets a unique 4-byte random nonce
2. **Comprehensive Encoding**: Captures all request components (method, headers, body, URL, etc.)
3. **Efficient Compression**: Uses Snappy compression + Base64 encoding
4. **Indexed Optimization**: Common HTTP methods and bypass modules use byte indices instead of full strings

#### Token Structure

```
[Version][Nonce][Scheme][Host][URI][Method][Headers][BypassModule][Body]
│    1B  │  6B  │  Var │ Var │Var│  Var  │   Var   │     Var     │ Var │
```

- **Version** (1 byte): Token format version
- **Nonce** (6 bytes): Unique 4-byte random identifier + length prefix
- **Variable Fields**: All request components with length prefixes
- **Final Encoding**: `base64(snappy(raw_bytes))`

<img src="images/gobypass403-debug-token-structure.png" alt="gobypass403 Debug Token Structure" width="400"/>

#### Debug Token Usage

**For Request Reproduction** (`-r` flag):
```bash
./gobypass403 -r "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**In Debug Mode** (`-d` flag):
```bash
./gobypass403 -u https://target.com/admin -d
```
When debug mode is enabled, each HTTP request also includes the debug token as a custom header, making it visible in request logs and easier to correlate with results.

**Token Decoding Process**:
1. Base64 decode the token string
2. Snappy decompress the bytes
3. Parse the structured binary format
4. Reconstruct the exact original request
5. Execute the request with identical parameters

#### Token Storage and Access

- **SQLite Database**: All debug tokens are stored in the `debug_token` column
- **Exclusive Storage**: Debug tokens are ONLY available in the SQLite database (not in terminal output)
- **Persistent Access**: Tokens remain available for reproduction even after scan completion
- **Query Support**: Use SQL queries to find tokens based on status codes, modules, or other criteria

Example SQL query to find debug tokens:
```sql
SELECT debug_token, curl_cmd, status_code 
FROM scan_results 
WHERE status_code = 200 AND bypass_module = 'headers_ip';
```

This debug token system enables precise request reproduction, detailed analysis, and integration with other security testing workflows.

# Changelog

Full changelog at [CHANGELOG](./CHANGELOG.md).

# Motivation

Traditional Go-based security tools often struggle with WAF bypasses because Go's standard libraries are designed to be secure by default, automatically normalizing URLs and encoding special characters. This makes it difficult to test certain types of bypasses that rely on specific URL structures or character sequences.

Go-Bypass-403 solves this by:
1. Using a custom URL parser that preserves raw paths
2. Implementing curl-like path preservation
3. Maintaining exact URL structures throughout the testing process
4. Allowing for true raw URL manipulation without automatic sanitization
5. The best similar tool that is publicly available was developed by [laluka](https://github.com/laluka) and can be found at the following URL: [bypass-url-parser](https://github.com/laluka/bypass-url-parser). It is written in Python, however, it uses curl for each bypass attempt, as curl supports `--path-as-is` to send raw payloads. Unfortunately, this tool is extremely slow because it uses curl to send the requests.
Quote from laluka:
> If you wonder why this code is nothing but a dirty curl wrapper, here's why:
>>    Most of the python requests do url/path/parameter encoding/decoding, and I hate this.
>>    If I submit raw chars, I want raw chars to be sent.
>>    If I send a weird path, I want it weird, not normalized.
>>
>This is surprisingly hard to achieve in python without losing all of the lib goodies like parsing, ssl/tls encapsulation and so on.
So, be like me, use curl as a backend, it's gonna be just fine.

## Credits


This tool was inspired by and based on [laluka's bypass-url-parser](https://github.com/laluka/bypass-url-parser). All credit for the original concept and bypass techniques goes to him.

Special thanks to [laluka](https://github.com/laluka) for open-sourcing his work and his vast bypass techniques implemented in his tool.


This project is licensed under the [MIT License](LICENSE).