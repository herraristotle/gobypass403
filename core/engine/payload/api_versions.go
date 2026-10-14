package payload

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// apiVersionPrefixes is the semantic prefix wordlist (superset of unKover's
// /v2 /v3 /api/v1 /api/v2 /api), per SPEC-unkover-gaps.md.
var apiVersionPrefixes = []string{
	"/v1", "/v2", "/v3", "/v4", "/v5", "/v6", "/v7", "/v8", "/v9",
	"/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
}

// apiVersionSwapTargets replace the first /vN[^/]*/ segment of the path
// (unKover swap set v2 v3 v4 v1.1 v2.0, expanded to v1..v9).
var apiVersionSwapTargets = []string{
	"v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v1.1", "v2.0",
}

// versionSegmentRe matches a /vN.../ path segment (unKover: /v[0-9][^/]*/).
var versionSegmentRe = regexp.MustCompile(`/v[0-9][^/]*`)

// validPrefixRe: path-safe characters only; custom prefixes failing this
// are dropped (typo guard for -spoof-prefix values).
var validPrefixRe = regexp.MustCompile(`^/[a-zA-Z0-9._~/-]*$`)

// normalizeCustomPrefixes parses a comma-separated -spoof-prefix value into
// normalized prefixes: trimmed, leading slash ensured, trailing slash
// stripped, invalid/empty entries dropped, deduped against each other and
// the wordlist.
func normalizeCustomPrefixes(raw string, wordlist []string) []string {
	if raw == "" {
		return nil
	}
	seen := make(map[string]struct{}, len(wordlist))
	for _, p := range wordlist {
		seen[p] = struct{}{}
	}
	var out []string
	for _, entry := range strings.Split(raw, ",") {
		p := strings.TrimSpace(entry)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		p = strings.TrimRight(p, "/")
		if p == "" || !validPrefixRe.MatchString(p) {
			GB403Logger.Warning().Msgf("api_versions: dropping invalid custom prefix %q", entry)
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

/*
GenerateAPIVersionPayloads generates unKover `api_version` parity payloads,
two sub-techniques:

 1. **Prefix injection:** each wordlist prefix (plus any -spoof-prefix custom
    values) is prepended to the original path. Some servers route
    /v2/admin or /api/admin without the ACL applied to /admin.
 2. **Version swap:** if the path contains a /vN.../ segment, it is replaced
    with each swap target (identity swaps are skipped). A route registered
    under another API version may be unprotected.

The original query string is preserved; scheme and host are unchanged.
*/
func (pg *PayloadGenerator) GenerateAPIVersionPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return allJobs
	}

	originalPath := parsedURL.Path
	if originalPath == "" {
		originalPath = "/"
	}
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       pg.method,
		Body:         pg.body,
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	uniqueRawURIs := make(map[string]struct{})
	addJob := func(rawURI string) {
		if _, dup := uniqueRawURIs[rawURI]; dup {
			return
		}
		uniqueRawURIs[rawURI] = struct{}{}
		job := baseJob
		job.RawURI = rawURI
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	// Sub-technique 1: prefix injection (wordlist + custom -spoof-prefix).
	prefixes := make([]string, 0, len(apiVersionPrefixes))
	prefixes = append(prefixes, apiVersionPrefixes...)
	prefixes = append(prefixes, normalizeCustomPrefixes(pg.spoofPrefix, apiVersionPrefixes)...)

	for _, prefix := range prefixes {
		addJob(prefix + originalPath + query)
	}

	// Sub-technique 2: version swap on the first /vN.../ segment.
	if loc := versionSegmentRe.FindStringIndex(originalPath); loc != nil {
		head := originalPath[:loc[0]]
		tail := originalPath[loc[1]:]
		for _, target := range apiVersionSwapTargets {
			swapped := fmt.Sprintf("%s/%s%s", head, target, tail)
			if swapped == originalPath {
				continue // identity swap
			}
			addJob(swapped + query)
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}
