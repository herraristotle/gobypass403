package payload

import (
	"strconv"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// paramBoundaryValues are the HackTricks parameter-boundary values
// (research-acquisition-report.md §3 P3 row: `-234/0/99999999`).
var paramBoundaryValues = []string{"-234", "0", "99999999"}

// GenerateParamManipulationPayloads generates query-layer parameter
// manipulation payloads (research-acquisition-report.md §3 P3, HackTricks
// "Parameter Manipulation"). For a target WITH a query it mutates each
// value to the boundary set (plus numeric increment, id=123→124), drops
// each parameter individually, reverses the order, and appends
// `&<name>=true` for every name in internal_param_names.lst (seeded from
// Parallax's parameters.txt, 6,452 names). For a queryless target it emits
// only the add-variants (`?<name>=true`). Query strings are rebuilt from
// the raw pairs — never re-encoded, so byte-level oddities in the original
// query survive into every payload.
func (pg *PayloadGenerator) GenerateParamManipulationPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return jobs
	}

	path := parsedURL.Path
	query := parsedURL.Query

	var pairs []string
	if query != "" {
		pairs = strings.Split(query, "&")
	}

	addJob := func(newQuery string) {
		rawURI := path
		if newQuery != "" {
			rawURI += "?" + newQuery
		}
		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       pg.method,
			Body:         pg.body,
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}
		job.PayloadToken = GeneratePayloadToken(job)
		jobs = append(jobs, job)
	}

	// 1. Mutate existing values: boundaries + numeric increment
	work := make([]string, len(pairs))
	for i, pair := range pairs {
		k, v, hasValue := pair, "", false
		if idx := strings.IndexByte(pair, '='); idx >= 0 {
			k, v, hasValue = pair[:idx], pair[idx+1:], true
		}
		copy(work, pairs)
		for _, boundary := range paramBoundaryValues {
			work[i] = k + "=" + boundary
			addJob(strings.Join(work, "&"))
		}
		if hasValue {
			if n, err := strconv.Atoi(v); err == nil {
				work[i] = k + "=" + strconv.Itoa(n+1)
				addJob(strings.Join(work, "&"))
			}
		}
	}

	// 2. Remove each parameter individually
	for i := range pairs {
		without := make([]string, 0, len(pairs)-1)
		without = append(without, pairs[:i]...)
		without = append(without, pairs[i+1:]...)
		addJob(strings.Join(without, "&"))
	}

	// 3. Reorder (reverse) — only meaningful with 2+ params
	if len(pairs) > 1 {
		reversed := make([]string, 0, len(pairs))
		for i := len(pairs) - 1; i >= 0; i-- {
			reversed = append(reversed, pairs[i])
		}
		addJob(strings.Join(reversed, "&"))
	}

	// 4. Add `&<name>=true` for every wordlist name
	names, err := ReadPayloadsFromFile("internal_param_names.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read parameter names: %v", err)
		return jobs
	}
	for _, name := range names {
		section := name + "=true"
		if query != "" {
			section = query + "&" + section
		}
		addJob(section)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(jobs), targetURL)
	return jobs
}
