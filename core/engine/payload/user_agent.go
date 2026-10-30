package payload

import (
	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/herraristotle/gobypass403/core/utils/logger"
)

// GenerateUserAgentPayloads generates per-job User-Agent payloads
// (research-acquisition-report.md §3 runner-up, addendum 3 Phase C): one
// payload per UA in internal_user_agents.lst (bup parity — bot/crawler,
// legacy and mobile UAs), carrying the value in the optional UserAgent
// field so rawhttp emits it as the request's User-Agent instead of the
// default browser constant. WAFs and IP-based ACLs frequently whitelist
// crawlers (Googlebot, Bingbot) or legacy agents.
func (pg *PayloadGenerator) GenerateUserAgentPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return allJobs
	}

	userAgents, err := ReadPayloadsFromFile("internal_user_agents.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read user agents: %v", err)
		return allJobs
	}

	rawURI := parsedURL.Path
	if parsedURL.Query != "" {
		rawURI += "?" + parsedURL.Query
	}

	for _, ua := range userAgents {
		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       pg.method,
			Body:         pg.body,
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
			UserAgent:    ua,
		}
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(allJobs), targetURL)
	return allJobs
}
