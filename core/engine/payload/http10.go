package payload

import (
	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// GenerateHTTP10Payloads generates the HTTP/1.0 protocol downgrade payloads
// (unKover test_http10 parity, spec addendum 2B). Reverse proxies sometimes
// apply ACLs only to HTTP/1.1 request parsing (or handle 1.0 differently in
// the chain), so the same request-target sent with an HTTP/1.0 request line
// can slip past. Two variants ship: the plain downgrade (unKover's exact
// `curl --http1.0` shape, verified against the testbed's
// :8081/access/rproxy/protocol10) and a Connection: close companion.
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
		HTTPVersion:  "HTTP/1.0",
	}

	// Plain HTTP/1.0 downgrade (unKover parity)
	job := baseJob
	job.PayloadToken = GeneratePayloadToken(job)
	jobs = append(jobs, job)

	// HTTP/1.0 + Connection: close companion
	job = baseJob
	job.Headers = []Headers{{Header: "Connection", Value: "close"}}
	job.PayloadToken = GeneratePayloadToken(job)
	jobs = append(jobs, job)

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(jobs), targetURL)
	return jobs
}
