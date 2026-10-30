package payload

import (
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/herraristotle/gobypass403/core/utils/logger"
)

// Negative control (SPEC-unkover-gaps.md Addendum 6, `-calibrate`).
//
// The calibration module sends a few requests to paths that cannot exist, in
// the same directory as the target, and the analyzer treats their responses as
// the server's default (wildcard / soft-404) shape. A response that matches a
// control is the server answering "nothing here as a success", not a bypass —
// the classic false positive of a 403 baseline against a 2xx soft-404 site.
//
// This mirrors unKover's `calibrate` (${dir}/${rand}) and ffuf's `-ac`.

// calibrationTokenLen lists one token length per probe. The lengths differ so
// that a soft-404 that echoes (and therefore resizes with) the requested path
// still produces recognisable control lengths, not a single fixed one.
var calibrationTokenLen = []int{8, 12, 16}

const calibrationCharset = "abcdefghijklmnopqrstuvwxyz0123456789"

// GenerateCalibrationPayloads builds the negative-control probe batch: one
// request per token length, each to a random non-existent sibling of the
// target's last path segment. The probes carry the configured method/body so
// they exercise the same route the other modules do.
func (pg *PayloadGenerator) GenerateCalibrationPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL for calibration")
		return allJobs
	}

	dir := calibrationDir(parsedURL.Path)
	for _, n := range calibrationTokenLen {
		rawURI := dir + calibrationToken(n)
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
		allJobs = append(allJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d calibration probe(s) for %s\n", len(allJobs), targetURL)
	return allJobs
}

// calibrationDir returns the directory a control probe belongs in: the target
// path with its last segment removed, including the trailing slash. "/", ""
// and "/a" all probe the root; "/a/b" and "/a/b/" probe "/a/".
func calibrationDir(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[:i+1]
	}
	return "/"
}

// calibrationToken returns a random token of n lowercase-alphanumerics drawn
// from the package RNG (the same locked generator the debug-token nonce uses).
func calibrationToken(n int) string {
	b := make([]byte, n)
	mu.Lock()
	for i := range b {
		b[i] = calibrationCharset[rnd.Uint32N(uint32(len(calibrationCharset)))]
	}
	mu.Unlock()
	return string(b)
}
