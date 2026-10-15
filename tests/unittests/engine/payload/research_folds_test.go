package tests

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// foldInIPLiterals are the 8 alternate loopback notations from report §4.3
// (nomore403 ips.txt + unKover IP_VALUES).
var foldInIPLiterals = []string{
	"0x7F000001", "0177.0000.0000.0001", "127.1", "127.1.1.1",
	"172.16.0.1", "::1", "[::1]", "::ffff:127.0.0.1",
}

// foldInMethods are the 10 verbs from report §4.4 (SecLists
// http-request-methods.txt diff); each must also gain its lowercase twin.
var foldInMethods = []string{
	"ARBITRARY", "BASELINE-CONTROL", "DEBUG", "MKACTIVITY", "MKCALENDAR",
	"MKREDIRECTREF", "MKWORKSPACE", "PURGE", "UNBIND", "UNLINK",
}

// foldInMidAtoms are the 13 backslash/double-encode atoms from report §4.5
// (nomore403 midpaths.txt diff).
var foldInMidAtoms = []string{
	"%5c", "%5c..%5c", "..%5c..%5c", `.\;/`, `\`, `\\`, `\..\`, `\..\\`,
	"/%252e%252e/", "//%252e/", "//%252e%252e/", "/..%252F", "/./..%2f",
}

func generateModule(t *testing.T, module string, targetURL string) []payload.BypassPayload {
	t.Helper()
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: module,
	})
	jobs := pg.Generate()
	if len(jobs) == 0 {
		t.Fatalf("%s generated no payloads", module)
	}
	return jobs
}

// TestIPHostsFoldIn8 pins the 8 alternate loopback notations AND the
// CF-Connecting_IP header fold (report §4.3 + §3 P2 header rows).
func TestIPHostsFoldIn8(t *testing.T) {
	jobs := generateModule(t, "headers_ip", "https://example.com/admin")

	values := make(map[string]bool)
	headers := make(map[string]bool)
	for _, j := range jobs {
		for _, h := range j.Headers {
			headers[h.Header] = true
			values[h.Value] = true
		}
	}
	for _, ip := range foldInIPLiterals {
		if !values[ip] {
			t.Errorf("headers_ip missing folded-in IP value %q", ip)
		}
	}
	if !headers["CF-Connecting_IP"] {
		t.Error("headers_ip missing folded-in header CF-Connecting_IP")
	}
}

// TestHTTPMethodsFoldIn10 pins the 10 folded-in verbs and their lowercase
// twins: 46 methods × 2 = 92 jobs for a queryless target (report §4.4).
func TestHTTPMethodsFoldIn10(t *testing.T) {
	jobs := generateModule(t, "http_methods", "https://example.com/admin")

	if len(jobs) != 92 {
		t.Errorf("http_methods generated %d payloads for 46 methods, want 92", len(jobs))
	}
	seen := make(map[string]bool)
	for _, j := range jobs {
		seen[j.Method] = true
	}
	for _, m := range foldInMethods {
		if !seen[m] {
			t.Errorf("http_methods missing verb %q", m)
		}
		if !seen[strings.ToLower(m)] {
			t.Errorf("http_methods missing lowercase twin %q", strings.ToLower(m))
		}
	}
}

// TestMidPathsFoldIn13 pins that each backslash/double-encode atom from
// report §4.5 produces at least one payload containing it.
func TestMidPathsFoldIn13(t *testing.T) {
	jobs := generateModule(t, "mid_paths", "https://example.com/admin/config")

	for _, atom := range foldInMidAtoms {
		found := false
		for _, j := range jobs {
			if strings.Contains(j.RawURI, atom) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("mid_paths produced no payload containing atom %q", atom)
		}
	}
}

// TestReferrerHeaderFoldIn pins the bare misspelling header Referrer
// (report §3, nomore403 headers.txt).
func TestReferrerHeaderFoldIn(t *testing.T) {
	jobs := generateModule(t, "headers_url", "https://example.com/admin")
	for _, j := range jobs {
		if len(j.Headers) == 1 && j.Headers[0].Header == "Referrer" {
			return
		}
	}
	t.Error("headers_url missing folded-in header Referrer")
}

// TestPortsFoldIn74443 pins port 74443 (report §3, bup internal_ports.lst).
func TestPortsFoldIn74443(t *testing.T) {
	jobs := generateModule(t, "headers_port", "https://example.com/admin")
	for _, j := range jobs {
		for _, h := range j.Headers {
			if strings.Contains(h.Value, "74443") {
				return
			}
		}
	}
	t.Error("headers_port missing folded-in port 74443")
}

// Parallax wordlists/headers.txt straggler fold: the full mechanical diff
// (1,131 parallax names, 77 already covered by the 206-name spoofing
// universe, 1,054 parallax-only) filtered down to 14 conservative,
// real-world names that fit an existing family and registry:
// scheme/proto indicators -> header_proto_schemes.lst,
// URL/referer/redirect indicators -> header_urls.lst,
// client/host identity -> header_ip_hosts.lst,
// method override -> header_http_methods.lst.
var parallaxProtoStragglers = []string{
	"Forwarded-Proto", "X-Forwarded-Protocol", "X-Forward-Proto",
	"X-Originally-Forwarded-Proto", "X-Https", "X-Scheme",
}

var parallaxURLStragglers = []string{
	"Coming-From", "X-Coming-From", "X-XHR-Referer",
	"X-Amz-Website-Redirect-Location",
}

var parallaxIPStragglers = []string{
	"ClientIP", "X-ClientIP", "X-Amzn-Remapped-Host",
}

var parallaxMethodStragglers = []string{"X-Original-HTTP-Command"}

// TestParallaxHeadersStragglerFold14 pins all 14 folded-in names at the
// payload layer: each must reach the wire under its module, X-Https must
// take the "on" value alongside Front-End-Https/X-Forwarded-SSL, and
// Forwarded-Proto must take a bare scheme (proto= formatting is reserved
// for the exact "Forwarded" header).
func TestParallaxHeadersStragglerFold14(t *testing.T) {
	schemeJobs := generateModule(t, "headers_scheme", "https://example.com/admin")
	schemeSeen := make(map[string]string) // header -> one observed value
	for _, j := range schemeJobs {
		if len(j.Headers) == 1 {
			if _, ok := schemeSeen[j.Headers[0].Header]; !ok {
				schemeSeen[j.Headers[0].Header] = j.Headers[0].Value
			}
		}
	}
	for _, h := range parallaxProtoStragglers {
		if _, ok := schemeSeen[h]; !ok {
			t.Errorf("headers_scheme missing folded-in header %q", h)
		}
	}
	if v, ok := schemeSeen["X-Https"]; !ok {
		// presence already reported above
	} else if v != "on" {
		t.Errorf("X-Https value = %q, want \"on\" (Front-End-Https class)", v)
	}
	if v, ok := schemeSeen["Forwarded-Proto"]; ok && strings.Contains(v, "=") {
		t.Errorf("Forwarded-Proto value = %q, want a bare scheme (proto= is reserved for Forwarded)", v)
	}

	urlJobs := generateModule(t, "headers_url", "https://example.com/admin")
	urlSeen := make(map[string]bool)
	for _, j := range urlJobs {
		if len(j.Headers) == 1 {
			urlSeen[j.Headers[0].Header] = true
		}
	}
	for _, h := range parallaxURLStragglers {
		if !urlSeen[h] {
			t.Errorf("headers_url missing folded-in header %q", h)
		}
	}

	ipJobs := generateModule(t, "headers_ip", "https://example.com/admin")
	ipSeen := make(map[string]bool)
	for _, j := range ipJobs {
		for _, h := range j.Headers {
			ipSeen[h.Header] = true
		}
	}
	for _, h := range parallaxIPStragglers {
		if !ipSeen[h] {
			t.Errorf("headers_ip missing folded-in header %q", h)
		}
	}

	methodJobs := generateModule(t, "headers_method", "https://example.com/admin")
	methodSeen := make(map[string]bool)
	for _, j := range methodJobs {
		for _, h := range j.Headers {
			methodSeen[h.Header] = true
		}
	}
	for _, h := range parallaxMethodStragglers {
		if !methodSeen[h] {
			t.Errorf("headers_method missing folded-in header %q", h)
		}
	}
}
