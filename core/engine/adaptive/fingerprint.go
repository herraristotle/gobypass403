/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Building a Fingerprint from what the scanner already has in hand: the baseline
response's status, its Server header and its raw response header lines. No
extra request is sent for this — dumb_check runs first for every target, so its
response is the fingerprint (decision C.1).
*/
package adaptive

import "strings"

// NewFingerprint turns one scanned response into a Fingerprint. headerLines are
// the raw "Name: value" response lines; every non-empty line is kept for marker
// matching, and the Set-Cookie lines additionally yield the "name=value" pairs
// (the attributes after the first ';' are dropped).
func NewFingerprint(status int, server string, headerLines []string) Fingerprint {
	fp := Fingerprint{Status: status, Server: server}

	for _, line := range headerLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fp.Headers = append(fp.Headers, line)

		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "set-cookie") {
			continue
		}
		cookie, _, _ := strings.Cut(strings.TrimSpace(value), ";")
		if cookie = strings.TrimSpace(cookie); cookie != "" {
			fp.Cookies = append(fp.Cookies, cookie)
		}
	}

	return fp
}
