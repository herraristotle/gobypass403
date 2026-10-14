package tests

import (
	"strings"
	"testing"
)

// TestForwardedQuotedPair pins the WAF-evasion quoted-pair value shape for
// the Forwarded header (addendum 3 Phase D item 11, HackTricks
// proxy-waf-protections-bypass: `Forwarded: for="[..]"`): alongside the
// plain RFC 7239 variations (by=/for=/host=) the generator must also emit
// the quoted for= form the WAF rule-bypass research uses.
func TestForwardedQuotedPair(t *testing.T) {
	jobs := generateModule(t, "headers_ip", "https://example.com/admin")

	plainFor, quotedFor := 0, 0
	for _, j := range jobs {
		for _, h := range j.Headers {
			if !strings.EqualFold(h.Header, "Forwarded") {
				continue
			}
			switch {
			case strings.HasPrefix(h.Value, `for="`) && strings.HasSuffix(h.Value, `"`):
				quotedFor++
			case strings.HasPrefix(h.Value, "for="):
				plainFor++
			}
		}
	}
	if quotedFor == 0 {
		t.Error("headers_ip missing quoted-pair Forwarded variation for=\"[...]\"")
	}
	if plainFor == 0 {
		t.Error("headers_ip lost the plain for= variation")
	}
}
