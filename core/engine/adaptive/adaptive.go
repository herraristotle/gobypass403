/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Adaptive module ordering for Addendum 5 Phase C (adaptive-order).

Given the fingerprint of a target's baseline response (the Server header, WAF/
CDN marker headers and cookies the scanner already captured for dumb_check),
Order promotes the modules that historically pay off against that
fingerprint to the front of the run's module list.

The heuristic is data: Rules is a table of
markers -> promoted modules, pinned by tests. Order is promotion-only — the
result is always a permutation of its input, so -adaptive alone can never add
or remove a module, only try the promising ones sooner. An unknown fingerprint
returns the input order untouched.

Nothing here talks to the network, the DB, the logger or the CLI: the scanner
supplies the fingerprint and the order, so the whole table is unit-testable.
*/
package adaptive

import (
	"slices"
	"strings"
)

// Fingerprint is what the baseline response told us about the target: its
// status, the Server header value, the raw response header lines and the
// cookies. Matching is case-insensitive; empty fields simply match nothing.
type Fingerprint struct {
	Status  int
	Server  string
	Headers []string
	Cookies []string
}

// Rule promotes Modules when any of Markers appears anywhere in the
// fingerprint. Rules is ordered: when several match, an earlier rule's
// promoted modules come first.
type Rule struct {
	Name     string
	Markers  []string
	Promotes []string
}

// Rule order matters: the first matching rule promotes first, and a module
// promoted by several rules keeps its earliest position. Keep the table sorted
// by how often the fingerprint is seen in the wild (CDNs/WAFs first).
var (
	ruleCloudflare = Rule{
		Name: "cloudflare",
		Markers: []string{
			"cloudflare", "cf-ray", "cf-cache-status", "cf-request-id",
			"cf_clearance", "__cf_bm", "__cfduid",
		},
		// Cloudflare trusts its own forwarding headers first; path tricks and
		// the nginx-fronted origin bypasses follow.
		Promotes: []string{"headers_ip", "headers_host", "end_paths", "nginx_bypasses"},
	}

	ruleNginx = Rule{
		Name:     "nginx",
		Markers:  []string{"nginx"},
		Promotes: []string{"nginx_bypasses", "end_paths", "mid_paths", "case_substitution"},
	}

	ruleHaproxy = Rule{
		Name:     "haproxy",
		Markers:  []string{"haproxy"},
		Promotes: []string{"haproxy_bypasses", "end_paths", "headers_url", "case_substitution"},
	}

	ruleAkamai = Rule{
		Name: "akamai",
		Markers: []string{
			"akamaighost", "x-akamai", "akamai-grn", "ak_bmsc", "_abck", "bm_sz",
		},
		Promotes: []string{"headers_host", "headers_url", "path_prefix", "case_substitution"},
	}

	ruleCloudFront = Rule{
		Name:     "cloudfront",
		Markers:  []string{"cloudfront", "x-amz-cf-id", "x-amz-cf-pop"},
		Promotes: []string{"headers_host", "headers_url", "headers_ip", "end_paths"},
	}

	ruleAzure = Rule{
		Name:     "azure",
		Markers:  []string{"azure", "x-azure-ref", "x-msedge-ref"},
		Promotes: []string{"headers_host", "headers_url", "case_substitution", "end_paths"},
	}

	ruleVarnish = Rule{
		Name:     "varnish",
		Markers:  []string{"x-served-by", "x-varnish", "x-cache", "x-fastly-request-id"},
		Promotes: []string{"headers_url", "headers_host", "char_encode", "end_paths"},
	}

	ruleIIS = Rule{
		Name:     "iis",
		Markers:  []string{"microsoft-iis", "x-aspnet", "x-powered-by: asp.net"},
		Promotes: []string{"headers_method", "case_substitution", "char_encode", "end_paths"},
	}

	ruleApache = Rule{
		Name:     "apache",
		Markers:  []string{"apache"},
		Promotes: []string{"case_substitution", "char_encode", "end_paths", "mid_paths"},
	}

	ruleF5 = Rule{
		Name:     "f5",
		Markers:  []string{"bigipserver", "x-wa-info", "ts01"},
		Promotes: []string{"headers_url", "headers_host", "end_paths"},
	}
)

// Rules is the heuristic table, in evaluation order.
var Rules = []Rule{
	ruleCloudflare,
	ruleNginx,
	ruleHaproxy,
	ruleAkamai,
	ruleCloudFront,
	ruleAzure,
	ruleVarnish,
	ruleIIS,
	ruleApache,
	ruleF5,
}

// Order returns modules with every rule the fingerprint matches promoted to
// the front (rule order first, then the order the rule lists them), leaving
// the relative order of all other modules untouched. It never adds or removes
// a module; an unmatched or empty fingerprint returns modules unchanged.
func Order(modules []string, fp Fingerprint) []string {
	if len(modules) == 0 {
		return modules
	}

	haystack := fp.haystack()

	promoted := make([]string, 0, len(modules))
	seen := make(map[string]bool, len(modules))
	for _, r := range Rules {
		if !r.matches(haystack) {
			continue
		}
		for _, m := range r.Promotes {
			if seen[m] || !slices.Contains(modules, m) {
				continue
			}
			seen[m] = true
			promoted = append(promoted, m)
		}
	}
	if len(promoted) == 0 {
		return modules
	}

	out := make([]string, 0, len(modules))
	out = append(out, promoted...)
	for _, m := range modules {
		if !seen[m] {
			out = append(out, m)
		}
	}
	return out
}

// haystack is the lower-cased blob every marker is searched for.
func (fp Fingerprint) haystack() string {
	var b strings.Builder
	b.Grow(len(fp.Server) + 64)
	b.WriteString(strings.ToLower(fp.Server))
	for _, h := range fp.Headers {
		b.WriteByte('\n')
		b.WriteString(strings.ToLower(h))
	}
	for _, c := range fp.Cookies {
		b.WriteByte('\n')
		b.WriteString(strings.ToLower(c))
	}
	return b.String()
}

// matches reports whether any marker appears in the (already lower-cased)
// haystack.
func (r Rule) matches(haystack string) bool {
	for _, marker := range r.Markers {
		if strings.Contains(haystack, marker) {
			return true
		}
	}
	return false
}
