package tests

// Task B2 (SPEC-unkover-gaps.md Addendum 5, Phase B): the pure expansion
// decision.
//
// Rules under test (approved plan):
//   * Path family: ask the module's own generator what it would send to the
//     confirmed RawURI (one more application of the same transformation,
//     depth 1) via an injected Composer, then drop anything already sent.
//   * Method family: case-permutation twins and a trailing-space twin of the
//     method that worked (http_methods), or of the method-valued header
//     (headers_method).
//   * Header-value family: notation + neighbour variants of an IP that
//     worked (headers_ip).
//   * Everything else: unsupported -> no expansion.
//   * Always: deterministic, deduped, capped by PerHit and by the remaining
//     per-target budget.

import (
	"strconv"
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/expand"
	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// fakeComposer records the RawURI it was asked about and returns canned
// payloads, so the path family is testable without a live generator.
type fakeComposer struct {
	calls []string
	out   []payload.BypassPayload
}

func (f *fakeComposer) Compose(rawURI string) []payload.BypassPayload {
	f.calls = append(f.calls, rawURI)
	return f.out
}

func payloadFor(uri string) payload.BypassPayload {
	return payload.BypassPayload{
		Scheme: "https", Host: "t.example", RawURI: uri, Method: "GET",
		BypassModule: "end_paths",
	}
}

func urisOf(ps []payload.BypassPayload) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.RawURI)
	}
	return out
}

func TestSupported(t *testing.T) {
	yes := []string{
		"path_prefix", "mid_paths", "end_paths", "char_encode",
		"case_substitution", "nginx_bypasses", "haproxy_bypasses",
		"unicode_path_normalization", "unicode_path_truncation",
		"unicode_path_experimental",
		"http_methods", "headers_method",
		"headers_ip",
	}
	no := []string{
		"", "dumb_check", "param_manipulation", "user_agent", "http10",
		"api_versions", "headers_scheme", "headers_port", "headers_url",
		"headers_host", "headers_hop_by_hop", "nope",
	}
	for _, m := range yes {
		if !expand.Supported(m) {
			t.Errorf("Supported(%q) = false, want true", m)
		}
	}
	for _, m := range no {
		if expand.Supported(m) {
			t.Errorf("Supported(%q) = true, want false", m)
		}
	}
}

func TestMutatePathFamilyComposesOnceAndDedupes(t *testing.T) {
	confirmed := "/access/nginx/suffix;.css"
	sent := []string{confirmed, "/access/nginx/suffix;.js", "/access/nginx/suffix;.php"}

	composer := &fakeComposer{out: []payload.BypassPayload{
		payloadFor(confirmed),                        // the hit itself
		payloadFor("/access/nginx/suffix;.js"),       // already sent
		payloadFor("/access/nginx/suffix;.css;.js"),  // 3rd candidate
		payloadFor("/access/nginx/suffix;.css;.png"), // 4th candidate
		payloadFor("/access/nginx/suffix;.css;.png"), // duplicate
		payloadFor("/access/nginx/suffix;.php;.css"), // 6th candidate
	}}

	got := expand.Mutate(expand.Request{
		Module:  expand.ModuleEndPaths,
		Payload: payloadFor(confirmed),
		Sent:    sent,
	}, composer, expand.PerHit)

	if len(composer.calls) != 1 || composer.calls[0] != confirmed {
		t.Fatalf("composer calls = %v, want exactly [%s]", composer.calls, confirmed)
	}
	want := []string{
		"/access/nginx/suffix;.css;.js",
		"/access/nginx/suffix;.css;.png",
		"/access/nginx/suffix;.php;.css",
	}
	gotURIs := urisOf(got)
	if len(gotURIs) != len(want) {
		t.Fatalf("derived %v, want %v", gotURIs, want)
	}
	for i := range want {
		if gotURIs[i] != want[i] {
			t.Errorf("derived[%d] = %q, want %q", i, gotURIs[i], want[i])
		}
	}
	for _, g := range got {
		if g.BypassModule != expand.ModuleEndPaths {
			t.Errorf("derived payload module = %q, want %q", g.BypassModule, expand.ModuleEndPaths)
		}
	}
}

func TestMutateUnsupportedModuleExpandsNothing(t *testing.T) {
	composer := &fakeComposer{out: []payload.BypassPayload{payloadFor("/x")}}
	got := expand.Mutate(expand.Request{
		Module:  "param_manipulation",
		Payload: payloadFor("/access/nginx/suffix;.css"),
	}, composer, expand.PerHit)

	if len(got) != 0 {
		t.Errorf("unsupported module produced %d payloads, want 0", len(got))
	}
	if len(composer.calls) != 0 {
		t.Errorf("composer must not be called for an unsupported module")
	}
}

func TestMutateMethodFamilyCaseAndSpaceTwins(t *testing.T) {
	hit := payloadFor("/access/apache/records")
	hit.Method = "Get"
	hit.BypassModule = expand.ModuleHTTPMethods

	// The module already sent the plain forms; only novel twins may appear.
	sent := []string{hit.RawURI}

	got := expand.Mutate(expand.Request{
		Module:  expand.ModuleHTTPMethods,
		Payload: hit,
		Sent:    sent,
	}, &fakeComposer{}, expand.PerHit)

	if len(got) == 0 {
		t.Fatalf("method family derived nothing for method %q", hit.Method)
	}
	seen := map[string]bool{}
	for _, g := range got {
		if g.RawURI != hit.RawURI {
			t.Errorf("method twins must keep the request-target: got %q", g.RawURI)
		}
		if g.Method == hit.Method {
			t.Errorf("derived method %q equals the confirmed method", g.Method)
		}
		if !methodsEqualFold(g.Method, hit.Method) {
			t.Errorf("derived method %q must be a case/space sibling of %q", g.Method, hit.Method)
		}
		if seen[g.Method] {
			t.Errorf("duplicate derived method %q", g.Method)
		}
		seen[g.Method] = true
	}
	if !seen["get"] || !seen["GET"] || !seen["get "] {
		t.Errorf("expected lowercase, uppercase and trailing-space twins; got %v", seen)
	}
}

func methodsEqualFold(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// The module often tests its own case variants (http_methods sends both
// `acl` and `ACL`), so a plain twin can name a shape that is already on the
// wire. Re-sending it costs a request and proves nothing, so Mutate must skip
// shapes the batch already sent.
func TestMutateSkipsShapesTheBatchAlreadySent(t *testing.T) {
	hit := payloadFor("/access")
	hit.Method = "ACL"
	hit.BypassModule = expand.ModuleHTTPMethods

	alreadySent := hit
	alreadySent.Method = "acl"

	got := expand.Mutate(expand.Request{
		Module:     expand.ModuleHTTPMethods,
		Payload:    hit,
		Sent:       []string{hit.RawURI},
		SentShapes: []string{expand.ShapeKey(alreadySent)},
	}, nil, expand.PerHit)

	if len(got) == 0 {
		t.Fatal("expected derived requests for the method family")
	}
	for _, g := range got {
		if g.Method == "acl" {
			t.Errorf("re-derived %q, a shape the batch already sent", g.Method)
		}
		if g.Method == hit.Method {
			t.Errorf("re-derived the confirmed method %q", hit.Method)
		}
	}
}

func TestMutateHeaderIPFamilyNotationsAndNeighbours(t *testing.T) {
	hit := payloadFor("/access")
	hit.BypassModule = expand.ModuleHeadersIP
	hit.Headers = []payload.Headers{{Header: "X-Forwarded-For", Value: "127.0.0.1"}}

	got := expand.Mutate(expand.Request{
		Module:  expand.ModuleHeadersIP,
		Payload: hit,
	}, &fakeComposer{}, expand.PerHit)

	if len(got) == 0 {
		t.Fatalf("header-IP family derived nothing for 127.0.0.1")
	}
	values := map[string]bool{}
	for _, g := range got {
		if len(g.Headers) != 1 || g.Headers[0].Header != "X-Forwarded-For" {
			t.Fatalf("derived headers = %+v, want the winning header name", g.Headers)
		}
		if g.Headers[0].Value == "127.0.0.1" {
			t.Errorf("derived value equals the confirmed value")
		}
		if values[g.Headers[0].Value] {
			t.Errorf("duplicate derived value %q", g.Headers[0].Value)
		}
		values[g.Headers[0].Value] = true
	}
	for _, want := range []string{"2130706433", "0177.0.0.1", "0x7f000001", "127.0.0.2"} {
		if !values[want] {
			t.Errorf("expected notation/neighbour %q; got %v", want, values)
		}
	}
}

func TestMutateRespectsBudgetCapAndIsDeterministic(t *testing.T) {
	confirmed := "/a;.css"
	candidates := make([]payload.BypassPayload, 0, 300)
	for i := 0; i < 300; i++ {
		candidates = append(candidates, payloadFor("/a;.css;.x"+strconv.Itoa(i)))
	}
	composer := &fakeComposer{out: candidates}
	req := expand.Request{Module: expand.ModuleEndPaths, Payload: payloadFor(confirmed)}

	first := urisOf(expand.Mutate(req, composer, expand.PerHit))
	if len(first) != expand.PerHit {
		t.Fatalf("derived %d payloads, want the PerHit cap %d", len(first), expand.PerHit)
	}

	budget := 10
	capped := urisOf(expand.Mutate(req, composer, budget))
	if len(capped) != budget {
		t.Fatalf("derived %d payloads with budget %d", len(capped), budget)
	}

	if zero := expand.Mutate(req, composer, 0); len(zero) != 0 {
		t.Errorf("budget 0 derived %d payloads, want 0", len(zero))
	}

	second := urisOf(expand.Mutate(req, composer, expand.PerHit))
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("non-deterministic output at %d: %q vs %q", i, first[i], second[i])
		}
	}
}
