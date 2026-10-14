package tests

import (
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// referer trust words pinned by unKover REFERER_VALUES (spec addendum)
var expectedRefererTrustWords = []string{"admin", "dashboard", "internal"}

// TestHeadersURLFullPathOnOriginalPath pins the unKover header_override
// shape: the override header carrying the full path must also be sent ON
// the original request-target, not only on "/" (proven against the
// 403.brutelogic.net testbed: X-Original-URL on /access/nginx/rewrite).
func TestHeadersURLFullPathOnOriginalPath(t *testing.T) {
	moduleName := "headers_url"
	targetURL := "http://example.com/access/nginx/rewrite"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.GenerateHeadersURLPayloads(targetURL, moduleName)

	headers, err := payload.ReadPayloadsFromFile("header_urls.lst")
	if err != nil {
		t.Fatalf("Failed to read header list: %v", err)
	}

	found := make(map[string]bool)
	for _, j := range jobs {
		if j.RawURI != "/access/nginx/rewrite" || len(j.Headers) != 1 {
			continue
		}
		if j.Headers[0].Value == "/access/nginx/rewrite" {
			found[j.Headers[0].Header] = true
		}
	}
	for _, h := range headers {
		if !found[h] {
			t.Errorf("Missing full-path-on-original-path variant for header %q", h)
		}
	}
}

// TestHeadersURLFullPathVariantWithQuery pins the query-aware variants:
// RawURI keeps path+query; header carries path and path+query.
func TestHeadersURLFullPathVariantWithQuery(t *testing.T) {
	moduleName := "headers_url"
	targetURL := "http://example.com/access/nginx/rewrite?a=1&b=2"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.GenerateHeadersURLPayloads(targetURL, moduleName)

	wantPathValue, wantPathQueryValue := false, false
	for _, j := range jobs {
		if j.RawURI != "/access/nginx/rewrite?a=1&b=2" || len(j.Headers) != 1 {
			continue
		}
		if j.Headers[0].Header != "X-Original-URL" {
			continue
		}
		if j.Headers[0].Value == "/access/nginx/rewrite" {
			wantPathValue = true
		}
		if j.Headers[0].Value == "/access/nginx/rewrite?a=1&b=2" {
			wantPathQueryValue = true
		}
	}
	if !wantPathValue {
		t.Error("Missing path-only header value on original path+query RawURI")
	}
	if !wantPathQueryValue {
		t.Error("Missing path+query header value on original path+query RawURI")
	}
}

// TestHeadersURLRefererTrustWords pins the unKover referer_trust shape:
// scheme://host/<word> Referers sent on the original request-target.
func TestHeadersURLRefererTrustWords(t *testing.T) {
	moduleName := "headers_url"
	targetURL := "http://example.com/access/nginx/internal?x=1"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.GenerateHeadersURLPayloads(targetURL, moduleName)

	refererish := map[string]bool{"Referer": true, "X-Referer": true, "X-Referrer": true}
	found := make(map[string]map[string]bool) // header -> word -> ok
	for _, j := range jobs {
		if j.RawURI != "/access/nginx/internal?x=1" || len(j.Headers) != 1 {
			continue
		}
		h := j.Headers[0].Header
		if !refererish[h] {
			continue
		}
		for _, w := range expectedRefererTrustWords {
			if j.Headers[0].Value == "http://example.com/"+w {
				if found[h] == nil {
					found[h] = make(map[string]bool)
				}
				found[h][w] = true
			}
		}
	}
	for h := range refererish {
		for _, w := range expectedRefererTrustWords {
			if !found[h][w] {
				t.Errorf("Missing referer trust variant %s: http://example.com/%s", h, w)
			}
		}
	}
}
