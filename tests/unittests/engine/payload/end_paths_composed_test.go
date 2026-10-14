package tests

import (
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// Regression pin for GenerateEndPathsPayloads' base-path/suffix separator
// logic: the breaker × static-ext composition class (testbed rproxy/profile
// "Parser Confusion") must keep generating both `/.js` (dir-breaker + ext)
// and `.js` (plain ext) forms.

// TestEndPathsComposedStaticExtShapes pins the breaker × static-ext
// composition class (testbed rproxy/profile "Parser Confusion"): the
// separator logic must emit both `/.js` (dir-breaker + ext) and `.js`
// (plain ext) forms. Regression guard for refactors of GenerateEndPathsPayloads.
func TestEndPathsComposedStaticExtShapes(t *testing.T) {
	moduleName := "end_paths"
	targetURL := "https://403.brutelogic.net/access/rproxy/profile"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.Generate()
	if len(jobs) == 0 {
		t.Fatal("end_paths generated no payloads")
	}

	want := map[string]bool{
		"/access/rproxy/profile/.js":   false,
		"/access/rproxy/profile/.html": false,
		"/access/rproxy/profile/.json": false,
		"/access/rproxy/profile.js":    false,
	}
	for _, j := range jobs {
		if _, ok := want[j.RawURI]; ok {
			want[j.RawURI] = true
		}
	}
	for uri, found := range want {
		if !found {
			t.Errorf("end_paths missing composed payload %q", uri)
		}
	}
}

// TestEndPathsResearchFoldIn33 pins representative payloads from the
// report §4.2 wordlist append (static-ext, cache-deception, unKover
// breaker suffixes), including the free composed `/.php` form.
func TestEndPathsResearchFoldIn33(t *testing.T) {
	moduleName := "end_paths"
	targetURL := "https://example.com/admin"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.Generate()
	if len(jobs) == 0 {
		t.Fatal("end_paths generated no payloads")
	}

	want := []string{
		"/admin/.php",     // static ext, composed form
		"/admin/.jsp",     // static ext
		"/admin/;.css",    // cache-deception breaker + ext
		"/admin/;x",       // unKover SUFFIXES
		"/admin/%3B.json", // unKover encoded breaker + ext
		"/admin/%0d%0a",   // CRLF suffix
		"/admin/.orig",    // backup ext
	}
	found := make(map[string]bool)
	for _, j := range jobs {
		found[j.RawURI] = true
	}
	for _, uri := range want {
		if !found[uri] {
			t.Errorf("end_paths missing folded-in payload %q", uri)
		}
	}
}
