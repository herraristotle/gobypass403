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
