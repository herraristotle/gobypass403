package tests

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// TestParamManipulationWithQuery pins the query-layer manipulations
// (addendum 3 Phase D item 12, HackTricks "Parameter Manipulation"):
// for target ?id=123&b=x — mutate each value to the boundary set
// (-234/0/99999999) plus numeric increment (123→124), drop each param
// individually, reverse the order, and append &<name>=true for every name
// in internal_param_names.lst.
func TestParamManipulationWithQuery(t *testing.T) {
	moduleName := "param_manipulation"
	targetURL := "https://example.com/admin?id=123&b=x"

	names, err := payload.ReadPayloadsFromFile("internal_param_names.lst")
	if err != nil {
		t.Fatalf("read internal_param_names.lst: %v", err)
	}

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.Generate()
	if len(jobs) == 0 {
		t.Fatal("param_manipulation generated no payloads")
	}

	// mutate: id {0,-234,99999999,124} + b {0,-234,99999999} = 7
	// remove: 2; reorder: 1; add: len(names)
	want := 7 + 2 + 1 + len(names)
	if len(jobs) != want {
		t.Errorf("generated %d payloads, want %d (7 mutate + 2 remove + 1 reorder + %d add)",
			len(jobs), want, len(names))
	}

	found := make(map[string]bool)
	for _, j := range jobs {
		if j.BypassModule != moduleName {
			t.Errorf("payload BypassModule = %q, want %q", j.BypassModule, moduleName)
		}
		if !strings.HasPrefix(j.RawURI, "/admin?") {
			t.Errorf("payload RawURI = %q, want query manipulation on /admin?", j.RawURI)
		}
		if len(j.Headers) != 0 {
			t.Errorf("payload has %d Headers, param manipulation is query-layer only", len(j.Headers))
		}
		found[j.RawURI] = true
	}

	// mutate (boundaries + numeric increment — full query rebuilt, others kept)
	for _, uri := range []string{
		"/admin?id=0&b=x", "/admin?id=-234&b=x", "/admin?id=99999999&b=x",
		"/admin?id=124&b=x", // id=123 → 124
		"/admin?id=123&b=-234", // mutate keeps position: pairs rebuilt in order
	} {
		if !found[uri] {
			t.Errorf("missing payload %q", uri)
		}
	}
	// remove
	for _, uri := range []string{"/admin?b=x", "/admin?id=123"} {
		if !found[uri] {
			t.Errorf("missing remove-param payload %q", uri)
		}
	}
	// reorder (reverse)
	if !found["/admin?b=x&id=123"] {
		t.Error("missing reorder payload /admin?b=x&id=123")
	}
	// add variants
	if !found["/admin?id=123&b=x&id=true"] {
		t.Error("missing add-param payload &id=true")
	}
}

// TestParamManipulationQueryless pins behavior for targets without a
// query: one payload per parameter name, all as ?<name>=true.
func TestParamManipulationQueryless(t *testing.T) {
	moduleName := "param_manipulation"
	targetURL := "https://example.com/admin"

	names, err := payload.ReadPayloadsFromFile("internal_param_names.lst")
	if err != nil {
		t.Fatalf("read internal_param_names.lst: %v", err)
	}

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.Generate()
	if len(jobs) != len(names) {
		t.Errorf("generated %d payloads for queryless target, want %d (one per name)", len(jobs), len(names))
	}
	for _, j := range jobs {
		if !strings.HasPrefix(j.RawURI, "/admin?") || !strings.HasSuffix(j.RawURI, "=true") {
			t.Errorf("payload RawURI = %q, want /admin?<name>=true", j.RawURI)
		}
	}
}

// TestParamManipulationRegistered pins registration (append-only: after
// user_agent).
func TestParamManipulationRegistered(t *testing.T) {
	last := ""
	for _, m := range payload.BypassModulesRegistry {
		last = m
	}
	if last != "param_manipulation" {
		t.Errorf("last registry entry = %q, want param_manipulation", last)
	}
}
