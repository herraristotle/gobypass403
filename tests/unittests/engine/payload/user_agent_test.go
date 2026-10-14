package tests

import (
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// TestUserAgentGeneration pins the user_agent module (addendum 3, Phase C):
// one payload per line of internal_user_agents.lst (bup's 45-line UA list),
// carrying the UA in the optional UserAgent field (not in Headers — rawhttp
// emits the field as the request's User-Agent, replacing the default).
func TestUserAgentGeneration(t *testing.T) {
	moduleName := "user_agent"
	targetURL := "https://example.com/admin/login?x=1"

	uas, err := payload.ReadPayloadsFromFile("internal_user_agents.lst")
	if err != nil {
		t.Fatalf("read internal_user_agents.lst: %v", err)
	}

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	jobs := pg.Generate()
	if len(jobs) == 0 {
		t.Fatal("user_agent generated no payloads")
	}
	if len(jobs) != len(uas) {
		t.Errorf("generated %d payloads, want %d (one per UA)", len(jobs), len(uas))
	}

	uaSet := make(map[string]bool, len(uas))
	for _, ua := range uas {
		uaSet[ua] = true
	}
	seen := make(map[string]bool)
	for _, j := range jobs {
		if j.BypassModule != moduleName {
			t.Errorf("payload BypassModule = %q, want %q", j.BypassModule, moduleName)
		}
		if j.RawURI != "/admin/login?x=1" {
			t.Errorf("payload RawURI = %q, want original request-target", j.RawURI)
		}
		if len(j.Headers) != 0 {
			t.Errorf("payload has %d Headers, want 0 (UA rides the UserAgent field)", len(j.Headers))
		}
		if j.UserAgent == "" {
			t.Error("payload UserAgent is empty")
			continue
		}
		if !uaSet[j.UserAgent] {
			t.Errorf("payload UserAgent %q not in internal_user_agents.lst", j.UserAgent)
		}
		seen[j.UserAgent] = true
	}
	for _, ua := range uas {
		if !seen[ua] {
			t.Errorf("missing payload for UA %q", ua)
		}
	}
}

// TestUserAgentTokenRoundtrip pins token field 9 (optional UserAgent):
// encode → decode preserves the UA; a default job without UA decodes empty.
func TestUserAgentTokenRoundtrip(t *testing.T) {
	withUA := payload.BypassPayload{
		OriginalURL:  "https://example.com/admin",
		Method:       "GET",
		Scheme:       "https",
		Host:         "example.com",
		RawURI:       "/admin",
		BypassModule: "user_agent",
		UserAgent:    "CCBot/2.0 (http://commoncrawl.org/faq/)",
	}
	withUA.PayloadToken = payload.GeneratePayloadToken(withUA)
	dec, err := payload.DecodePayloadToken(withUA.PayloadToken)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.UserAgent != withUA.UserAgent {
		t.Errorf("roundtrip UserAgent = %q, want %q", dec.UserAgent, withUA.UserAgent)
	}

	// Default payload: no UserAgent written (token fields stay optional /
	// append-only; absent field 9 = empty UA).
	plain := payload.BypassPayload{
		OriginalURL:  "https://example.com/",
		Method:       "GET",
		Scheme:       "https",
		Host:         "example.com",
		RawURI:       "/",
		BypassModule: "headers_url",
	}
	plain.PayloadToken = payload.GeneratePayloadToken(plain)
	dec2, err := payload.DecodePayloadToken(plain.PayloadToken)
	if err != nil {
		t.Fatalf("decode plain: %v", err)
	}
	if dec2.UserAgent != "" {
		t.Errorf("plain token decoded UserAgent = %q, want empty", dec2.UserAgent)
	}
	if dec2.BypassModule != "headers_url" || dec2.RawURI != "/" {
		t.Errorf("plain token corrupted: %+v", dec2)
	}
}

// TestUserAgentRegistered pins registration (append-only registry: after
// headers_method, which in turn must sit after http10).
func TestUserAgentRegistered(t *testing.T) {
	last := ""
	for _, m := range payload.BypassModulesRegistry {
		last = m
	}
	if last != "user_agent" {
		t.Errorf("last registry entry = %q, want user_agent appended after headers_method", last)
	}
	// Cross-check the chain: http10 < headers_method < user_agent
	idx := map[string]int{}
	for i, m := range payload.BypassModulesRegistry {
		idx[m] = i
	}
	if !(idx["http10"] < idx["headers_method"] && idx["headers_method"] < idx["user_agent"]) {
		t.Errorf("registry order broken: http10=%d headers_method=%d user_agent=%d",
			idx["http10"], idx["headers_method"], idx["user_agent"])
	}
}
