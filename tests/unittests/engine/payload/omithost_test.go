package tests

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	"github.com/slicingmelon/gobypass403/core/engine/recon"
)

// TestHeadersHostOmitHost pins the Host-header-removal variant (addendum 3
// Phase D item 10, report §3 P2): headers_host always emits one payload
// that sends NO Host header at all (HackTricks "remove the Host header").
// It is generated before the recon-cache gate, so it ships even when recon
// data is absent. The raw request bytes must contain no `Host:` line.
func TestHeadersHostOmitHost(t *testing.T) {
	moduleName := "headers_host"
	targetURL := "https://example.com/admin"

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
		ReconCache:   recon.NewReconCache(),
	})
	jobs := pg.Generate()

	var omit *payload.BypassPayload
	for i := range jobs {
		if jobs[i].OmitHost {
			omit = &jobs[i]
			break
		}
	}
	if omit == nil {
		t.Fatal("headers_host generated no OmitHost payload")
	}
	if len(omit.Headers) != 0 {
		t.Errorf("OmitHost payload has %d Headers, want 0", len(omit.Headers))
	}
	if omit.RawURI != "/admin" {
		t.Errorf("OmitHost RawURI = %q, want /admin", omit.RawURI)
	}

	// Raw wire bytes: no Host header line
	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())
	bb, _ := rawhttp.BuildRawRequest(client, *omit)
	raw := string(bb.B)
	for _, line := range strings.Split(raw[:strings.Index(raw, "\r\n\r\n")], "\r\n") {
		if len(line) >= 5 && strings.EqualFold(line[:5], "Host:") {
			t.Errorf("raw request still emits Host header: %q", line)
		}
	}
	// Accept/UA still present (only Host removed)
	if !strings.Contains(raw, "Accept: */*") {
		t.Error("raw request lost standard headers — removal must be Host-only")
	}
}

// TestOmitHostTokenRoundtrip pins token field 10: OmitHost survives
// encode→decode; default payloads keep it false and byte-stable.
func TestOmitHostTokenRoundtrip(t *testing.T) {
	omit := payload.BypassPayload{
		OriginalURL:  "https://example.com/admin",
		Method:       "GET",
		Scheme:       "https",
		Host:         "example.com",
		RawURI:       "/admin",
		BypassModule: "headers_host",
		OmitHost:     true,
	}
	omit.PayloadToken = payload.GeneratePayloadToken(omit)
	dec, err := payload.DecodePayloadToken(omit.PayloadToken)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !dec.OmitHost {
		t.Error("roundtrip OmitHost = false, want true")
	}
	if dec.RawURI != "/admin" {
		t.Errorf("roundtrip corrupted other fields: %+v", dec)
	}

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
	if dec2.OmitHost {
		t.Error("plain token decoded OmitHost = true, want false")
	}
}

// TestOmitHostCurlPoC pins the curl repro for Host removal: -H 'Host:'
// (empty value makes curl omit the header entirely).
func TestOmitHostCurlPoC(t *testing.T) {
	omit := payload.BypassPayload{
		Method: "GET", Scheme: "https", Host: "example.com",
		RawURI: "/admin", BypassModule: "headers_host", OmitHost: true,
	}
	poc := string(rawhttp.BuildCurlCommandPoc(omit, nil))
	if !strings.Contains(poc, "-H 'Host:'") {
		t.Errorf("PoC %q missing -H 'Host:'", poc)
	}
}
