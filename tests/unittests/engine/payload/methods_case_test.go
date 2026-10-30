package tests

import (
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
)

// TestHTTPMethodsCaseVariants pins the unKover `method_case` parity: every
// method in internal_http_methods.lst gets a lowercase twin, with identical
// request shape except the Method itself (issue: SPEC-unkover-gaps.md).
func TestHTTPMethodsCaseVariants(t *testing.T) {
	moduleName := "http_methods"

	methods, err := payload.ReadPayloadsFromFile("internal_http_methods.lst")
	if err != nil {
		t.Fatalf("Failed to read method list: %v", err)
	}

	uniqueMethods := make(map[string]struct{})
	for _, m := range methods {
		if m != "" {
			uniqueMethods[m] = struct{}{}
		}
	}

	t.Run("WithoutQueryTwinPerMethod", func(t *testing.T) {
		targetURL := "http://example.com/admin/config"
		pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
			TargetURL:    targetURL,
			BypassModule: moduleName,
		})
		jobs := pg.GenerateHTTPMethodsPayloads(targetURL, moduleName)
		if len(jobs) == 0 {
			t.Fatal("No payloads generated")
		}

		// One base-case payload per method and per lowercase twin.
		if want := 2 * len(uniqueMethods); len(jobs) != want {
			t.Errorf("Expected %d payloads (2x %d methods), got %d", want, len(uniqueMethods), len(jobs))
		}

		// Every list method and its lowercase form must be present.
		seenMethods := make(map[string]int)
		tokens := make(map[string]struct{})
		for _, j := range jobs {
			seenMethods[j.Method]++
			if _, dup := tokens[j.PayloadToken]; dup {
				t.Errorf("Duplicate payload token for method %s", j.Method)
			}
			tokens[j.PayloadToken] = struct{}{}
		}
		for m := range uniqueMethods {
			if seenMethods[m] != 1 {
				t.Errorf("Expected exactly 1 payload for method %q, got %d", m, seenMethods[m])
			}
			lower := strings.ToLower(m)
			if seenMethods[lower] != 1 {
				t.Errorf("Expected exactly 1 payload for lowercase method %q, got %d", lower, seenMethods[lower])
			}
		}

		// Lowercase twins match their uppercase twin in RawURI/headers/body.
		jobsByMethod := make(map[string][]payload.BypassPayload)
		for _, j := range jobs {
			jobsByMethod[j.Method] = append(jobsByMethod[j.Method], j)
		}
		for m := range uniqueMethods {
			lower := strings.ToLower(m)
			upperJobs := jobsByMethod[m]
			lowerJobs := jobsByMethod[lower]
			if len(upperJobs) != len(lowerJobs) {
				t.Errorf("Method %q has %d payloads but %q has %d", m, len(upperJobs), lower, len(lowerJobs))
				continue
			}
			for i := range upperJobs {
				if upperJobs[i].RawURI != lowerJobs[i].RawURI {
					t.Errorf("Twin RawURI mismatch for %s/%s: %q vs %q", m, lower, upperJobs[i].RawURI, lowerJobs[i].RawURI)
				}
				if upperJobs[i].Body != lowerJobs[i].Body {
					t.Errorf("Twin Body mismatch for %s/%s: %q vs %q", m, lower, upperJobs[i].Body, lowerJobs[i].Body)
				}
				if len(upperJobs[i].Headers) != len(lowerJobs[i].Headers) {
					t.Errorf("Twin Headers length mismatch for %s/%s", m, lower)
					continue
				}
				for h := range upperJobs[i].Headers {
					if upperJobs[i].Headers[h] != lowerJobs[i].Headers[h] {
						t.Errorf("Twin Header mismatch for %s/%s: %+v vs %+v",
							m, lower, upperJobs[i].Headers[h], lowerJobs[i].Headers[h])
					}
				}
			}
		}
	})

	t.Run("PostQueryAsBodyAppliesToLowercase", func(t *testing.T) {
		targetURL := "http://example.com/login?user=x&pass=y"
		pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
			TargetURL:    targetURL,
			BypassModule: moduleName,
		})
		jobs := pg.GenerateHTTPMethodsPayloads(targetURL, moduleName)

		// 2x37 base payloads + one query-as-body variant each for POST and post.
		if want := 2*len(uniqueMethods) + 2; len(jobs) != want {
			t.Errorf("Expected %d payloads, got %d", want, len(jobs))
		}

		for _, method := range []string{"POST", "post"} {
			found := false
			for _, j := range jobs {
				if j.Method != method || j.Body == "" {
					continue
				}
				if j.RawURI != "/login" {
					t.Errorf("%s query-as-body RawURI = %q, want /login", method, j.RawURI)
				}
				if j.Body != "user=x&pass=y" {
					t.Errorf("%s query-as-body Body = %q, want query string", method, j.Body)
				}
				hasCT := false
				for _, h := range j.Headers {
					if h.Header == "Content-Type" && h.Value == "application/x-www-form-urlencoded" {
						hasCT = true
					}
				}
				if !hasCT {
					t.Errorf("%s query-as-body missing Content-Type header: %+v", method, j.Headers)
				}
				found = true
			}
			if !found {
				t.Errorf("No query-as-body payload found for method %q", method)
			}
		}
	})
}
