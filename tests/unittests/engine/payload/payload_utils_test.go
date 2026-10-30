package tests

import (
	"strings"
	"testing"

	"github.com/herraristotle/gobypass403/core/engine/payload"
)

func TestURLConversions(t *testing.T) {
	tests := []struct {
		name          string
		inputURL      string
		method        string
		headers       []payload.Headers
		expectedJob   payload.BypassPayload
		expectedError bool
		roundTrip     bool // test if URL->Job->URL matches
	}{
		{
			name:     "Standard URL",
			inputURL: "https://example.com/path/to/resource",
			method:   "GET",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/path/to/resource",
			},
			roundTrip: true,
		},
		{
			name:     "URL with Unicode Path Separator",
			inputURL: "https://example.com/path／to／resource",
			method:   "GET",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/path/to/resource", // normalized
			},
			roundTrip: false, // will not match exactly due to normalization
		},
		{
			name:     "URL with Port",
			inputURL: "http://localhost:8080/api/v1",
			method:   "POST",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "POST",
				Scheme: "http",
				Host:   "localhost:8080",
				RawURI: "/api/v1",
			},
			roundTrip: true,
		},
		{
			name:     "URL with Query Parameters",
			inputURL: "https://api.example.com/search?q=test&page=1",
			method:   "GET",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "api.example.com",
				RawURI: "/search",
			},
			roundTrip: false, // query params are stripped
		},
		{
			name:     "URL with Special Characters",
			inputURL: "https://example.com/path%20with%20spaces",
			method:   "GET",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/path%20with%20spaces",
			},
			roundTrip: true,
		},
		{
			name:          "Invalid URL",
			inputURL:      "not-a-url",
			method:        "GET",
			headers:       []payload.Headers{},
			expectedError: true,
		},
		{
			name:     "URL with Different Unicode Normalizations",
			inputURL: "https://example.com/café／test",
			method:   "GET",
			headers:  []payload.Headers{},
			expectedJob: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/café/test", // normalized
			},
			roundTrip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test FullURLToBypassPayload
			job, err := payload.FullURLToBypassPayload(tt.inputURL, tt.method, tt.headers)

			if tt.expectedError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Check job fields
			if job.Method != tt.expectedJob.Method {
				t.Errorf("Method mismatch: got %v, want %v", job.Method, tt.expectedJob.Method)
			}
			if job.Scheme != tt.expectedJob.Scheme {
				t.Errorf("Scheme mismatch: got %v, want %v", job.Scheme, tt.expectedJob.Scheme)
			}
			if job.Host != tt.expectedJob.Host {
				t.Errorf("Host mismatch: got %v, want %v", job.Host, tt.expectedJob.Host)
			}
			if job.RawURI != tt.expectedJob.RawURI {
				t.Errorf("RawURI mismatch: got %v, want %v", job.RawURI, tt.expectedJob.RawURI)
			}

			// Test round-trip if specified
			if tt.roundTrip {
				roundTripURL := payload.BypassPayloadToFullURL(job)
				if roundTripURL != tt.inputURL {
					t.Errorf("Round-trip mismatch:\ngot:  %v\nwant: %v", roundTripURL, tt.inputURL)
				}
			}
		})
	}
}

// TestNormalizationForms specifically tests the normalization function
func TestNormalizationForms(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "NFKC Normalization",
			input:    "https://example.com/path／to／resource",
			expected: "https://example.com/path/to/resource",
			wantErr:  false,
		},
		{
			name:     "Mixed Unicode",
			input:    "https://example.com/café＋test",
			expected: "https://example.com/café+test",
			wantErr:  false,
		},
		{
			name:     "No Normalization Needed",
			input:    "https://example.com/normal/path",
			expected: "https://example.com/normal/path",
			wantErr:  false,
		},
		// Add more test cases based on your unicode_path_chars.lst
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized, err := payload.TryNormalizationForms(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if normalized != tt.expected {
				t.Errorf("got %q, want %q", normalized, tt.expected)
			}
		})
	}
}

func TestPayloadTokenWithUnicode(t *testing.T) {
	tests := []struct {
		name     string
		input    payload.BypassPayload
		wantFail bool
	}{
		{
			name: "Chinese Path with Mixed Characters",
			input: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/路径/测试/文件.jpg",
				Headers: []payload.Headers{
					{Header: "X-Custom", Value: "测试值"},
				},
			},
		},
		{
			name: "Japanese Path with Special Characters",
			input: payload.BypassPayload{
				Method: "POST",
				Scheme: "https",
				Host:   "example.co.jp",
				RawURI: "/パス/テスト/ファイル名に★☆♪も.png",
				Headers: []payload.Headers{
					{Header: "X-Test", Value: "テスト値"},
				},
			},
		},
		{
			name: "Mixed Unicode Path",
			input: payload.BypassPayload{
				Method: "GET",
				Scheme: "http",
				Host:   "localhost",
				RawURI: "/path/文件/パス/🔒/test/café/über/", // Emojis, CJK, Latin Extended
				Headers: []payload.Headers{
					{Header: "X-Path", Value: "パス/文件"},
				},
			},
		},
		{
			name: "Very Long Unicode Path",
			input: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/测试/" + strings.Repeat("文件/", 7) + "end.txt", // Long repeating Unicode
				Headers: []payload.Headers{
					{Header: "X-Long", Value: "测试"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate token
			token := payload.GeneratePayloadToken(tt.input)
			if token == "" {
				t.Fatal("failed to generate token")
			}

			// Decode token
			decoded, err := payload.DecodePayloadToken(token)
			if tt.wantFail {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("failed to decode token: %v", err)
			}

			// Compare original and decoded data
			if decoded.Method != tt.input.Method {
				t.Errorf("Method mismatch: got %v, want %v", decoded.Method, tt.input.Method)
			}
			if decoded.Scheme != tt.input.Scheme {
				t.Errorf("Scheme mismatch: got %v, want %v", decoded.Scheme, tt.input.Scheme)
			}
			if decoded.Host != tt.input.Host {
				t.Errorf("Host mismatch: got %v, want %v", decoded.Host, tt.input.Host)
			}
			if decoded.RawURI != tt.input.RawURI {
				t.Errorf("RawURI mismatch:\ngot:  %v\nwant: %v", decoded.RawURI, tt.input.RawURI)
			}

			// Print token lengths for analysis
			t.Logf("Token length for %s: %d", tt.name, len(token))
		})
	}
}

func TestPayloadTokenWithUnicode2(t *testing.T) {
	tests := []struct {
		name     string
		input    payload.BypassPayload
		wantFail bool
	}{
		{
			name: "Chinese Path with Mixed Characters",
			input: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/路径/测试/文件.jpg",
				Headers: []payload.Headers{
					{Header: "X-Custom", Value: "测试值"},
				},
			},
		},
		{
			name: "Japanese Path with Special Characters",
			input: payload.BypassPayload{
				Method: "POST",
				Scheme: "https",
				Host:   "example.co.jp",
				RawURI: "/パス/テスト/ファイル.png",
				Headers: []payload.Headers{
					{Header: "X-Test", Value: "テスト値"},
				},
			},
		},
		{
			name: "Mixed Unicode Path",
			input: payload.BypassPayload{
				Method: "GET",
				Scheme: "http",
				Host:   "localhost",
				RawURI: "/path/文件/パス/🔒/test/café/",
				Headers: []payload.Headers{
					{Header: "X-Path", Value: "パス/文件"},
				},
			},
		},
		{
			name: "Long Unicode Path Within Limits",
			input: payload.BypassPayload{
				Method: "GET",
				Scheme: "https",
				Host:   "example.com",
				RawURI: "/测试/" + strings.Repeat("文件/", 10) + "end.txt", // Shorter but still tests length
				Headers: []payload.Headers{
					{Header: "X-Long", Value: "测试"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Print original lengths in bytes
			t.Logf("Original RawURI length in bytes: %d", len([]byte(tt.input.RawURI)))

			// Generate token
			token := payload.GeneratePayloadToken(tt.input)
			if token == "" {
				t.Fatal("failed to generate token")
			}

			// Decode token
			decoded, err := payload.DecodePayloadToken(token)
			if tt.wantFail {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("failed to decode token: %v", err)
			}

			// Compare original and decoded data
			if decoded.Method != tt.input.Method {
				t.Errorf("Method mismatch: got %v, want %v", decoded.Method, tt.input.Method)
			}
			if decoded.Scheme != tt.input.Scheme {
				t.Errorf("Scheme mismatch: got %v, want %v", decoded.Scheme, tt.input.Scheme)
			}
			if decoded.Host != tt.input.Host {
				t.Errorf("Host mismatch: got %v, want %v", decoded.Host, tt.input.Host)
			}
			if decoded.RawURI != tt.input.RawURI {
				t.Errorf("RawURI mismatch:\ngot:  %v\nwant: %v", decoded.RawURI, tt.input.RawURI)
			}

			// Print token and decoded lengths for analysis
			t.Logf("Token length: %d", len(token))
			t.Logf("Decoded RawURI length in bytes: %d", len([]byte(decoded.RawURI)))
		})
	}
}
