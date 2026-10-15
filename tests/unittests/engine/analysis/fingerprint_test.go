package tests

// Task A1 (SPEC-unkover-gaps.md Addendum 5, Phase A): response
// fingerprint + byte-safe normalization.
//
// The analyzer's whole job rests on this being deterministic: two bodies
// that differ only in server formatting must yield the same digest (so the
// 453 near-identical suffix responses collapse), while any real byte
// difference must not. Normalization must also never panic on arbitrary
// bytes (previews can be binary/compressed).

import (
	"strings"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
)

func TestNormalizeCollapsesWhitespaceAndTrims(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"\n\t \r\n", ""},
		{"hello", "hello"},
		{"  hello  ", "hello"},
		{"hello   world", "hello world"},
		{"hello\nworld", "hello world"},
		{"a\t\tb  \n c\r\n", "a b c"},
		{"<html>\n  <body>hi</body>\n</html>", "<html> <body>hi</body> </html>"},
	}
	for _, c := range cases {
		if got := analysis.Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeIsByteSafe(t *testing.T) {
	// Invalid UTF-8 and NUL bytes must not panic, and non-whitespace
	// content must survive (only whitespace runs collapse).
	in := string([]byte{0xff, 0x00, 0x20, 0x20, 0xfe, 0x09, 0xff})
	out := analysis.Normalize(in)
	if out == "" {
		t.Fatalf("non-whitespace binary content was normalized away")
	}
	if strings.Contains(out, "  ") {
		t.Errorf("whitespace run not collapsed: %q", out)
	}
	if !strings.HasPrefix(out, string([]byte{0xff, 0x00})) {
		t.Errorf("leading non-whitespace bytes were dropped: %q", out)
	}
}

func TestFingerprintFormattingEquivalence(t *testing.T) {
	a := analysis.Row{
		StatusCode: 200, ContentType: "text/html", ContentLength: 40,
		ResponseBodyPreview: "<html>\n <body>x</body>\n</html>",
	}
	b := analysis.Row{
		StatusCode: 200, ContentType: "text/html", ContentLength: 40,
		ResponseBodyPreview: "<html> <body>x</body> </html>",
	}
	if analysis.NewFingerprint(a).Digest != analysis.NewFingerprint(b).Digest {
		t.Errorf("whitespace-equivalent bodies must share a digest")
	}

	c := a
	c.ResponseBodyPreview = "<html> <body>y</body> </html>"
	if analysis.NewFingerprint(a).Digest == analysis.NewFingerprint(c).Digest {
		t.Errorf("different bodies must not share a digest")
	}
}

func TestFingerprintMediaTypeAndLength(t *testing.T) {
	fp := analysis.NewFingerprint(analysis.Row{
		StatusCode: 403, ContentType: "Text/HTML; charset=UTF-8",
		ContentLength: 0, ResponseBodyBytes: 40, ResponseBodyPreview: "x",
	})
	if fp.MediaType != "text/html" {
		t.Errorf("MediaType = %q, want %q", fp.MediaType, "text/html")
	}
	if fp.Length != 40 {
		t.Errorf("Length = %d, want 40 (fallback to ResponseBodyBytes)", fp.Length)
	}

	fp2 := analysis.NewFingerprint(analysis.Row{
		StatusCode: 200, ContentLength: 1234, ResponseBodyBytes: 99,
		ResponseBodyPreview: "y",
	})
	if fp2.Length != 1234 {
		t.Errorf("Length = %d, want 1234", fp2.Length)
	}
}

func TestFingerprintDeterministicAndKeyed(t *testing.T) {
	r := analysis.Row{
		StatusCode: 200, ContentType: "application/json",
		ContentLength: 7, ResponseBodyPreview: `{"a":1}`,
	}
	f1, f2 := analysis.NewFingerprint(r), analysis.NewFingerprint(r)
	if f1 != f2 {
		t.Errorf("fingerprint not deterministic: %+v vs %+v", f1, f2)
	}

	k := f1.Key()
	for _, part := range []string{"200", "application/json", f1.Digest, "7"} {
		if !strings.Contains(k, part) {
			t.Errorf("Key() = %q must contain %q", k, part)
		}
	}

	other := r
	other.StatusCode = 201
	if f1.Key() == analysis.NewFingerprint(other).Key() {
		t.Errorf("Key must differ when status differs")
	}
	other = r
	other.ResponseBodyPreview = `{"a":2}`
	if f1.Key() == analysis.NewFingerprint(other).Key() {
		t.Errorf("Key must differ when body differs")
	}
}
