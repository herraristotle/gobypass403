/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Response fingerprinting for the offline differential analyzer
(SPEC-unkover-gaps.md Addendum 5, Phase A). Pure and deterministic by
design: no logger, no database, no scan-path coupling — the same package
is reused by Phases B/C.
*/
package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Row is the subset of a scan_results row the analyzer works with.
type Row struct {
	TargetURL           string `json:"target_url"`
	BypassModule        string `json:"bypass_module"`
	StatusCode          int    `json:"status_code"`
	ContentLength       int64  `json:"content_length"`
	ContentType         string `json:"content_type"`
	ResponseBodyPreview string `json:"response_body_preview"`
	ResponseBodyBytes   int    `json:"response_body_bytes"`
	CurlCMD             string `json:"curl_cmd"`
}

// Fingerprint identifies a response shape. Responses sharing a Fingerprint
// are treated as members of the same cluster.
type Fingerprint struct {
	Status    int    `json:"status"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Length    int64  `json:"length"`
}

// Key returns the exact cluster key for the fingerprint.
func (f Fingerprint) Key() string {
	return strconv.Itoa(f.Status) + "|" + f.MediaType + "|" + f.Digest + "|" +
		strconv.FormatInt(f.Length, 10)
}

// NewFingerprint derives the fingerprint of a response row.
func NewFingerprint(r Row) Fingerprint {
	return FingerprintFrom(r.StatusCode, r.ContentType, []byte(r.ResponseBodyPreview),
		r.ContentLength, r.ResponseBodyBytes)
}

// FingerprintFrom derives a fingerprint from live response data. The live
// scan (Phase B) fingerprints the preview bytes and drops them, so it never
// retains response bodies; NewFingerprint delegates here so there is exactly
// one normalisation/hash implementation.
func FingerprintFrom(status int, contentType string, preview []byte, contentLength int64, bodyBytes int) Fingerprint {
	return Fingerprint{
		Status:    status,
		MediaType: MediaType(contentType),
		Digest:    digest(Normalize(string(preview))),
		Length:    lengthFrom(contentLength, bodyBytes),
	}
}

// MediaType lowercases a Content-Type and strips its parameters, so
// "Text/HTML; charset=UTF-8" and "text/html" fingerprint identically.
func MediaType(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

func lengthFrom(contentLength int64, bodyBytes int) int64 {
	if contentLength > 0 {
		return contentLength
	}
	return int64(bodyBytes)
}

// Normalize collapses every run of ASCII whitespace bytes to a single space
// and trims both ends, so bodies differing only in server-side formatting
// fingerprint identically. It is byte-safe: the input is never assumed to be
// valid UTF-8, and non-whitespace bytes (including NUL and 0xFF) survive.
func Normalize(preview string) string {
	var b strings.Builder
	b.Grow(len(preview))

	inSpace := false
	started := false
	for i := 0; i < len(preview); i++ {
		c := preview[i]
		if isSpaceByte(c) {
			if started {
				inSpace = true
			}
			continue
		}
		if inSpace {
			b.WriteByte(' ')
			inSpace = false
		}
		b.WriteByte(c)
		started = true
	}
	return b.String()
}

func isSpaceByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
