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
	TargetURL           string
	BypassModule        string
	StatusCode          int
	ContentLength       int64
	ContentType         string
	ResponseBodyPreview string
	ResponseBodyBytes   int
	CurlCMD             string
}

// Fingerprint identifies a response shape. Responses sharing a Fingerprint
// are treated as members of the same cluster.
type Fingerprint struct {
	Status    int
	MediaType string
	Digest    string
	Length    int64
}

// Key returns the exact cluster key for the fingerprint.
func (f Fingerprint) Key() string {
	return strconv.Itoa(f.Status) + "|" + f.MediaType + "|" + f.Digest + "|" +
		strconv.FormatInt(f.Length, 10)
}

// NewFingerprint derives the fingerprint of a response row.
func NewFingerprint(r Row) Fingerprint {
	return Fingerprint{
		Status:    r.StatusCode,
		MediaType: MediaType(r.ContentType),
		Digest:    digest(Normalize(r.ResponseBodyPreview)),
		Length:    lengthOf(r),
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

func lengthOf(r Row) int64 {
	if r.ContentLength > 0 {
		return r.ContentLength
	}
	return int64(r.ResponseBodyBytes)
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
