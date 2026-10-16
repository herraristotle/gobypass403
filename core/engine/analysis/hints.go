/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Wildcard hint (SPEC-unkover-gaps.md Addendum 7). A BYPASS cluster whose members
come from many distinct requests is the shape of a catch-all: one page served
for everything, classified BYPASS only because the run had no negative control
to compare against. The hint names that shape and points at -calibrate. It is
never a verdict and never suppresses anything -- suppression belongs to
Addendum 6's control, behind -calibrate.

Pure and derived on demand: hints live outside Report, so Text() and JSON() are
byte-identical whether or not a caller asks for them.
*/
package analysis

import "fmt"

// minWildcardRequests is how many distinct requests must share one BYPASS
// fingerprint before the cluster looks like a catch-all. A wildcard needs more
// than one request by definition; five keeps a stray duplicate from firing.
const minWildcardRequests = 5

// Hint is a cluster that looks like a catch-all rather than a finding.
type Hint struct {
	TargetURL   string      `json:"target_url"`
	Fingerprint Fingerprint `json:"fingerprint"`
	Requests    int         `json:"requests"` // distinct stored request lines
	Module      string      `json:"module"`   // the cluster's representative module
}

// String is the operator-facing one-liner, shared by the live printer and
// -analyze so both say the same thing.
func (h Hint) String() string {
	return fmt.Sprintf(
		"wildcard-shaped cluster: %d requests returned the same %d %s %dB (%s) - the shape of a catch-all/soft-404; rerun with -calibrate to confirm",
		h.Requests, h.Fingerprint.Status, h.Fingerprint.MediaType, h.Fingerprint.Length, h.Module)
}

// WildcardHints reports the catch-all-shaped clusters of a finished analysis,
// per target and in report order. A target whose run supplied negative
// controls is skipped: the classification already answered the question there,
// and with controls anything wildcard-shaped is CALIBRATED, never BYPASS.
func WildcardHints(rep Report) []Hint {
	var hints []Hint
	for _, tr := range rep.Targets {
		if tr.CalibrationControls > 0 {
			continue
		}
		for _, cl := range tr.Clusters {
			if cl.Class != ClassBypass {
				continue
			}
			n := distinctRequests(cl)
			if n < minWildcardRequests {
				continue
			}
			hints = append(hints, Hint{
				TargetURL:   tr.TargetURL,
				Fingerprint: cl.Fingerprint,
				Requests:    n,
				Module:      cl.Representative.BypassModule,
			})
		}
	}
	return hints
}

// distinctRequests counts the distinct request lines behind a cluster. Row
// clusters carry their members (the offline analyzer and the live print site
// both classify stored rows). Observation clusters deliberately keep no member
// rows -- the scanner holds its own job array -- and their refs are one per
// response, so the ref count is the same number.
func distinctRequests(cl Cluster) int {
	if len(cl.Members) == 0 {
		return len(cl.Refs)
	}
	seen := make(map[string]bool, len(cl.Members))
	for _, m := range cl.Members {
		seen[m.CurlCMD] = true
	}
	return len(seen)
}
