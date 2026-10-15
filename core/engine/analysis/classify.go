/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Clustering + classification for the offline differential analyzer
(SPEC-unkover-gaps.md Addendum 5, Phase A). Pure: takes rows, returns a
report; no logger, no database, no scan-path coupling.
*/
package analysis

import (
	"encoding/json"
	"sort"
)

// Baseline sources reported per target.
const (
	BaselineDumbCheck = "dumb_check" // target's dumb_check rows were the baseline
	BaselineModal     = "modal"      // no dumb_check rows; target's most common shape was
)

// Class ranks a cluster by how much it departs from the baseline; lower is
// more interesting, and the value doubles as the report ordering.
type Class int

const (
	ClassBypass  Class = iota // status class improves on the baseline
	ClassVariant              // same status class, different body
	ClassDup                  // identical to the baseline
	ClassNoise                // empty, non-improving artifact
)

// String returns the class name used in reports.
func (c Class) String() string {
	switch c {
	case ClassBypass:
		return "BYPASS"
	case ClassVariant:
		return "VARIANT"
	case ClassDup:
		return "DUP"
	case ClassNoise:
		return "NOISE"
	}
	return "UNKNOWN"
}

// MarshalJSON renders the class as its human-readable name.
func (c Class) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// Cluster is the set of responses sharing one Fingerprint.
type Cluster struct {
	Fingerprint    Fingerprint `json:"fingerprint"`
	Class          Class       `json:"class"`
	Count          int         `json:"count"`
	Representative Row         `json:"representative"`
	Members        []Row       `json:"members"`
}

// TargetReport is the analysis of one target_url.
type TargetReport struct {
	TargetURL      string    `json:"target_url"`
	Rows           int       `json:"rows"`
	BaselineSource string    `json:"baseline_source"`
	BaselineStatus int       `json:"baseline_status"`
	Clusters       []Cluster `json:"clusters"`
}

// Report is the analysis of a whole findings database.
type Report struct {
	Targets []TargetReport `json:"targets"`
}

// ClassifyReport groups rows by target_url and classifies each target,
// returning targets sorted by URL for deterministic output.
func ClassifyReport(rows []Row) Report {
	byTarget := make(map[string][]Row)
	for _, r := range rows {
		byTarget[r.TargetURL] = append(byTarget[r.TargetURL], r)
	}

	urls := make([]string, 0, len(byTarget))
	for u := range byTarget {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	rep := Report{Targets: make([]TargetReport, 0, len(urls))}
	for _, u := range urls {
		rep.Targets = append(rep.Targets, Classify(u, byTarget[u]))
	}
	return rep
}

// Classify clusters one target's rows and classifies each cluster against
// the target's baseline (dumb_check rows; the target's modal fingerprint
// when there are none).
func Classify(targetURL string, rows []Row) TargetReport {
	tr := TargetReport{TargetURL: targetURL, Rows: len(rows)}

	// Cluster rows by exact fingerprint, preserving first-seen order so
	// tie-breaks are deterministic.
	order := make([]string, 0, len(rows))
	clusters := make(map[string]*Cluster)
	for _, r := range rows {
		fp := NewFingerprint(r)
		k := fp.Key()
		cl, ok := clusters[k]
		if !ok {
			cl = &Cluster{Fingerprint: fp}
			clusters[k] = cl
			order = append(order, k)
		}
		cl.Members = append(cl.Members, r)
		cl.Count++
	}

	// Baseline selection.
	baselineSet := make(map[string]bool)
	var baselineRows []Row
	for _, r := range rows {
		if r.BypassModule == "dumb_check" {
			baselineRows = append(baselineRows, r)
		}
	}
	if len(baselineRows) > 0 {
		tr.BaselineSource = BaselineDumbCheck
		for _, r := range baselineRows {
			baselineSet[NewFingerprint(r).Key()] = true
		}
		tr.BaselineStatus = modalStatus(baselineRows)
	} else {
		tr.BaselineSource = BaselineModal
		if k := modalClusterKey(order, clusters); k != "" {
			baselineSet[k] = true
			tr.BaselineStatus = clusters[k].Fingerprint.Status
		}
	}

	// Classification. Order matters: a fingerprint identical to the
	// baseline is a DUP even if its status "improves" (e.g. a baseline
	// 200 on an unprotected target); an empty-body 2xx is still a BYPASS,
	// only empty non-improving responses are NOISE.
	emptyDigest := digest("")
	tr.Clusters = make([]Cluster, 0, len(order))
	for _, k := range order {
		cl := clusters[k]
		cl.Representative = representative(cl.Members)
		switch {
		case baselineSet[k]:
			cl.Class = ClassDup
		case statusImproves(cl.Fingerprint.Status, tr.BaselineStatus):
			cl.Class = ClassBypass
		case cl.Fingerprint.Length == 0 && cl.Fingerprint.Digest == emptyDigest:
			cl.Class = ClassNoise
		default:
			cl.Class = ClassVariant
		}
		tr.Clusters = append(tr.Clusters, *cl)
	}

	sort.SliceStable(tr.Clusters, func(i, j int) bool {
		a, b := tr.Clusters[i], tr.Clusters[j]
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Representative.CurlCMD != b.Representative.CurlCMD {
			return a.Representative.CurlCMD < b.Representative.CurlCMD
		}
		return a.Fingerprint.Key() < b.Fingerprint.Key()
	})
	return tr
}

// statusImproves reports whether status crosses from a denial class
// (4xx/5xx) into a success or redirect class (2xx/3xx) relative to the
// baseline. Going 403 -> 404 is not an improvement (both are denials).
func statusImproves(status, baselineStatus int) bool {
	c := status / 100
	return (c == 2 || c == 3) && c < baselineStatus/100
}

// modalStatus returns the most frequent status code, ties broken by the
// smallest code (deterministic).
func modalStatus(rows []Row) int {
	counts := make(map[int]int, len(rows))
	for _, r := range rows {
		counts[r.StatusCode]++
	}
	best, bestN := 0, -1
	for s, n := range counts {
		if n > bestN || (n == bestN && s < best) {
			best, bestN = s, n
		}
	}
	return best
}

// modalClusterKey returns the key of the largest cluster, ties broken by
// the smallest key (deterministic given the first-seen order).
func modalClusterKey(order []string, clusters map[string]*Cluster) string {
	best := ""
	bestN := -1
	for _, k := range order {
		n := clusters[k].Count
		if n > bestN || (n == bestN && k < best) {
			best, bestN = k, n
		}
	}
	return best
}

// representative picks a cluster's canonical member deterministically: the
// lexicographically smallest curl command, then module name.
func representative(members []Row) Row {
	best := members[0]
	for _, m := range members[1:] {
		if m.CurlCMD < best.CurlCMD ||
			(m.CurlCMD == best.CurlCMD && m.BypassModule < best.BypassModule) {
			best = m
		}
	}
	return best
}
