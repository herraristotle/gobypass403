/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Clustering + classification for the differential analyzer
(SPEC-unkover-gaps.md Addendum 5). Pure: takes rows (offline, Phase A) or
already-computed fingerprints (live scan, Phase B) and returns a report; no
logger, no database, no scan-path coupling.

Both entry points share one classification core so the offline report and
the live expansion decision can never drift apart:

	Classify(rows []Row)                          -- offline: full rows
	ClassifyObservations(obs []Observation)       -- live: fingerprints only
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

// Observation is a response the live scan already fingerprinted and then
// discarded (no body preview retained): a 6.5k-payload module costs a few
// hundred KB of fingerprints instead of tens of MB of bodies. Ref is the
// caller's own index for that response, so it can recover the request it
// actually sent (needed to derive expansion payloads) without this package
// knowing anything about the scan.
type Observation struct {
	Fingerprint Fingerprint `json:"fingerprint"`
	Module      string      `json:"module"`
	CurlCMD     string      `json:"curl_cmd"`
	Ref         int         `json:"ref"`
}

// Cluster is the set of responses sharing one Fingerprint.
type Cluster struct {
	Fingerprint    Fingerprint `json:"fingerprint"`
	Class          Class       `json:"class"`
	Count          int         `json:"count"`
	Representative Row         `json:"representative"`
	Members        []Row       `json:"members"`
	// Refs indexes the caller's observations, in member order (live-scan
	// path only). Members is empty there: the scanner already holds its own
	// job array and must not be duplicated.
	Refs []int `json:"refs,omitempty"`
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
	observed := make([]obsRow, 0, len(rows))
	for i := range rows {
		r := rows[i]
		observed = append(observed, obsRow{
			fp:     NewFingerprint(r),
			module: r.BypassModule,
			curl:   r.CurlCMD,
			ref:    i,
			full:   &r,
		})
	}

	cores, source, baselineStatus := classifyRows(observed)

	tr := TargetReport{
		TargetURL:      targetURL,
		Rows:           len(rows),
		BaselineSource: source,
		BaselineStatus: baselineStatus,
		Clusters:       make([]Cluster, 0, len(cores)),
	}
	for _, c := range cores {
		cl := Cluster{
			Fingerprint: c.fp,
			Class:       c.class,
			Count:       len(c.members),
			Members:     make([]Row, 0, len(c.members)),
		}
		for _, m := range c.members {
			cl.Members = append(cl.Members, *m.full)
		}
		cl.Representative = *c.members[c.rep].full
		tr.Clusters = append(tr.Clusters, cl)
	}
	return tr
}

// ClassifyObservations classifies a target from pre-computed fingerprints
// (the live scan path). Results match Classify for equivalent input.
func ClassifyObservations(targetURL string, obs []Observation) TargetReport {
	observed := make([]obsRow, 0, len(obs))
	for _, o := range obs {
		observed = append(observed, obsRow{
			fp:     o.Fingerprint,
			module: o.Module,
			curl:   o.CurlCMD,
			ref:    o.Ref,
		})
	}

	cores, source, baselineStatus := classifyRows(observed)

	tr := TargetReport{
		TargetURL:      targetURL,
		Rows:           len(obs),
		BaselineSource: source,
		BaselineStatus: baselineStatus,
		Clusters:       make([]Cluster, 0, len(cores)),
	}
	for _, c := range cores {
		cl := Cluster{
			Fingerprint: c.fp,
			Class:       c.class,
			Count:       len(c.members),
			Refs:        make([]int, 0, len(c.members)),
		}
		for _, m := range c.members {
			cl.Refs = append(cl.Refs, m.ref)
		}
		rep := c.members[c.rep]
		cl.Representative = Row{
			TargetURL:     targetURL,
			BypassModule:  rep.module,
			CurlCMD:       rep.curl,
			StatusCode:    rep.fp.Status,
			ContentLength: rep.fp.Length,
			ContentType:   rep.fp.MediaType,
		}
		tr.Clusters = append(tr.Clusters, cl)
	}
	return tr
}

// obsRow is one response as the classifier sees it: a fingerprint plus the
// two strings needed to pick and describe a representative. full is set only
// on the Row path, where clusters must reproduce complete Rows.
type obsRow struct {
	fp     Fingerprint
	module string
	curl   string
	ref    int
	full   *Row
}

// clusterCore is a classified cluster before it is adapted to whichever
// entry point asked for it.
type clusterCore struct {
	fp      Fingerprint
	class   Class
	rep     int // index into members of the representative
	members []obsRow
}

// classifyRows is the single classification core: cluster by exact
// fingerprint, choose a baseline, classify, order. Deterministic — no map
// iteration reaches the output.
func classifyRows(rows []obsRow) (clusters []clusterCore, baselineSource string, baselineStatus int) {
	order := make([]string, 0, len(rows))
	byKey := make(map[string]*clusterCore)
	for _, r := range rows {
		k := r.fp.Key()
		cl, ok := byKey[k]
		if !ok {
			cl = &clusterCore{fp: r.fp}
			byKey[k] = cl
			order = append(order, k)
		}
		cl.members = append(cl.members, r)
	}

	// Baseline selection.
	baselineSet := make(map[string]bool)
	var baseline []obsRow
	for _, r := range rows {
		if r.module == BaselineDumbCheck {
			baseline = append(baseline, r)
		}
	}
	if len(baseline) > 0 {
		baselineSource = BaselineDumbCheck
		for _, r := range baseline {
			baselineSet[r.fp.Key()] = true
		}
		baselineStatus = modalStatus(baseline)
	} else {
		baselineSource = BaselineModal
		if k := modalClusterKey(order, byKey); k != "" {
			baselineSet[k] = true
			baselineStatus = byKey[k].fp.Status
		}
	}

	// Classification. Order matters: a fingerprint identical to the
	// baseline is a DUP even if its status "improves" (e.g. a baseline
	// 200 on an unprotected target); an empty-body 2xx is still a BYPASS,
	// only empty non-improving responses are NOISE.
	emptyDigest := digest("")
	out := make([]clusterCore, 0, len(order))
	for _, k := range order {
		cl := byKey[k]
		cl.rep = representativeIndex(cl.members)
		switch {
		case baselineSet[k]:
			cl.class = ClassDup
		case statusImproves(cl.fp.Status, baselineStatus):
			cl.class = ClassBypass
		case cl.fp.Length == 0 && cl.fp.Digest == emptyDigest:
			cl.class = ClassNoise
		default:
			cl.class = ClassVariant
		}
		out = append(out, *cl)
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.class != b.class {
			return a.class < b.class
		}
		if len(a.members) != len(b.members) {
			return len(a.members) > len(b.members)
		}
		ac, bc := a.members[a.rep], b.members[b.rep]
		if ac.curl != bc.curl {
			return ac.curl < bc.curl
		}
		return a.fp.Key() < b.fp.Key()
	})

	return out, baselineSource, baselineStatus
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
func modalStatus(rows []obsRow) int {
	counts := make(map[int]int, len(rows))
	for _, r := range rows {
		counts[r.fp.Status]++
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
func modalClusterKey(order []string, clusters map[string]*clusterCore) string {
	best := ""
	bestN := -1
	for _, k := range order {
		n := len(clusters[k].members)
		if n > bestN || (n == bestN && k < best) {
			best, bestN = k, n
		}
	}
	return best
}

// representativeIndex picks a cluster's canonical member deterministically:
// the lexicographically smallest curl command, then module name.
func representativeIndex(members []obsRow) int {
	best := 0
	for i := 1; i < len(members); i++ {
		m, b := members[i], members[best]
		if m.curl < b.curl || (m.curl == b.curl && m.module < b.module) {
			best = i
		}
	}
	return best
}
