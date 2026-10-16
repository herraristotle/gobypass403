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

// CalibrationModule is the synthetic module whose rows are the negative
// control of a `-calibrate` run (Addendum 6): responses to a path that cannot
// exist. A cluster matching one is the server's default response, not a hit.
const CalibrationModule = "calibration"

// calibrationTolerance is how far a response length may differ from a control
// and still be considered the same default page (unKover `is_wildcard` uses
// the same 50-byte allowance). An identical body digest matches regardless.
const calibrationTolerance = 50

// Class ranks a cluster by how much it departs from the baseline; lower is
// more interesting, and the value doubles as the report ordering.
type Class int

const (
	ClassBypass     Class = iota // status class improves on the baseline
	ClassVariant                 // same status class, different body
	ClassDup                     // identical to the baseline
	ClassNoise                   // empty, non-improving artifact
	ClassCalibrated              // matches the negative control (-calibrate): the
	// server's wildcard/soft-404 default, never a finding
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
	case ClassCalibrated:
		return "CALIBRATED"
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
	// RepresentativeRef is the caller's own index (Observation.Ref) of the
	// representative member, so the caller can recover the request it sent
	// (needed to derive expansion payloads). Meaningful for observation-built
	// clusters; the Row path carries the Representative itself.
	RepresentativeRef int `json:"representative_ref,omitempty"`
}

// TargetReport is the analysis of one target_url.
type TargetReport struct {
	TargetURL      string    `json:"target_url"`
	Rows           int       `json:"rows"`
	BaselineSource string    `json:"baseline_source"`
	BaselineStatus int       `json:"baseline_status"`
	Clusters       []Cluster `json:"clusters"`
	// CalibrationControls is the number of negative-control responses the run
	// supplied (Addendum 6). Zero means calibration did not run.
	CalibrationControls int `json:"calibration_controls,omitempty"`
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

	cores, source, baselineStatus, controls := classifyRows(observed)

	tr := TargetReport{
		TargetURL:           targetURL,
		Rows:                len(rows),
		BaselineSource:      source,
		BaselineStatus:      baselineStatus,
		CalibrationControls: controls,
		Clusters:            make([]Cluster, 0, len(cores)),
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

	cores, source, baselineStatus, controls := classifyRows(observed)

	tr := TargetReport{
		TargetURL:           targetURL,
		Rows:                len(obs),
		BaselineSource:      source,
		BaselineStatus:      baselineStatus,
		CalibrationControls: controls,
		Clusters:            make([]Cluster, 0, len(cores)),
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
		cl.RepresentativeRef = rep.ref
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
func classifyRows(rows []obsRow) (clusters []clusterCore, baselineSource string, baselineStatus int, controls int) {
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
	// Negative controls (Addendum 6): the fingerprints of a `-calibrate` run's
	// impossible-path probes.
	var controlSet []Fingerprint
	for _, r := range rows {
		switch r.module {
		case BaselineDumbCheck:
			baseline = append(baseline, r)
		case CalibrationModule:
			controlSet = append(controlSet, r.fp)
		}
	}
	controls = len(controlSet)
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
	// 200 on an unprotected target); a cluster matching the negative
	// control is CALIBRATED (the server's default page) and is never a
	// BYPASS, however much its status class improves; an empty-body 2xx is
	// still a BYPASS, only empty non-improving responses are NOISE.
	emptyDigest := digest("")
	out := make([]clusterCore, 0, len(order))
	for _, k := range order {
		cl := byKey[k]
		cl.rep = representativeIndex(cl.members)
		switch {
		case baselineSet[k]:
			cl.class = ClassDup
		case matchesControl(cl.fp, controlSet):
			cl.class = ClassCalibrated
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

	return out, baselineSource, baselineStatus, controls
}

// matchesControl reports whether a fingerprint is one of the negative
// controls: the target answered an impossible path with it, so it is the
// server's default (wildcard / soft-404) response and not a finding.
//
// A control matches on the same status and media type, and then either an
// identical body digest (an exact wildcard — stronger than unKover, which
// compares size only) or a length within calibrationTolerance bytes (an
// echoing soft-404 stamps the requested path, so the digest differs but the
// page is the same).
func matchesControl(fp Fingerprint, controls []Fingerprint) bool {
	for _, c := range controls {
		if fp.Status != c.Status || fp.MediaType != c.MediaType {
			continue
		}
		if fp.Digest == c.Digest {
			return true
		}
		if d := fp.Length - c.Length; d <= calibrationTolerance && d >= -calibrationTolerance {
			return true
		}
	}
	return false
}

// statusImproves reports whether status crosses from a denial class
// (4xx/5xx) into a success class (2xx) relative to the baseline. Going
// 403 -> 404 is not an improvement (both are denials).
//
// Redirects (3xx) are deliberately NOT an improvement. A redirect is not
// proof of access: the canonical false positive is a scheme redirect
// (http://<origin>/.env -> 301 https://host/.env -> 403), which improves
// 403 to 301 while still serving nothing (observed live on billpoint.co).
// Such a response stays visible as a VARIANT with its curl PoC, so the
// operator can follow it by hand, but it is never auto-promoted to BYPASS.
// This matches the spec's written contract -- "status class improved vs
// baseline (e.g. baseline 403 -> 2xx)" -- and drops unKover's 3xx-as-success
// rule, which unKover only got away with because it also runs a wildcard
// negative control (deferred here).
func statusImproves(status, baselineStatus int) bool {
	c := status / 100
	return c == 2 && c < baselineStatus/100
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
