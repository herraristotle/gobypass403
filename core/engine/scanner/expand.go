/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Expansion (SPEC-unkover-gaps.md Addendum 5, Phase B) — `-expand`.

While the flag is on, every response is fingerprinted *before* the display
filters, so a run with `-mc 200` still has the target's dumb_check denial as
its baseline. When a module's batch finishes, that batch is classified with the
Phase A classifier and, if it confirmed a BYPASS, a bounded depth-1 batch is
derived around the shape that worked (core/engine/expand).

Off by default: with the flag off nothing here runs and the scan output is
byte-identical to before.
*/
package scanner

import (
	"github.com/slicingmelon/gobypass403/core/engine/analysis"
	"github.com/slicingmelon/gobypass403/core/engine/expand"
	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	"github.com/slicingmelon/gobypass403/core/utils/helpers"
)

// expandState collects compact observations for the target being scanned.
// Single-goroutine use: the response loop and the post-batch decision both run
// on the caller's goroutine, one target at a time.
//
// No response bodies are retained: an observation is a fingerprint (status,
// media type, body digest, length) plus the curl command, which is what makes
// classifying a 6.5k-payload module affordable mid-scan.
type expandState struct {
	// enabled runs the expansion decision; collect only fingerprints responses
	// (-expand does both, -adaptive only collects, for its triage evidence).
	enabled bool
	collect bool

	target string
	budget int // requests left for this target, across all modules

	// baseline is the target's dumb_check batch (dumb_check runs first:
	// registry order, and validateModule prepends it).
	baselineObs  []analysis.Observation
	baselineReqs []payload.BypassPayload

	// batch is the module batch in flight.
	batchObs  []analysis.Observation
	batchReqs []payload.BypassPayload
}

func newExpandState(collect, enabled bool) expandState {
	return expandState{enabled: enabled, collect: collect, budget: expand.PerTarget}
}

// startTarget resets the baseline and the expansion budget when the scan moves
// to another URL.
func (e *expandState) startTarget(target string) {
	if e.target == target {
		return
	}
	e.target = target
	e.budget = expand.PerTarget
	e.baselineObs = nil
	e.baselineReqs = nil
	e.startBatch()
}

// startBatch drops the previous module's observations so a decision can only
// ever be made about the batch in flight.
func (e *expandState) startBatch() {
	e.batchObs = e.batchObs[:0]
	e.batchReqs = e.batchReqs[:0]
}

// observe records one response, before the display filters can drop it. req is
// the request that produced it (its index in the batch is the observation ref,
// which is how a decision recovers the shape to expand).
func (e *expandState) observe(r *rawhttp.RawHTTPResponseDetails, req payload.BypassPayload) {
	e.batchObs = append(e.batchObs, analysis.Observation{
		Fingerprint: analysis.FingerprintFrom(
			r.StatusCode, string(r.ContentType), r.ResponsePreview,
			r.ContentLength, r.ResponseBytes,
		),
		Module:  req.BypassModule,
		CurlCMD: helpers.SanitizeNonPrintableBytesForCurl(r.CurlCommand),
		Ref:     len(e.batchReqs),
	})
	e.batchReqs = append(e.batchReqs, req)
}

// finishBaseline promotes the batch that just ran to the target's baseline.
// Called after the dumb_check module, which always runs first.
func (e *expandState) finishBaseline() {
	e.baselineObs = append(e.baselineObs[:0], e.batchObs...)
	e.baselineReqs = append(e.baselineReqs[:0], e.batchReqs...)
}

// finishControls folds the calibration module's batch (Addendum 6) into the
// baseline, so a wildcard control shapes live classification exactly as the
// baseline does: a cluster matching it can never be a BYPASS mid-scan, which is
// what keeps -expand from acting on a soft-404. Called after the calibration
// module, which runs right after dumb_check.
func (e *expandState) finishControls() {
	e.baselineObs = append(e.baselineObs, e.batchObs...)
	e.baselineReqs = append(e.baselineReqs, e.batchReqs...)
}

// decide classifies the batch in flight (against the target's baseline) and
// returns the requests to send next. Empty means "send nothing": unsupported
// module, no confirmed hit in this batch, or no budget left.
//
// The batch is classified together with the baseline so the baseline informs
// DUP/BYPASS, but a hit is only accepted when it has a member from this batch
// (baseline-only clusters are skipped), which is what keeps depth at 1.
func (e *expandState) decide(module, targetURL string, composer expand.Composer) []payload.BypassPayload {
	if !e.enabled || len(e.batchObs) == 0 || e.budget <= 0 {
		return nil
	}

	obs := make([]analysis.Observation, 0, len(e.baselineObs)+len(e.batchObs))
	obs = append(obs, e.baselineObs...)
	obs = append(obs, e.batchObs...)

	reqs := make([]payload.BypassPayload, 0, len(e.baselineReqs)+len(e.batchReqs))
	reqs = append(reqs, e.baselineReqs...)
	reqs = append(reqs, e.batchReqs...)

	report := analysis.ClassifyObservations(targetURL, obs)
	hit, ok := expand.Decide(module, report, reqs, len(e.baselineReqs))
	if !ok {
		return nil
	}

	sent := make([]string, 0, len(e.batchReqs))
	shapes := make([]string, 0, len(e.batchReqs))
	for _, p := range e.batchReqs {
		sent = append(sent, p.RawURI)
		shapes = append(shapes, expand.ShapeKey(p))
	}

	derived := expand.Mutate(expand.Request{
		Module:     module,
		Payload:    hit,
		Sent:       sent,
		SentShapes: shapes,
	}, composer, e.budget)
	e.budget -= len(derived)
	return derived
}

// expandMarker tags a stored curl command as expansion output. It is a shell
// comment, so a copy-pasted PoC still runs; the module field is left alone so
// the results table keeps grouping the row under its module.
const expandMarker = " # expanded"

// expansionJobs turns derived payloads into real jobs: same shape as a
// module's own jobs, with the debug token generated from the final request, so
// the DB row, the display and `-r` resends cannot tell an expansion request
// from any other one apart from the marker.
func expansionJobs(derived []payload.BypassPayload) []payload.BypassPayload {
	jobs := make([]payload.BypassPayload, 0, len(derived))
	for _, p := range derived {
		p.PayloadToken = payload.GeneratePayloadToken(p)
		jobs = append(jobs, p)
	}
	return jobs
}

// moduleComposer re-runs a module's *own* generator against an arbitrary
// RawURI: expansion is then "the module's transformation, applied once more to
// the shape that worked", instead of a reimplementation that could drift from
// the module it imitates.
type moduleComposer struct {
	opts    *ScannerOpts
	module  string
	baseURL string // scheme://host of the target being scanned
	method  string
	body    string
}

func (c moduleComposer) Compose(rawURI string) []payload.BypassPayload {
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    c.baseURL + rawURI,
		BypassModule: c.module,
		ReconCache:   c.opts.ReconCache,
		SpoofHeader:  c.opts.SpoofHeader,
		SpoofIP:      c.opts.SpoofIP,
		SpoofPrefix:  c.opts.SpoofPrefix,
		Method:       c.method,
		Body:         c.body,
	})
	return pg.Generate()
}
