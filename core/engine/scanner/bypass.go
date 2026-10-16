/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fortio.org/progressbar"
	"github.com/slicingmelon/go-rawurlparser"
	"github.com/slicingmelon/gobypass403/core/engine/analysis"
	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	"github.com/slicingmelon/gobypass403/core/utils/helpers"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// IsValidBypassModule checks if a module is valid
func IsValidBypassModule(moduleName string) bool {
	return slices.Contains(payload.BypassModulesRegistry, moduleName)
}

type BypassEngagement struct {
	bypassmodule string
	once         sync.Once
	opts         *ScannerOpts
	requestPool  *rawhttp.RequestWorkerPool
	totalJobs    int
}

func NewBypassEngagement(bypassmodule string, targetURL string, scannerOpts *ScannerOpts, totalJobs int) *BypassEngagement {
	httpClientOpts := rawhttp.DefaultHTTPClientOptions()

	// Override specific settings from user options
	httpClientOpts.BypassModule = bypassmodule
	httpClientOpts.Timeout = time.Duration(scannerOpts.Timeout) * time.Millisecond

	// Set response body preview size - buffer adjustments handled in NewHTTPClient
	httpClientOpts.ResponseBodyPreviewSize = scannerOpts.ResponseBodyPreviewSize

	// and proxy ofc
	httpClientOpts.ProxyURL = scannerOpts.Proxy

	// Pass custom HTTP headers to client options
	httpClientOpts.CustomHTTPHeaders = scannerOpts.CustomHTTPHeaders

	// Apply a delay between requests
	if scannerOpts.RequestDelay > 0 {
		httpClientOpts.RequestDelay = time.Duration(scannerOpts.RequestDelay) * time.Millisecond
	}

	httpClientOpts.MaxRetries = scannerOpts.MaxRetries
	httpClientOpts.RetryDelay = time.Duration(scannerOpts.RetryDelay) * time.Millisecond
	httpClientOpts.MaxConsecutiveFailedReqs = scannerOpts.MaxConsecutiveFailedReqs

	httpClientOpts.AutoThrottle = scannerOpts.AutoThrottle

	// Disable streaming of response body if disabled via cli options
	if scannerOpts.DisableStreamResponseBody {
		httpClientOpts.StreamResponseBody = false
	}

	// Adjust MaxConnsPerHost based on max concurrent requests
	// Add 50% more connections than workers for buffer, ensure it's at least the default
	maxConcurrentReqs := scannerOpts.ConcurrentRequests
	calculatedMaxConns := maxConcurrentReqs + (maxConcurrentReqs / 2)
	if calculatedMaxConns > httpClientOpts.MaxConnsPerHost {
		httpClientOpts.MaxConnsPerHost = calculatedMaxConns
	}

	return &BypassEngagement{
		bypassmodule: bypassmodule,
		once:         sync.Once{},
		opts:         scannerOpts,
		totalJobs:    totalJobs,
		requestPool:  rawhttp.NewRequestWorkerPool(httpClientOpts, scannerOpts.ConcurrentRequests),
	}
}

// Stop the BypassEngagement
// Also close the requestworkerpool
func (w *BypassEngagement) Stop() {
	w.once.Do(func() {
		if w.requestPool != nil {
			w.requestPool.Close()
		}
	})
}

// RunAllBypasses runs all bypass modules for a target URL
func (s *Scanner) RunAllBypasses(targetURL string) int {
	totalFindings := 0

	// One state per target run (Addendum 5 Phase D): the seen-RawURI history
	// and the expansion bookkeeping belong to this target, not to the scanner,
	// so another target can be scanned at the same time.
	ts := newTargetState(s.scannerOpts.Expand)

	// Addendum 5 Phase D: with -resume the checkpoint names the (target,
	// module) pairs that already finished, and each pair is made durable as
	// soon as its module completes, so a crash loses at most the module that
	// was running. Both calls are nil-safe, so a plain run pays nothing.
	progress := s.scannerOpts.Progress

	modules := strings.Split(s.scannerOpts.BypassModule, ",")
	for _, module := range modules {
		module = strings.TrimSpace(module)
		if module == "" {
			continue
		}

		if progress.Has(targetURL, module) {
			GB403Logger.Verbose().Msgf("Skipping %s for %s (already scanned)\n", module, targetURL)
			continue
		}

		findings := s.runBypassModule(module, targetURL, ts)
		totalFindings += findings

		progress.Mark(targetURL, module)
		if err := progress.Save(); err != nil {
			GB403Logger.Warning().Msgf("Could not update the resume checkpoint: %v\n", err)
		}
	}

	return totalFindings
}

// effectiveTargetURL rebuilds the generation URL from an imported request
// (--request-file, issue #2 phase 2): scheme from -u, host from the file's
// Host header when present (else -u's host), path+query from the file's
// request-target. Path modules then derive variants from the file's path.
func effectiveTargetURL(targetURL string, pr *rawhttp.ParsedRequest) string {
	parsed, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse target URL %s: %v", targetURL, err)
		return targetURL
	}
	host := parsed.Host
	if pr.Host != "" {
		host = pr.Host
	}
	return parsed.Scheme + "://" + host + pr.RawURI
}

// RunBypassModule runs a specific bypass module and returns the number of
// findings. The module gets a fresh target state: a one-off call is a target of
// its own, so it must not inherit or leave behind another target's history.
func (s *Scanner) RunBypassModule(bypassModule string, targetURL string) int {
	return s.runBypassModule(bypassModule, targetURL, newTargetState(s.scannerOpts.Expand))
}

// runBypassModule is RunBypassModule over a caller-owned target state, which is
// how RunAllBypasses shares one history across the modules of a single target.
func (s *Scanner) runBypassModule(bypassModule string, targetURL string, ts *targetState) int {
	if !IsValidBypassModule(bypassModule) {
		GB403Logger.Error().Msgf("Invalid bypass module: %s\n", bypassModule)
		return 0
	}

	// With --request-file the imported request is the base every module
	// mutates: its request-target and Host drive generation, its method/body
	// feed the generator (the file already carries them; -X/--data are
	// mutually exclusive with --request-file).
	method := s.scannerOpts.Method
	body := s.scannerOpts.Body
	if pr := s.scannerOpts.ParsedRequest; pr != nil {
		method = pr.Method
		body = pr.Body
		targetURL = effectiveTargetURL(targetURL, pr)
	}

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: bypassModule,
		ReconCache:   s.scannerOpts.ReconCache,
		SpoofHeader:  s.scannerOpts.SpoofHeader,
		SpoofIP:      s.scannerOpts.SpoofIP,
		SpoofPrefix:  s.scannerOpts.SpoofPrefix,
		Method:       method,
		Body:         body,
	})

	allJobs := pg.Generate()

	// Inject the imported request's headers into every job (Host and
	// Content-Length are excluded at parse time: Host comes from the
	// effective URL, Content-Length is recomputed by the builder).
	// Payload-level headers ride debug tokens and -r resends with full
	// fidelity, unlike client-level custom headers.
	if pr := s.scannerOpts.ParsedRequest; pr != nil && len(pr.Headers) > 0 {
		for i := range allJobs {
			headers := make([]payload.Headers, 0, len(allJobs[i].Headers)+len(pr.Headers))
			headers = append(headers, allJobs[i].Headers...)
			headers = append(headers, pr.Headers...)
			allJobs[i].Headers = headers
		}
	}

	// Filter unique payloads based on RawURI
	allJobs = ts.filterUniqueBypassPayloads(allJobs, bypassModule)

	totalJobs := len(allJobs)
	if totalJobs == 0 {
		GB403Logger.Warning().Msgf("No jobs generated for bypass module: %s\n", bypassModule)
		return 0
	}

	// -expand: fingerprint every response this batch sends, even the ones the
	// display filters drop, so the target's baseline is available and a
	// confirmed hit is recognisable without -mc.
	var expandIdx map[string]int
	expandBaseURL := ""
	if ts.expand.enabled {
		ts.expand.startTarget(targetURL)
		ts.expand.startBatch()
		expandIdx = make(map[string]int, totalJobs)
		for i := range allJobs {
			expandIdx[allJobs[i].PayloadToken] = i
		}
		if parsed, err := rawurlparser.RawURLParse(targetURL); err == nil {
			expandBaseURL = parsed.Scheme + "://" + parsed.Host
		}
	}

	// Print bypass module info
	GB403Logger.PrintBypassModuleInfo(bypassModule, totalJobs, targetURL)

	maxModuleNameLength := 0
	for _, module := range payload.BypassModulesRegistry {
		if len(module) > maxModuleNameLength {
			maxModuleNameLength = len(module)
		}
	}

	worker := NewBypassEngagement(bypassModule, targetURL, s.scannerOpts, totalJobs)
	defer worker.Stop()

	// Create formatted prefix with padding for progress bar
	prefix := bypassModule + strings.Repeat(" ", maxModuleNameLength-len(bypassModule)+1)
	// Create new progress bar
	bar := NewProgressBar(prefix, progressbar.RedBar, 1, &s.progressBarEnabled)

	count := s.scanBatch(worker, allJobs, expandIdx, false, bar, ts)

	// -expand: the batch that just finished may have confirmed a hit. Decide
	// here and send the derived batch; once it is sent this module's flow is
	// over (depth 1: an expansion batch is never classified).
	if ts.expand.enabled {
		if bypassModule == analysis.BaselineDumbCheck {
			ts.expand.finishBaseline()
		} else if derived := ts.expand.decide(bypassModule, targetURL, moduleComposer{
			opts: s.scannerOpts, module: bypassModule, baseURL: expandBaseURL,
			method: method, body: body,
		}); len(derived) > 0 {
			count += s.expandBatch(bypassModule, targetURL, prefix, derived, ts)
		}
	}

	return count
}

// scanBatch runs one batch of jobs through the shared pipeline: progress bar,
// the display filters, result rows and the DB writes. It returns how many
// findings were stored.
//
// jobIndex maps a job's payload token back to its slot in jobs, which is how a
// response is attributed to the request that produced it; nil disables that
// attribution (an expansion batch is never observed). markExpanded tags the
// stored curl commands as expansion output — the module field is left alone so
// the results table still groups the rows under the module.
func (s *Scanner) scanBatch(worker *BypassEngagement, jobs []payload.BypassPayload, jobIndex map[string]int, markExpanded bool, bar *ProgressBar, ts *targetState) int {
	totalJobs := len(jobs)
	maxConcurrentReqs := s.scannerOpts.ConcurrentRequests

	// -max-reqs: reserve before submitting and send only what was granted, so
	// the total on the wire is exactly the limit. A truncated batch is a hard
	// stop for new requests; results gathered so far are kept.
	if s.budget != nil {
		granted := s.budget.Reserve(totalJobs)
		if granted < totalJobs && s.reportBudgetExhausted() {
			GB403Logger.Warning().Msgf("Request budget reached (%d requests); stopping the scan here - results so far are kept\n", s.budget.Limit())
		}
		if granted == 0 {
			return 0
		}
		jobs = jobs[:granted]
		totalJobs = granted
	}

	responses := worker.requestPool.ProcessRequests(jobs)
	var dbWg sync.WaitGroup
	resultCount := atomic.Int32{}

	for response := range responses {
		if response == nil {
			continue
		}

		// Update progress bar
		completed := worker.requestPool.GetReqWPCompletedTasks()
		currentRate := worker.requestPool.GetRequestRate()
		avgRate := worker.requestPool.GetAverageRequestRate()
		msg := fmt.Sprintf(
			"Max Concurrent [%d req] | Rate [%d req/s] Avg [%d req/s] | Completed %d/%d    ",
			maxConcurrentReqs, currentRate, avgRate, completed, uint64(totalJobs),
		)
		bar.WriteAbove(msg)

		// -expand: observe before the display filters drop the response
		// (a -mc 200 run must still see the dumb_check denial).
		if ts.expand.enabled && jobIndex != nil {
			if idx, ok := jobIndex[string(response.DebugToken)]; ok {
				ts.expand.observe(response, jobs[idx])
			}
		}

		// Check status code - if no match, skip
		if !matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
			rawhttp.ReleaseResponseDetails(response)
			bar.Progress((float64(completed) / float64(totalJobs)) * 100.0)
			continue
		}

		// Check content type if required
		if len(s.scannerOpts.MatchContentTypeBytes) > 0 {
			contentTypeMatched := false
			for _, matchType := range s.scannerOpts.MatchContentTypeBytes {
				if bytes.Contains(response.ContentType, matchType) {
					contentTypeMatched = true
					break
				}
			}
			if !contentTypeMatched {
				rawhttp.ReleaseResponseDetails(response)
				bar.Progress((float64(completed) / float64(totalJobs)) * 100.0)
				continue
			}
		}

		// Check min content length
		if s.scannerOpts.MinContentLength > 0 {
			if response.ContentLength < 0 || response.ContentLength < int64(s.scannerOpts.MinContentLength) {
				rawhttp.ReleaseResponseDetails(response)
				bar.Progress((float64(completed) / float64(totalJobs)) * 100.0)
				continue
			}
		}

		// Check max content length
		if s.scannerOpts.MaxContentLength > 0 && response.ContentLength >= 0 {
			if response.ContentLength > int64(s.scannerOpts.MaxContentLength) {
				rawhttp.ReleaseResponseDetails(response)
				bar.Progress((float64(completed) / float64(totalJobs)) * 100.0)
				continue
			}
		}

		// Process valid result
		sanitizedCurlCmd := helpers.SanitizeNonPrintableBytesForCurl(response.CurlCommand)
		if markExpanded {
			sanitizedCurlCmd += expandMarker
		}

		result := &Result{
			TargetURL:           string(response.URL),
			BypassModule:        string(response.BypassModule),
			StatusCode:          response.StatusCode,
			ResponseHeaders:     helpers.SanitizeNonPrintableBytes(response.ResponseHeaders),
			CurlCMD:             sanitizedCurlCmd,
			ResponseBodyPreview: string(response.ResponsePreview),
			ContentType:         string(response.ContentType),
			ContentLength:       response.ContentLength,
			ResponseBodyBytes:   response.ResponseBytes,
			Title:               string(response.Title),
			ServerInfo:          string(response.ServerInfo),
			RedirectURL:         helpers.SanitizeNonPrintableBytes(response.RedirectURL),
			ResponseTime:        response.ResponseTime,
			DebugToken:          string(response.DebugToken),
		}

		rawhttp.ReleaseResponseDetails(response)
		progressPercent := (float64(completed) / float64(totalJobs)) * 100.0
		progressPercent = min(progressPercent, 100.0)
		bar.Progress(progressPercent)

		dbWg.Add(1)
		go func(res *Result) {
			defer dbWg.Done()
			if err := AppendResultsToDB([]*Result{res}); err != nil {
				GB403Logger.Error().Msgf("Failed to write result to DB: %v\n\n", err)
			} else {
				resultCount.Add(1)
			}
		}(result)
	}

	bar.End()
	fmt.Println()

	dbWg.Wait()

	return int(resultCount.Load())
}

// expandBatch sends the derived requests for a confirmed hit through the same
// pipeline as any other batch: the same worker settings, the same filters, the
// same DB write path. Depth 1: an expansion batch is never classified again.
func (s *Scanner) expandBatch(module, targetURL, prefix string, derived []payload.BypassPayload, ts *targetState) int {
	jobs := expansionJobs(derived)

	GB403Logger.Info().Msgf(
		"Expansion: sending %d derived requests around a confirmed hit in %s (%d budget left for this target)",
		len(jobs), module, ts.expand.budget)

	expWorker := NewBypassEngagement(module, targetURL, s.scannerOpts, len(jobs))
	defer expWorker.Stop()

	expBar := NewProgressBar(prefix+"+expand", progressbar.RedBar, 1, &s.progressBarEnabled)
	// No job index: expansion responses are never observed, so they can never
	// confirm a hit of their own.
	return s.scanBatch(expWorker, jobs, nil, true, expBar, ts)
}

// ResendRequestFromToken
// Resend a request from a payload token (debug token)
func (s *Scanner) ResendRequestFromToken(debugToken string, resendCount int) ([]*Result, error) {

	tokenData, err := payload.DecodePayloadToken(debugToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode debug token: %w", err)
	}

	bypassPayload := payload.BypassPayload{
		OriginalURL:  tokenData.OriginalURL,
		Method:       tokenData.Method,
		Scheme:       tokenData.Scheme,
		Host:         tokenData.Host,
		RawURI:       tokenData.RawURI,
		Headers:      tokenData.Headers,
		Body:         tokenData.Body,
		BypassModule: tokenData.BypassModule,
	}

	targetURL := payload.BypassPayloadToBaseURL(bypassPayload)
	totalJobs := resendCount // Total jobs for the progress bar

	// Update concurrent requets to 1
	s.scannerOpts.ConcurrentRequests = 1

	// Create a new worker for the bypass module
	worker := NewBypassEngagement(bypassPayload.BypassModule, targetURL, s.scannerOpts, totalJobs)
	defer worker.Stop()

	jobs := make([]payload.BypassPayload, 0, totalJobs)
	for i := 0; i < totalJobs; i++ {
		jobCopy := bypassPayload // Create a copy to avoid sharing the same job reference
		jobCopy.PayloadToken = payload.GeneratePayloadToken(bypassPayload)
		jobs = append(jobs, jobCopy)
	}

	// Create formatted prefix for progress bar
	prefix := fmt.Sprintf("[Resend] %s", bypassPayload.BypassModule)
	// Create new progress bar
	bar := NewProgressBar(prefix, progressbar.BlueBar, 1, &s.progressBarEnabled)
	bar.Progress(0)

	responses := worker.requestPool.ProcessRequests(jobs)
	var results []*Result

	for response := range responses {
		completed := worker.requestPool.GetReqWPCompletedTasks()

		if response == nil {
			progressPercent := (float64(completed) / float64(totalJobs)) * 100.0
			progressPercent = min(progressPercent, 100.0)
			bar.Progress(progressPercent)
			continue
		}

		// Process Valid Response
		if matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
			sanitizedCurlCmd := helpers.SanitizeNonPrintableBytesForCurl(response.CurlCommand)

			result := &Result{
				TargetURL:           targetURL,
				BypassModule:        string(response.BypassModule),
				StatusCode:          response.StatusCode,
				ResponseHeaders:     helpers.SanitizeNonPrintableBytes(response.ResponseHeaders),
				CurlCMD:             sanitizedCurlCmd,
				ResponseBodyPreview: string(response.ResponsePreview),
				ContentType:         string(response.ContentType),
				ContentLength:       response.ContentLength,
				ResponseBodyBytes:   response.ResponseBytes,
				Title:               string(response.Title),
				ServerInfo:          string(response.ServerInfo),
				RedirectURL:         helpers.SanitizeNonPrintableBytes(response.RedirectURL),
				ResponseTime:        response.ResponseTime,
				DebugToken:          string(response.DebugToken),
			}
			results = append(results, result)
		}

		rawhttp.ReleaseResponseDetails(response)

		// Update progress bar
		currentRate := worker.requestPool.GetRequestRate()
		avgRate := worker.requestPool.GetAverageRequestRate()
		maxConcurrentReqs := s.scannerOpts.ConcurrentRequests

		msg := fmt.Sprintf(
			"Max Concurrent [%d req] | Rate [%d req/s] Avg [%d req/s] | Completed %d/%d    ",
			maxConcurrentReqs, currentRate, avgRate, completed, uint64(totalJobs),
		)
		bar.WriteAbove(msg)

		progressPercent := (float64(completed) / float64(totalJobs)) * 100.0
		progressPercent = min(progressPercent, 100.0)
		bar.Progress(progressPercent)
	}

	finalCompleted := worker.requestPool.GetReqWPCompletedTasks()

	// Calculate the final, accurate progress percentage
	finalProgressPercent := (float64(finalCompleted) / float64(totalJobs)) * 100.0
	finalProgressPercent = min(finalProgressPercent, 100.0)
	bar.Progress(finalProgressPercent)
	bar.End()

	fmt.Println()

	return results, nil
}

// match HTTP status code in list
// if codes is nil, match all status codes
func matchStatusCodes(code int, codes []int) bool {
	if codes == nil { // Still need nil check
		return true
	}
	return slices.Contains(codes, code)
}
