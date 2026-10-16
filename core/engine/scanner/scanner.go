/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/slicingmelon/go-rawurlparser"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	"github.com/slicingmelon/gobypass403/core/engine/recon"
	GB403ErrorHandler "github.com/slicingmelon/gobypass403/core/utils/error"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

type ScannerOpts struct {
	Timeout                   int
	ConcurrentRequests        int
	MatchStatusCodes          []int
	MatchContentTypeBytes     [][]byte
	MinContentLength          int
	MaxContentLength          int
	Debug                     bool
	Verbose                   bool
	BypassModule              string
	OutDir                    string
	ResultsDBFile             string
	RequestDelay              int
	MaxRetries                int
	RetryDelay                int
	MaxConsecutiveFailedReqs  int
	AutoThrottle              bool
	Proxy                     string
	EnableHTTP2               bool
	SpoofHeader               string
	SpoofIP                   string
	SpoofPrefix               string
	CustomHTTPHeaders         []string // Custom HTTP headers in "Name: Value" format
	FollowRedirects           bool
	ResponseBodyPreviewSize   int
	DisableStreamResponseBody bool
	DisableProgressBar        bool
	ResendRequest             string
	Method                    string                 // HTTP method for base requests (default GET)
	Body                      string                 // Request body for base requests (default none)
	ParsedRequest             *rawhttp.ParsedRequest // Base request imported via --request-file (issue #2, phase 2)
	ReconCache                *recon.ReconCache
	Expand                    bool // -expand: derive a bounded depth-1 batch around a confirmed hit (Addendum 5 Phase B)
	MaxReqs                   int  // -max-reqs: hard stop after this many requests, 0 = unlimited (Addendum 5 Phase D)
	// Progress is the resume checkpoint (Addendum 5 Phase D). Non-nil only for
	// -resume runs: completed (target, module) pairs are skipped and every newly
	// finished one is recorded. nil means checkpointing is off.
	Progress *Progress
	// ConcurrentTargets is -tw: how many targets may be scanned at once, at
	// most one per host. 1 (or 0) keeps the sequential loop.
	ConcurrentTargets int
}

// Scanner represents the main scanner structure, perhaps the highest level in the hierarchy of the tool
type Scanner struct {
	scannerOpts        *ScannerOpts
	urls               []string
	progressBarEnabled atomic.Bool
	budget             *RequestBudget
	budgetAnnounced    atomic.Bool
}

// NewScanner creates a new Scanner instance
func NewScanner(opts *ScannerOpts, urls []string) *Scanner {
	s := &Scanner{
		scannerOpts: opts,
		urls:        urls,
	}
	// Addendum 5 Phase D: one progress bar cannot describe several targets at
	// once, so -tw > 1 keeps it off (the CLI prints the one-line warning).
	s.progressBarEnabled.Store(!opts.DisableProgressBar && opts.ConcurrentTargets <= 1)
	if opts.MaxReqs > 0 {
		s.budget = NewRequestBudget(opts.MaxReqs)
	}

	return s
}

// Run runs the scanner
func (s *Scanner) Run() error {
	defer s.Close()

	GB403Logger.Info().Msgf("Initializing scanner with %d URLs", len(s.urls))

	if s.scannerOpts.ConcurrentTargets > 1 {
		s.runTargetPool(s.reportTarget)
	} else {
		for _, url := range s.urls {
			s.scanTarget(url, s.reportTarget)
		}
	}

	// Print completion summary
	GB403Logger.Success().Msgf("Findings saved to %s\n", s.scannerOpts.ResultsDBFile)
	GB403ErrorHandler.GetErrorHandler().PrintErrorStats()

	return nil
}

// scanTarget scans one target and hands its finding count to report. The report
// call is the per-target output (table and summary); the pool serialises it, so
// two targets never interleave mid-table.
func (s *Scanner) scanTarget(url string, report func(string, int)) {
	parsedURL, err := rawurlparser.RawURLParse(url)
	if err != nil {
		GB403ErrorHandler.GetErrorHandler().HandleErrorAndContinue(err, GB403ErrorHandler.ErrorContext{
			Host:         parsedURL.BaseURL(),
			ErrorSource:  "Scanner.Run.URLParse",
			BypassModule: s.scannerOpts.BypassModule,
		})
		return
	}

	totalFindings := s.RunAllBypasses(url)
	report(url, totalFindings)
}

// reportTarget prints the results table and the summary line for one finished
// target. With -tw > 1 the pool calls this in completion order.
func (s *Scanner) reportTarget(url string, totalFindings int) {
	// Print results table immediately after scanning this URL
	if err := PrintResultsTableFromDB(url, s.scannerOpts.BypassModule); err != nil {
		GB403Logger.Error().Msgf("Failed to display results: %v\n", err)
	}
	fmt.Println()

	// Print summary for this URL
	GB403Logger.Success().Msgf("Found %d results for %s", totalFindings, url)
	fmt.Println()
}

// runTargetPool scans the targets concurrently (Addendum 5 Phase D, -tw). Work
// is distributed as one bucket of targets per host, so a worker owns a host
// until its targets are done and two targets of the same host are never in
// flight together; different hosts run side by side. report is called once per
// finished target, under a lock, in completion order.
func (s *Scanner) runTargetPool(report func(string, int)) {
	buckets := groupTargetsByHost(s.urls)
	if len(buckets) == 0 {
		return
	}

	workers := min(s.scannerOpts.ConcurrentTargets, len(buckets))

	jobs := make(chan []string)
	var wg sync.WaitGroup
	var reportMu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for bucket := range jobs {
				for _, url := range bucket {
					s.scanTarget(url, func(url string, findings int) {
						reportMu.Lock()
						defer reportMu.Unlock()
						report(url, findings)
					})
				}
			}
		}()
	}

	for _, bucket := range buckets {
		jobs <- bucket
	}
	close(jobs)
	wg.Wait()
}

// groupTargetsByHost buckets targets by the host:port serving them, keeping the
// input order both between buckets and inside one. The scheme is dropped on
// purpose: http and https to the same host:port are the same service, and
// politeness is about the service. A target that does not parse gets a bucket
// of its own, keyed by its literal text.
func groupTargetsByHost(urls []string) [][]string {
	buckets := make([][]string, 0, len(urls))
	index := make(map[string]int, len(urls))

	for _, url := range urls {
		key := url
		if parsed, err := rawurlparser.RawURLParse(url); err == nil {
			key = parsed.GetHostname() + ":" + parsed.GetPort()
		}

		i, ok := index[key]
		if !ok {
			i = len(buckets)
			index[key] = i
			buckets = append(buckets, nil)
		}
		buckets[i] = append(buckets[i], url)
	}

	return buckets
}

// Close the scanner instance
func (s *Scanner) Close() {
	// Reset error handler instance (this will also close ristretto caches)
	GB403ErrorHandler.ResetInstance()

	// Cleanup sqlite db (findings db)
	CleanupFindingsDB()
}
