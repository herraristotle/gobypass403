/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type multiFlag struct {
	name   string
	usage  string
	value  any
	defVal any
}

var flags []multiFlag

type onOffFlag struct {
	val *bool
}

func (f *onOffFlag) String() string {
	if f.val == nil {
		return "off"
	}
	if *f.val {
		return "on"
	}
	return "off"
}

func (f *onOffFlag) Set(value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "on", "1", "true":
		*f.val = true
	case "off", "0", "false":
		*f.val = false
	default:
		return fmt.Errorf("invalid value %q: use on/off, 1/0, or true/false", value)
	}
	return nil
}

// stringSliceFlag implements flag.Value for collecting multiple string values
type stringSliceFlag struct {
	values *[]string
}

func (f *stringSliceFlag) String() string {
	if f.values == nil || len(*f.values) == 0 {
		return ""
	}
	return strings.Join(*f.values, ", ")
}

func (f *stringSliceFlag) Set(value string) error {
	*f.values = append(*f.values, value)
	return nil
}

// flagDefinitions is the flag table for one parse. Kept separate from
// parseFlags so flag registration (and the -expand wiring) stays testable
// without parsing os.Args.
func flagDefinitions(opts *CliOptions) []multiFlag {
	return []multiFlag{
		{name: "u,url", usage: "Target URL (example: https://cms.facebook.com/login)", value: &opts.URL},
		{name: "l,urls-file", usage: "File containing list of target URLs (one per line)", value: &opts.URLsFile},
		{name: "shf,substitute-hosts-file", usage: "File containing a list of hosts to substitute target URL's hostname (mostly used in CDN bypasses by providing a list of CDNs)", value: &opts.SubstituteHostsFile},
		{name: "m,module", usage: "Bypass module (all,path_prefix,mid_paths,end_paths,http_methods,case_substitution,char_encode,nginx_bypasses,haproxy_bypasses,unicode_path_normalization,unicode_path_truncation,headers_scheme,headers_ip,headers_port,headers_url,headers_host,headers_hop_by_hop,api_versions,http10,headers_method,user_agent,param_manipulation). Supports glob patterns with * (e.g., headers*,*bypass*)", value: &opts.Module, defVal: "all"},
		{name: "em,exclude-module", usage: "Exclude specific bypass modules. Supports glob patterns with * (e.g., -em unicode*,*experimental). Takes precedence over -m", value: &opts.ExcludeModule},
		{name: "o,outdir", usage: "Output directory", value: &opts.OutDir},
		{name: "cr,concurrent-requests", usage: "Number of max concurrent requests", value: &opts.ConcurrentRequests, defVal: 15},
		{name: "T,timeout", usage: "Total timeout (in milliseconds)", value: &opts.Timeout, defVal: 20000},
		{name: "delay", usage: "Delay between requests (in milliseconds) (0 means no delay)", value: &opts.Delay, defVal: 0},
		{name: "max-retries", usage: "Maximum number of retries for failed requests (0 means no retries)", value: &opts.MaxRetries, defVal: 2},
		{name: "retry-delay", usage: "Delay between retries (in milliseconds)", value: &opts.RetryDelay, defVal: 500},
		{name: "max-cfr,max-consecutive-fails", usage: "Maximum number of consecutive failed requests before cancelling the current bypass module", value: &opts.MaxConsecutiveFailedReqs, defVal: 15},
		{name: "at,auto-throttle", usage: "Enable automatic request throttling (on/off, 1/0)",
			value: &onOffFlag{val: &opts.AutoThrottle}, defVal: "on"},
		{name: "v,verbose", usage: "Verbose output", value: &opts.Verbose, defVal: false},
		{name: "d,debug", usage: "Debug mode with request canaries", value: &opts.Debug, defVal: false},
		{name: "mc,match-status-code", usage: "Filter results by HTTP status codes (example: -mc 200, 301, 5xx, all). Default: All status codes", value: &opts.MatchStatusCodesStr},
		{name: "mct,match-content-type", usage: "Filter results by content type(s) substring (example: -mct application/json,text/html)", value: &opts.MatchContentType},
		{name: "min-cl,min-content-length", usage: "Filter results by minimum Content-Length (example: -min-cl 100)", value: &opts.MinContentLengthStr},
		{name: "max-cl,max-content-length", usage: "Filter results by maximum Content-Length (example: -max-cl 5000)", value: &opts.MaxContentLengthStr},
		{name: "H,header", usage: "Custom HTTP header (example: -H \"X-My-Header: value\"), can be used multiple times", value: &stringSliceFlag{values: &opts.CustomHTTPHeaders}},
		{name: "X,request", usage: "HTTP method used for base requests, applied by all bypass modules (example: -X POST)", value: &opts.Method, defVal: "GET"},
		{name: "data", usage: "Request body sent verbatim with base requests; a leading @ reads the body from a file (example: --data 'user=admin', --data @body.json). No Content-Type is added automatically, use -H", value: &opts.Data},
		{name: "request-file", usage: "File containing one raw HTTP request (request line, headers, body) used as the base request for all modules; cannot be combined with -X/--request or --data. -u still supplies scheme/port (example: --request-file captured.req)", value: &opts.RequestFile},
		{name: "sc,strict-scheme", usage: "Only test URLs with the original scheme from input (prevents auto-expansion to http/https)", value: &opts.StrictScheme, defVal: false},
		{name: "http2", usage: "Enable HTTP2 client", value: &opts.EnableHTTP2, defVal: false},
		{name: "x,proxy", usage: "Proxy URL (format: http://proxy:port) (Example: -x http://127.0.0.1:8080)", value: &opts.Proxy},
		{name: "spoof-header", usage: "Add more headers used to spoof IPs (example: X-SecretIP-Header,X-GO-IP)", value: &opts.SpoofHeader},
		{name: "spoof-ip", usage: "Add more spoof IPs (example: 10.10.20.20,172.16.30.10)", value: &opts.SpoofIP},
		{name: "spoof-prefix", usage: "Add more path prefixes tested by the api_versions module (example: /internal,/v2beta)", value: &opts.SpoofPrefix},
		{name: "fr,follow-redirects", usage: "Follow HTTP redirects", value: &opts.FollowRedirects},
		{name: "rbps,response-body-preview-size", usage: "Maximum number of bytes to retrieve from response body", value: &opts.ResponseBodyPreviewSize, defVal: 3096},
		{name: "drbs,disable-response-body-streaming", usage: "Disables streaming of response body (default: False)", value: &opts.DisableStreamResponseBody, defVal: false},
		{name: "dpb,disable-progress-bar", usage: "Disable progress bar", value: &opts.DisableProgressBar, defVal: false},
		{name: "r,resend,resend-request", usage: "Resend the exact request using the debug token (example: -r xyzdebugtoken)", value: &opts.ResendRequest},
		{name: "rn,resend-num,resend-request-num", usage: "Number of times to resend the debugged request", value: &opts.ResendNum, defVal: 1},
		{name: "analyze", usage: "Analyze an existing results database offline (read-only) and print the differential report, then exit (example: -analyze /tmp/scan/results.db)", value: &opts.AnalyzeDB},
		{name: "analyze-json", usage: "With -analyze: also write the report as JSON to this file (example: -analyze-json /tmp/report.json)", value: &opts.AnalyzeJSON},
		{name: "profile", usage: "Enable pprof profiler", value: &opts.Profile, defVal: false},
		{name: "scan-profile", usage: "Scan scope preset: full (all bypass modules) or triage (high-signal subset for first-pass triage; explicit -m wins, -em subtracts)", value: &opts.ScanProfile, defVal: "full"},
		{name: "adaptive", usage: "Order the modules by the baseline fingerprint and run the deep families once a confirmed 403 produced a novel cluster (off by default; the fingerprint costs no extra request)", value: &opts.Adaptive, defVal: false},
		{name: "calibrate", usage: "Send a negative-control probe to a path that cannot exist and suppress any result matching it (kills wildcard/soft-404 false positives; off by default, costs 3 requests per target)", value: &opts.Calibrate, defVal: false},
		{name: "warn-wildcard", usage: "With -calibrate off: report a BYPASS cluster whose many distinct requests share one response as wildcard-shaped and point at -calibrate (a hint only, it never suppresses or reclassifies anything; works with -analyze; off by default)", value: &opts.WarnWildcard, defVal: false},
		{name: "expand", usage: "Expand around a confirmed hit: derive a bounded depth-1 batch from the request that worked (off by default; 256 extra requests per hit, 1024 per target)", value: &opts.Expand, defVal: false},
		{name: "max-reqs", usage: "Hard stop after this many requests across the whole run (0 = unlimited). Counts every request sent, including expansion batches", value: &opts.MaxReqs, defVal: 0},
		{name: "resume", usage: "Continue an interrupted run: skip the (target, module) pairs scan.progress.json in the output dir already marks complete", value: &opts.Resume, defVal: false},
		{name: "tw", usage: "Scan this many targets at once, at most one per host (1 = sequential, the default). Disables the progress bar and prints each target's table as it finishes", value: &opts.TargetWorkers, defVal: 1},
		{name: "update-payloads", usage: "Update payload files to latest version", value: &opts.UpdatePayloads, defVal: false},
	}
}

func parseFlags() (*CliOptions, error) {
	opts := &CliOptions{}

	flags := flagDefinitions(opts)

	// Set up custom usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "GoByPASS403 v%s\n\n", GOBYPASS403_VERSION)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		for _, f := range flags {
			names := strings.Split(f.name, ",")
			if len(names) > 1 {
				fmt.Fprintf(os.Stderr, "  -%s, -%s\n", names[0], names[1])
			} else {
				fmt.Fprintf(os.Stderr, "  -%s\n", names[0])
			}

			if f.defVal != nil {
				fmt.Fprintf(os.Stderr, "        %s (Default: %v)\n", f.usage, f.defVal)
			} else {
				fmt.Fprintf(os.Stderr, "        %s\n", f.usage)
			}
		}
	}

	// Register all flags
	for _, f := range flags {
		for _, name := range strings.Split(f.name, ",") {
			name = strings.TrimSpace(name)
			switch v := f.value.(type) {
			case *string: // Handles opts.URL, opts.URLsFile, etc. AND the new Str flags
				if def, ok := f.defVal.(string); ok {
					flag.StringVar(v, name, def, f.usage)
				} else {
					flag.StringVar(v, name, "", f.usage) // Default empty string ""
				}
			case *int:
				if def, ok := f.defVal.(int); ok {
					flag.IntVar(v, name, def, f.usage)
				} else {
					flag.IntVar(v, name, 0, f.usage)
				}
			case *bool:
				if def, ok := f.defVal.(bool); ok {
					flag.BoolVar(v, name, def, f.usage)
				} else {
					flag.BoolVar(v, name, false, f.usage)
				}
			case *onOffFlag: // Handle the custom on/off flag type
				flag.Var(v, name, f.usage) // Register using flag.Var
			case *stringSliceFlag: // Handle the string slice flag type
				flag.Var(v, name, f.usage) // Register using flag.Var
			}
		}
	}

	// Parse flags
	flag.Parse()

	// Record explicitly-set flags relevant to --request-file exclusivity
	// (flag defaults would otherwise be indistinguishable from user input)
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "X", "request":
			opts.methodSet = true
		case "data":
			opts.dataSet = true
		case "m", "module":
			opts.moduleSet = true
		}
	})

	// Set defaults and validate
	opts.setDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}

	return opts, nil
}
