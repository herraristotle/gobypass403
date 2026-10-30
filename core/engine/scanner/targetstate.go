/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
	"github.com/herraristotle/gobypass403/core/engine/payload"
	GB403Logger "github.com/herraristotle/gobypass403/core/utils/logger"
)

// targetState is everything one target's scan owns while it runs: the payloads
// it has already sent (a path module must not repeat a shape another module
// already tried) and the expansion bookkeeping of the batch in flight.
//
// It exists so that scanning a target needs no process-wide mutable state:
// before Phase D these lived in the Scanner and in package globals that
// RunAllBypasses reset per target, which meant two targets could not be scanned
// at the same time. One target is still scanned by one goroutine, so no lock is
// needed here; the isolation, not the concurrency inside a target, is the point.
type targetState struct {
	seen     map[string]string // rawURI -> bypassModule that sent it first
	expand   expandState
	adaptive adaptiveState
}

// newTargetState returns the state for one target run.
func newTargetState(expandEnabled, adaptiveEnabled bool) *targetState {
	return &targetState{
		seen:     make(map[string]string),
		expand:   newExpandState(expandEnabled || adaptiveEnabled, expandEnabled),
		adaptive: adaptiveState{enabled: adaptiveEnabled},
	}
}

// modulesToFilter are the path-shape modules whose payloads overlap heavily:
// once a RawURI has been sent by one of them, the others may skip it. Modules
// outside this list are sent in full and leave the seen map untouched.
var modulesToFilter = map[string]bool{
	"case_substitution":          true,
	"char_encode":                true,
	"end_paths":                  true,
	"mid_paths":                  true,
	"nginx_bypasses":             true,
	"path_prefix":                true,
	"unicode_path_normalization": true,
	"unicode_path_truncation":    true,
	"unicode_path_experimental":  true,
}

// filterUniqueBypassPayloads drops the payloads of a filtered module whose
// RawURI this target has already sent through another filtered module. The
// first module to send a shape keeps it; the others lose it.
func (ts *targetState) filterUniqueBypassPayloads(payloads []payload.BypassPayload, bypassModule string) []payload.BypassPayload {
	if !modulesToFilter[bypassModule] {
		return payloads
	}

	filtered := make([]payload.BypassPayload, 0, len(payloads))
	initialSize := len(ts.seen)

	for _, p := range payloads {
		previousModule, seen := ts.seen[p.RawURI]

		// Add payloads that are unique to this target or belong to this module
		if !seen || previousModule == bypassModule {
			filtered = append(filtered, p)

			if !seen {
				ts.seen[p.RawURI] = bypassModule
			}
		}
	}

	// Calculate new unique RawURIs added
	newSize := len(ts.seen)
	addedURIs := newSize - initialSize

	GB403Logger.Verbose().Msgf("[%s] Filtered payloads: %d -> %d | Global RawURIs: %d -> %d (%d new unique)",
		bypassModule, len(payloads), len(filtered), initialSize, newSize, addedURIs)

	return filtered
}
