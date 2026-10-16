/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Report rendering for the offline differential analyzer
(SPEC-unkover-gaps.md Addendum 5, Phase A). Pure string / JSON builders:
the CLI layer prints or writes whatever this returns.
*/
package analysis

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// membersShown is how many member curl commands a cluster lists before
// collapsing the rest into "+N more identical (first: ...)".
const membersShown = 5

// Text renders the report as deterministic, human-readable text.
func (r Report) Text() string {
	var b strings.Builder

	rows := 0
	for _, t := range r.Targets {
		rows += t.Rows
	}
	fmt.Fprintf(&b, "Findings analysis: %d target(s), %d row(s)\n", len(r.Targets), rows)

	for _, t := range r.Targets {
		fmt.Fprintf(&b, "\n=== %s ===\n", t.TargetURL)
		fmt.Fprintf(&b, "baseline: %s (status %d)\n", t.BaselineSource, t.BaselineStatus)
		if t.CalibrationControls > 0 {
			fmt.Fprintf(&b, "calibration: %d control response(s)\n", t.CalibrationControls)
		}

		for _, c := range t.Clusters {
			mediaType := c.Fingerprint.MediaType
			if mediaType == "" {
				mediaType = "-"
			}
			fmt.Fprintf(&b, "  %-7s %d  %-16s %dB  x%d  %s\n",
				c.Class, c.Fingerprint.Status, mediaType, c.Fingerprint.Length,
				c.Count, c.Representative.CurlCMD)
			if c.Count > 1 {
				fmt.Fprintf(&b, "    members: %s\n", membersLine(c.Members))
			}
		}
	}

	b.WriteString("\nnote: fingerprints derive from the stored body preview (possibly " +
		"truncated at capture time); clustering is exact-digest only.\n")
	return b.String()
}

// JSON renders the report as indented JSON with stable field names.
func (r Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// membersLine lists up to membersShown member curls (sorted, deterministic)
// and collapses the remainder, naming the first collapsed member.
func membersLine(members []Row) string {
	curls := make([]string, 0, len(members))
	for _, m := range members {
		curls = append(curls, m.CurlCMD)
	}
	sort.Strings(curls)

	shown := curls
	hidden := 0
	if len(curls) > membersShown {
		shown = curls[:membersShown]
		hidden = len(curls) - membersShown
	}

	line := strings.Join(shown, "; ")
	if hidden > 0 {
		line += fmt.Sprintf("; +%d more identical (first: %s)", hidden, curls[membersShown])
	}
	return line
}
