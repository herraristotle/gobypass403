/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Offline analysis mode (SPEC-unkover-gaps.md Addendum 5, Phase A).

-analyze <results.db> re-reads a finished scan and reports what actually
departed from each target's baseline (BYPASS / VARIANT / DUP / NOISE)
without re-scanning anything. -analyze-json <file> additionally writes the
same report as JSON for further processing.

This path never creates an output directory or database and never sends a
request; the input DB is opened read-only.
*/
package cli

import (
	"fmt"
	"os"

	"github.com/slicingmelon/gobypass403/core/engine/analysis"
)

// handleAnalyze runs the offline analyzer and returns. The text report is
// printed to stdout (pipeable); the JSON copy is written only when asked.
func (r *Runner) handleAnalyze() error {
	opts := r.RunnerOptions

	report, err := analysis.Analyze(opts.AnalyzeDB)
	if err != nil {
		return err
	}

	fmt.Printf("Findings database: %s\n\n", opts.AnalyzeDB)
	fmt.Print(report.Text())

	if opts.WarnWildcard {
		printWildcardHints(report)
	}

	if opts.AnalyzeJSON == "" {
		return nil
	}

	data, err := report.JSON()
	if err != nil {
		return fmt.Errorf("failed to render JSON report: %w", err)
	}
	if err := os.WriteFile(opts.AnalyzeJSON, data, 0o644); err != nil {
		return fmt.Errorf("failed to write JSON report %q: %w", opts.AnalyzeJSON, err)
	}
	fmt.Printf("\nJSON report written to: %s\n", opts.AnalyzeJSON)

	return nil
}

// printWildcardHints names the catch-all-shaped clusters of an offline report
// (Addendum 9). Same rule as the live run -- WildcardHints over the classified
// report -- so both paths say the same thing about the same database, and the
// hint stays a hint: it names a shape and the remedy, it suppresses nothing.
func printWildcardHints(report analysis.Report) {
	hints := analysis.WildcardHints(report)
	if len(hints) == 0 {
		return
	}

	fmt.Println()
	fmt.Println("Wildcard hints (the shape of a catch-all, not a finding - rerun the scan with -calibrate to confirm):")
	for _, h := range hints {
		fmt.Printf("  %s\n    %s\n", h.TargetURL, h)
	}
}
