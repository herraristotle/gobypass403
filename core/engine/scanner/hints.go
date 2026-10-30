/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec

Live half of the wildcard hint (SPEC-unkover-gaps.md Addendum 9). Read-only and
post-hoc: the rows are already in the findings database when this runs, so the
hint never costs a request, and it cannot disagree with -analyze, which
classifies the same rows with the same code.
*/
package scanner

import (
	"github.com/herraristotle/gobypass403/core/engine/analysis"
	GB403Logger "github.com/herraristotle/gobypass403/core/utils/logger"
)

// WildcardHintsForTarget reads the rows a finished run stored for one target
// and returns the catch-all-shaped clusters among them. Read-only: the rows are
// already in the findings database, so this costs no request.
func WildcardHintsForTarget(targetURL string) ([]analysis.Hint, error) {
	rows, err := analysis.TargetRows(dbPath, targetURL)
	if err != nil {
		return nil, err
	}

	return analysis.WildcardHints(analysis.ClassifyReport(rows)), nil
}

// PrintWildcardHints reports, for one finished target, any BYPASS cluster that
// looks like a catch-all: many distinct requests answered with one response.
// The run had no negative control to compare against (-calibrate), so the shape
// is a prompt to rerun with it -- never a verdict and never a suppression.
func PrintWildcardHints(targetURL string) error {
	hints, err := WildcardHintsForTarget(targetURL)
	if err != nil {
		return err
	}

	for _, h := range hints {
		GB403Logger.Warning().Msgf("%s", h)
	}
	return nil
}
