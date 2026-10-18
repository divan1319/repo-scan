package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/divan1319/repo-scan/internal/analyzer"
)

type Summary struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

type Report struct {
	Findings   []analyzer.Finding `json:"findings"`
	Skipped    []string           `json:"skipped"`
	Suppressed int                `json:"suppressed"`
	Summary    Summary            `json:"summary"`
}

func New(findings []analyzer.Finding, skipped []string, suppressed int) Report {

	fs := slices.Clone(findings)

	if fs == nil {
		fs = []analyzer.Finding{}
	}

	slices.SortStableFunc(fs, func(a, b analyzer.Finding) int {
		return cmp.Or(
			cmp.Compare(a.File, b.File),
			cmp.Compare(a.Line, b.Line),
		)
	})

	sk := slices.Clone(skipped)

	if sk == nil {
		sk = []string{}
	}

	var sum Summary

	for _, f := range fs {
		switch f.Severity {
		case analyzer.High:
			sum.High++
		case analyzer.Medium:
			sum.Medium++
		case analyzer.Low:
			sum.Low++
		}
	}

	return Report{
		Findings:   fs,
		Skipped:    sk,
		Suppressed: suppressed,
		Summary:    sum,
	}
}

func (r Report) WriteText(w io.Writer) error {

	for _, f := range r.Findings {
		var err error
		if f.Line == 0 {
			_, err = fmt.Fprintf(w, "%s: [%s] %s: %s\n", f.File, f.Severity, f.Rule, f.Message)
		} else {
			_, err = fmt.Fprintf(w, "%s:%d: [%s] %s: %s\n", f.File, f.Line, f.Severity, f.Rule, f.Message)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ") // sin prefijo, 2 espacios por nivel
	enc.SetEscapeHTML(false)

	return enc.Encode(r)
}
