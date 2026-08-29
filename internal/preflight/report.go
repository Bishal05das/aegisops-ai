package preflight

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// RenderJSON writes the report as machine-readable JSON.
//
// CI consumes this form: the pipeline asserts on `healthy` rather than parsing
// human output, and the per-check `duration_ms` doubles as an early warning that
// a dependency is getting slow.
func RenderJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// glyphs are deliberately ASCII-safe with a colour layer applied separately, so
// output stays readable when piped to a file or a CI log.
func glyph(s Status) string {
	switch s {
	case StatusOK:
		return "PASS"
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	default:
		return "SKIP"
	}
}

const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiDim    = "\033[2m"
	ansiBold   = "\033[1m"
)

func colorFor(s Status) string {
	switch s {
	case StatusOK:
		return ansiGreen
	case StatusWarn:
		return ansiYellow
	case StatusFail:
		return ansiRed
	default:
		return ansiDim
	}
}

// RenderText writes an aligned, operator-facing report.
//
// color is passed in rather than auto-detected so the caller owns the TTY
// decision — this keeps the renderer a pure function and therefore testable.
func RenderText(w io.Writer, rep Report, color bool) error {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + ansiReset
	}

	nameWidth := len("CHECK")
	for _, r := range rep.Results {
		if len(r.Name) > nameWidth {
			nameWidth = len(r.Name)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", paint(ansiBold, "AegisOps preflight"))
	fmt.Fprintf(&b, "%s\n", paint(ansiDim, strings.Repeat("─", 72)))

	for _, r := range rep.Results {
		status := paint(colorFor(r.Status), glyph(r.Status))
		line := r.Detail
		if r.Error != "" {
			line = r.Error
		}
		fmt.Fprintf(&b, "  %s  %-*s  %s  %s\n",
			status,
			nameWidth, r.Name,
			paint(ansiDim, fmt.Sprintf("%5dms", r.Millis)),
			line,
		)
		if r.Target != "" {
			fmt.Fprintf(&b, "        %-*s  %s\n", nameWidth, "", paint(ansiDim, "→ "+r.Target))
		}
		if r.Hint != "" && r.Status != StatusOK {
			fmt.Fprintf(&b, "        %-*s  %s\n", nameWidth, "", paint(ansiYellow, "↳ fix: "+r.Hint))
		}
	}

	counts := rep.Counts()
	fmt.Fprintf(&b, "%s\n", paint(ansiDim, strings.Repeat("─", 72)))
	summary := fmt.Sprintf("%d passed, %d warned, %d failed, %d skipped  (%dms)",
		counts[StatusOK], counts[StatusWarn], counts[StatusFail], counts[StatusSkip], rep.Duration)

	if rep.Healthy {
		fmt.Fprintf(&b, "  %s  %s\n", paint(ansiGreen+ansiBold, "ENVIRONMENT READY"), paint(ansiDim, summary))
	} else {
		fmt.Fprintf(&b, "  %s  %s\n", paint(ansiRed+ansiBold, "ENVIRONMENT NOT READY"), paint(ansiDim, summary))
	}

	_, err := io.WriteString(w, b.String())
	return err
}
