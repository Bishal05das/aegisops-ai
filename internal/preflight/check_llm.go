package preflight

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// OllamaCheck verifies the local inference runtime is up AND that the specific
// model the platform is configured to use has actually been pulled.
//
// This distinction matters more than it looks. A running Ollama with the wrong
// model produces a confident-looking 404 deep inside the first agent run, long
// after the operator has stopped watching. Catching it at preflight turns a
// confusing runtime failure into a one-line instruction.
//
// A reachable daemon that is missing the model is a warning, not a failure: the
// stack is otherwise usable and the fix is a single `ollama pull`.
type OllamaCheck struct {
	base
	Endpoint string
	// RequiredModel is matched against both `name` and `model` fields, and
	// tolerates the implicit `:latest` tag Ollama applies.
	RequiredModel string
}

// NewOllamaCheck builds a probe against an Ollama-compatible endpoint.
func NewOllamaCheck(endpoint, model string) *OllamaCheck {
	endpoint = strings.TrimRight(endpoint, "/")
	return &OllamaCheck{
		base: base{
			name:     "llm",
			target:   endpoint + " (" + model + ")",
			severity: Required,
			hint:     "run `ollama serve`, then `ollama pull " + model + "`",
		},
		Endpoint:      endpoint,
		RequiredModel: model,
	}
}

// ollamaTagsResponse mirrors the subset of GET /api/tags we depend on.
type ollamaTagsResponse struct {
	Models []struct {
		Name  string `json:"name"`
		Model string `json:"model"`
		Size  int64  `json:"size"`
	} `json:"models"`
}

// Probe implements Check.
func (c *OllamaCheck) Probe(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint+"/api/tags", nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegisops-preflight")

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET /api/tags: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /api/tags returned %s", resp.Status)
	}

	var tags ollamaTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", fmt.Errorf("decode /api/tags (is this an Ollama endpoint?): %w", err)
	}

	if len(tags.Models) == 0 {
		return "ollama reachable, no models pulled",
			fmt.Errorf("%w: no models available; run `ollama pull %s`", ErrDegraded, c.RequiredModel)
	}

	names := make([]string, 0, len(tags.Models))
	var found bool
	var size int64
	for _, m := range tags.Models {
		id := m.Name
		if id == "" {
			id = m.Model
		}
		names = append(names, id)
		if modelMatches(id, c.RequiredModel) || modelMatches(m.Model, c.RequiredModel) {
			found, size = true, m.Size
		}
	}

	if !found {
		return fmt.Sprintf("ollama reachable, %d model(s): %s", len(names), strings.Join(names, ", ")),
			fmt.Errorf("%w: required model %q not pulled; run `ollama pull %s`",
				ErrDegraded, c.RequiredModel, c.RequiredModel)
	}

	return fmt.Sprintf("ollama serving %s (%s), %d model(s) available",
		c.RequiredModel, humanBytes(size), len(names)), nil
}

// modelMatches compares two Ollama model references, treating a bare name as
// equivalent to that name with the implicit `:latest` tag.
func modelMatches(have, want string) bool {
	if have == "" || want == "" {
		return false
	}
	return normalizeModel(have) == normalizeModel(want)
}

func normalizeModel(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	if !strings.Contains(m, ":") {
		return m + ":latest"
	}
	return m
}

// humanBytes renders a byte count with a binary unit suffix.
func humanBytes(n int64) string {
	if n <= 0 {
		return "unknown size"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// GoRuntimeCheck asserts the process is running on a Go toolchain new enough for
// the language features this codebase relies on. It needs no network, so it is
// the one check that always produces a result.
type GoRuntimeCheck struct {
	base
	Minimum string
	actual  func() string
}

// NewGoRuntimeCheck builds a local toolchain assertion.
func NewGoRuntimeCheck(minimum string, actual func() string) *GoRuntimeCheck {
	return &GoRuntimeCheck{
		base: base{
			name:     "go-runtime",
			target:   "local toolchain",
			severity: Required,
			hint:     "install Go " + minimum + " or newer: https://go.dev/dl/",
		},
		Minimum: minimum,
		actual:  actual,
	}
}

// Probe implements Check.
func (c *GoRuntimeCheck) Probe(_ context.Context) (string, error) {
	got := strings.TrimPrefix(c.actual(), "go")
	want := strings.TrimPrefix(c.Minimum, "go")
	if compareSemverish(got, want) < 0 {
		return "", fmt.Errorf("go %s is older than the required %s", got, want)
	}
	return "go " + got, nil
}

// compareSemverish compares dotted numeric versions ("1.24.3" vs "1.24"),
// ignoring any pre-release suffix. Returns -1, 0 or 1.
func compareSemverish(a, b string) int {
	pa, pb := splitVersion(a), splitVersion(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	// Trim anything non-numeric from the tail, e.g. "1.24rc1" -> "1.24".
	var parts []int
	for _, seg := range strings.Split(v, ".") {
		n := 0
		for _, r := range seg {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		parts = append(parts, n)
	}
	return parts
}

var (
	_ Check = (*OllamaCheck)(nil)
	_ Check = (*GoRuntimeCheck)(nil)
)
