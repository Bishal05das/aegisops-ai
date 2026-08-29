package preflight

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleReport() Report {
	return Report{
		Started:  time.Now(),
		Duration: 42,
		Healthy:  false,
		Results: []Result{
			{Name: "postgres", Target: "localhost:5434", Status: StatusOK,
				Detail: "postgres backend responding", Millis: 3},
			{Name: "llm", Target: "http://localhost:11434", Status: StatusWarn,
				Error: "degraded: model missing", Hint: "ollama pull qwen2.5:7b", Millis: 8},
			{Name: "rabbitmq", Target: "localhost:5672", Status: StatusFail,
				Error: "connection refused", Hint: "run make dev-up", Millis: 1},
			{Name: "jaeger", Target: "http://localhost:16686", Status: StatusSkip,
				Detail: "filtered out"},
		},
	}
}

func TestRenderTextIsPlainWithoutColor(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	if err := RenderText(&b, sampleReport(), false); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	out := b.String()

	if strings.Contains(out, "\033[") {
		t.Error("output contains ANSI codes with color=false — it would corrupt CI logs and files")
	}
	for _, want := range []string{"PASS", "WARN", "FAIL", "SKIP", "ENVIRONMENT NOT READY"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	// Remediation must appear for anything that is not passing, since that is
	// the only part of the report an operator has to act on.
	if !strings.Contains(out, "ollama pull qwen2.5:7b") {
		t.Error("output missing the hint for the degraded check")
	}
}

func TestRenderTextEmitsColorWhenRequested(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	if err := RenderText(&b, sampleReport(), true); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if !strings.Contains(b.String(), ansiRed) {
		t.Error("expected a red FAIL marker with color=true")
	}
}

func TestRenderTextHealthyBanner(t *testing.T) {
	t.Parallel()

	rep := sampleReport()
	rep.Healthy = true
	var b strings.Builder
	if err := RenderText(&b, rep, false); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if !strings.Contains(b.String(), "ENVIRONMENT READY") {
		t.Error("healthy report must announce readiness")
	}
}

func TestRenderJSONIsMachineReadable(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	if err := RenderJSON(&b, sampleReport()); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	// CI branches on this shape, so decode it back rather than string-matching.
	var got struct {
		Healthy bool `json:"healthy"`
		Results []struct {
			Name     string `json:"name"`
			Status   string `json:"status"`
			Duration int64  `json:"duration_ms"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(b.String()), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, b.String())
	}
	if got.Healthy {
		t.Error("healthy = true, want false")
	}
	if len(got.Results) != 4 {
		t.Fatalf("got %d results, want 4", len(got.Results))
	}
	if got.Results[0].Name != "postgres" || got.Results[0].Status != "ok" {
		t.Errorf("first result = %+v", got.Results[0])
	}
	if got.Results[0].Duration != 3 {
		t.Errorf("duration_ms = %d, want 3", got.Results[0].Duration)
	}
}
