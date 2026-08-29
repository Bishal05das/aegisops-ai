package preflight

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeCheck is a programmable Check used to exercise the runner's classification
// logic without touching the network.
type fakeCheck struct {
	name  string
	sev   Severity
	delay time.Duration
	panic bool
	err   error
}

func (f *fakeCheck) Name() string       { return f.name }
func (f *fakeCheck) Target() string     { return "fake://" + f.name }
func (f *fakeCheck) Hint() string       { return "hint-" + f.name }
func (f *fakeCheck) Severity() Severity { return f.sev }

func (f *fakeCheck) Probe(ctx context.Context) (string, error) {
	if f.panic {
		panic("boom")
	}
	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(f.delay):
		}
	}
	if f.err != nil {
		return "", f.err
	}
	return "detail-" + f.name, nil
}

func TestRunnerClassifiesOutcomes(t *testing.T) {
	t.Parallel()

	checks := []Check{
		&fakeCheck{name: "healthy", sev: Required},
		&fakeCheck{name: "required-down", sev: Required, err: errors.New("connection refused")},
		&fakeCheck{name: "optional-down", sev: Optional, err: errors.New("connection refused")},
		&fakeCheck{name: "degraded", sev: Required, err: fmt.Errorf("%w: model missing", ErrDegraded)},
		&fakeCheck{name: "panicky", sev: Required, panic: true},
	}

	rep := Runner{Timeout: time.Second}.Run(context.Background(), checks)

	want := map[string]Status{
		"healthy":       StatusOK,
		"required-down": StatusFail,
		"optional-down": StatusWarn, // optional failures never break the run
		"degraded":      StatusWarn, // answered, but not fully as expected
		"panicky":       StatusFail, // a panicking probe must not kill the tool
	}
	if len(rep.Results) != len(want) {
		t.Fatalf("got %d results, want %d", len(rep.Results), len(want))
	}
	for _, r := range rep.Results {
		if got := want[r.Name]; r.Status != got {
			t.Errorf("%s: status = %q, want %q (err=%q)", r.Name, r.Status, got, r.Error)
		}
	}
	if rep.Healthy {
		t.Error("Healthy = true, want false when a required check failed")
	}
}

// A required failure must be the only thing that flips Healthy — otherwise
// operators learn to ignore a permanently-red preflight.
func TestRunnerHealthyWithOnlyWarnings(t *testing.T) {
	t.Parallel()

	rep := Runner{Timeout: time.Second}.Run(context.Background(), []Check{
		&fakeCheck{name: "ok", sev: Required},
		&fakeCheck{name: "opt", sev: Optional, err: errors.New("nope")},
		&fakeCheck{name: "deg", sev: Required, err: fmt.Errorf("%w: partial", ErrDegraded)},
	})

	if !rep.Healthy {
		t.Errorf("Healthy = false, want true (warnings must not fail the run)")
	}
}

// Checks run concurrently but must be reported in declaration order, so output
// is diffable between runs.
func TestRunnerPreservesDeclarationOrder(t *testing.T) {
	t.Parallel()

	checks := []Check{
		&fakeCheck{name: "slow", sev: Required, delay: 120 * time.Millisecond},
		&fakeCheck{name: "medium", sev: Required, delay: 60 * time.Millisecond},
		&fakeCheck{name: "fast", sev: Required},
	}

	start := time.Now()
	rep := Runner{Timeout: time.Second}.Run(context.Background(), checks)
	elapsed := time.Since(start)

	got := []string{rep.Results[0].Name, rep.Results[1].Name, rep.Results[2].Name}
	if got[0] != "slow" || got[1] != "medium" || got[2] != "fast" {
		t.Errorf("order = %v, want [slow medium fast]", got)
	}
	// Serial execution would take at least 180ms; concurrent is bounded by the
	// slowest single check.
	if elapsed > 150*time.Millisecond {
		t.Errorf("elapsed = %v, want < 150ms — checks did not run concurrently", elapsed)
	}
}

func TestRunnerPerCheckTimeout(t *testing.T) {
	t.Parallel()

	rep := Runner{Timeout: 40 * time.Millisecond}.Run(context.Background(), []Check{
		&fakeCheck{name: "hangs", sev: Required, delay: 5 * time.Second},
		&fakeCheck{name: "quick", sev: Required},
	})

	if rep.Results[0].Status != StatusFail {
		t.Errorf("hanging check status = %q, want %q", rep.Results[0].Status, StatusFail)
	}
	if !strings.Contains(rep.Results[0].Error, "deadline exceeded") {
		t.Errorf("error = %q, want a deadline error", rep.Results[0].Error)
	}
	// One slow dependency must not starve the others.
	if rep.Results[1].Status != StatusOK {
		t.Errorf("quick check status = %q, want %q", rep.Results[1].Status, StatusOK)
	}
}

func TestRunnerOnlyFilterSkipsRatherThanOmits(t *testing.T) {
	t.Parallel()

	rep := Runner{
		Timeout: time.Second,
		Only:    map[string]bool{"wanted": true},
	}.Run(context.Background(), []Check{
		&fakeCheck{name: "wanted", sev: Required},
		&fakeCheck{name: "ignored", sev: Required, err: errors.New("would fail")},
	})

	// The filtered check is reported as skipped, not dropped: a report that
	// silently omits checks is worse than one that says it did not run them.
	if len(rep.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(rep.Results))
	}
	if rep.Results[1].Status != StatusSkip {
		t.Errorf("filtered check status = %q, want %q", rep.Results[1].Status, StatusSkip)
	}
	if !rep.Healthy {
		t.Error("Healthy = false; a skipped failing check must not fail the run")
	}
}

func TestRunnerFailureCarriesHint(t *testing.T) {
	t.Parallel()

	rep := Runner{Timeout: time.Second}.Run(context.Background(), []Check{
		&fakeCheck{name: "broken", sev: Required, err: errors.New("refused")},
	})
	if rep.Results[0].Hint != "hint-broken" {
		t.Errorf("Hint = %q, want the check's remediation text", rep.Results[0].Hint)
	}
}

func TestReportCounts(t *testing.T) {
	t.Parallel()

	rep := Runner{Timeout: time.Second}.Run(context.Background(), []Check{
		&fakeCheck{name: "a", sev: Required},
		&fakeCheck{name: "b", sev: Required},
		&fakeCheck{name: "c", sev: Optional, err: errors.New("x")},
	})
	counts := rep.Counts()
	if counts[StatusOK] != 2 || counts[StatusWarn] != 1 {
		t.Errorf("counts = %v, want 2 ok / 1 warn", counts)
	}
}
