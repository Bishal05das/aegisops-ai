package harness

import (
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// ExecStatus is the result of actually running a tool.
type ExecStatus string

// Execution results.
const (
	ExecSucceeded ExecStatus = "succeeded"
	ExecFailed    ExecStatus = "failed"
	ExecTimedOut  ExecStatus = "timed_out"
	// ExecDryRun means the harness logged full intent and returned synthetic
	// success without touching infrastructure. It is a first-class outcome, not
	// an error: dry-run is the default outside production, so switching to live
	// execution is a deliberate act.
	ExecDryRun ExecStatus = "dry_run"
)

// Valid reports whether the status is defined.
func (e ExecStatus) Valid() bool {
	switch e {
	case ExecSucceeded, ExecFailed, ExecTimedOut, ExecDryRun:
		return true
	default:
		return false
	}
}

// MaxOutputLen caps captured stdout/stderr.
//
// A tool that returns a 200 MB log dump must not be able to exhaust memory or
// bloat the row; the executor truncates and records that it did. The cap is
// generous enough to hold a useful excerpt.
const MaxOutputLen = 64 << 10

// Execution records what the harness did after a request passed every gate.
//
// One execution per tool call, enforced by a unique constraint. That is what
// makes idempotency observable: a redelivered event finds the execution already
// present rather than restarting the container a second time.
type Execution struct {
	ID         shared.ID
	ToolCallID shared.ID

	Status ExecStatus
	// DryRun is stored separately from Status so a query can distinguish "this
	// deployment never executes anything" from "this particular call was
	// skipped", which matters when auditing whether a remediation really ran.
	DryRun bool

	ExitCode  *int
	Stdout    string
	Stderr    string
	Truncated bool
	Error     string

	StartedAt  time.Time
	FinishedAt time.Time
	DurationMS int64

	CreatedAt time.Time
}

// NewExecution builds a validated execution record.
func NewExecution(clock shared.Clock, toolCallID shared.ID, status ExecStatus, dryRun bool) (*Execution, error) {
	now := clock.Now()
	e := &Execution{
		ID:         shared.NewID(),
		ToolCallID: toolCallID,
		Status:     status,
		DryRun:     dryRun,
		StartedAt:  now,
		FinishedAt: now,
		CreatedAt:  now,
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// Validate checks the execution's invariants.
func (e *Execution) Validate() error {
	v := shared.NewValidator("execution")
	v.NotZeroID(e.ID, "id")
	v.NotZeroID(e.ToolCallID, "tool_call_id")
	v.Check(e.Status.Valid(), "status",
		"must be one of: succeeded, failed, timed_out, dry_run")
	v.MaxLen(e.Stdout, "stdout", MaxOutputLen)
	v.MaxLen(e.Stderr, "stderr", MaxOutputLen)
	v.Check(e.DurationMS >= 0, "duration_ms", "cannot be negative")
	return v.Err()
}

// Complete stamps the finish time and derives the duration.
func (e *Execution) Complete(clock shared.Clock, status ExecStatus) {
	e.FinishedAt = clock.Now()
	e.Status = status
	e.DurationMS = e.FinishedAt.Sub(e.StartedAt).Milliseconds()
}

// CaptureOutput stores tool output, truncating anything oversized and recording
// that it did so — silently dropping the tail would make a postmortem read a
// complete log that was not.
func (e *Execution) CaptureOutput(stdout, stderr string) {
	e.Stdout, e.Truncated = truncate(stdout, MaxOutputLen)
	var stderrTruncated bool
	e.Stderr, stderrTruncated = truncate(stderr, MaxOutputLen)
	e.Truncated = e.Truncated || stderrTruncated
}

// Succeeded reports whether infrastructure was actually changed successfully.
// A dry run returns false: nothing happened.
func (e *Execution) Succeeded() bool { return e.Status == ExecSucceeded && !e.DryRun }

const truncationNotice = "\n… [output truncated by AegisOps]"

func truncate(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	keep := limit - len(truncationNotice)
	if keep < 0 {
		keep = 0
	}
	return s[:keep] + truncationNotice, true
}
