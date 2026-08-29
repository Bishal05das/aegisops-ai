// Package preflight verifies that every backing service AegisOps depends on is
// reachable and actually speaking the protocol we expect.
//
// Why this exists as real, tested code rather than a shell script:
//
//   - A TCP connect proves a port is open, not that PostgreSQL is behind it.
//     Every check here completes a protocol handshake, so "healthy" means the
//     service answered in its own language.
//   - It is the same failure taxonomy the platform uses at runtime. A dependency
//     that is unreachable, reachable-but-wrong, or degraded are three different
//     situations and the operator needs to be told which one.
//   - It has zero third-party dependencies. PostgreSQL, Redis and AMQP are
//     probed by writing their wire protocols directly over net.Conn.
//
// Checks are independent and run concurrently under a shared deadline; results
// are reported in declaration order so output is stable across runs.
package preflight

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Status is the outcome classification of a single check.
type Status string

const (
	// StatusOK means the dependency answered correctly.
	StatusOK Status = "ok"
	// StatusWarn means the dependency answered, but something is off — an
	// optional component is missing or a value is not what we expect. The run
	// still succeeds.
	StatusWarn Status = "warn"
	// StatusFail means the dependency is unreachable or not what it claims.
	StatusFail Status = "fail"
	// StatusSkip means the check was filtered out or is not applicable.
	StatusSkip Status = "skip"
)

// Severity declares whether a failing check should fail the whole run.
type Severity int

const (
	// Required dependencies must pass; their failure fails the run.
	Required Severity = iota
	// Optional dependencies downgrade a failure to a warning.
	Optional
)

// ErrDegraded is returned by a Check that answered but is not fully healthy.
// The runner maps it to StatusWarn instead of StatusFail.
var ErrDegraded = errors.New("degraded")

// Check probes exactly one dependency.
//
// Implementations must be safe for concurrent use and must respect ctx: the
// runner enforces a deadline and a slow check must not pin the whole run.
type Check interface {
	// Name is the stable identifier used for filtering (-only) and JSON keys.
	Name() string
	// Target is the human-readable address being probed, for the report.
	Target() string
	// Severity decides whether a failure is fatal to the run.
	Severity() Severity
	// Hint is operator-facing remediation shown when the check does not pass.
	Hint() string
	// Probe performs the handshake. The returned detail is shown on success;
	// a non-nil error (or ErrDegraded) explains the failure.
	Probe(ctx context.Context) (detail string, err error)
}

// Result is the outcome of running one Check.
type Result struct {
	Name     string        `json:"name"`
	Target   string        `json:"target"`
	Status   Status        `json:"status"`
	Detail   string        `json:"detail,omitempty"`
	Error    string        `json:"error,omitempty"`
	Hint     string        `json:"hint,omitempty"`
	Duration time.Duration `json:"-"`
	Millis   int64         `json:"duration_ms"`

	order int // preserves declaration order across concurrent completion
}

// OK reports whether the result should be treated as a pass.
func (r Result) OK() bool {
	return r.Status == StatusOK || r.Status == StatusWarn || r.Status == StatusSkip
}

// Report is the full outcome of a preflight run.
type Report struct {
	Results  []Result  `json:"results"`
	Started  time.Time `json:"started_at"`
	Duration int64     `json:"duration_ms"`
	Healthy  bool      `json:"healthy"`
}

// Counts summarises the report by status.
func (rep Report) Counts() map[Status]int {
	out := map[Status]int{}
	for _, r := range rep.Results {
		out[r.Status]++
	}
	return out
}

// Runner executes a set of checks with a per-check timeout.
type Runner struct {
	// Timeout bounds each individual check. Zero means DefaultCheckTimeout.
	Timeout time.Duration
	// Only, when non-empty, restricts execution to checks whose Name is a key.
	// Excluded checks are reported as StatusSkip so the report stays complete.
	Only map[string]bool
}

// DefaultCheckTimeout is deliberately short. A dependency that cannot complete a
// handshake in five seconds is not usable by an incident-response system whose
// entire value proposition is reacting fast.
const DefaultCheckTimeout = 5 * time.Second

// Run executes every check concurrently and returns an ordered Report.
//
// The parent ctx bounds the whole run; each check additionally gets its own
// timeout so one hung dependency cannot consume the entire budget.
func (r Runner) Run(ctx context.Context, checks []Check) Report {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultCheckTimeout
	}

	started := time.Now()
	results := make([]Result, len(checks))

	var wg sync.WaitGroup
	for i, c := range checks {
		if r.Only != nil && !r.Only[c.Name()] {
			results[i] = Result{
				Name: c.Name(), Target: c.Target(),
				Status: StatusSkip, Detail: "filtered out", order: i,
			}
			continue
		}

		wg.Add(1)
		go func(i int, c Check) {
			defer wg.Done()
			defer func() {
				// A panicking probe must degrade to a failed check, never take
				// down the operator's diagnostic tool.
				if p := recover(); p != nil {
					results[i] = Result{
						Name: c.Name(), Target: c.Target(), Status: StatusFail,
						Error: fmt.Sprintf("panic: %v", p), Hint: c.Hint(), order: i,
					}
				}
			}()
			results[i] = runOne(ctx, timeout, i, c)
		}(i, c)
	}
	wg.Wait()

	sort.SliceStable(results, func(a, b int) bool { return results[a].order < results[b].order })

	rep := Report{
		Results:  results,
		Started:  started,
		Duration: time.Since(started).Milliseconds(),
		Healthy:  true,
	}
	for _, res := range rep.Results {
		if res.Status == StatusFail {
			rep.Healthy = false
		}
	}
	return rep
}

// runOne applies the timeout, classifies the error, and times the probe.
func runOne(ctx context.Context, timeout time.Duration, order int, c Check) Result {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	detail, err := c.Probe(cctx)
	elapsed := time.Since(start)

	res := Result{
		Name:     c.Name(),
		Target:   c.Target(),
		Detail:   detail,
		Duration: elapsed,
		Millis:   elapsed.Milliseconds(),
		order:    order,
	}

	switch {
	case err == nil:
		res.Status = StatusOK
	case errors.Is(err, ErrDegraded):
		// Answered, but not fully as expected — surface it without failing.
		res.Status = StatusWarn
		res.Error = err.Error()
		res.Hint = c.Hint()
	case c.Severity() == Optional:
		res.Status = StatusWarn
		res.Error = err.Error()
		res.Hint = c.Hint()
	default:
		res.Status = StatusFail
		res.Error = err.Error()
		res.Hint = c.Hint()
	}
	return res
}
