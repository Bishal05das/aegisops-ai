package harness

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// DefaultExecTimeout bounds one tool invocation.
//
// A tool that hangs holds an execution slot and, worse, leaves the system unsure
// whether the action happened — the worst state to be in during an incident. The
// bound is per invocation and a tool may declare a shorter one.
const DefaultExecTimeout = 60 * time.Second

// Executor is gate five: it invokes a tool that has passed every other gate.
//
// # Why this is a separate type from the Harness
//
// Because it is the only thing in the system that can cause an effect, and it
// should be possible to point at one type and say "this is the code that touches
// production". It holds the registry and nothing else — no policy, no
// permission, no approval state. By the time a request reaches Execute, those
// questions are settled, and an executor that could re-open them would be a
// second place where the answer might differ.
type Executor struct {
	registry *Registry
	clock    shared.Clock
	timeout  time.Duration

	// dryRun makes every execution synthetic.
	//
	// Default true, and that default is the point: switching a deployment to
	// live execution is a deliberate configuration act, not something that
	// happens because someone forgot to set a flag. See ADR 0011.
	dryRun bool
}

// ExecutorConfig configures the executor.
type ExecutorConfig struct {
	Registry *Registry
	Clock    shared.Clock
	Timeout  time.Duration
	// Live turns off dry-run. Named for what it enables rather than what it
	// disables, so a configuration file reads `live: true` when the system can
	// change infrastructure — the affirmative form is harder to set by accident.
	Live bool
}

// NewExecutor builds the executor.
func NewExecutor(cfg ExecutorConfig) *Executor {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultExecTimeout
	}
	clock := cfg.Clock
	if clock == nil {
		clock = shared.SystemClock{}
	}
	return &Executor{
		registry: cfg.Registry,
		clock:    clock,
		timeout:  timeout,
		dryRun:   !cfg.Live,
	}
}

var _ ports.ToolExecutor = (*Executor)(nil)

// DryRun reports whether executions are synthetic.
func (e *Executor) DryRun() bool { return e.dryRun }

// Known implements ports.ToolExecutor.
func (e *Executor) Known(tool, action string) bool { return e.registry.Known(tool, action) }

// Execute invokes the tool and returns the record of what happened.
//
// A tool that fails produces an Execution with status failed and a nil error.
// The distinction matters: "the remediation ran and failed" is a fact about
// infrastructure that belongs in the incident timeline, while a returned error
// means the harness itself could not proceed. Collapsing them would make a
// broken Docker socket look like a failed restart.
func (e *Executor) Execute(ctx context.Context, req *harness.ToolCallRequest) (*harness.Execution, error) {
	const op = "harness.Executor.Execute"

	if !req.Decision.Permits() {
		// Defence in depth. The pipeline already checked, but this is the last
		// function before infrastructure changes, and it should be impossible to
		// call it with an unapproved request even by mistake.
		return nil, fmt.Errorf("%s: refusing to execute a request whose decision is %s",
			op, req.Decision)
	}

	tool, ok := e.registry.Lookup(req.Tool)
	if !ok {
		return nil, fmt.Errorf("%s: tool %q is not registered", op, req.Tool)
	}
	desc, ok := e.registry.Describe(req.Tool, req.Action)
	if !ok {
		return nil, fmt.Errorf("%s: tool %q has no action %q", op, req.Tool, req.Action)
	}

	exec, err := harness.NewExecution(e.clock, req.ID, harness.ExecSucceeded, e.dryRun)
	if err != nil {
		return nil, fmt.Errorf("%s: build the execution record: %w", op, err)
	}

	timeout := e.timeout
	if desc.Timeout > 0 && desc.Timeout < timeout {
		timeout = desc.Timeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, invokeErr := invoke(callCtx, tool, ports.ToolInvocation{
		ToolCallID: req.ID,
		Action:     req.Action,
		Params:     req.Params,
		DryRun:     e.dryRun,
		IncidentID: req.IncidentID,
	})

	switch {
	case invokeErr != nil && errors.Is(callCtx.Err(), context.DeadlineExceeded):
		// Timed out is its own status, not a failure. After a timeout nobody
		// knows whether the action took effect, and a postmortem needs to see
		// that uncertainty rather than a confident "it failed".
		exec.Complete(e.clock, harness.ExecTimedOut)
		exec.Error = fmt.Sprintf("the tool did not return within %s; whether the action "+
			"took effect is unknown", timeout)
	case invokeErr != nil:
		exec.Complete(e.clock, harness.ExecFailed)
		exec.Error = invokeErr.Error()
	case e.dryRun:
		exec.Complete(e.clock, harness.ExecDryRun)
	default:
		exec.Complete(e.clock, harness.ExecSucceeded)
	}

	exec.CaptureOutput(result.Stdout, result.Stderr)
	exec.ExitCode = result.ExitCode
	return exec, nil
}

// invoke calls a tool and converts a panic into an error.
//
// A tool is the least trustworthy code in the process: it shells out, parses
// third-party output and talks to daemons that change under it. A panic there
// must not take down a control plane that is, at that moment, the thing managing
// an outage.
func invoke(ctx context.Context, tool ports.Tool, call ports.ToolInvocation) (result ports.ToolResult, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("the tool panicked: %v", p)
		}
	}()
	return tool.Invoke(ctx, call)
}

// NoopTool satisfies ports.Tool for an action set with no implementation.
//
// Phase 6 ships the gates; Phase 7 ships the tools. Registering descriptors
// backed by this lets the whole pipeline — validation, permission, policy,
// approval, execution, audit — run end to end and be tested against real
// Postgres before a single line of Docker code exists.
//
// It refuses to do anything outside dry-run. That is not a placeholder detail:
// if Phase 7 is delayed or a descriptor is left registered against it by
// mistake, the failure is a recorded error rather than a silent success that a
// responder would read as "the remediation ran".
type NoopTool struct {
	desc ports.ToolDescriptor
}

// NewNoopTool wraps a descriptor with an inert implementation.
func NewNoopTool(desc ports.ToolDescriptor) *NoopTool { return &NoopTool{desc: desc} }

// Descriptor implements ports.Tool.
func (t *NoopTool) Descriptor() ports.ToolDescriptor { return t.desc }

// Invoke implements ports.Tool.
func (t *NoopTool) Invoke(_ context.Context, call ports.ToolInvocation) (ports.ToolResult, error) {
	if !call.DryRun {
		return ports.ToolResult{}, fmt.Errorf(
			"%s.%s has no implementation in this build; it arrives in Phase 7. "+
				"Refusing to report success for an action that did not happen",
			t.desc.Name, call.Action)
	}
	return ports.ToolResult{
		Output: map[string]any{
			"dry_run": true,
			"would_have_run": fmt.Sprintf("%s.%s with %d parameter(s)",
				t.desc.Name, call.Action, len(call.Params)),
		},
		Stdout:  fmt.Sprintf("[dry run] %s.%s\n", t.desc.Name, call.Action),
		Changed: false,
	}, nil
}
