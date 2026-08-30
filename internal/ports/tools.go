package ports

import (
	"context"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// Tool is one capability the harness can invoke against real infrastructure.
//
// # Why agents never hold one of these
//
// A Tool has an Invoke method. That single fact is why `internal/agents` must
// never import an implementation of this interface: an agent holding a Tool
// could act, and the entire design rests on it being unable to. Agents produce
// *descriptions* of tool calls; the harness owns the things that can run them.
//
// Implementations arrive in Phase 7. Phase 6 defines the seam and the gates that
// stand in front of it.
type Tool interface {
	// Descriptor declares what this tool is and what it accepts. The registry
	// validates parameters against it before any gate downstream runs, so a
	// malformed call is rejected before it can reach a permission check that
	// might otherwise allow it.
	Descriptor() ToolDescriptor

	// Invoke performs the action.
	//
	// Called only after every gate has passed. It must respect ctx — the
	// harness bounds every invocation, and a tool that ignores cancellation
	// holds an execution slot open past its deadline.
	Invoke(ctx context.Context, call ToolInvocation) (ToolResult, error)
}

// ToolDescriptor is a tool's self-description.
type ToolDescriptor struct {
	// Name is the tool half of the "tool.action" pair — "docker", "kubernetes".
	Name string

	// Description is shown to operators and, in Phase 8, to the model.
	Description string

	// Actions enumerates what the tool can do, keyed by action name.
	Actions map[string]ActionDescriptor
}

// ActionDescriptor declares one action and the parameters it accepts.
type ActionDescriptor struct {
	// Description explains the action in one line.
	Description string

	// Params declares each accepted parameter. A parameter not declared here is
	// rejected rather than ignored: silently dropping an argument the model
	// meant to pass would execute a *different* action from the one approved.
	Params map[string]ParamSpec

	// Mutating marks an action that changes infrastructure.
	//
	// Declared by the tool and cross-checked against the policy table at
	// startup. A mutating action policied as read-only is a misconfiguration
	// that would let a container restart execute automatically, so the two
	// sources of truth are reconciled rather than trusted independently.
	Mutating bool

	// Timeout bounds this specific action. Zero means the harness default.
	Timeout time.Duration
}

// ParamKind is a parameter's type.
type ParamKind string

// Parameter kinds. Deliberately few: parameters are assembled by a language
// model, and every additional type is another shape to validate and another way
// to be surprised.
const (
	ParamString ParamKind = "string"
	ParamInt    ParamKind = "int"
	ParamBool   ParamKind = "bool"
	ParamFloat  ParamKind = "float"
)

// ParamSpec constrains one parameter.
//
// The constraints exist because these values come from an LLM and end up as
// arguments to infrastructure calls. `Pattern` on a container name is not
// bureaucracy — it is what stops a hallucinated value from being interpreted as
// something other than a name by whatever runs downstream.
type ParamSpec struct {
	Kind        ParamKind
	Required    bool
	Description string

	// Default is applied when the parameter is absent and not required.
	Default any

	// Enum restricts a string to a fixed set. Preferred over Pattern wherever
	// the set is knowable, because an allowlist cannot be widened by a clever
	// input the way a regex can be satisfied by an unexpected one.
	Enum []string

	// Pattern is an anchored regular expression a string must match. Compiled
	// once at registration; a tool whose pattern does not compile fails to
	// register rather than silently accepting everything.
	Pattern string

	// Min and Max bound a numeric parameter. Both zero means unbounded.
	Min, Max float64

	// MaxLen bounds a string. Zero means the registry default.
	MaxLen int
}

// ToolInvocation is what the harness hands a tool once every gate has passed.
//
// It carries no decision-making context — no policy, no approval, no agent
// identity beyond attribution. A tool cannot re-decide whether it should run,
// because by the time it holds one of these that question is settled.
type ToolInvocation struct {
	ToolCallID shared.ID
	Action     string
	Params     map[string]any

	// DryRun asks the tool to describe what it would do without doing it.
	//
	// Passed to the tool rather than handled entirely above it because some
	// tools can do meaningfully better than "return nothing" — a Kubernetes
	// apply can server-side dry-run and report the real diff.
	DryRun bool

	// IncidentID and RequestID are for the tool's own logging and for any
	// annotation it leaves on the infrastructure it touches.
	IncidentID shared.ID
	RequestID  string
}

// ToolResult is what a tool reports back.
//
// Stdout, Stderr and ExitCode are captured into the execution record today.
// Output and Changed are the Phase 7 contract and are **not yet persisted** —
// the executions table has no structured-output column, and adding one belongs
// with the phase that produces real output to put in it. They are declared here
// for the same reason the tool descriptors are declared before their
// implementations: so the shape is agreed before anything depends on it.
type ToolResult struct {
	// Output is the machine-readable result. Phase 7 carries it into the
	// execution record and makes it available to later agents as evidence.
	Output map[string]any

	Stdout   string
	Stderr   string
	ExitCode *int

	// Changed reports whether infrastructure was actually modified. A restart
	// that found the container already stopped did not change anything, and a
	// postmortem should be able to tell those apart.
	Changed bool
}

// ToolExecutor runs a tool call that has passed every gate.
//
// A port rather than a concrete type so the harness can be wired to a dry-run
// executor in development and a live one in production, and so tests can assert
// the gates without a Docker daemon. See harness.DryRunExecutor.
type ToolExecutor interface {
	// Execute invokes the tool and records what happened.
	//
	// The returned Execution is always non-nil when err is nil. A tool that
	// fails produces an Execution with status failed rather than an error: the
	// harness needs the record either way, and "the remediation ran and failed"
	// is a different fact from "the harness could not run it".
	Execute(ctx context.Context, req *harness.ToolCallRequest) (*harness.Execution, error)

	// Known reports whether a tool.action pair can be executed at all.
	Known(tool, action string) bool
}
