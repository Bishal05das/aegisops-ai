// Package agents implements the seven specialists and the engine that
// coordinates them.
//
// # The boundary
//
// Read [Agent] with one question in mind: what can an implementation of it do to
// your infrastructure? The answer is nothing.
//
// [Agent.Execute] returns an [Output]. The most powerful thing an Output can
// contain is a slice of *harness.ToolCallRequest — a struct with no methods that
// act, no client, no credentials, no network. An agent describes an action; it
// cannot take one. Turning a description into an effect is the harness's job,
// behind five gates the agent cannot reach past.
//
// This is why the package imports internal/domain/harness (for the request type)
// and never internal/tools. A Phase 12 import-graph test asserts that, so the
// boundary is a build failure rather than a review comment.
//
// See docs/adr/0006-harness-as-security-boundary.md.
package agents

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// Agent is one specialist.
//
// Implementations must be safe for concurrent use: the orchestrator fans several
// out at once, and the same instance serves every incident.
type Agent interface {
	// Kind identifies which of the seven this is.
	Kind() agent.Kind

	// Describe is a one-line charter, shown in the API and in logs.
	Describe() string

	// Execute performs the agent's work.
	//
	// It must respect ctx: an incident resolved by another path, or a
	// deadline exceeded, must be able to stop work in flight. A reasoner call
	// is the slowest thing here and is the reason ctx matters.
	Execute(ctx context.Context, in Input) (Output, error)
}

// Input is what an agent is given.
type Input struct {
	// Incident is a snapshot, not a live handle. Agents do not mutate it —
	// the orchestrator owns the aggregate and applies changes through the
	// repository, where optimistic locking can catch a conflict. An agent
	// holding a mutable aggregate would make lost updates invisible.
	Incident *incident.Incident

	// Task is this agent's unit of work, already persisted.
	Task *agent.Task

	// Evidence is what earlier agents found. Diagnosis reads what Monitoring
	// and Log Analysis produced; Action reads the diagnosis. This is the
	// dependency the orchestrator's phasing exists to satisfy.
	Evidence *Evidence

	// Params carries per-dispatch configuration.
	Params map[string]any
}

// Output is what an agent produces.
type Output struct {
	// Summary is a human-readable conclusion, written to the incident timeline.
	Summary string

	// Findings is the machine-readable result. Schemaless because each agent
	// produces a different shape and later agents read only the keys they
	// understand — a typed union would need editing for every new agent.
	Findings map[string]any

	// ToolCalls are INTENTS, not actions.
	//
	// The entire attack surface an agent presents. If a reasoner hallucinates
	// Action "delete_all_volumes", this slice carries that string to the
	// harness, which refuses it and writes an audit row. Nothing here executes.
	ToolCalls []*harness.ToolCallRequest

	// Confidence is the agent's self-reported certainty, 0..1.
	//
	// Load-bearing: the policy engine routes a low-confidence conclusion to a
	// human even when the action is otherwise automatic. A weak local model
	// reasoning poorly is precisely what that check catches.
	Confidence float64

	// NextAgents lets an agent request follow-up work. Advisory only — the
	// orchestrator decides, because an agent that could schedule itself could
	// loop forever.
	NextAgents []agent.Kind
}

// Evidence is the shared, growing record of what an investigation has learned.
//
// Passed to every agent so that reasoning happens over the whole picture rather
// than one agent's slice of it.
//
// Safe for concurrent use. The orchestrator runs three agents at once in its
// first wave, so every method here takes the lock — including the readers.
//
// The maps are unexported so that they cannot be read without one. That is the
// point rather than an accident of style: an earlier version guarded only the
// writes and told callers to take a Snapshot before reading, which was wrong
// twice over. *Taking the snapshot is itself a read of the shared maps*, so the
// race detector caught concurrent iteration against a guarded write — and even
// with that fixed, exported maps let any caller reach past the lock entirely.
// A type that owns an invariant has to own the access too; a locking protocol
// every caller must remember is a bug waiting for its first forgetful caller.
type Evidence struct {
	mu sync.RWMutex

	// findings maps an agent kind to what it produced.
	findings map[agent.Kind]map[string]any

	// summaries maps an agent kind to its one-line conclusion, which is what
	// gets rendered into a reasoner prompt.
	summaries map[agent.Kind]string

	// confidences records each agent's certainty, so Diagnosis can weight
	// evidence from an agent that was itself unsure.
	confidences map[agent.Kind]float64

	// errors records agents that failed. Deliberately preserved rather than
	// discarded: "the Log Analysis agent could not reach the cluster" is itself
	// evidence, and a diagnosis reached without it should say so.
	errors map[agent.Kind]string
}

// NewEvidence builds an empty evidence set.
func NewEvidence() *Evidence {
	return &Evidence{
		findings:    make(map[agent.Kind]map[string]any),
		summaries:   make(map[agent.Kind]string),
		confidences: make(map[agent.Kind]float64),
		errors:      make(map[agent.Kind]string),
	}
}

// Record adds one agent's output.
func (e *Evidence) Record(kind agent.Kind, out Output) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if out.Findings != nil {
		e.findings[kind] = out.Findings
	}
	e.summaries[kind] = out.Summary
	e.confidences[kind] = out.Confidence
}

// RecordError notes that an agent failed.
func (e *Evidence) RecordError(kind agent.Kind, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errors[kind] = err.Error()
}

// Has reports whether an agent contributed findings.
func (e *Evidence) Has(kind agent.Kind) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.findings[kind]
	return ok
}

// Get returns one agent's findings, detached from the shared map.
func (e *Evidence) Get(kind agent.Kind) map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	src := e.findings[kind]
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// Snapshot returns a detached deep-ish copy.
//
// Handing an agent the live Evidence would let one agent's write race another's
// read. The copy is taken under the read lock, so the snapshot itself is safe to
// take while other agents are recording.
func (e *Evidence) Snapshot() *Evidence {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := NewEvidence()
	for k, v := range e.findings {
		copied := make(map[string]any, len(v))
		for kk, vv := range v {
			copied[kk] = vv
		}
		out.findings[k] = copied
	}
	for k, v := range e.summaries {
		out.summaries[k] = v
	}
	for k, v := range e.confidences {
		out.confidences[k] = v
	}
	for k, v := range e.errors {
		out.errors[k] = v
	}
	return out
}

// Complete reports whether enough evidence exists to diagnose.
//
// Monitoring is the floor: a diagnosis with no metrics is guesswork. Log
// analysis is desirable but not required — a cluster that will not serve logs is
// itself a common failure mode, and refusing to diagnose because of it would
// leave the system useless exactly when it is needed.
func (e *Evidence) Complete() bool {
	return e.Has(agent.KindMonitoring)
}

// AgentCount reports how many agents have contributed a conclusion.
func (e *Evidence) AgentCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.summaries)
}

// FailureCount reports how many agents errored.
func (e *Evidence) FailureCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.errors)
}

// Fields renders evidence for a reasoner prompt or a log line.
func (e *Evidence) Fields() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := map[string]any{}
	for kind, summary := range e.summaries {
		out[string(kind)] = summary
	}
	if len(e.errors) > 0 {
		out["failed_agents"] = e.errors
	}
	return out
}

// intent builds a tool-call request attributed to an agent.
//
// A helper rather than a constructor on the domain type, because every agent
// building an intent needs the same attribution — incident, agent identity, and
// a reason — and forgetting the reason would produce a request the harness
// refuses for a confusing cause.
func intent(clock shared.Clock, in Input, agentID shared.ID, agentName, tool, action, reason string) (*harness.ToolCallRequest, error) {
	req, err := harness.NewToolCallRequest(clock, in.Incident.ID, agentID, tool, action, reason)
	if err != nil {
		return nil, fmt.Errorf("build tool call request: %w", err)
	}
	req.AgentName = agentName
	if in.Task != nil {
		taskID := in.Task.ID
		req.TaskID = &taskID
	}
	return req, nil
}

// base carries what every agent shares.
type base struct {
	kind     agent.Kind
	describe string
	clock    shared.Clock
	// id is the agent's registered database identity, needed to attribute a
	// tool call and a task.
	id shared.ID
	// name is the registered name, carried on tool calls so the audit ledger
	// reads as "the action agent requested…" without a lookup.
	name string
}

// Kind implements Agent.
func (b base) Kind() agent.Kind { return b.kind }

// Describe implements Agent.
func (b base) Describe() string { return b.describe }

// ID returns the agent's registered identity.
func (b base) ID() shared.ID { return b.id }

// Name returns the agent's registered name.
func (b base) Name() string { return b.name }

// Registration binds a code-level agent to its database row.
//
// Agents are constructed from code and reconciled into the agents table at
// startup, so the roster cannot drift from what the binary actually implements —
// see AgentRepository.Upsert.
type Registration struct {
	ID   shared.ID
	Name string
	Kind agent.Kind
}

// DefaultTimeout bounds a single agent's execution.
//
// Generous because a reasoner call on CPU takes seconds, and mean because an
// agent that hangs holds an investigation open. The orchestrator applies it per
// agent, not per investigation, so one slow specialist cannot consume the whole
// budget.
const DefaultTimeout = 2 * time.Minute
