package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// remediationPlan is the Action agent's parsed answer.
type remediationPlan struct {
	Summary string         `json:"summary"`
	Tool    string         `json:"tool"`
	Action  string         `json:"action"`
	Params  map[string]any `json:"params"`
	Reason  string         `json:"reason"`
}

// parseRemediation decodes a remediation plan from a reasoner's answer.
//
// Strict on purpose. A reasoner that returns prose where JSON was demanded has
// not answered the question, and guessing at its intent is exactly how a
// remediation ends up targeting the wrong thing. The caller turns a parse
// failure into an escalation, not into a default action.
func parseRemediation(content string) (remediationPlan, error) {
	var plan remediationPlan

	// Models frequently wrap JSON in a markdown fence even when told not to.
	// Tolerating that is not laxity — it is not ambiguity, and refusing over a
	// decoration would waste an expensive call.
	cleaned := stripCodeFence(strings.TrimSpace(content))

	if err := json.Unmarshal([]byte(cleaned), &plan); err != nil {
		return plan, fmt.Errorf("remediation plan is not valid JSON: %w", err)
	}
	if plan.Tool == "" || plan.Action == "" {
		return plan, fmt.Errorf("remediation plan names no tool or action")
	}
	if plan.Reason == "" {
		// The harness requires a reason and would refuse this anyway; failing
		// here produces a clearer message than a downstream validation error.
		return plan, fmt.Errorf("remediation plan carries no justification")
	}
	if plan.Params == nil {
		plan.Params = map[string]any{}
	}
	return plan, nil
}

// stripCodeFence removes a surrounding ```json fence if present.
func stripCodeFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSuffix(strings.TrimSpace(s), "```")
}

// -----------------------------------------------------------------------------
// Scripted reasoner
// -----------------------------------------------------------------------------

// ScriptedReasoner answers from a fixed table instead of a model.
//
// Not a throwaway stub. It serves two real purposes:
//
//   - **The system runs with no model at all.** A developer who has not pulled
//     4.7 GB of weights can still start the daemon, file an incident and watch a
//     full investigation execute.
//   - **Orchestration becomes assertable.** A test cannot make claims about the
//     output of a sampled 7B model, but it can assert that the right agents ran
//     in the right order, that a low-confidence diagnosis produced no tool call,
//     and that the harness refused what it was supposed to refuse. Those are the
//     properties worth testing, and they need a deterministic reasoner to be
//     testable at all.
//
// Phase 8 adds the Ollama implementation beside this one; both satisfy
// ports.Reasoner, so nothing above the port changes.
type ScriptedReasoner struct {
	mu sync.RWMutex
	// answers maps a task name to a canned response.
	answers map[string]ports.ReasoningResponse
	// fallback answers any task with no entry.
	fallback ports.ReasoningResponse
	// failures maps a task name to an error, for exercising failure paths.
	failures map[string]error
	// delay simulates reasoning latency, so a test can exercise timeouts and
	// concurrency without a real model.
	delay time.Duration
	// calls records what was asked, so a test can assert on the prompts an
	// agent actually built.
	calls []ports.ReasoningRequest
}

// NewScriptedReasoner builds a reasoner with sensible default answers.
func NewScriptedReasoner() *ScriptedReasoner {
	return &ScriptedReasoner{
		answers:  defaultScript(),
		failures: map[string]error{},
		fallback: ports.ReasoningResponse{
			Content:    "No scripted answer for this task.",
			Confidence: 0.5,
			Model:      "scripted",
		},
	}
}

var _ ports.Reasoner = (*ScriptedReasoner)(nil)

// Name implements ports.Reasoner.
func (r *ScriptedReasoner) Name() string { return "scripted" }

// Reason implements ports.Reasoner.
func (r *ScriptedReasoner) Reason(ctx context.Context, req ports.ReasoningRequest) (ports.ReasoningResponse, error) {
	r.mu.Lock()
	r.calls = append(r.calls, req)
	delay := r.delay
	failure := r.failures[req.Task]
	answer, known := r.answers[req.Task]
	fallback := r.fallback
	r.mu.Unlock()

	if delay > 0 {
		// Honour cancellation while "thinking", exactly as a real reasoner
		// must: an incident resolved by another path cancels work in flight.
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ports.ReasoningResponse{}, &ports.ReasoningError{
				Op: "scripted.Reason", Kind: ports.ReasoningTimeout,
				Message: "cancelled while reasoning", Underlying: ctx.Err(),
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return ports.ReasoningResponse{}, &ports.ReasoningError{
			Op: "scripted.Reason", Kind: ports.ReasoningTimeout,
			Message: "context is already done", Underlying: err,
		}
	}
	if failure != nil {
		return ports.ReasoningResponse{}, failure
	}
	if !known {
		return fallback, nil
	}
	return answer, nil
}

// SetAnswer overrides the response for one task.
func (r *ScriptedReasoner) SetAnswer(task string, resp ports.ReasoningResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[task] = resp
}

// SetFailure makes one task fail, for exercising failure handling.
func (r *ScriptedReasoner) SetFailure(task string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures[task] = err
}

// SetDelay makes every call take the given time.
func (r *ScriptedReasoner) SetDelay(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delay = d
}

// Calls returns the requests received, so a test can assert on the prompts.
func (r *ScriptedReasoner) Calls() []ports.ReasoningRequest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ports.ReasoningRequest, len(r.calls))
	copy(out, r.calls)
	return out
}

// CallCount reports how many times the reasoner was invoked.
func (r *ScriptedReasoner) CallCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.calls)
}

// defaultScript is a coherent walkthrough of one plausible incident.
//
// Written as a single consistent story — a memory leak in a worker pool leading
// to OOM kills, remediated by a container restart — so that running the daemon
// with no model still demonstrates the whole pipeline rather than producing
// disconnected placeholder text.
func defaultScript() map[string]ports.ReasoningResponse {
	return map[string]ports.ReasoningResponse{
		"plan_investigation": {
			Content: "Dispatching monitoring, log analysis and security in parallel. " +
				"They read different sources and none depends on another's output.",
			Confidence: 0.9, Model: "scripted", PromptVersion: "v1",
		},
		"collect_metrics": {
			Content: "Memory on the affected pods climbs steadily to the limit and then " +
				"resets, consistent with repeated OOM kills. CPU and network are normal.",
			Confidence: 0.85, Model: "scripted", PromptVersion: "v1",
		},
		"analyse_logs": {
			Content: "Repeated \"container killed due to memory limit\" entries, each " +
				"preceded by a burst of worker-pool allocations that are never released.",
			Confidence: 0.8, Model: "scripted", PromptVersion: "v1",
		},
		"security_review": {
			Content: "No indicators of compromise. The allocation pattern is internal " +
				"and matches a recent deployment, not an external actor.",
			Confidence: 0.9, Model: "scripted", PromptVersion: "v1",
		},
		"diagnose": {
			Content: "A memory leak in the worker pool: allocations are retained across " +
				"requests, exhausting the container limit and triggering OOM kills.",
			Confidence: 0.82, Model: "scripted", PromptVersion: "v1",
		},
		"plan_remediation": {
			// Deliberately JSON: the Action agent parses this, so the scripted
			// path exercises the same parser the real model's output will hit.
			Content: `{"summary":"Restart the affected container to reclaim leaked memory. ` +
				`This buys time; the leak still needs a code fix.",` +
				`"tool":"docker","action":"restart_container",` +
				`"params":{"container":"api-worker","graceful":true},` +
				`"reason":"The worker pool has exhausted its memory limit and is being ` +
				`OOM killed repeatedly. A restart reclaims the leaked allocations and ` +
				`restores service while the underlying leak is fixed."}`,
			Confidence: 0.78, Model: "scripted", PromptVersion: "v1",
		},
		"write_postmortem": {
			Content: "The api-worker service became unavailable after repeated OOM kills " +
				"caused by a memory leak in its worker pool. A container restart restored " +
				"service. Prevention: bound the pool's retained allocations and add a " +
				"memory-growth alert ahead of the container limit.",
			Confidence: 0.85, Model: "scripted", PromptVersion: "v1",
		},
	}
}
