package ports

import (
	"context"
	"time"
)

// Reasoner turns a structured question into a structured answer.
//
// This is the seam between the agents and the LLM, and it is deliberately not
// called "LLMProvider". Agents do not need to know a language model exists —
// they need something that reasons over evidence. That framing is what allows
// three very different implementations to coexist:
//
//   - internal/llm/ollama    — a local model (Phase 8)
//   - agents/reasoning       — scripted, deterministic (this phase, and tests)
//   - a future rules engine   — for failure modes where a model adds nothing
//
// The scripted implementation is not a stub to be thrown away. Deterministic
// reasoning is what makes the Phase 12 end-to-end scenarios assertable at all:
// a test cannot assert on the output of a sampled 7B model, but it can assert
// that the orchestrator dispatched the right agents in the right order and that
// the harness refused the action it was supposed to refuse.
type Reasoner interface {
	// Reason answers one question. Implementations must respect ctx: a
	// reasoner is the slowest thing in an investigation, and an incident that
	// resolves by other means must be able to cancel work in flight.
	Reason(ctx context.Context, req ReasoningRequest) (ReasoningResponse, error)

	// Name identifies the backing implementation for logs and the audit trail.
	// A postmortem asking "why did it conclude that" needs to know whether a
	// model or a script produced the answer.
	Name() string
}

// ReasoningRequest is one question put to a reasoner.
type ReasoningRequest struct {
	// Task names what is being asked, e.g. "diagnose" or "plan_remediation".
	// Implementations select a prompt template by it.
	Task string

	// SystemPrompt constrains the reasoner's role and output shape.
	SystemPrompt string

	// Context is the evidence to reason over: metrics, log excerpts, prior
	// findings. Structured rather than pre-rendered so each implementation
	// formats it in whatever way suits it.
	Context map[string]any

	// Question is the specific thing being asked.
	Question string

	// ResponseSchema describes the JSON shape expected back.
	//
	// Every reasoning result in this system is parsed into a typed struct. A
	// model that returns prose where JSON was requested breaks the pipeline
	// regardless of how good the prose is, so the shape is stated up front and
	// validated on the way back.
	ResponseSchema string

	// MaxTokens and Temperature bound the answer. Temperature is near zero
	// throughout: diagnosis needs to be as reproducible as a sampled model
	// allows, which is a correctness requirement rather than a style choice.
	MaxTokens   int
	Temperature float64

	// Timeout bounds this single call. Zero means the implementation's default.
	Timeout time.Duration
}

// ReasoningResponse is a reasoner's answer.
type ReasoningResponse struct {
	// Content is the raw answer, usually JSON matching ResponseSchema.
	Content string

	// Confidence is the reasoner's self-reported certainty, 0..1.
	//
	// Load-bearing rather than decorative: the policy engine routes a
	// low-confidence conclusion to a human even when the proposed action is
	// otherwise automatic. A weak local model reasoning poorly is exactly what
	// that check exists to catch.
	Confidence float64

	// Model and PromptVersion identify what produced this, so a postmortem can
	// reproduce the reasoning inputs exactly.
	Model         string
	PromptVersion string

	// TokensIn, TokensOut and Duration feed the metrics in Phase 11 — LLM cost
	// and latency are the two numbers that determine whether an agentic loop is
	// viable on given hardware.
	TokensIn  int
	TokensOut int
	Duration  time.Duration
}

// ReasoningError distinguishes a reasoner failing from a reasoner answering
// unusably.
//
// The difference decides what happens next. An unreachable model is retryable
// and transient; a model that returned prose where JSON was demanded will do it
// again, and the caller should re-prompt with a repair instruction rather than
// blindly retrying the identical request.
type ReasoningError struct {
	Op         string
	Kind       ReasoningErrorKind
	Message    string
	Underlying error
	// RawContent is what came back when the failure was a parse failure, so a
	// repair prompt can quote it and a log can show what the model actually said.
	RawContent string
}

// ReasoningErrorKind classifies a reasoning failure.
type ReasoningErrorKind string

// Reasoning failure kinds.
const (
	// ReasoningUnavailable means the reasoner could not be reached. Retryable.
	ReasoningUnavailable ReasoningErrorKind = "unavailable"
	// ReasoningTimeout means the call exceeded its deadline. Retryable.
	ReasoningTimeout ReasoningErrorKind = "timeout"
	// ReasoningMalformed means the answer did not match the requested schema.
	// Retry with a repair prompt, not with the same request.
	ReasoningMalformed ReasoningErrorKind = "malformed_response"
	// ReasoningRefused means the reasoner declined to answer.
	ReasoningRefused ReasoningErrorKind = "refused"
)

// Error implements error.
func (e *ReasoningError) Error() string {
	if e.Underlying != nil {
		return e.Op + ": " + string(e.Kind) + ": " + e.Message + ": " + e.Underlying.Error()
	}
	return e.Op + ": " + string(e.Kind) + ": " + e.Message
}

// Unwrap supports errors.Is and errors.As.
func (e *ReasoningError) Unwrap() error { return e.Underlying }

// Retryable reports whether re-issuing the same request could plausibly succeed.
func (e *ReasoningError) Retryable() bool {
	return e.Kind == ReasoningUnavailable || e.Kind == ReasoningTimeout
}
