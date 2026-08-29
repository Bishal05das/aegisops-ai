# ADR 0003 — Local LLMs only, behind a provider port

- **Status:** accepted
- **Date:** 2026-08-29
- **Phase:** 1 (decision) / 8 (implementation)

## Context

The reasoning layer needs an LLM. A hosted API would be the path of least
resistance — but for this system it is the wrong choice on three independent
grounds, any one of which would be sufficient:

1. **Data sensitivity.** Diagnosis requires feeding the model production logs,
   stack traces, environment variables, config and topology. That is among the
   most sensitive data an organisation holds, and shipping it to a third party
   during an outage is a decision most security teams would veto.
2. **Availability coupling.** An incident-response system that stops working
   when its vendor has an incident is not an incident-response system. Network
   partitions are precisely when you need it most.
3. **Cost shape.** Agentic loops are token-hungry — a single investigation may
   involve 20+ completions across seven agents. Per-token pricing turns a busy
   incident week into an unbounded bill.

Additionally, this project has a hard constraint: **no paid APIs.**

## Decision

All inference runs locally. Access is exclusively through a port:

```go
// internal/ports
type LLMProvider interface {
    Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error)
    Stream(ctx context.Context, req CompletionRequest) (iter.Seq2[Chunk, error], error)
    Embed(ctx context.Context, texts []string) ([][]float32, error)
    Model() string
    Health(ctx context.Context) error
}
```

**Primary provider:** Ollama (`internal/llm/ollama`) — HTTP, trivially
implemented over `net/http`, and already installed on the target machine.

**Default model:** `qwen2.5:7b`. Chosen for strong instruction-following and
reliable structured JSON output at 7B, which matters more here than raw
reasoning: every agent's output is parsed as a typed struct, and a model that
emits prose where JSON was requested breaks the pipeline regardless of how
clever the prose is.

**Additional adapters:** `llamacpp` (direct GGUF), `mock` (scripted, for tests).

### Design rules that follow

- **Never trust model output shape.** Every completion that must be structured is
  decoded into a Go struct with validation. A parse failure is a retryable error
  with a repair prompt, not a panic.
- **Model choice is configuration.** `AEGIS_LLM_PROVIDER` / `AEGIS_LLM_MODEL`.
  No agent contains a model name.
- **Every call is bounded.** Timeout, token cap, and a context that is cancelled
  when the incident is resolved.
- **Prompts are versioned artefacts.** Stored under `internal/agents/prompts/`
  and recorded by version in the audit log, so a postmortem can reproduce the
  exact reasoning inputs.

## Consequences

**Positive**

- Fully air-gapped after the initial `ollama pull`. No egress, no vendor.
- Deterministic cost: electricity.
- `temperature=0.1` plus a local model gives near-reproducible runs — valuable
  for E2E testing, and impossible to guarantee against a moving hosted endpoint.

**Negative**

- A 7B model reasons less well than a frontier model. Expect weaker root-cause
  inference on genuinely novel failures.
- Latency: ~2–10 s per completion on CPU. An investigation takes minutes.
- ~5 GB disk and ~6 GB RAM while resident.

**Mitigations**

- The confidence score from the Diagnosis Agent is load-bearing. Low confidence
  routes to a human rather than to an action.
- Long-term memory (pgvector) supplies precedent from past incidents, which
  lifts a 7B model's practical accuracy far more than raw parameter count does.
- The port makes "upgrade to a 32B model on a GPU box" a config change.
- Risk tiering means weak reasoning cannot cause a destructive action — the
  harness gates that independently.

## Alternatives rejected

| Option | Why not |
|---|---|
| OpenAI / Anthropic / Gemini APIs | Paid; excluded by project constraint. Also fails the data-sensitivity and availability arguments above. |
| Fine-tuning a small model | Needs labelled incident data that does not exist yet. RAG over real history is strictly better at this stage. |
| Rules engine, no LLM | Handles known failure modes only. The value here is in the unknown ones. |
