# ADR 0002 — Hexagonal (ports and adapters) architecture

- **Status:** accepted
- **Date:** 2026-08-29
- **Phase:** 1

## Context

AegisOps has an unusually high number of swappable external systems:

- LLM provider (Ollama today, llama.cpp or vLLM tomorrow, a mock in tests)
- event bus (RabbitMQ in production, in-process in unit tests)
- persistence (Postgres in production, in-memory in tests)
- tools (Docker, Kubernetes, Linux, Git, … an open-ended list by design)

It also has a hard requirement that a whole *layer* — the agents — must be
provably unable to reach infrastructure.

A layered-by-technology structure (`handlers/`, `models/`, `db/`) makes both of
these awkward: business rules end up depending on driver types, and "who can
reach what" becomes a convention rather than a fact.

## Decision

Ports and adapters, with the dependency rule enforced by package structure.

```
internal/domain/   entities, value objects, domain errors.
                   Imports nothing outside the standard library. Ever.

internal/ports/    interfaces the core needs the outside world to satisfy:
                   IncidentRepository, EventBus, LLMProvider, ToolExecutor,
                   Clock, IDGenerator.

internal/services/ use cases. Depend on domain + ports. No driver imports.

adapters/          repository/postgres, events/rabbitmq, llm/ollama,
                   memory/redis, api/, tools/*. Implement ports.
```

Composition happens exactly once, in `cmd/aegisopsd/main.go`. That file is the
only place in the codebase that knows RabbitMQ exists.

### Two ports carry unusual weight

```go
// The agents' entire window onto the world. Note what is absent: no client,
// no connection, no credentials. Just a request and a result.
type ToolExecutor interface {
    Execute(ctx context.Context, req domain.ToolCallRequest) (domain.ToolResult, error)
}

// Swapping models must never touch agent code.
type LLMProvider interface {
    Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error)
    Embed(ctx context.Context, texts []string) ([][]float32, error)
    Model() string
}
```

## Consequences

**Positive**

- **Testability.** The agent orchestrator is tested with a scripted
  `LLMProvider`, an in-memory repository and a fake `ToolExecutor` — no Docker,
  no database, no model, and deterministic output. This is what makes the
  Phase 12 E2E scenarios feasible at all.
- **The security boundary becomes structural.** `internal/agents` importing a
  Docker client is a compile-time-visible architectural violation, catchable by
  an import-graph lint rule, not a code-review judgement call.
- **Genuine substitutability.** Each swap in the table below is a one-line change
  in `main.go`.

**Negative**

- More packages and more indirection. Following a request end to end means
  reading three files instead of one.
- Some mapping boilerplate between DTO ⇄ domain ⇄ database row. Accepted
  deliberately: those three shapes drift apart over time, and pretending they are
  the same type is how HTTP field names end up dictating a schema migration.

**Negative, honestly stated**

For a CRUD service this would be over-engineering. It is justified here by the
swap count and by the security boundary — not by architectural preference.

## Enforcement

Phase 12 adds a test that walks the import graph and fails if:

- `internal/domain` imports anything outside stdlib
- `internal/agents` transitively imports any package under `internal/tools`
- `internal/services` imports any adapter package
