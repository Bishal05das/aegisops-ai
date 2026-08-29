# ADR 0001 — Raw `net/http`, no web framework

- **Status:** accepted
- **Date:** 2026-08-29
- **Phase:** 1

## Context

Go's ecosystem offers Gin, Fiber, Echo and Chi. All of them work. All of them
also hide the parts of an HTTP server that determine whether a control plane
survives production: timeout configuration, graceful shutdown ordering, body
size limits, and the exact semantics of middleware ordering.

AegisOps is a control plane that executes actions against real infrastructure.
When it misbehaves, the questions are "which middleware swallowed that context
cancellation?" and "why did shutdown drop an in-flight approval?" — questions a
framework makes harder to answer, not easier.

## Decision

Use the Go standard library only. `net/http`, `context`, `encoding/json`,
`database/sql`, `crypto/*`.

Hand-write:

- the router (Go 1.22+ `ServeMux` supports method-and-wildcard patterns —
  `POST /api/incidents/{id}` — which removes the last real reason to import one)
- the middleware chain, as `func(http.Handler) http.Handler`
- request decoding, validation and the error-to-status mapping
- JWT verification and RBAC enforcement
- rate limiting
- graceful shutdown

## Consequences

**Positive**

- Timeouts, shutdown and body limits are explicit and reviewable in one file.
- Zero dependency CVEs in the request path — the largest single attack surface
  of any web service.
- The panic-recovery, auth and audit middleware are ours, so a request that
  reaches a tool execution can be traced through code we wrote end to end.
- Demonstrates the depth this project exists to demonstrate.

**Negative**

- More code to write and test. Roughly 400–600 lines across Phases 2 and 4 that
  a framework would have supplied.
- No community middleware. Anything exotic (content negotiation, HTTP/3) is ours
  to build.

**Mitigation**

- `pkg/httpx` isolates the generic HTTP machinery from AegisOps domain logic, so
  it is independently testable and, if it ever needed replacing, replaceable.

## Alternatives rejected

| Option | Why not |
|---|---|
| **Chi** | Genuinely close to stdlib and a fine choice. Rejected because stdlib `ServeMux` now covers its routing feature set, so it would add a dependency for nothing. |
| **Gin / Fiber / Echo** | Own the context type, own error handling, own the middleware contract. Fiber is not even `net/http`-based, which would rule out standard tooling. |
| **gRPC-only** | Poor fit for human approval workflows and browser-based operator UIs. gRPC may still be added later for agent↔agent transport. |
