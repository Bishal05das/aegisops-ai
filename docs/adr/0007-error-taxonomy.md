# ADR 0007 — Errors carry two audiences

- **Status:** accepted
- **Date:** 2026-08-29
- **Phase:** 2

## Context

An error in AegisOps travels a long way: a Postgres driver failure surfaces in a
repository, passes through a service, through the harness, and finally into an
HTTP response or an audit log entry. Along that path it acquires two audiences
whose needs are directly opposed.

| | Needs | Must never see |
|---|---|---|
| **Operator** | failing operation, driver error, parameters, incident ID | — |
| **API caller** | stable code, safe message, correlation ID | schema names, queries, file paths, internal IDs |

Go's convention — `fmt.Errorf("load incident: %w", err)` — serves the operator
well and the caller not at all. Handing that string to a client leaks internal
structure and tells them nothing actionable. The common alternative, returning a
bare `"internal error"`, serves the caller badly and the operator worse.

A second, quieter problem: `errors.New` carries no classification, so every
handler ends up re-deriving "is this a 404 or a 500?" from string matching or
sentinel comparisons. That logic drifts between handlers.

## Decision

One structured type, `pkg/errs.Error`, carrying both views, plus a `Kind` that is
the *sole* input to HTTP status selection.

```go
type Error struct {
    Op      string         // "postgres.IncidentRepo.Get" — builds a call chain
    Kind    Kind           // drives HTTP status AND retry policy
    Code    string         // stable, client-facing: "incident_not_found"
    Message string         // safe to display
    Err     error          // wrapped cause — never crosses the boundary
    Fields  map[string]any // structured log context
}
```

`Error.Public()` is the only method that produces client-facing output. For every
kind except `Internal` it returns the author-written message; for `Internal` it
substitutes a generic string unconditionally, because an `Internal` message may
embed a driver error.

### Consequences that fall out of the design

**`Internal` is the zero value.** An `Error` whose kind was never set, and any
plain error that never passed through this package, classifies as `Internal` and
therefore renders as an opaque 500. The conservative disclosure is the default;
leaking requires an explicit decision.

**Status mapping is total.** `Kind.HTTPStatus()` is a closed switch with a
`default`, so an unmapped kind cannot escape as a 200.

**Context errors are translated explicitly.** `context.Canceled` and
`DeadlineExceeded` arrive from deep inside the standard library without passing
through `E`. `StatusOf` intercepts them: cancellation becomes 499, deadline
becomes 504. Counting a client hanging up as a 500 pollutes the error rate that
pages an on-call.

**Log level follows fault, not status.** `ShouldLogAsError` distinguishes server
faults from client mistakes. A 404 logs at debug, a 401 at warn, a 500 at error.
Logging every 4xx at error level is precisely how an error dashboard becomes
noise that operators learn to ignore — at which point it has negative value.

**`Ops()` replaces stack traces.** Nested errors form a readable call path
(`api.CreateIncident: service.Create: postgres.Insert`) at a fraction of the cost
of capturing a stack on every error — which matters when errors are a normal
control-flow outcome, as they are for a harness that rejects requests by design.

**`Retryable()` is a first-class question.** The harness must decide between
backing off and dead-lettering a failed tool execution. Deriving that from a
status code at the transport layer would place the decision in the wrong place;
`Timeout`, `Unavailable` and `RateLimited` are retryable, everything else is not.

**One rendering path.** `internal/api/render.WriteError` is the single exit point
for every failing request, which is what makes "no internal detail leaks" and
"every error carries a request ID" enforceable rather than aspirational.

## Consequences

**Positive**

- The information-leak class of bug is closed structurally, not by review.
- Clients get one envelope shape and a stable `code` to branch on.
- Every error response carries a request ID that maps to exactly one log line.
- Handlers contain no status-code logic; they return classified errors.

**Negative**

- Every call site must pick a `Kind`, and picking wrong misrenders the response.
  Mitigated by `Internal` being the safe default.
- `Op` strings are maintained by hand and can drift after a rename. Accepted:
  a stale `Op` is a cosmetic log defect, whereas per-error stack capture is a
  real cost on a hot path.
- `errs.E`'s variadic signature is less type-safe than separate constructors.
  Chosen for call-site readability; misuse is caught and surfaced in the message
  rather than silently dropped.

## Alternatives rejected

| Option | Why not |
|---|---|
| `fmt.Errorf` + sentinels | No classification; every handler re-derives status from string or sentinel matching, and that logic drifts. |
| `github.com/pkg/errors` | Stack traces on every error are costly where errors are normal control flow, and it still solves neither the classification nor the disclosure problem. |
| Separate `PublicError` / `InternalError` types | Forces a conversion at every layer boundary; the conversion is exactly what gets forgotten. |
| RFC 7807 `application/problem+json` | Reasonable, and the envelope here is deliberately close to it. Rejected for now because `problem+json` has no natural slot for a correlation ID and the `type` URI field is dead weight for an internal API. Worth revisiting if the API becomes public. |
