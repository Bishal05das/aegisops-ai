# ADR 0008 — `database/sql` with pgx as driver; a hand-written migration runner

- **Status:** accepted
- **Date:** 2026-08-29
- **Phase:** 3

## Context

Phase 3 introduces the project's **first third-party dependency**. Phases 1 and 2
had none: `go.mod` carried no `require` block, and PostgreSQL, Redis and AMQP
were probed by writing their wire protocols directly over `net.Conn`.

That streak has to end here, and the reason is worth being precise about. The
"raw Go" constraint is about not hiding the machinery that determines whether a
control plane survives production — routing, middleware ordering, timeouts,
shutdown. It is not an argument for reimplementing the PostgreSQL frontend/backend
protocol, which is roughly 15,000 lines including binary type codecs, COPY, SSL
negotiation and SASL authentication. Writing that badly would be worse than not
writing it: a subtly wrong type codec silently corrupts data.

So the question is not *whether* to take a driver, but which interface to use.

## Decision

**`database/sql` as the interface, `github.com/jackc/pgx/v5/stdlib` as the
driver.** A hand-written migration runner. No ORM, no query builder, no
migration library.

```go
import _ "github.com/jackc/pgx/v5/stdlib"   // registered for its side effect only

db, err := sql.Open("pgx", dsn)
```

`pgx` is imported in exactly one file. Every repository speaks `database/sql`.

### Why `database/sql` rather than native pgx

Native `pgx` is faster (roughly 10–20% on high-throughput workloads), has richer
type support, and is what most Go teams reach for. It was rejected here for three
reasons:

1. **The project brief names `database/sql` as an allowed package.** That is a
   constraint on this codebase, and it is satisfiable without cost.
2. **pgvector does not require it.** The concern that pushed toward native pgx —
   vector types for Phase 9 — turns out to be a non-issue: a vector round-trips
   through `driver.Valuer`/`sql.Scanner` like any other custom type. JSONB works
   as `[]byte` plus `encoding/json`, and `= ANY($1)` accepts a Go `[]string`
   through pgx's stdlib adapter (verified, not assumed).
3. **The swap point that matters is elsewhere.** If `COPY` or `LISTEN/NOTIFY`
   are ever needed, moving to native pgx happens inside
   `internal/repository/postgres` — behind the repository port — without a
   single service or domain type changing. That is what the hexagon is for.

What `database/sql` costs: a small performance overhead, and no access to
Postgres-specific features without dropping to a raw connection. What it buys:
`*sql.DB` pooling semantics that every Go developer already knows,
`*sql.Tx` for the context-carried transaction manager, and a driver-agnostic
error path — the adapter matches on SQLSTATE through a small local interface
rather than importing `pgconn`.

### Why no ORM or query builder

Queries here are not generic CRUD. The optimistic-locking update, the sequence
assignment inside `AppendEvent`, the advisory-locked audit append, and keyset
pagination all depend on writing exactly the SQL intended. An ORM would obscure
the `WHERE version = $n` clause that is the entire point of that update, and a
query builder would add a layer of indirection over SQL that is already the
clearest expression of the intent.

The cost is real: hand-written scanning is positional and a column reordered in
the `SELECT` list without reordering `Scan` is a silent bug. Mitigated by naming
the column list as a single shared constant per table, never `SELECT *`.

### Why a hand-written migration runner

~250 lines instead of golang-migrate or goose, for three properties that are
easier to guarantee than to verify in a dependency:

- **Advisory locking.** Several replicas start simultaneously during a rolling
  deploy. `pg_advisory_lock` makes "only one migrates" a three-line guarantee.
- **Checksum verification.** Editing a migration that has already run diverges
  the database from the repository silently — the file says one thing, the
  database holds another, and nothing complains until a query fails in
  production. Recording a SHA-256 turns that into a startup error naming the
  file and telling the operator to add a new migration instead.
- **Embedding.** `go:embed` means a binary carries its own schema and can
  migrate itself in a container with no volume mount and no second artefact to
  keep in step with the image.

## Consequences

**Positive**

- One dependency (plus three transitive), auditable, from a maintained project.
- Every SQL statement in the codebase is visible and reviewable.
- The migration runner's failure modes are ours to reason about, and its
  advisory lock makes startup migration safe with any replica count.
- Swapping to native pgx, or to another Postgres driver entirely, is contained
  within one package.

**Negative**

- Positional `Scan` is fragile. A column added to a `SELECT` list without a
  matching `Scan` destination fails at runtime, not compile time. Partly
  mitigated by shared column constants; fully mitigated only by the integration
  tests, which is why every repository has round-trip coverage.
- More boilerplate per repository than an ORM would need.
- The migration runner is ours to maintain, including its edge cases. It
  deliberately does not support out-of-order versions or partial application:
  gaps are refused at load time, because a database that no clean run can
  reproduce is worse than a failed deploy.

**Deliberately deferred**

`ToolCallRepository`, `TaskRepository` and `PolicyRepository` are declared as
ports and their tables exist, but their adapters land in the phases that consume
them (6, 5 and 6 respectively). Writing them now would mean writing them against
guessed requirements.

## Alternatives rejected

| Option | Why not |
|---|---|
| **Native pgx v5 + pgxpool** | Genuinely better on raw throughput and types. Rejected because the brief names `database/sql`, the pgvector concern evaporated on inspection, and the port makes it a contained future change rather than a decision that must be made now. |
| **`lib/pq`** | In maintenance mode, no longer receiving feature work. pgx is the actively developed driver. |
| **GORM / ent / sqlc** | GORM and ent hide the exact SQL that several of these queries depend on. sqlc is closer in spirit — it generates from real SQL — but it adds a code-generation step to the build for a schema whose queries are hand-tuned anyway. |
| **golang-migrate / goose** | Both work. Rejected for the reasons above: the three properties that matter are ~250 lines to own outright, and owning them means the advisory-lock and checksum semantics are exactly what this system needs rather than what the library chose. |
| **A separate vector database** | Covered by [ADR 0005](0005-postgres-with-pgvector.md): the dual-write consistency problem is not worth the vector performance at this scale. |
