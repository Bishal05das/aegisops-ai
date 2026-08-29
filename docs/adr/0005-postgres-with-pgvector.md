# ADR 0005 — One PostgreSQL for records and vectors; Redis for working memory

- **Status:** accepted
- **Date:** 2026-08-29
- **Phase:** 1 (decision) / 3 and 9 (implementation)

## Context

The system needs three distinct kinds of storage:

1. **Records** — incidents, tasks, executions, approvals, users, audit log.
   Relational, transactional, permanent, queried by exact predicate.
2. **Semantic memory** — "have we seen a failure like this before?" Requires
   embedding similarity search over past postmortems and runbooks.
3. **Working memory** — the current incident's state, an agent's scratchpad,
   distributed locks, idempotency keys. High-churn, short-lived, expendable.

The obvious architecture — Postgres + Pinecone/Qdrant + Redis — introduces a
dual-write problem between (1) and (2) that is worse than it first appears.

## Decision

**Two engines, three roles.**

### PostgreSQL 17 + pgvector — records *and* semantic memory

```sql
-- Records and their embeddings share a transaction boundary.
CREATE TABLE memory_records (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id  UUID REFERENCES incidents(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,           -- postmortem | runbook | resolution
    content      TEXT NOT NULL,
    embedding    vector(768) NOT NULL,    -- nomic-embed-text
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON memory_records
    USING hnsw (embedding vector_cosine_ops);
```

The decisive argument: **an incident and the embedding of its postmortem must be
written atomically.** With a separate vector database, writing the incident and
writing the vector are two operations with no shared transaction. A crash
between them leaves the system either remembering an incident it cannot recall,
or recalling one that does not exist. Solving that properly requires an outbox
and a reconciliation job — real, ongoing complexity — to buy vector performance
this system will not need for years.

Additional benefits:

- Hybrid queries in one statement:
  *"semantically similar incidents, in the payments service, resolved in the
  last 90 days, where the remediation succeeded."* One SQL query, one plan.
- Foreign keys and `ON DELETE CASCADE` mean deleting an incident cannot orphan
  its memory.
- One backup, one restore, one connection pool, one operational surface.

### Redis 7.4 — working memory only

```
incident:{id}:state       hash    live status, current phase
incident:{id}:context     string  JSON agent scratchpad     TTL 4h
agent:{id}:lock           string  SET NX PX — single-executor guarantee
idem:{key}                string  idempotency        TTL 24h
```

Rule: **nothing in Redis is a source of truth.** Flushing it costs at most the
in-flight investigations, which can be reconstructed from Postgres.
`appendonly no` and `maxmemory-policy allkeys-lru` make that explicit rather
than aspirational.

## Consequences

**Positive**

- No dual-write consistency problem, and therefore no outbox and no reconciler.
- Hybrid semantic + relational queries in a single plan.
- One less service to run, secure, back up and monitor.
- pgvector's HNSW index handles millions of vectors comfortably — far beyond the
  thousands this system will accumulate.

**Negative**

- pgvector is slower than a dedicated vector engine at very high dimensionality
  and scale. Irrelevant at 10³–10⁵ vectors; would matter at 10⁸.
- Embedding writes add load to the transactional database. Mitigated by writing
  embeddings asynchronously *after* the incident closes — never on the hot path.
- HNSW index build is memory-hungry. Sized in Phase 15.

**Operational note**

Extensions are created by `deployments/compose/config/postgres/init/`, which runs
**only on an empty volume**. Schema is owned by versioned migrations
(`internal/database/migrations`) — never by the init script, because an init
script that does not re-run is a silent source of drift.

## Alternatives rejected

| Option | Why not |
|---|---|
| Postgres + Qdrant/Pinecone | Dual-write consistency problem; second operational surface; hosted options cost money. |
| Postgres only, no vectors | Keyword search misses paraphrased incidents — "OOMKilled" vs "container ran out of memory" — which is exactly the recall the system needs. |
| Redis as primary store | No relational integrity, no transactions across entities. Unacceptable for an audit ledger. |
| SQLite | No concurrent writers, no pgvector, no realistic production path. |
