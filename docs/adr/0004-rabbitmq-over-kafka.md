# ADR 0004 — RabbitMQ as the event bus, behind a port

- **Status:** accepted
- **Date:** 2026-08-29
- **Phase:** 1 (decision) / 5 (implementation)

## Context

The system is event-driven by design: the Incident Manager must not hold a
direct reference to the Monitoring Agent, and the harness must not know who
asked for an approval. Components publish facts; other components react.

The workload has a specific shape:

- **Low volume.** Tens to hundreds of events per incident. Not millions/sec.
- **Small messages.** A few KB of JSON.
- **Routing-heavy.** `incident.*`, `agent.*`, `approval.*`, `tool.*` with
  different consumers per pattern.
- **Retry and dead-letter matter.** A failed tool execution must be retried with
  backoff and eventually parked for inspection.
- **Replay does not matter much.** Postgres is the system of record. The event
  log is transport, not truth.

Hardware constraint: a 16 GB workstation that is also running Postgres, Redis,
Grafana, Jaeger and a 7B model.

## Decision

**RabbitMQ 4.0**, accessed exclusively through:

```go
// internal/ports
type EventBus interface {
    Publish(ctx context.Context, ev domain.Event) error
    Subscribe(ctx context.Context, pattern string, h Handler) (Subscription, error)
    Close() error
}
```

Two adapters ship:

- `internal/events/rabbitmq` — production
- `internal/events/inproc` — a channel-backed bus for unit and E2E tests

`AEGIS_EVENTBUS_DRIVER` selects between them.

### Topology

```
exchange: aegisops.events   (topic, durable)

routing keys      incident.detected      incident.resolved
                  agent.started          agent.completed
                  task.created
                  tool.requested         tool.executed
                  approval.required      approval.granted   approval.denied

queues            q.orchestrator     ← incident.*, agent.*
                  q.harness          ← tool.requested
                  q.notifications    ← approval.required
                  q.audit            ← #          (everything, for the ledger)
                  q.dead-letter      ← rejected / expired
```

`q.audit` binding to `#` is deliberate: the audit ledger observes every fact on
the bus without any publisher needing to know it exists.

## Consequences

**Positive**

- ~150 MB resident vs 2–3 GB for a Kafka broker. On this machine that difference
  is the difference between a stack that runs and one that swaps.
- Topic exchanges give the routing model we actually need, declaratively.
- Native DLQ and per-message TTL — retry semantics we would otherwise hand-roll.
- Management UI at `:15672` makes event flow visible during development, which
  matters a great deal when debugging a multi-agent choreography.
- The `inproc` adapter means unit tests need no broker at all.

**Negative**

- No log replay. Cannot rebuild state by re-reading the topic from offset 0.
  Accepted: Postgres holds the truth; the bus only moves it.
- Lower ceiling than Kafka (~50k msg/s vs millions). Three orders of magnitude
  above what this system will produce.
- Clustering is more operationally involved than Kafka's.

## Migration path

Because `EventBus` is a port, moving to Kafka means adding
`internal/events/kafka` and changing one config value. No agent, service or
harness code changes. That is the whole reason the port exists.

Trigger conditions for revisiting: sustained >10k events/sec, or a genuine
requirement for event-sourced state reconstruction.

## Alternatives rejected

| Option | Why not |
|---|---|
| **Kafka** | Correct at 100× this scale. Here it costs 2–3 GB and significant operational complexity to buy replay we do not need. |
| **NATS JetStream** | Genuinely excellent — lighter than RabbitMQ with better Go ergonomics. Rejected only because the project brief names Kafka or RabbitMQ. Worth revisiting. |
| **Redis Pub/Sub** | Fire-and-forget with no delivery guarantee. Losing an `ApprovalRequired` event is unacceptable. |
| **Postgres `LISTEN/NOTIFY`** | Tempting (one fewer service) but caps at 8 KB, drops on disconnect, and couples the bus to the database's availability. |
