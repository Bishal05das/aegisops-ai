# ADR 0010 — Event-driven agent orchestration

- **Status:** accepted
- **Date:** 2026-08-29
- **Phase:** 5

## Context

Seven agents have to investigate an incident. The question this phase answers is
not *what each agent does* — that is Phase 8, when a real model arrives — but
**who decides what runs, in what order, and what an agent is allowed to do with
its conclusion.**

Three properties had to hold before any of it was worth writing:

1. An incident report must return to the caller immediately. An investigation
   takes seconds to minutes; an HTTP request must not.
2. Agents depend on each other. Diagnosis is worthless without telemetry, and a
   remediation is worse than worthless without a diagnosis.
3. **No agent may touch infrastructure.** This is ADR 0006, and Phase 5 is the
   first phase where a violation would actually be possible.

## Decision 1 — Investigations are triggered by an event, not by the request

`POST /api/v1/incidents` writes the incident, publishes `incident.detected`, and
returns **202 Accepted**.

202, not 201: the row exists, but the thing the caller cares about has not
happened. 201 Created would claim the work is done. A client watches the
timeline endpoint to see agents working.

The publish happens **after** the transaction commits, never inside it. Publishing
first would let a subscriber begin investigating an incident that a subsequent
rollback erased — the orchestrator would load an ID that does not exist. The cost
of committing first is that a crash between commit and publish loses the trigger;
that trade is deliberate, and a reconciliation sweep for `detected` incidents with
no tasks is the standard repair (Phase 10).

### Why a bus and not a goroutine

`go investigate(id)` would work today. It stops working at the first of these:
a second replica, a restart mid-investigation, or anything else wanting to know
an incident was detected. The bus is a port (`ports.EventBus`) with an in-process
adapter now and RabbitMQ in Phase 10; the topic strings and matching semantics
are already AMQP's, so the swap does not change any publisher or subscriber.

The in-process adapter implements `*` and `#` matching **locally** rather than
treating a pattern as a literal, specifically so a subscription that works in a
test works identically against a broker.

## Decision 2 — Phasing is concurrent-then-sequential

```
                    incident_manager          (plan)
                           │
        ┌──────────────────┼──────────────────┐
   monitoring        log_analysis         security      ← concurrent
        └──────────────────┼──────────────────┘
                       diagnosis                        ← needs all evidence
                           │
                        action                           ← needs a diagnosis
                           │
                     documentation                       ← needs everything
```

The first wave is concurrent because its three members share no dependency and
their latency is dominated by a model call. Running them in sequence would triple
the time to a diagnosis, which is the number that matters during an outage. The
tail is sequential because each step genuinely needs the one before it.

This is a fixed graph, not agent-chosen. Agents may *suggest* follow-up work via
`Output.NextAgents`, but the orchestrator decides — an agent that could schedule
itself could loop forever, and a model that can choose its own next step can be
argued into choosing badly by a prompt-injected log line.

### The evidence floor

Diagnosis requires monitoring evidence and refuses without it. Log analysis
failing is tolerated: a cluster that will not serve logs is a common failure mode,
and refusing to diagnose because of it would make the system useless exactly when
it is needed. Losing *all* telemetry is different — a diagnosis with no metrics is
guesswork, and guesswork reaching the Action agent is the thing every other
control here exists to prevent. So the investigation escalates and marks the
incident `failed` rather than producing a confident answer from nothing.

## Decision 3 — Agents emit intents; the orchestrator publishes them; nobody executes

`Agent.Execute` returns an `Output`. The most powerful thing an `Output` can carry
is `[]*harness.ToolCallRequest` — a struct with no methods that act, no client, no
credentials, no network. An agent describes an action. It cannot take one.

The orchestrator publishes each request as `tool.requested` and stops. There is no
execution path in this package. If a model hallucinates
`action: "delete_all_volumes"`, that string travels to the harness, which refuses
it and writes an audit row — the failure mode is a logged refusal, not an outage.

Enforcement is structural, not documentary: `internal/agents` imports
`internal/domain/harness` for the request type and never `internal/tools`. Phase 12
adds an import-graph test so the boundary is a build failure rather than a review
comment.

Two independent gates stand between a weak model and a mutating action:

| Gate | Where | What it stops |
|---|---|---|
| `MinRemediationConfidence` (0.5) | Action agent | A low-confidence diagnosis never becomes a proposal at all — there is nothing for the harness to refuse, because nothing was proposed. |
| Permission + policy + approval | Harness (Phase 6) | A confidently *wrong* proposal. Confidence is self-reported, so it cannot be the only gate. |

Six of the seven agents cannot propose a mutation at all. `agent.Kind.CanMutate()`
is true for exactly one kind, that ratio is asserted in a test, and the API exposes
it per agent so a UI can show which one is not read-only.

## Decision 4 — The `Reasoner` port is the model seam

Every agent depends on `ports.Reasoner`, never on a model. `ScriptedReasoner`
returns fixed, coherent answers today; Phase 8 adds an Ollama adapter. Nothing in
`internal/agents` changes when it does.

Deliberate, not incidental: it satisfies ADR 0003 (no paid APIs, models are
replaceable), and it makes every test here deterministic and offline. A test suite
that needs a 4.7 GB model to run is a test suite that does not run in CI.

`ReasoningError` distinguishes retryable failures (`unavailable`, `timeout`) from
permanent ones (`malformed_response`, `refused`), because retrying a model that
returned unparseable JSON just burns the incident's time budget.

## Consequences

**Good.** Incidents return in milliseconds. Agents are unit-testable with no
infrastructure and no model. The security boundary is a property of the type
system rather than a convention. Swapping to RabbitMQ or to a real LLM touches one
adapter each.

**Costs, accepted.** An investigation's progress lives in Postgres rather than
memory, so every step is a write — that is what makes the timeline a real audit
trail, and it is why the write path had to be correct (below). At-least-once
delivery means redeliveries happen, so the orchestrator dedupes by incident ID and
caps concurrent investigations.

**A bug worth recording.** Concurrent agents append to a shared timeline. Sequence
numbers were assigned by reading `max(seq)` and inserting, so two concurrent
appends read the same value and one lost a unique-constraint race. The repository
returned `ErrConflict` documenting *"the caller retries"* — and the orchestrator,
like every caller, only logged a warning.

The visible symptom: a timeline showing tool requests from an agent that never
appeared to start.

The lesson is about where an invariant belongs. *Every* caller of `AppendEvent`
can only respond to a conflict by retrying, so a contract that pushes the retry
onto callers guarantees the bug at each one. The fix is a per-incident
`pg_advisory_xact_lock` **inside** the adapter: serialisation is the adapter's
job, and the port now says implementations MUST serialise. Per incident, not
globally, so unrelated incidents still proceed in parallel.

The same mistake, in the same shape, appeared in `Evidence`: writes were guarded
by a mutex and readers were told to call `Snapshot()` first — but *taking the
snapshot is itself a read of the shared map*. Both are now the type's own
responsibility rather than a protocol callers must remember.

Both are covered by regression tests that fail against the original code.

## Alternatives rejected

**A workflow engine (Temporal, Cadence).** Durable execution is genuinely the
right shape for this problem, and at a larger scale it would win. It is a server,
a worker SDK and a programming model — for a fixed seven-node graph, the
orchestrator is a few hundred lines and owes nothing.

**Letting the model plan the graph.** The obvious "agentic" design, and the reason
it is rejected is the whole premise of this system: a model that chooses its own
next step can be argued into choosing badly by a log line it was asked to read. A
fixed graph makes prompt injection unable to change *what runs* — only what a
single agent concludes, which the harness then refuses to act on unchecked.

**Executing tool calls in the orchestrator.** Faster to write, and it would delete
ADR 0006. The harness exists so that the answer to "what can a compromised agent
do?" is *file a request*.

## References

- ADR 0002 — hexagonal architecture (the ports this phase adds)
- ADR 0003 — local models only (why `Reasoner` is a port)
- ADR 0004 — RabbitMQ over Kafka (the adapter Phase 10 supplies)
- ADR 0006 — the harness as security boundary (what Decision 3 protects)
