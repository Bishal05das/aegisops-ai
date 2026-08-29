<div align="center">

# AegisOps AI

**An autonomous AI DevOps engineer that investigates incidents — and cannot touch your infrastructure without permission.**

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Framework](https://img.shields.io/badge/framework-none%20(stdlib%20only)-2ea44f)](docs/adr/0001-raw-go-no-framework.md)
[![LLM](https://img.shields.io/badge/LLM-local%20only-blueviolet)](docs/adr/0003-local-llm-only.md)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

---

## Overview

AegisOps AI is a control plane that runs the on-call loop end to end:

```
observe → hypothesise → gather evidence → diagnose → plan → act → verify → document
```

Seven specialised agents collaborate on an incident. A local LLM does the
reasoning. **A harness does the acting** — and the agents cannot bypass it.

### The problem it solves

Automating incident *investigation* with an LLM is straightforward. Automating
incident *remediation* is where systems get dangerous, because a model that
reasons its way to "the fastest fix is to recreate the database" has reasoned
coherently and is about to destroy a company.

Prompt engineering does not fix this. "Never delete data" in a system prompt is a
polite request, defeated by an unusual log excerpt or by attacker-controlled text
pasted into an incident description.

**AegisOps puts the mitigation in a different layer from the failure.**

```
        AI Agent  ──── emits a description of an action, never an action ────┐
            │                                                                │
            ▼                                                                │
    Agent Orchestrator                                                       │
            │                                                                │
            ▼                                                                │
    ╔═══════════════════════════════════════════════════════════════╗        │
    ║  HARNESS — the security boundary                              ║        │
    ║                                                               ║        │
    ║   Tool Registry → Permission → Policy → Approval → Audit      ║ ◀──────┘
    ║   (exists?)      (allowed?)   (risky?)  (human?)   (record)   ║
    ╚═══════════════════════════════════════════════════════════════╝
            │
            ▼
         Tools ──▶ Infrastructure
```

An agent's most powerful possible output is a `ToolCallRequest` — a struct with
no methods, no client and no credentials. If the model hallucinates
`delete_all_volumes`, the result is a **logged rejection**, not an outage.

📐 Full design: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** ·
📋 Decisions: **[docs/adr/](docs/adr/)**

---

## Features

| | |
|---|---|
| 🤖 **Seven collaborating agents** | Incident Manager, Monitoring, Log Analysis, Diagnosis, Security, Action, Documentation |
| 🛡️ **Five-gate harness** | Registry → Permission → Policy → Approval → Audit. Every gate can veto. |
| 🔒 **Deny-by-default permissions** | Six of seven agents are structurally read-only |
| ⚖️ **Risk-tiered autonomy** | low → automatic · medium/high → human approval · forbidden → unreachable |
| 📝 **Unconditional audit ledger** | Rejections recorded as fully as executions |
| 🧠 **Learns from history** | Postmortems embedded into pgvector; retrieved as precedent on the next incident |
| 🏠 **Fully offline** | Local LLM. No API keys, no egress, no vendor bill |
| 🔌 **Everything is swappable** | LLM, event bus, database and tools all sit behind ports |
| 📊 **Observable by construction** | Structured logs, Prometheus metrics, OpenTelemetry traces |
| 🧵 **Standard library only** | No web framework. Hand-written router, middleware, auth |

---

## Technology stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Go 1.26 | Concurrency, static binaries, strong stdlib |
| HTTP | `net/http` — **no framework** | [ADR 0001](docs/adr/0001-raw-go-no-framework.md) |
| Architecture | Hexagonal (ports & adapters) | [ADR 0002](docs/adr/0002-hexagonal-architecture.md) |
| LLM | Ollama + `qwen2.5:7b` | [ADR 0003](docs/adr/0003-local-llm-only.md) |
| Events | RabbitMQ 4.0 (topic exchange) | [ADR 0004](docs/adr/0004-rabbitmq-over-kafka.md) |
| Records + vectors | PostgreSQL 17 + pgvector | [ADR 0005](docs/adr/0005-postgres-with-pgvector.md) |
| Working memory | Redis 7.4 | [ADR 0005](docs/adr/0005-postgres-with-pgvector.md) |
| Security model | Harness as boundary; JWT + RBAC | [ADR 0006](docs/adr/0006-harness-as-security-boundary.md) |
| Error handling | Typed taxonomy, dual-audience | [ADR 0007](docs/adr/0007-error-taxonomy.md) |
| Persistence | `database/sql` + pgx; hand-written migrations | [ADR 0008](docs/adr/0008-database-sql-with-pgx.md) |
| Auth | Hand-written HS256 JWT, argon2id, rotating refresh | [ADR 0009](docs/adr/0009-authentication-and-rbac.md) |
| Observability | `log/slog`, Prometheus, OpenTelemetry → Jaeger | — |
| Dev / prod | Docker Compose / Kubernetes + Helm | — |

---

## Installation

### Requirements

| | Minimum | This machine |
|---|---|---|
| Go | **1.26** | ✅ 1.24.3 — auto-fetches the pinned 1.26.7 |
| Docker + Compose v2 | 24 / 2.20 | ✅ 27.5.1 / 2.32.4 |
| Ollama | 0.3 | ✅ 0.24.0 |
| RAM | 8 GB (16 GB with the model resident) | ✅ 16 GB |
| Disk | ~12 GB | ✅ |

> **You do not need to install Go 1.26 by hand.** `go.mod` pins
> `toolchain go1.26.7`, so any Go 1.21+ on your machine fetches it automatically
> on first build. The floor is not arbitrary: Go backports security fixes only
> to the two most recent majors, and CI's `govulncheck` job fails the build on an
> aged-out toolchain — which is exactly how Go 1.24 was caught here, carrying
> seven unpatched stdlib CVEs in `crypto/tls`, `crypto/x509`, `net/http`,
> `net/url`, `net/textproto` and `encoding/asn1`.

### Quick start

```bash
# 1. Local model (once, ~4.7 GB)
ollama pull qwen2.5:7b

# 2. Configuration
make env             # .env.example → .env
make gen-secret      # paste into AEGIS_JWT_SECRET

# 3. Bring up the stack — blocks until every dependency is verified
make dev-up
```

Expected tail of `make dev-up`:

```
AegisOps preflight
────────────────────────────────────────────────────────────────────────
  PASS  go-runtime       0ms  go 1.26.7
  PASS  postgres         2ms  postgres backend responding (TLS not configured)
  PASS  redis            1ms  redis 7.4.11 responding
  PASS  rabbitmq         3ms  AMQP 0-9 broker responding (Connection.Start received)
  PASS  rabbitmq-ui      9ms  credentials valid, RabbitMQ 4.0.9
  PASS  llm              1ms  ollama serving qwen2.5:7b (4.4 GiB), 1 model(s) available
  PASS  prometheus       1ms  HTTP 200
  PASS  grafana          1ms  HTTP 200
  PASS  jaeger           1ms  HTTP 200
────────────────────────────────────────────────────────────────────────
  ENVIRONMENT READY  9 passed, 0 warned, 0 failed, 0 skipped  (10ms)
```

### Service endpoints

| Service | URL | Credentials |
|---|---|---|
| PostgreSQL | `localhost:5434` | `aegis` / `aegis_dev_password` |
| Redis | `localhost:6380` | — |
| RabbitMQ | `localhost:5672` · [UI](http://localhost:15672) | `aegis` / `aegis_dev_password` |
| Prometheus | http://localhost:9090 | — |
| Grafana | http://localhost:3000 | anonymous admin |
| Jaeger | http://localhost:16686 | — |
| Ollama | http://localhost:11434 | host-native |

> **Non-default ports are intentional.** Postgres is on **5434** and Redis on
> **6380** because this machine already runs native instances on 5432/5433 and
> 6379. Pointing at 6379 would silently share state with an unrelated server —
> there is an integration test that fails if you do.

---

## Usage

```bash
make help          # every target, grouped
make preflight     # verify the environment
make run           # start the control plane on :8080
make run-check     # validate configuration and exit
make test          # unit tests
make verify        # full local gate: fmt + vet + lint + race tests + build + preflight
make dev-down      # stop the stack (keeps data)
make dev-clean     # stop and DELETE all volumes (prompts for confirmation)
```

### Authentication

```bash
# The API cannot bootstrap itself: every endpoint that creates a user needs an
# admin, and there is no admin until one exists. Seeding one via migration would
# put a password in version control, so it is a CLI command instead.
go run ./cmd/aegisctl user create --email you@example.com --role admin

curl -s -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"..."}' | jq .

curl -s localhost:8080/api/v1/auth/me -H "Authorization: Bearer $TOKEN" | jq .
```

Passwords are never accepted as a flag — an argument is visible in `ps` and in
shell history. `aegisctl` reads them from the terminal with echo disabled, or
from `AEGISCTL_PASSWORD` for automation.

### Database

```bash
make db-migrate           # apply pending migrations
make db-status            # what is applied, and whether any file changed after applying
make db-rollback STEPS=1  # revert
make test-integration     # repository tests against the real database
```

Migrations are embedded in the binary and applied on startup under a Postgres
advisory lock, so several replicas starting at once serialise rather than race.
Editing a migration that has already run is refused with a message naming the
file — the database and the repository must not describe different schemas.

### The API

```bash
make run     # in one terminal

curl -s localhost:8080/healthz                | jq .   # liveness  — never touches dependencies
curl -s localhost:8080/readyz                 | jq .   # readiness — per-dependency detail
curl -s localhost:8080/api/v1/version         | jq .   # build identity
curl -s localhost:8080/api/v1/nope            | jq .   # 404 in the standard envelope
curl -s -X POST localhost:8080/healthz        | jq .   # 405, with an Allow header
```

Every response — success or failure — carries an `X-Request-ID` that appears in
exactly one server log line:

```json
{"error":{"code":"route_not_found","message":"no route matches GET /api/v1/nope",
          "request_id":"01M16EG446GH170RQ8R664V71V"}}
```

Inspect the stack:

```bash
make dev-ps
make dev-logs SVC=rabbitmq
make psql
make redis-cli
```

Targeted preflight:

```bash
go run ./cmd/preflight -only postgres,redis     # subset
go run ./cmd/preflight -json                    # machine-readable
go run ./cmd/preflight -wait 60s                # retry while the stack boots
```

> Incident creation, agent execution and the approval workflow are documented as
> each phase lands (Phases 5–8).

---

## Preflight: why it exists

A TCP connect proves a port is open. It does not prove PostgreSQL is behind it.

`make preflight` completes each service's own handshake, with **zero third-party
dependencies** — every protocol is spoken directly over `net.Conn`:

| Check | Handshake | Catches |
|---|---|---|
| `postgres` | `SSLRequest` (8 bytes) → `S`/`N` | something else squatting on 5434 |
| `redis` | RESP `PING` → `+PONG`, then `INFO server` | wrong server, wrong password |
| `rabbitmq` | `AMQP\0\0\x09\x01` → `Connection.Start` | broker on a different AMQP version |
| `rabbitmq-ui` | authenticated `GET /api/overview` | wrong credentials |
| `llm` | `GET /api/tags` + model-name match | daemon up, required model not pulled |

Failures are classified, not merged: **fail** (required dependency down),
**warn** (optional, or reachable-but-degraded), **skip** (filtered out). A
missing Ollama model warns rather than fails — the stack is usable and the fix is
one `ollama pull`, which the report prints for you.

Exit codes: `0` ready · `1` a required dependency failed · `2` invalid usage.

---

## Testing

```bash
make test         # unit tests, no infrastructure required
make test-race    # under the race detector — what CI runs
make cover        # coverage.html
```

Integration tests need the stack up and are behind a build tag:

```bash
make dev-up
set -a && . ./.env && set +a
go test -tags=integration -v ./tests/integration/...
```

Testing philosophy: the protocol probes are covered from **both sides**. Unit
tests spin real in-process TCP servers that emit correct, degraded and malformed
responses — proving the probes decode them correctly. Integration tests run the
same probes against the real servers — proving those servers produce what the
probes accept. Neither alone is sufficient.

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs quality → unit
tests + integration tests + security scan → build. Integration tests use real
Postgres/Redis/RabbitMQ service containers; mocking them would prove nothing
about wire protocols.

---

## Project layout

```
cmd/
  aegisopsd/     control-plane daemon (API + orchestrator)
  aegisctl/      operator CLI
  migrate/       migration runner
  preflight/     environment doctor                    ✅ Phase 1

internal/
  domain/        entities and domain errors — imports nothing outside stdlib
  ports/         interfaces the core requires of the outside world
  api/           HTTP driving adapter (raw net/http)
  services/      application use cases
  agents/        the seven agents + orchestrator
  harness/       registry · permission · policy · approval · audit
  tools/         docker · kubernetes · linux · database · monitoring · git
  llm/           provider port + ollama · llamacpp
  memory/        shortterm (redis) · longterm (pgvector)
  events/        bus port + inproc · rabbitmq
  repository/    postgres implementations
  database/      pool + migrations
  security/      jwt · rbac · ratelimit · secrets
  observability/ logging · metrics · tracing
  preflight/     dependency probes                     ✅ Phase 1
  version/       build identity                        ✅ Phase 1

pkg/             reusable, domain-free: httpx · logger · errs · validate · id
tests/           integration · e2e · testdata
deployments/     compose · docker · k8s · helm
docs/            ARCHITECTURE.md · adr/
```

Dependency rule: arrows point inward. `domain` knows nothing; adapters know
`ports`; nothing above the core knows which adapter is wired in. Composition
happens once, in `cmd/aegisopsd/main.go`.

---

## Architecture decisions

Each links to a full ADR with the alternatives that were rejected and why.

**[Why raw Go?](docs/adr/0001-raw-go-no-framework.md)** — This is a control plane
that executes actions against real infrastructure. When it misbehaves, the
questions are "which middleware swallowed that cancellation?" and "why did
shutdown drop an in-flight approval?" A framework makes those harder to answer.
Go 1.22's `ServeMux` handles `POST /api/incidents/{id}` natively, removing the
last real reason to import a router.

**[Why local LLM?](docs/adr/0003-local-llm-only.md)** — Diagnosis means feeding
the model production logs, stack traces and config. Three independent reasons not
to send that to a vendor: data sensitivity, availability coupling (an
incident-response system that fails when its vendor has an incident is not one),
and unbounded per-token cost across a 20-completion agentic loop.

**[Why event-driven?](docs/adr/0004-rabbitmq-over-kafka.md)** — Seven agents plus
a harness plus an approval workflow is an N×N coupling problem if components call
each other. Components publish *facts*; others react. The audit ledger binds to
`#` and observes everything without any publisher knowing it exists.

**[Why one database for records and vectors?](docs/adr/0005-postgres-with-pgvector.md)**
— An incident and the embedding of its postmortem must commit atomically. A
separate vector store makes that two operations with no shared transaction, so a
crash between them leaves the system remembering an incident it cannot recall.
Fixing that properly needs an outbox and a reconciler — real complexity, to buy
vector performance this system will not need for years.

**[Why a harness?](docs/adr/0006-harness-as-security-boundary.md)** — Because
guardrails made of tokens fail the same way the model fails. The mitigation has
to live in a different layer.

**[Why a typed error taxonomy?](docs/adr/0007-error-taxonomy.md)** — An error
leaving a repository has two audiences with opposite needs: the operator wants
the driver message, the caller must never see it. `errs.Error` carries both and
only `Public()` crosses the boundary, so `pq: relation "incidents" does not
exist` becomes an opaque 500 with a request ID — and the full chain still lands
in the log.

---

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | Architecture, repository, development environment | ✅ |
| 2 | HTTP server, configuration, logging, error handling | ✅ |
| 3 | PostgreSQL layer, migrations, repository pattern | ✅ |
| 4 | Authentication (JWT) and RBAC | ✅ |
| 5 | Agent orchestration engine | ⏳ next |
| 6 | Harness engine | |
| 7 | Tool ecosystem | |
| 8 | Local LLM integration | |
| 9 | Memory system | |
| 10 | Infrastructure integration | |
| 11 | Observability | |
| 12 | Testing hardening | |
| 13 | Docker deployment | |
| 14 | Kubernetes deployment | |
| 15 | Production hardening | |

### Future improvements

- Import-graph test enforcing that `internal/agents` cannot reach `internal/tools`
- Multi-cluster support with per-cluster credential scoping
- Slack / PagerDuty approval channels
- Confidence-calibrated autonomy: raise the risk ceiling as historical accuracy improves
- Adversarial evaluation harness — prompt-injected incident descriptions attempting to elicit forbidden actions
- gRPC transport for agent-to-agent messaging

---

## License

MIT — see [LICENSE](LICENSE).
