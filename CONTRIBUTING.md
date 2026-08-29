# Contributing

## Branching model

`main` is protected and always deployable. **Nothing is committed to it
directly** — every change arrives through a pull request whose CI is green.

```
main   ●────────────────────────────────●──────────────────────►
       │  chore: initialize repository   ▲  squash merge
       │                                 │
       └──●──────────────────────────────┘
          feat/phase-1-2-foundation      CI must pass:
                                           quality → tests → security → build
```

### Branch names

One branch per development phase, or per logical change within one:

| Prefix | Use |
|---|---|
| `feat/` | new capability — `feat/phase-3-database` |
| `fix/` | bug fix — `fix/readiness-cache-race` |
| `refactor/` | behaviour-preserving change |
| `docs/` | documentation or ADRs only |
| `chore/` | tooling, CI, dependencies |

### The loop

```bash
git switch main && git pull
git switch -c feat/phase-3-database

# ... work ...

make verify          # run the CI gate locally BEFORE pushing
git push -u origin feat/phase-3-database
gh pr create --base main
```

`make verify` runs the same checks as CI (`fmt-check`, `vet`, `lint`,
`test-race`, `build`) plus a live `preflight`. Running it locally is not
optional politeness — it is how you avoid burning a CI cycle to learn that
`gofmt` moved a brace.

## What CI enforces

Defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Jobs are
ordered by how fast they fail, so a formatting slip never costs a container
pull:

| Job | Checks |
|---|---|
| **quality** | `go mod tidy` is clean · `gofmt -s` · `go vet` · `golangci-lint` |
| **unit-tests** | `go test -race` with coverage |
| **integration-tests** | Real PostgreSQL + Redis + RabbitMQ service containers, gated on a green `preflight` |
| **security** | `govulncheck` · Trivy filesystem scan → SARIF |
| **build** | Every binary in `cmd/`, version-stamped |

Integration tests use real service containers rather than mocks on purpose: the
preflight probes assert wire-protocol behaviour, and a mocked CI would prove
nothing about them.

## Commit messages

```
<type>: <imperative summary, ≤72 chars>

Why the change is being made, not what the diff shows. If a design decision
was made, state the alternative that was rejected and the reason.
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`.

## Non-negotiables

These are properties the architecture exists to guarantee. A PR that weakens one
needs an ADR arguing the case, not just a passing test suite.

1. **Agents never hold a handle to infrastructure.** `internal/agents` must have
   no import path — direct or transitive — reaching `internal/tools`. An agent's
   most powerful output is a `ToolCallRequest`: pure data, no client, no
   credentials. See [ADR 0006](docs/adr/0006-harness-as-security-boundary.md).
2. **The audit log is unconditional.** Rejections are recorded as fully as
   executions. A harness that only logs what it executed discards its most
   valuable signal.
3. **No web framework.** Standard library only.
   See [ADR 0001](docs/adr/0001-raw-go-no-framework.md).
4. **No paid LLM APIs.** Inference is local and behind a provider port.
   See [ADR 0003](docs/adr/0003-local-llm-only.md).
5. **Internal errors never leak their cause.** Only `errs.Error.Public()`
   crosses the boundary. See [ADR 0007](docs/adr/0007-error-taxonomy.md).
6. **Secrets are typed.** Use `config.Secret`; `.Reveal()` marks every
   deliberate plaintext handling site and is greppable.

## Architecture decisions

Anything that changes a boundary, a dependency, or a security property gets an
ADR in [`docs/adr/`](docs/adr/). Copy the shape of an existing one: context,
decision, consequences (positive *and* negative), and the alternatives you
rejected with the reason. An ADR that lists no downsides has not been thought
through.
