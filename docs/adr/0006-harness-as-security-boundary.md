# ADR 0006 — The harness is the security boundary

- **Status:** accepted
- **Date:** 2026-08-29
- **Phase:** 1 (decision) / 6 (implementation)

## Context

This is the decision the entire project turns on.

An LLM given tools will, eventually, request the wrong one. Not through
malice — through a plausible chain of reasoning from incomplete evidence. A
model that concludes "the database is in a corrupt state, the fastest recovery is
to recreate it" has reasoned coherently and is about to destroy a company.

Prompt engineering does not solve this. "Never delete data" in a system prompt is
a *request*, and it is defeated by ordinary distribution shift, by an unusual log
excerpt, or by an operator pasting attacker-controlled text into an incident
description. Guardrails made of tokens fail in the same way the model fails.

The mitigation cannot live in the same layer as the failure.

## Decision

**Every action passes through a harness that the agent cannot influence.**

### Structural enforcement

Agents do not hold clients. They emit intent:

```go
// internal/domain/harness — pure data. No methods that do anything.
type ToolCallRequest struct {
    AgentID    AgentID
    IncidentID IncidentID
    Tool       string
    Action     string
    Params     map[string]any
    Reason     string      // the model's justification, recorded verbatim
    Confidence float64
}
```

`internal/agents` has no import path to `internal/tools`. This is checked by a
Phase 12 import-graph test, so the boundary is a build failure rather than a
review comment.

### Five gates, fixed order, each able to veto

**1. Tool Registry** — plugin-based. Does the tool exist? Is the action declared?
Do the parameters satisfy its schema? Unknown tool or malformed params are
rejected before anything else runs.

**2. Permission Engine** — deny by default. Per-agent allowlists:

```yaml
action_agent:
  allow: [restart_container, restart_service, scale_deployment, rollback_deployment]
  deny:  [delete_database, drop_table, delete_volume, delete_namespace]

monitoring_agent:
  allow: [get_metrics, get_health, list_containers, describe_pod]
  # no mutating action is reachable, allowlisted or not
```

Six of the seven agents have read-only permission sets. Exactly one can propose
a mutation.

**3. Policy Engine** — risk tiering decides autonomy:

| Risk | Examples | Behaviour |
|---|---|---|
| **low** | read metrics, tail logs, list pods | execute automatically |
| **medium** | restart a container, scale a deployment | approval required |
| **high** | restart a database, rollback a release, modify a firewall | approval required + justification |
| **forbidden** | drop a table, delete a volume, delete a namespace | never executable by any agent |

`forbidden` is not "requires a very senior approver". It is not reachable
through this system at all. Some actions should require a human at a terminal.

**4. Human Approval** — blocks execution, emits `ApprovalRequired`, waits with a
timeout. Timeout denies; it never defaults to allow. The approval record stores
who approved, when, and what they were shown — because "what did the human
actually see before clicking yes" is the first question in any postmortem of an
approved-but-wrong action.

**5. Audit Log** — append-only, written on **every** path.

The critical property: **rejections are logged as fully as executions.** A
harness that only records what it executed discards its most valuable signal.
"The Action Agent requested `delete_database` at 03:14, reasoning `X`, and was
blocked by policy" is the line that tells you your model has drifted — and you
only get it if the audit log is unconditional.

### Additional invariants

- **Dry-run by default.** `AEGIS_HARNESS_DRY_RUN=true` in development: tools log
  full intent and return synthetic success. Disabling it is a deliberate act.
- **Every execution is bounded.** Timeout, output size cap, cancellable context.
- **Least privilege at the infrastructure edge.** The harness's own Kubernetes
  ServiceAccount and Docker socket access are scoped to what the tool set needs,
  so even a harness bug cannot exceed those grants.
- **Idempotency.** Requests carry a key; a retried restart does not restart twice.

## Consequences

**Positive**

- The blast radius of a model failure is bounded by policy, not by prompt
  quality. This is the only property that makes autonomous remediation defensible
  to a security review.
- The audit log is a complete record of intent, including rejected intent.
- The permission matrix is data, so it is reviewable, diffable and testable
  without reading Go.
- Testable directly: Phase 12's Scenario 2 asserts that a forbidden request is
  rejected *and* audited.

**Negative**

- Latency: five gates on every call. Measured in microseconds against tool
  executions measured in seconds — an acceptable ratio.
- Approval friction. Medium-risk actions cannot be fully autonomous, which caps
  how much the system can do unattended. This is the intended trade, not a
  shortcoming.
- The permission matrix is another artefact to maintain. Phase 7 makes tools
  declare their own risk tier at registration to keep it in sync.

**The failure mode we accept**

The harness itself is now the critical trusted component. A bug in the policy
engine is worse than a bug anywhere else. It therefore gets the highest test
coverage requirement in the project (Phase 12: 100% branch coverage on
permission and policy evaluation) and its rules are data rather than code.
