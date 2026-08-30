# ADR 0011 — The harness engine: five gates, one ledger

- **Status:** accepted
- **Date:** 2026-08-30
- **Phase:** 6

## Context

Phase 5 gave the agents a way to say what they want. `tool.requested` events were
published and nothing subscribed. This phase is the subscriber, and it is the
part of the system that decides whether a sentence produced by a language model
becomes a change to production.

[ADR 0006](0006-harness-as-security-boundary.md) established *that* the harness
is the boundary. This records *how*.

## Decision 1 — Five gates, in this order

```
ToolCallRequest
      │
      ▼
 ① Registry     does this tool.action exist, and are the parameters valid?
      │                                      ↓ denied_unknown_tool / denied_invalid_params
      ▼
 ② Permission   may THIS AGENT KIND use it?  (deny by default)
      │                                      ↓ denied_permission
      ▼
 ③ Policy       how risky, and does a human decide?
      │                                      ↓ denied_policy
      ▼
 ④ Approval     a human with authority for THIS RISK TIER rules
      │                                      ↓ rejected / expired
      ▼
 ⑤ Execution    invoke, bounded and recorded
```

Each gate is cheaper and more certain than the next, and each narrows what the
following one must reason about.

**Registry first** because an unknown tool or malformed parameters make every
later question meaningless. Evaluating a permission rule against parameters that
were never coherent produces a verdict about nothing.

**Permission before policy** because permission is a pure lookup against a cached
matrix answering the broadest question — may this agent touch this at all. An
agent with no business calling a tool never reaches the code that reasons about
how risky the call would be.

**Policy before approval** because policy is what decides whether a human is
needed. **Execution last**, and only for a request that survived all four.

### Permission and policy are separate tables

They answer different questions. Permissions are per-agent and change when an
agent's role changes; policies are per-action and change when an organisation's
risk appetite does. Collapsing them would mean re-stating every risk tier once
per agent, and the first copy to drift would be a silent privilege escalation.

Both are **data, not code**: reviewable, diffable, and changeable without a
deploy — which matters because these two tables are the thing standing between a
hallucinated action and production.

### Deny by default, everywhere

An action with no matching allow rule is refused. An action with no policy is
refused. An unrecognised risk tier is refused. An unrecognised autonomy ceiling
grants no autonomy.

The consequence, stated plainly: **a tool added in Phase 7 is unusable by every
agent until someone writes a permission row and a policy row for it.** That is
the correct direction of failure. The opposite — a new tool being usable until
someone remembers to restrict it — puts the burden of safety on memory.

This bit during this very phase, which is the best evidence it works: see
Consequences.

## Decision 2 — Audit is not a gate, it is the spine

Every path out of `Evaluate` writes an audit entry, including — especially — the
rejections. The write is a `defer`, not a call repeated at each return, so an
early return added in future *cannot* forget it.

A harness that only logged what it executed would throw away its most valuable
signal. This line:

> the Action agent requested `database.drop_table` at 03:14, reasoning X, and was
> blocked by policy

is what tells you the model has drifted. You only get it if the write is
unconditional.

An audit outage does not un-gate anything: the refusal still happens, and the
failure is logged at `ERROR` with the text `AUDIT WRITE FAILED`, because a
silently lost entry would make the hash chain verify against a history missing
exactly the row someone wanted gone.

Parameters are redacted before they reach the ledger. They are assembled by a
model from whatever it read — logs, config, environment — and the ledger is a
table operators browse.

## Decision 3 — Approval authority is per risk tier, checked at the harness

An operator may approve a container restart and may not approve a database
rollback. Both arrive at the same endpoint, because a route cannot know whether
the request behind `{id}` is medium or high risk. So the route requires only
`approval:read`, and the real check happens in the harness against the loaded
request.

**Rejecting requires no authority.** Stopping an action is safe, and requiring
seniority to say "no" would mean a junior responder who spots a bad remediation
has to go find someone while it sits in the queue. Approving is what needs
authority.

**Forbidden is unapprovable by anyone**, and three independent layers enforce it:
the policy engine refuses before it ever reaches a human; the approval gate
refuses a forbidden request explicitly; and `rbac.ApprovalPermissionFor` returns
*unrepresentable* for the tier, so there is no permission to hold. It takes
removing all three to break the property — verified by mutation testing.

**The approver's role is read from the database, not the JWT.** A token is a
snapshot of who someone was when it was issued. Reading fresh means revoking
authority takes effect on the next action rather than the next login, which
matters most in exactly the case you would want it to: someone whose access is
being withdrawn while an incident is in progress.

### Approvals expire

Thirty minutes by default. Expiry is a safety control, not tidiness: an approval
queue without it means a restart proposed during Tuesday's outage can be approved
on Friday against a system that has since been fixed, redeployed or rolled back.
The approver would be authorising an action whose context no longer exists.

Expiry is recorded as its own outcome, so a postmortem can tell *"we decided not
to"* from *"nobody looked"*.

### Approvals are re-validated before execution

A human approves a decision made under the policy as it stood. Between proposal
and execution the policy may have changed — an action moved into the forbidden
tier, or the ceiling lowered. Both the policy and the parameter schema are
re-checked at execution, so a stale click cannot run something the deployment has
since decided it will not do.

## Decision 4 — The autonomy ceiling escalates; it does not refuse

`AEGIS_HARNESS_MAX_AUTO_RISK` names the riskiest action executed *without* asking
a human. Above it, the action is escalated, not refused — refusing would mean an
operator could not authorise a rollback even when they want to, which is not what
"maximum automatic risk" says.

`none` is a real setting meaning no autonomy at all: every action, including
reading logs, waits for a human. It is represented as `allowAuto=false` rather
than as a `Risk` value, and that is load-bearing — see Consequences.

Forbidden sits outside the dial entirely. `Risk.AtOrBelow` returns false for
forbidden against every ceiling including forbidden itself, so no setting
authorises dropping a table.

## Decision 5 — Dry-run is the default, and it is a first-class outcome

`ExecDryRun` is a status, not an error, and `dry_run` is stored separately from
`status` so a query can distinguish *"this deployment never executes anything"*
from *"this particular call was skipped"*. Switching to live execution is a
deliberate configuration act, and the daemon logs `LIVE EXECUTION ENABLED` at
`WARN` when it happens.

Phase 6 registers the Phase 7 tool *declarations* backed by `NoopTool`, which
**refuses to run outside dry-run**. If a descriptor is left inert by mistake, the
failure is a recorded error rather than a synthetic success a responder would
read as "the remediation ran".

Writing the descriptors before the implementations was deliberate: the parameter
schema is the contract three other things are already written against — the
permission matrix, the policy table, and the agents — so writing it first lets
all four be reconciled before any code exists that can restart a container.

## Consequences

**Good.** There is one place a reader can point at and say "this is the code that
touches production" (`Executor`). The security-relevant decisions are data, so
they are reviewable without reading Go. Every decision, including refusals, is on
a verifiable ledger. Phase 7 adds implementations without touching a gate.

**Costs, accepted.** Every tool call is several database round trips; the
permission and policy matrices are cached with a one-minute TTL and explicit
invalidation to keep the safety gate from becoming the slowest thing in the
pipeline — because a slow safety gate is one people want to skip. A cold cache
fails closed; a warm one serves stale-but-real rules through a brief database
outage. Stale is safe; absent is not.

**Three bugs this phase found, all in the same direction.**

*Path traversal in my own parameter schema.* The pattern for a file path was
`/([a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+` and the comment above it said "no parent
traversal". It did not deliver that: `.` is in the character class, so `..` is a
valid segment and `/var/log/../../etc/shadow` matched. Go's RE2 has no negative
lookahead, so "any segment that is not `..`" cannot be written directly; the fix
requires every segment to *start* with an alphanumeric or underscore, which makes
`.` and `..` unrepresentable. An allowlist of leading characters cannot be
widened by an encoding trick the way a blocklist of sequences can. Caught by a
test written from the comment rather than from the code.

*The autonomy ceiling silently loosening.* `MaxAutoRisk` accepts `"none"`, but
`Risk("none").Valid()` is false, so my first implementation fell through to a
`RiskLow` default — turning the *strictest* setting into a permissive one,
silently, in the dangerous direction. That is why "none" now has its own field
rather than being smuggled through a type that cannot represent it.

*Ten actions the catalog declared and no policy governed.* Found by
`ReconcileTools` at startup: `kubernetes.get_pods has no policy and cannot run
until one is added`. The read-only agents could gather no evidence at all.
Migration 0008 closes it, and the integration test now asserts **zero**
reconciliation problems rather than "no dangerous ones".

Note the direction of that last one: the bug made the system *too restrictive*.
That is deny-by-default working as designed rather than in spite of it — a
missing policy row produced a useless deployment, not an unsafe one.

## Alternatives rejected

**Open Policy Agent / Rego.** A real policy language, and the right answer at a
larger scale. It is a sidecar or an embedded interpreter plus a language every
reviewer has to learn, to express a decision that is currently four fields and a
comparison. The moment policies need conditions richer than
`Policy.Conditions` can express, this should be revisited.

**Checking approval authority in middleware.** Cleaner-looking, and wrong: the
required permission depends on the *risk tier of the request behind the ID*,
which the route does not know. Middleware would have to load the request, at
which point it is the handler.

**Trusting the role in the JWT.** One less query per approval. It also means a
revoked operator keeps their authority until their token expires, which is
precisely the window in which it matters.

**Letting an unpoliced action default to low risk.** Would have avoided migration
0008 entirely — by making "somebody forgot to tier this action" indistinguishable
from "this action is safe".

## References

- ADR 0006 — the harness as security boundary (what this implements)
- ADR 0009 — RBAC (`ApprovalPermissionFor` making forbidden unrepresentable)
- ADR 0010 — event-driven orchestration (where `tool.requested` comes from)
- Migration 0004 — the seeded permission matrix and policy table
- Migration 0008 — policy coverage for the full catalog
