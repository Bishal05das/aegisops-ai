package harness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	domainagent "github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/version"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// Harness is the security boundary, assembled.
//
// It subscribes to tool.requested, runs each request through the five gates, and
// records every outcome. Nothing else in the system may execute a tool: the
// executor is held here and handed out to nobody.
type Harness struct {
	registry   *Registry
	permission *PermissionEngine
	policy     *PolicyEngine
	approval   *ApprovalGate
	executor   ports.ToolExecutor

	calls     ports.ToolCallRepository
	audit     ports.AuditRepository
	incidents ports.IncidentRepository
	agents    ports.AgentRepository
	bus       ports.EventBus

	clock shared.Clock
	log   *slog.Logger
}

// Deps are the collaborators the harness needs.
type Deps struct {
	Registry   *Registry
	Permission *PermissionEngine
	Policy     *PolicyEngine
	Approval   *ApprovalGate
	Executor   ports.ToolExecutor

	Calls     ports.ToolCallRepository
	Audit     ports.AuditRepository
	Incidents ports.IncidentRepository
	Agents    ports.AgentRepository
	Bus       ports.EventBus

	Clock  shared.Clock
	Logger *slog.Logger
}

// New builds the harness.
func New(d Deps) *Harness {
	clock := d.Clock
	if clock == nil {
		clock = shared.SystemClock{}
	}
	log := d.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Harness{
		registry: d.Registry, permission: d.Permission, policy: d.Policy,
		approval: d.Approval, executor: d.Executor,
		calls: d.Calls, audit: d.Audit, incidents: d.Incidents, agents: d.Agents,
		bus: d.Bus, clock: clock, log: log,
	}
}

// Start subscribes the harness to the events it acts on.
func (h *Harness) Start(ctx context.Context) error {
	const op = "harness.Harness.Start"

	if _, err := h.bus.Subscribe(ctx, ports.TopicToolRequested, h.onToolRequested); err != nil {
		return fmt.Errorf("%s: subscribe to %s: %w", op, ports.TopicToolRequested, err)
	}

	h.log.Info("harness started",
		"tools", len(h.registry.Tools()),
		"autonomy_ceiling", string(h.policy.Ceiling()),
		"approval_ttl", h.approval.TTL().String(),
		"dry_run", h.isDryRun())
	return nil
}

func (h *Harness) isDryRun() bool {
	if e, ok := h.executor.(*Executor); ok {
		return e.DryRun()
	}
	return false
}

// onToolRequested handles an agent's intent arriving on the bus.
func (h *Harness) onToolRequested(ctx context.Context, e ports.Event) error {
	rawID, _ := e.Payload["tool_call_id"].(string)
	id, err := shared.ParseID(rawID)
	if err != nil {
		// Returning an error would have the bus retry a message that can never
		// succeed. Log it and drop it.
		h.log.Warn("tool.requested carried no usable tool_call_id",
			"event_id", e.ID, "raw", rawID)
		return nil //nolint:nilerr // a malformed message must not be retried forever
	}

	req, err := h.calls.Get(ctx, id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			// Returning the error would have the bus redeliver forever: the row
			// is not coming back. Drop it, loudly.
			h.log.Warn("tool.requested names a tool call that does not exist",
				"tool_call_id", id.String())
			return nil //nolint:nilerr // an unprocessable message must not be retried
		}
		// A transient database error: ask for redelivery.
		return fmt.Errorf("harness: load tool call %s: %w", id, err)
	}

	_, err = h.Evaluate(ctx, req)
	return err
}

// Result is the harness's complete verdict on one request.
type Result struct {
	Request   *harness.ToolCallRequest
	Execution *harness.Execution
	// Reason is the operator-facing explanation of the outcome.
	Reason string
}

// Evaluate runs one request through every gate.
//
// # Why the gates are in this order
//
// Each gate is cheaper and more certain than the next, and each narrows what the
// following one has to reason about:
//
//  1. **Registry** first, because an unknown tool or malformed parameters make
//     every later question meaningless. Evaluating a permission rule against
//     parameters that were never coherent produces a verdict about nothing.
//  2. **Permission** second: it is a pure lookup against a cached matrix, and it
//     answers the broadest question — may this agent touch this at all. Asking
//     it before policy means an agent that has no business calling a tool never
//     reaches the code that reasons about how risky the call would be.
//  3. **Policy** third. It needs the request to be real and permitted before
//     tiering it, and it is the gate that can send the request to a human.
//  4. **Approval** fourth, and only if policy asked for it.
//  5. **Execution** last, and only for a request that survived all four.
//
// # Audit is not a gate
//
// It is the spine. Every path out of this function writes an audit entry,
// including — especially — the rejections. A harness that only logged what it
// executed would throw away its most valuable signal: "the Action agent
// requested delete_database at 03:14, reasoning X, and was blocked" is the line
// that tells you the model has drifted, and you only get it if the write is
// unconditional. That is why the write is deferred rather than repeated at each
// return: an early return added later cannot forget it.
func (h *Harness) Evaluate(ctx context.Context, req *harness.ToolCallRequest) (res Result, err error) {
	const op = "harness.Harness.Evaluate"

	ctx = logger.WithIncidentID(ctx, req.IncidentID.String())
	log := h.log.With(
		"tool_call_id", req.ID.String(),
		"incident_id", req.IncidentID.String(),
		"agent", req.AgentName,
		"call", req.Qualified())

	res.Request = req

	// Idempotency. The bus delivers at least once, so a redelivered event is
	// expected — and without this, a redelivery would restart the container a
	// second time. Checked here rather than at the subscriber because Evaluate
	// is also reachable from the approval path.
	if req.Decision.Terminal() {
		log.Debug("tool call already decided; ignoring a redelivery",
			"decision", string(req.Decision))
		res.Reason = fmt.Sprintf("already %s", req.Decision)
		return res, nil
	}

	// The unconditional audit write. Deferred so that no return path — present
	// or future — can skip it.
	defer func() {
		h.record(ctx, req, res.Execution, res.Reason, err)
	}()

	// ---- gate 1: registry -------------------------------------------------
	if !h.registry.Known(req.Tool, req.Action) {
		res.Reason = fmt.Sprintf("no tool named %s exposes an action %s; "+
			"the agent asked for something that does not exist", req.Tool, req.Action)
		h.deny(ctx, req, harness.DecisionDeniedUnknown, res.Reason, log)
		return res, nil
	}

	normalised, paramErr := h.registry.ValidateParams(req.Tool, req.Action, req.Params)
	if paramErr != nil {
		res.Reason = fmt.Sprintf("the parameters are not valid for %s: %s",
			req.Qualified(), paramErr.Error())
		h.deny(ctx, req, harness.DecisionDeniedParams, res.Reason, log)
		return res, nil
	}

	// ---- gate 2: permission ----------------------------------------------
	agentKind, kindErr := h.agentKind(ctx, req)
	if kindErr != nil {
		return res, fmt.Errorf("%s: %w", op, kindErr)
	}

	verdict, permErr := h.permission.Check(ctx, agentKind, req.Tool, req.Action)
	if permErr != nil {
		// The matrix could not be loaded. Fail closed: return an error so the
		// bus retries, rather than deciding without the rules.
		return res, fmt.Errorf("%s: %w", op, permErr)
	}
	if !verdict.Allowed {
		res.Reason = verdict.Reason
		h.deny(ctx, req, harness.DecisionDeniedPermission, res.Reason, log)
		return res, nil
	}

	// ---- gate 3: policy ---------------------------------------------------
	ruling, polErr := h.policy.Evaluate(ctx, req)
	if polErr != nil {
		return res, fmt.Errorf("%s: %w", op, polErr)
	}
	req.Risk = ruling.Risk

	switch ruling.Decision {
	case harness.DecisionDeniedPolicy:
		res.Reason = ruling.Reason
		h.deny(ctx, req, harness.DecisionDeniedPolicy, res.Reason, log)
		return res, nil

	case harness.DecisionAwaitingApproval:
		// ---- gate 4: park for a human ------------------------------------
		req.Decision = harness.DecisionAwaitingApproval
		req.DecisionNote = ruling.Reason
		res.Reason = ruling.Reason
		if updErr := h.calls.Update(ctx, req); updErr != nil {
			return res, fmt.Errorf("%s: park for approval: %w", op, updErr)
		}
		h.publish(ctx, req, ports.TopicApprovalRequired, map[string]any{
			"risk":       string(req.Risk),
			"expires_at": h.approval.ExpiresAt(req).UTC().Format(time.RFC3339),
			"reason":     ruling.Reason,
		})
		h.timeline(ctx, req, incident.EventApprovalRequired,
			fmt.Sprintf("%s proposed %s and is waiting for a human: %s",
				req.AgentName, req.Qualified(), ruling.Reason))
		log.Info("awaiting human approval", "risk", string(req.Risk), "reason", ruling.Reason)
		return res, nil
	}

	// ---- gate 5: execute --------------------------------------------------
	req.Decision = harness.DecisionAllowed
	req.DecisionNote = ruling.Reason
	if updErr := h.calls.Update(ctx, req); updErr != nil {
		return res, fmt.Errorf("%s: record the decision: %w", op, updErr)
	}

	exec, execErr := h.execute(ctx, req, normalised, log)
	res.Execution = exec
	if execErr != nil {
		return res, fmt.Errorf("%s: %w", op, execErr)
	}
	res.Reason = ruling.Reason
	return res, nil
}

// ApplyApproval applies a human's ruling and, on approval, executes.
//
// Separate from Evaluate because it re-enters the pipeline at gate five with a
// decision a human made, and because the authority check has no analogue in the
// automatic path.
func (h *Harness) ApplyApproval(ctx context.Context, id shared.ID, decision ApprovalDecision, by Approver, note string) (res Result, err error) {
	const op = "harness.Harness.ApplyApproval"

	req, err := h.calls.Get(ctx, id)
	if err != nil {
		return res, fmt.Errorf("%s: %w", op, err)
	}
	res.Request = req

	ctx = logger.WithIncidentID(ctx, req.IncidentID.String())
	log := h.log.With("tool_call_id", id.String(), "call", req.Qualified(),
		"approver", by.Email, "ruling", string(decision))

	defer func() {
		h.record(ctx, req, res.Execution, res.Reason, err)
	}()

	if ruleErr := h.approval.Rule(req, decision, by, note); ruleErr != nil {
		res.Reason = ruleErr.Error()
		log.Warn("approval refused", "error", ruleErr)
		return res, ruleErr
	}

	// Re-evaluate the policy before acting on the approval.
	//
	// A human approved a decision made under the policy as it stood when the
	// request was proposed. If the policy changed since — an action moved into
	// the forbidden tier, or the autonomy ceiling was lowered — the approval is
	// stale, and honouring it would let a stale click execute something the
	// deployment has since decided it will not do.
	if req.Decision == harness.DecisionApproved {
		ruling, polErr := h.policy.Evaluate(ctx, req)
		if polErr != nil {
			return res, fmt.Errorf("%s: %w", op, polErr)
		}
		if ruling.Decision == harness.DecisionDeniedPolicy {
			req.Deny(h.clock, harness.DecisionDeniedPolicy, ruling.Reason)
			res.Reason = fmt.Sprintf("the policy changed after this was proposed: %s", ruling.Reason)
			if updErr := h.calls.Update(ctx, req); updErr != nil {
				return res, fmt.Errorf("%s: %w", op, updErr)
			}
			log.Warn("approval refused: the policy changed since the request was made",
				"code", ErrApprovalStalePolicy, "reason", ruling.Reason)
			return res, &ApprovalError{Code: ErrApprovalStalePolicy, Detail: res.Reason}
		}
	}

	if updErr := h.calls.Update(ctx, req); updErr != nil {
		return res, fmt.Errorf("%s: %w", op, updErr)
	}

	verb, timelineEvent := "approved", incident.EventApprovalGranted
	if req.Decision == harness.DecisionRejected {
		verb, timelineEvent = "rejected", incident.EventApprovalDenied
	}
	res.Reason = fmt.Sprintf("%s %s %s", by.Email, verb, req.Qualified())
	h.timeline(ctx, req, timelineEvent, res.Reason+": "+note)
	h.publish(ctx, req, approvalTopic(req.Decision), map[string]any{
		"approver_id": by.UserID.String(), "approver": by.Email,
		"risk": string(req.Risk), "note": note,
	})

	if req.Decision != harness.DecisionApproved {
		log.Info("request rejected by a human")
		return res, nil
	}

	// Re-validate parameters. They have not changed, but the schema may have:
	// a tool upgraded between proposal and approval could have tightened a
	// constraint, and executing against the old shape would run something the
	// current tool does not accept.
	normalised, paramErr := h.registry.ValidateParams(req.Tool, req.Action, req.Params)
	if paramErr != nil {
		res.Reason = fmt.Sprintf("the parameters are no longer valid for %s: %s",
			req.Qualified(), paramErr.Error())
		h.deny(ctx, req, harness.DecisionDeniedParams, res.Reason, log)
		return res, nil
	}

	exec, execErr := h.execute(ctx, req, normalised, log)
	res.Execution = exec
	if execErr != nil {
		return res, fmt.Errorf("%s: %w", op, execErr)
	}
	return res, nil
}

// ExpirePending sweeps requests nobody ruled on.
//
// Returns how many it expired. Run on a ticker by the daemon: without it, the
// queue accumulates stale proposals and an operator loses the ability to tell
// "waiting for me" from "waiting since Tuesday".
func (h *Harness) ExpirePending(ctx context.Context) (int, error) {
	const op = "harness.Harness.ExpirePending"

	page, err := h.calls.List(ctx, ports.ToolCallFilter{PendingApproval: true}, ports.Page{Limit: 200})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	var expired int
	for _, req := range page.Items {
		if !h.approval.Expire(req) {
			continue
		}
		if updErr := h.calls.Update(ctx, req); updErr != nil {
			h.log.Warn("could not expire a stale approval",
				"tool_call_id", req.ID.String(), "error", updErr)
			continue
		}
		h.record(ctx, req, nil, req.DecisionNote, nil)
		h.timeline(ctx, req, incident.EventApprovalDenied,
			fmt.Sprintf("%s expired unapproved: %s", req.Qualified(), req.DecisionNote))
		expired++
	}
	if expired > 0 {
		h.log.Info("expired stale approval requests", "count", expired)
	}
	return expired, nil
}

// execute runs the tool and records the execution.
func (h *Harness) execute(ctx context.Context, req *harness.ToolCallRequest, params map[string]any, log *slog.Logger) (*harness.Execution, error) {
	// Execute with the normalised parameters — defaults applied, types coerced —
	// while the request keeps the originals. The stored request is what a human
	// reviewed; substituting the normalised set would make the audit trail show
	// values the agent never proposed.
	toExecute := *req
	toExecute.Params = params

	exec, err := h.executor.Execute(ctx, &toExecute)
	if err != nil {
		return nil, fmt.Errorf("execute %s: %w", req.Qualified(), err)
	}

	if saveErr := h.calls.SaveExecution(ctx, exec); saveErr != nil {
		if errors.Is(saveErr, shared.ErrAlreadyExists) {
			// The unique constraint on tool_call_id caught a concurrent second
			// execution. The action ran twice at most once — the constraint is
			// what makes that observable rather than silent.
			log.Warn("an execution record already existed for this tool call; " +
				"a duplicate delivery reached the executor")
			return exec, nil
		}
		return exec, fmt.Errorf("save the execution record: %w", saveErr)
	}

	log.Info("tool call executed",
		"status", string(exec.Status),
		"dry_run", exec.DryRun,
		"duration_ms", exec.DurationMS)

	h.publish(ctx, req, ports.TopicToolExecuted, map[string]any{
		"status":      string(exec.Status),
		"dry_run":     exec.DryRun,
		"duration_ms": exec.DurationMS,
	})
	h.timeline(ctx, req, incident.EventToolExecuted,
		fmt.Sprintf("%s %s (%s)", req.Qualified(), exec.Status, execNote(exec)))
	return exec, nil
}

// deny records a terminal refusal.
func (h *Harness) deny(ctx context.Context, req *harness.ToolCallRequest, d harness.Decision, reason string, log *slog.Logger) {
	req.Deny(h.clock, d, reason)
	if err := h.calls.Update(ctx, req); err != nil {
		h.log.Error("could not persist a denial", "tool_call_id", req.ID.String(), "error", err)
	}
	// Warn, not Info. A refused tool call is the signal an operator most wants
	// to see: it means an agent asked for something it should not have.
	log.Warn("tool call denied", "decision", string(d), "reason", reason)

	h.timeline(ctx, req, incident.EventToolRejected,
		fmt.Sprintf("%s was denied %s: %s", req.AgentName, req.Qualified(), reason))
	h.publish(ctx, req, ports.TopicToolRejected, map[string]any{
		"decision": string(d), "reason": reason, "risk": string(req.Risk),
	})
}

// record writes the audit entry. Called from a defer on every path.
func (h *Harness) record(ctx context.Context, req *harness.ToolCallRequest, exec *harness.Execution, reason string, failure error) {
	if h.audit == nil {
		return
	}

	entry := harness.NewAuditEntry(h.clock, "agent", req.AgentName, req.Qualified(), outcomeFor(req, exec, failure))
	entry.ActorID = req.AgentID
	entry.ResourceType = "tool_call"
	entry.ResourceID = req.ID.String()
	incidentID := req.IncidentID
	entry.IncidentID = &incidentID
	callID := req.ID
	entry.ToolCallID = &callID
	entry.Reason = firstNonEmpty(reason, req.DecisionNote, req.Reason)
	entry.RequestID = logger.RequestID(ctx)
	entry.BuildVersion = version.Get().Version

	// Params are assembled by a language model from whatever it read — logs,
	// config, environment. Redact before they reach a table operators read.
	entry.Params = logger.RedactMap(req.Params)
	if exec != nil {
		entry.Result = map[string]any{
			"status": string(exec.Status), "dry_run": exec.DryRun,
			"duration_ms": exec.DurationMS,
		}
		entry.Error = exec.Error
	}
	if failure != nil {
		entry.Error = failure.Error()
	}

	// A failed audit write must be loud. The ledger is the reason the rest of
	// this package can be trusted, and silently losing an entry would make the
	// chain verify against a history missing exactly the row someone deleted.
	if err := h.audit.Append(ctx, entry); err != nil {
		h.log.Error("AUDIT WRITE FAILED — this decision is not in the ledger",
			"tool_call_id", req.ID.String(),
			"action", entry.Action,
			"outcome", string(entry.Outcome),
			"error", err)
	}
}

// outcomeFor maps the harness's state onto an audit outcome.
//
// An ApprovalError is a *denial*, not a failure. The distinction is not
// cosmetic: harness.OutcomeFailed means "the action ran and did not work", and
// labelling "a viewer tried to approve a medium-risk restart" that way would put
// an attempted privilege escalation in the same bucket as a failed container
// restart. The refused attempt is exactly the entry a reviewer wants to find,
// and it has to be findable by filtering for denials.
func outcomeFor(req *harness.ToolCallRequest, exec *harness.Execution, failure error) harness.Outcome {
	if failure != nil {
		var approvalErr *ApprovalError
		if errors.As(failure, &approvalErr) {
			return harness.OutcomeDenied
		}
		return harness.OutcomeFailed
	}
	if exec != nil {
		switch {
		case exec.DryRun:
			return harness.OutcomeDryRun
		case exec.Status == harness.ExecSucceeded:
			return harness.OutcomeExecuted
		default:
			return harness.OutcomeFailed
		}
	}
	if req.Decision.Permits() || req.Decision == harness.DecisionAwaitingApproval {
		return harness.OutcomeAllowed
	}
	return harness.OutcomeDenied
}

// agentKind resolves the agent kind the permission matrix is keyed by.
func (h *Harness) agentKind(ctx context.Context, req *harness.ToolCallRequest) (string, error) {
	if h.agents == nil {
		return req.AgentName, nil
	}
	a, err := h.agents.Get(ctx, req.AgentID)
	if err != nil {
		// Fail closed. An agent whose identity cannot be resolved cannot be
		// matched against the matrix, and guessing from the name would let an
		// unregistered agent inherit a registered one's permissions.
		return "", fmt.Errorf("resolve the agent that made this request: %w", err)
	}
	if !a.Enabled {
		return "", fmt.Errorf("agent %s is disabled and may not request tools", a.Name)
	}
	return string(a.Kind), nil
}

func (h *Harness) publish(ctx context.Context, req *harness.ToolCallRequest, topic string, payload map[string]any) {
	if h.bus == nil {
		return
	}
	payload["tool_call_id"] = req.ID.String()
	payload["tool"] = req.Tool
	payload["action"] = req.Action
	payload["agent_id"] = req.AgentID.String()

	if err := h.bus.Publish(ctx, ports.Event{
		Type: topic, IncidentID: req.IncidentID,
		ActorType: "system", ActorID: req.AgentID, ActorName: req.AgentName,
		Payload: payload, RequestID: logger.RequestID(ctx),
	}); err != nil {
		h.log.Warn("could not publish a harness event", "topic", topic, "error", err)
	}
}

func (h *Harness) timeline(ctx context.Context, req *harness.ToolCallRequest, typ incident.EventType, msg string) {
	if h.incidents == nil {
		return
	}
	ev, err := incident.NewEvent(h.clock, req.IncidentID, typ, incident.ActorAgent, msg)
	if err != nil {
		h.log.Warn("could not build a timeline entry", "error", err)
		return
	}
	ev.ActorID = req.AgentID
	ev.ActorName = req.AgentName
	ev.Payload = map[string]any{
		"tool_call_id": req.ID.String(),
		"call":         req.Qualified(),
		"decision":     string(req.Decision),
		"risk":         string(req.Risk),
	}
	if err := h.incidents.AppendEvent(ctx, ev); err != nil {
		h.log.Warn("could not append to the incident timeline",
			"incident_id", req.IncidentID.String(), "error", err)
	}
}

// approvalTopic maps a ruling onto the event other components subscribe to.
func approvalTopic(d harness.Decision) string {
	if d == harness.DecisionApproved {
		return ports.TopicApprovalGranted
	}
	return ports.TopicApprovalDenied
}

func execNote(e *harness.Execution) string {
	if e.DryRun {
		return "dry run; infrastructure untouched"
	}
	if e.Error != "" {
		return e.Error
	}
	return fmt.Sprintf("%dms", e.DurationMS)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// AgentKinds is re-exported for the composition root, which reconciles the
// permission matrix against the agent roster at startup.
var AgentKinds = domainagent.AllKinds
