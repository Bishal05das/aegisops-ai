package handlers

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/api/dto"
	"github.com/bishal05das/aegisops-ai/internal/api/middleware"
	"github.com/bishal05das/aegisops-ai/internal/api/render"
	domainharness "github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/harness"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/services"
	"github.com/bishal05das/aegisops-ai/pkg/errs"
	"github.com/bishal05das/aegisops-ai/pkg/httpx"
)

// Harness serves the approval queue, the rule surface and the audit ledger.
type Harness struct {
	approvals    *services.ApprovalService
	rules        *services.RuleService
	audit        *services.AuditService
	approvalTTL  time.Duration
	dryRun       bool
	maxBodyBytes int64
}

// NewHarness builds the handler.
func NewHarness(a *services.ApprovalService, r *services.RuleService, au *services.AuditService, approvalTTL time.Duration, dryRun bool, maxBody int64) *Harness {
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	return &Harness{approvals: a, rules: r, audit: au,
		approvalTTL: approvalTTL, dryRun: dryRun, maxBodyBytes: maxBody}
}

// ListPending handles GET /api/v1/approvals.
//
// The operator's work queue: everything an agent has proposed that a human must
// rule on. Each entry carries the model's own reasoning verbatim, because that
// text is what the approver is actually deciding about.
func (h *Harness) ListPending(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	res, err := h.approvals.Pending(ctx, pageFrom(r))
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	out := dto.ToolCallListResponse{
		ToolCalls:  make([]dto.ToolCallView, len(res.Items)),
		NextCursor: res.NextCursor, HasMore: res.HasMore, Count: len(res.Items),
	}
	for i, req := range res.Items {
		out.ToolCalls[i] = dto.NewToolCallView(req).WithExpiry(req.CreatedAt.Add(h.approvalTTL))
	}
	render.WriteJSON(w, r, http.StatusOK, out)
}

// GetToolCall handles GET /api/v1/tool-calls/{id}.
func (h *Harness) GetToolCall(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := toolCallID(r)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	req, err := h.approvals.Get(ctx, id)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	view := dto.NewToolCallView(req).WithExpiry(req.CreatedAt.Add(h.approvalTTL))
	if exec, execErr := h.approvals.Execution(ctx, id); execErr == nil {
		view.Execution = dto.NewExecutionView(exec)
	}
	render.WriteJSON(w, r, http.StatusOK, view)
}

// ListToolCalls handles GET /api/v1/tool-calls.
//
// The complete record of what the agents asked for — including everything that
// was refused. Filterable by decision so an operator can ask the question that
// matters most: "what did the harness stop this week?"
func (h *Harness) ListToolCalls(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Harness.ListToolCalls"
	ctx := r.Context()

	var f ports.ToolCallFilter
	q := r.URL.Query()

	if raw := q.Get("incident_id"); raw != "" {
		id, err := shared.ParseID(raw)
		if err != nil {
			render.WriteError(w, r, errs.E(op, errs.Invalid,
				"incident_id is not a valid UUID").WithCode("invalid_incident_id"))
			return
		}
		f.IncidentID = &id
	}
	for _, d := range q["decision"] {
		decision := domainharness.Decision(d)
		if !decision.Valid() {
			render.WriteError(w, r, errs.E(op, errs.Invalid,
				"unknown decision "+d).WithCode("invalid_decision"))
			return
		}
		f.Decisions = append(f.Decisions, decision)
	}
	for _, s := range q["risk"] {
		risk := domainharness.Risk(s)
		if !risk.Valid() {
			render.WriteError(w, r, errs.E(op, errs.Invalid,
				"unknown risk tier "+s).WithCode("invalid_risk"))
			return
		}
		f.Risks = append(f.Risks, risk)
	}
	f.PendingApproval = q.Get("pending") == "true"

	res, err := h.approvals.List(ctx, f, pageFrom(r))
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	out := dto.ToolCallListResponse{
		ToolCalls:  make([]dto.ToolCallView, len(res.Items)),
		NextCursor: res.NextCursor, HasMore: res.HasMore, Count: len(res.Items),
	}
	for i, req := range res.Items {
		out.ToolCalls[i] = dto.NewToolCallView(req).WithExpiry(req.CreatedAt.Add(h.approvalTTL))
	}
	render.WriteJSON(w, r, http.StatusOK, out)
}

// Decide handles POST /api/v1/approvals/{id}/decide.
//
// One endpoint for both rulings rather than separate approve and reject routes.
// The authority check depends on the request's risk tier, not on the URL, so
// splitting them would invite a reader to assume the two paths are differently
// protected when the protection is identical and lives in the harness.
func (h *Harness) Decide(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Harness.Decide"
	ctx := r.Context()
	principal := middleware.MustPrincipal(ctx)

	id, err := toolCallID(r)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	var req dto.DecideRequest
	if decErr := httpx.Decode(w, r, &req, h.maxBodyBytes); decErr != nil {
		render.WriteError(w, r, decErr)
		return
	}
	if valErr := req.Validate(); valErr != nil {
		render.WriteError(w, r, validationError(op, valErr))
		return
	}

	res, err := h.approvals.Decide(ctx, id, principal.UserID,
		harness.ApprovalDecision(req.Decision), req.Note)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	view := dto.NewToolCallView(res.Request)
	view.Execution = dto.NewExecutionView(res.Execution)
	render.WriteJSON(w, r, http.StatusOK, dto.DecideResponse{
		ToolCall: view,
		Executed: res.Execution != nil,
		Message:  res.Reason,
	})
}

// Rules handles GET /api/v1/harness/rules.
//
// The whole decision surface in one document: the permission matrix, the policy
// table, the registered tools and the deployment's autonomy ceiling. Returned
// together because "why was this denied?" is rarely answerable from any one of
// them, and joining three endpoints during an incident is how people guess.
func (h *Harness) Rules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	perms, err := h.rules.Permissions(ctx)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}
	policies, err := h.rules.Policies(ctx)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}
	ceiling := h.rules.Ceiling()

	out := dto.RulesResponse{
		AutonomyCeiling: string(ceiling),
		DryRun:          h.dryRun,
	}

	for _, kind := range harness.AgentKinds {
		for _, rule := range perms.Rules(string(kind)) {
			out.Permissions = append(out.Permissions, dto.PermissionView{
				ID: rule.ID.String(), AgentKind: rule.AgentKind,
				Tool: rule.Tool, Action: rule.Action, Effect: string(rule.Effect),
				Specificity: rule.Specificity(),
			})
		}
	}

	for _, p := range policies.All() {
		out.Policies = append(out.Policies, dto.PolicyView{
			ID: p.ID.String(), Name: p.Name, Description: p.Description,
			Tool: p.Tool, Action: p.Action, Risk: string(p.Risk),
			RequiresApproval: p.RequiresApproval, MinConfidence: p.MinConfidence,
			Priority: p.Priority, Enabled: p.Enabled,
			Reachable: p.Enabled && p.Risk.AtOrBelow(ceiling),
		})
	}

	summarise := func(tool, action string) *dto.ActionPolicySummary {
		p := policies.For(tool, action)
		if p == nil {
			return nil
		}
		return &dto.ActionPolicySummary{
			Risk: string(p.Risk), RequiresApproval: p.RequiresApproval,
			MinConfidence: p.MinConfidence,
			Reachable:     p.Risk.AtOrBelow(ceiling),
		}
	}
	for _, d := range h.rules.Tools() {
		view := dto.NewToolView(d, summarise)
		sort.Slice(view.Actions, func(i, j int) bool { return view.Actions[i].Name < view.Actions[j].Name })
		out.Tools = append(out.Tools, view)
	}

	render.WriteJSON(w, r, http.StatusOK, out)
}

// ListAudit handles GET /api/v1/audit.
func (h *Harness) ListAudit(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Harness.ListAudit"
	ctx := r.Context()

	var f ports.AuditFilter
	q := r.URL.Query()

	if raw := q.Get("incident_id"); raw != "" {
		id, err := shared.ParseID(raw)
		if err != nil {
			render.WriteError(w, r, errs.E(op, errs.Invalid,
				"incident_id is not a valid UUID").WithCode("invalid_incident_id"))
			return
		}
		f.IncidentID = &id
	}
	f.ActorType = q.Get("actor_type")
	f.Action = q.Get("action")
	for _, o := range q["outcome"] {
		outcome := domainharness.Outcome(o)
		if !outcome.Valid() {
			render.WriteError(w, r, errs.E(op, errs.Invalid,
				"unknown outcome "+o).WithCode("invalid_outcome"))
			return
		}
		f.Outcomes = append(f.Outcomes, outcome)
	}

	res, err := h.audit.List(ctx, f, pageFrom(r))
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	out := dto.AuditListResponse{
		Entries:    make([]dto.AuditEntryView, len(res.Items)),
		NextCursor: res.NextCursor, HasMore: res.HasMore,
	}
	for i, e := range res.Items {
		out.Entries[i] = dto.NewAuditEntryView(e)
	}
	if latest, latestErr := h.audit.LatestSeq(ctx); latestErr == nil {
		out.LatestSeq = latest
	}
	render.WriteJSON(w, r, http.StatusOK, out)
}

// VerifyAudit handles GET /api/v1/audit/verify.
//
// Recomputes the hash chain and reports the first entry that does not match.
// This is the endpoint that makes the ledger worth having: without a way to
// check it, "append-only" is a claim rather than a property.
func (h *Harness) VerifyAudit(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Harness.VerifyAudit"
	ctx := r.Context()
	q := r.URL.Query()

	fromSeq, err := int64Param(op, q.Get("from"), 0)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}
	toSeq, err := int64Param(op, q.Get("to"), 0)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	// Default to the most recent window rather than the whole ledger. An
	// operator asking "is the ledger intact?" almost always means "recently",
	// and a full verify on a year-old deployment during an incident is a very
	// effective way to make the database unavailable.
	if fromSeq == 0 && toSeq == 0 {
		latest, latestErr := h.audit.LatestSeq(ctx)
		if latestErr != nil {
			render.WriteError(w, r, latestErr)
			return
		}
		toSeq = latest
		fromSeq = max(1, latest-services.MaxVerifyRange+1)
	}

	result, err := h.audit.Verify(ctx, fromSeq, toSeq)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	render.WriteJSON(w, r, http.StatusOK, dto.ChainVerificationResponse{
		Checked: result.Checked, Valid: result.Valid,
		BrokenAtSeq: result.BrokenAtSeq, Reason: result.Reason,
		FromSeq: fromSeq, ToSeq: toSeq,
	})
}

// toolCallID extracts and validates the {id} path parameter.
func toolCallID(r *http.Request) (shared.ID, error) {
	id, err := shared.ParseID(r.PathValue("id"))
	if err != nil {
		return shared.Nil, errs.E("handlers.toolCallID", errs.Invalid,
			"the tool call id is not a valid UUID").WithCode("invalid_tool_call_id")
	}
	return id, nil
}

// int64Param parses an optional numeric query parameter.
//
// A malformed value is rejected rather than defaulted, unlike the pagination
// limit. Silently verifying a different range from the one asked for would let
// a tampered ledger pass a check that never covered the altered rows.
func int64Param(op, raw string, fallback int64) (int64, error) {
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, errs.E(op, errs.Invalid,
			"the sequence range must be a whole number").WithCode("invalid_range")
	}
	return n, nil
}
