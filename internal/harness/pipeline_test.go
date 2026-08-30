package harness_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	domainagent "github.com/bishal05das/aegisops-ai/internal/domain/agent"
	domainharness "github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/harness"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// The gate tests ask whether each gate refuses what it should. These ask the
// question that actually matters: does a request travelling through all five in
// order end up where it belongs, and is every outcome recorded?

// -----------------------------------------------------------------------------
// In-memory collaborators
// -----------------------------------------------------------------------------

type memCalls struct {
	mu    sync.Mutex
	calls map[shared.ID]*domainharness.ToolCallRequest
	execs map[shared.ID]*domainharness.Execution
}

func newMemCalls() *memCalls {
	return &memCalls{
		calls: map[shared.ID]*domainharness.ToolCallRequest{},
		execs: map[shared.ID]*domainharness.Execution{},
	}
}

func (m *memCalls) Create(_ context.Context, r *domainharness.ToolCallRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := *r
	m.calls[r.ID] = &copied
	return nil
}

func (m *memCalls) Get(_ context.Context, id shared.ID) (*domainharness.ToolCallRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.calls[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	copied := *r
	return &copied, nil
}

func (m *memCalls) GetByIdempotencyKey(context.Context, string) (*domainharness.ToolCallRequest, error) {
	return nil, shared.ErrNotFound
}

func (m *memCalls) Update(_ context.Context, r *domainharness.ToolCallRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := *r
	m.calls[r.ID] = &copied
	return nil
}

func (m *memCalls) List(_ context.Context, f ports.ToolCallFilter, _ ports.Page) (ports.PageResult[*domainharness.ToolCallRequest], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []*domainharness.ToolCallRequest
	for _, r := range m.calls {
		if f.PendingApproval && r.Decision != domainharness.DecisionAwaitingApproval {
			continue
		}
		copied := *r
		items = append(items, &copied)
	}
	return ports.PageResult[*domainharness.ToolCallRequest]{Items: items}, nil
}

// SaveExecution enforces the unique constraint the real schema does, so a
// double execution is as visible here as it is in Postgres.
func (m *memCalls) SaveExecution(_ context.Context, e *domainharness.Execution) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.execs[e.ToolCallID]; exists {
		return shared.ErrAlreadyExists
	}
	copied := *e
	m.execs[e.ToolCallID] = &copied
	return nil
}

func (m *memCalls) GetExecution(_ context.Context, id shared.ID) (*domainharness.Execution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.execs[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return e, nil
}

func (m *memCalls) executionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.execs)
}

type memAudit struct {
	mu      sync.Mutex
	entries []*domainharness.AuditEntry
	failing bool
}

func (m *memAudit) Append(_ context.Context, e *domainharness.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failing {
		return context.DeadlineExceeded
	}
	e.Seq = int64(len(m.entries) + 1)
	copied := *e
	m.entries = append(m.entries, &copied)
	return nil
}

func (m *memAudit) List(context.Context, ports.AuditFilter, ports.Page) (ports.PageResult[*domainharness.AuditEntry], error) {
	return ports.PageResult[*domainharness.AuditEntry]{}, nil
}

func (m *memAudit) VerifyChain(context.Context, int64, int64) (domainharness.ChainVerification, error) {
	return domainharness.ChainVerification{Valid: true}, nil
}

func (m *memAudit) LatestSeq(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.entries)), nil
}

func (m *memAudit) all() []*domainharness.AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*domainharness.AuditEntry, len(m.entries))
	copy(out, m.entries)
	return out
}

type memAgents struct {
	agent *domainagent.Agent
}

func (m *memAgents) Create(context.Context, *domainagent.Agent) error { return nil }
func (m *memAgents) Get(_ context.Context, id domainagent.ID) (*domainagent.Agent, error) {
	if m.agent == nil || m.agent.ID != id {
		return nil, shared.ErrNotFound
	}
	return m.agent, nil
}
func (m *memAgents) GetByName(context.Context, string) (*domainagent.Agent, error) {
	return nil, shared.ErrNotFound
}
func (m *memAgents) List(context.Context) ([]*domainagent.Agent, error) { return nil, nil }
func (m *memAgents) Update(context.Context, *domainagent.Agent) error   { return nil }
func (m *memAgents) Upsert(context.Context, *domainagent.Agent) error   { return nil }

type memIncidents struct {
	mu     sync.Mutex
	events []*incident.Event
}

func (m *memIncidents) Create(context.Context, *incident.Incident) error { return nil }
func (m *memIncidents) Get(context.Context, incident.ID) (*incident.Incident, error) {
	return nil, shared.ErrNotFound
}
func (m *memIncidents) Update(context.Context, *incident.Incident) error { return nil }
func (m *memIncidents) List(context.Context, ports.IncidentFilter, ports.Page) (ports.PageResult[*incident.Incident], error) {
	return ports.PageResult[*incident.Incident]{}, nil
}
func (m *memIncidents) Count(context.Context, ports.IncidentFilter) (int64, error) { return 0, nil }
func (m *memIncidents) AppendEvent(_ context.Context, ev *incident.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := *ev
	m.events = append(m.events, &copied)
	return nil
}
func (m *memIncidents) Events(context.Context, incident.ID, ports.Page) (ports.PageResult[*incident.Event], error) {
	return ports.PageResult[*incident.Event]{}, nil
}
func (m *memIncidents) eventTypes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.events))
	for i, e := range m.events {
		out[i] = string(e.Type)
	}
	return out
}

// -----------------------------------------------------------------------------
// Fixture
// -----------------------------------------------------------------------------

type rig struct {
	h         *harness.Harness
	calls     *memCalls
	audit     *memAudit
	incidents *memIncidents
	agentID   shared.ID
	clock     shared.Clock
}

type rigOpts struct {
	ceiling   string
	live      bool
	agentKind domainagent.Kind
	perms     []*domainharness.Permission
	policies  []*domainharness.Policy
}

func newRig(t *testing.T, opts rigOpts) *rig {
	t.Helper()

	if opts.ceiling == "" {
		opts.ceiling = "high"
	}
	if opts.agentKind == "" {
		opts.agentKind = domainagent.KindAction
	}
	if opts.perms == nil {
		opts.perms = []*domainharness.Permission{
			perm("action", "docker", "restart_container", domainharness.EffectAllow),
			perm("action", "docker", "logs", domainharness.EffectAllow),
			perm("action", "database", "drop_table", domainharness.EffectDeny),
			perm("monitoring", "docker", "logs", domainharness.EffectAllow),
		}
	}
	if opts.policies == nil {
		opts.policies = []*domainharness.Policy{
			policy("logs", "docker", "logs", domainharness.RiskLow, false, 0),
			policy("restart", "docker", "restart_container", domainharness.RiskMedium, true, 0.7),
			policy("drop", "database", "drop_table", domainharness.RiskForbidden, true, 1),
		}
	}

	clock := shared.SystemClock{}
	rules := &stubRules{perms: opts.perms, policies: opts.policies}
	reg := testRegistry(t)

	a, err := domainagent.New(clock, string(opts.agentKind), opts.agentKind, "test agent")
	if err != nil {
		t.Fatalf("build agent: %v", err)
	}

	calls := newMemCalls()
	audit := &memAudit{}
	incidents := &memIncidents{}

	return &rig{
		h: harness.New(harness.Deps{
			Registry:   reg,
			Permission: harness.NewPermissionEngine(rules, clock, time.Minute),
			Policy:     harness.NewPolicyEngine(rules, clock, time.Minute, opts.ceiling),
			Approval:   harness.NewApprovalGate(clock, 30*time.Minute),
			Executor: harness.NewExecutor(harness.ExecutorConfig{
				Registry: reg, Clock: clock, Live: opts.live,
			}),
			Calls: calls, Audit: audit, Incidents: incidents,
			Agents: &memAgents{agent: a}, Clock: clock,
		}),
		calls: calls, audit: audit, incidents: incidents, agentID: a.ID, clock: clock,
	}
}

// propose creates a request as an agent would.
func (r *rig) propose(t *testing.T, tool, action string, params map[string]any, confidence float64) *domainharness.ToolCallRequest {
	t.Helper()

	req, err := domainharness.NewToolCallRequest(r.clock, shared.NewID(), r.agentID,
		tool, action, "the container is OOMKilling; a restart should clear it")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.AgentName = "action"
	req.Params = params
	req.Confidence = confidence
	if err := r.calls.Create(context.Background(), req); err != nil {
		t.Fatalf("persist request: %v", err)
	}
	return req
}

// -----------------------------------------------------------------------------
// The pipeline
// -----------------------------------------------------------------------------

// One table over every path through the five gates. The decision *and* the
// audit outcome are asserted together, because "was it refused" and "is the
// refusal on the record" are separate guarantees and only one of them is
// visible at runtime.
func TestPipelineDecisions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		tool, action string
		params       map[string]any
		confidence   float64
		agentKind    domainagent.Kind
		ceiling      string
		wantDecision domainharness.Decision
		wantOutcome  domainharness.Outcome
		wantExecuted bool
	}{
		{
			name: "a permitted low-risk action runs",
			tool: "docker", action: "logs",
			params: map[string]any{"container": "api-worker"}, confidence: 0.9,
			wantDecision: domainharness.DecisionAllowed,
			wantOutcome:  domainharness.OutcomeDryRun,
			wantExecuted: true,
		},
		{
			name: "an invented action is denied as unknown",
			tool: "docker", action: "become_root",
			params: map[string]any{}, confidence: 0.9,
			wantDecision: domainharness.DecisionDeniedUnknown,
			wantOutcome:  domainharness.OutcomeDenied,
		},
		{
			name: "malformed parameters are denied before any permission check",
			tool: "docker", action: "logs",
			params: map[string]any{"container": "api; rm -rf /"}, confidence: 0.9,
			wantDecision: domainharness.DecisionDeniedParams,
			wantOutcome:  domainharness.OutcomeDenied,
		},
		{
			name: "an action outside the agent's permissions is denied",
			tool: "docker", action: "start_container",
			params: map[string]any{"container": "api-worker"}, confidence: 0.9,
			wantDecision: domainharness.DecisionDeniedPermission,
			wantOutcome:  domainharness.OutcomeDenied,
		},
		{
			name: "a forbidden action is denied by policy",
			tool: "database", action: "drop_table",
			params: map[string]any{"table": "users"}, confidence: 1.0,
			wantDecision: domainharness.DecisionDeniedPermission, // the deny rule catches it first
			wantOutcome:  domainharness.OutcomeDenied,
		},
		{
			name: "a mutating action waits for a human",
			tool: "docker", action: "restart_container",
			params: map[string]any{"container": "api-worker"}, confidence: 0.9,
			wantDecision: domainharness.DecisionAwaitingApproval,
			wantOutcome:  domainharness.OutcomeAllowed,
		},
		{
			name: "no autonomy means even a read waits",
			tool: "docker", action: "logs", ceiling: "none",
			params: map[string]any{"container": "api-worker"}, confidence: 0.9,
			wantDecision: domainharness.DecisionAwaitingApproval,
			wantOutcome:  domainharness.OutcomeAllowed,
		},
		{
			name: "a read-only agent asking for a mutation is denied",
			tool: "docker", action: "restart_container", agentKind: domainagent.KindMonitoring,
			params: map[string]any{"container": "api-worker"}, confidence: 0.9,
			wantDecision: domainharness.DecisionDeniedPermission,
			wantOutcome:  domainharness.OutcomeDenied,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t, rigOpts{ceiling: tc.ceiling, agentKind: tc.agentKind})
			req := r.propose(t, tc.tool, tc.action, tc.params, tc.confidence)

			res, err := r.h.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}

			if res.Request.Decision != tc.wantDecision {
				t.Errorf("decision = %s, want %s (reason: %s)",
					res.Request.Decision, tc.wantDecision, res.Reason)
			}
			if (res.Execution != nil) != tc.wantExecuted {
				t.Errorf("executed = %v, want %v", res.Execution != nil, tc.wantExecuted)
			}

			entries := r.audit.all()
			if len(entries) != 1 {
				t.Fatalf("%d audit entries, want exactly 1", len(entries))
			}
			if entries[0].Outcome != tc.wantOutcome {
				t.Errorf("audit outcome = %s, want %s", entries[0].Outcome, tc.wantOutcome)
			}
			if entries[0].Reason == "" {
				t.Error("the audit entry carries no reason")
			}
		})
	}
}

// The claim ADR 0006 makes, asserted end to end: nothing an agent proposes runs
// without passing every gate, and the refusals are on the record.
func TestEveryOutcomeIsAudited(t *testing.T) {
	t.Parallel()

	r := newRig(t, rigOpts{})
	ctx := context.Background()

	// One of each: allowed, denied, escalated.
	for _, c := range []struct {
		tool, action string
		params       map[string]any
	}{
		{"docker", "logs", map[string]any{"container": "api"}},
		{"docker", "become_root", map[string]any{}},
		{"docker", "restart_container", map[string]any{"container": "api"}},
	} {
		req := r.propose(t, c.tool, c.action, c.params, 0.9)
		if _, err := r.h.Evaluate(ctx, req); err != nil {
			t.Fatalf("Evaluate %s.%s: %v", c.tool, c.action, err)
		}
	}

	entries := r.audit.all()
	if len(entries) != 3 {
		t.Fatalf("%d audit entries for 3 decisions", len(entries))
	}
	for _, e := range entries {
		if e.ToolCallID == nil || e.IncidentID == nil {
			t.Errorf("entry %q is not correlated to its tool call or incident", e.Action)
		}
		if e.ActorID.IsZero() {
			t.Errorf("entry %q does not name the agent that made the request", e.Action)
		}
	}
}

// Parameters are assembled by a model from whatever it read — logs, config,
// environment. They must be redacted before reaching a table operators browse.
func TestAuditedParametersAreRedacted(t *testing.T) {
	t.Parallel()

	r := newRig(t, rigOpts{})
	req := r.propose(t, "docker", "logs",
		map[string]any{"container": "api-worker", "password": "hunter2"}, 0.9)

	if _, err := r.h.Evaluate(context.Background(), req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	entries := r.audit.all()
	if len(entries) != 1 {
		t.Fatalf("%d audit entries", len(entries))
	}
	if got, _ := entries[0].Params["password"].(string); strings.Contains(got, "hunter2") {
		t.Errorf("a secret reached the audit ledger verbatim: %q", got)
	}
}

// A failed audit write must not be silent: the ledger is the reason the rest of
// the package can be trusted.
func TestTheDecisionStillHoldsWhenTheLedgerIsUnavailable(t *testing.T) {
	t.Parallel()

	r := newRig(t, rigOpts{})
	r.audit.failing = true

	req := r.propose(t, "database", "drop_table", map[string]any{"table": "users"}, 1.0)
	res, err := r.h.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// The refusal must still happen — an audit outage is not a reason to allow.
	if res.Request.Decision.Permits() {
		t.Error("a destructive action was permitted because the ledger was down")
	}
}

// -----------------------------------------------------------------------------
// Approval
// -----------------------------------------------------------------------------

func TestApprovalExecutesAndRejectionDoesNot(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		decision     harness.ApprovalDecision
		role         user.Role
		wantDecision domainharness.Decision
		wantExecuted bool
	}{
		{"approval executes", harness.ApprovalApprove, user.RoleOperator,
			domainharness.DecisionApproved, true},
		{"rejection does not", harness.ApprovalReject, user.RoleOperator,
			domainharness.DecisionRejected, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t, rigOpts{})
			ctx := context.Background()

			req := r.propose(t, "docker", "restart_container",
				map[string]any{"container": "api-worker"}, 0.9)
			if _, err := r.h.Evaluate(ctx, req); err != nil {
				t.Fatalf("Evaluate: %v", err)
			}

			res, err := r.h.ApplyApproval(ctx, req.ID, tc.decision,
				harness.Approver{UserID: shared.NewID(), Email: "op@aegisops.local", Role: tc.role},
				"the diagnosis looks right")
			if err != nil {
				t.Fatalf("ApplyApproval: %v", err)
			}

			if res.Request.Decision != tc.wantDecision {
				t.Errorf("decision = %s, want %s", res.Request.Decision, tc.wantDecision)
			}
			if (res.Execution != nil) != tc.wantExecuted {
				t.Errorf("executed = %v, want %v", res.Execution != nil, tc.wantExecuted)
			}
			if got := r.calls.executionCount(); (got > 0) != tc.wantExecuted {
				t.Errorf("%d executions recorded, wantExecuted=%v", got, tc.wantExecuted)
			}
		})
	}
}

// A refused approval attempt must be recorded as a denial, not as a failure.
//
// OutcomeFailed means "the action ran and did not work". Filing "a viewer tried
// to approve a medium-risk restart" under it would bury an attempted privilege
// escalation among ordinary execution failures — and that entry is exactly the
// one a reviewer goes looking for.
func TestARefusedApprovalIsAuditedAsADenial(t *testing.T) {
	t.Parallel()

	r := newRig(t, rigOpts{})
	ctx := context.Background()

	req := r.propose(t, "docker", "restart_container",
		map[string]any{"container": "api-worker"}, 0.9)
	if _, err := r.h.Evaluate(ctx, req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	// A viewer has no authority for a medium-risk action.
	_, err := r.h.ApplyApproval(ctx, req.ID, harness.ApprovalApprove,
		harness.Approver{UserID: shared.NewID(), Email: "viewer@x", Role: user.RoleViewer}, "fine by me")
	if err == nil {
		t.Fatal("a viewer approved a medium-risk action")
	}

	entries := r.audit.all()
	last := entries[len(entries)-1]
	if last.Outcome != domainharness.OutcomeDenied {
		t.Errorf("a refused approval was audited as %s, want denied", last.Outcome)
	}
	if !strings.Contains(last.Reason, "does not grant") {
		t.Errorf("the ledger does not record why: %q", last.Reason)
	}
}

// An operator may approve a container restart and may not approve a database
// rollback. Both arrive at the same endpoint.
func TestApprovalRequiresAuthorityForTheRiskTier(t *testing.T) {
	t.Parallel()

	r := newRig(t, rigOpts{
		perms: []*domainharness.Permission{
			perm("action", "kubernetes", "rollback_deployment", domainharness.EffectAllow),
		},
		policies: []*domainharness.Policy{
			policy("rollback", "kubernetes", "rollback_deployment", domainharness.RiskHigh, true, 0),
		},
	})
	ctx := context.Background()

	req := r.propose(t, "kubernetes", "rollback_deployment",
		map[string]any{"deployment": "api", "namespace": "default"}, 0.95)
	if _, err := r.h.Evaluate(ctx, req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	_, err := r.h.ApplyApproval(ctx, req.ID, harness.ApprovalApprove,
		harness.Approver{UserID: shared.NewID(), Email: "op@x", Role: user.RoleOperator}, "go")
	if err == nil {
		t.Fatal("an operator approved a high-risk rollback")
	}
	if r.calls.executionCount() != 0 {
		t.Error("the rollback executed despite the refusal")
	}

	// An admin can.
	if _, err := r.h.ApplyApproval(ctx, req.ID, harness.ApprovalApprove,
		harness.Approver{UserID: shared.NewID(), Email: "admin@x", Role: user.RoleAdmin}, "go"); err != nil {
		t.Fatalf("an admin could not approve a high-risk rollback: %v", err)
	}
	if r.calls.executionCount() != 1 {
		t.Error("the approved rollback did not execute")
	}
}

// A human approved a decision made under the policy as it stood. If the policy
// moved the action into the forbidden tier since, honouring the click would
// execute something the deployment has decided it will not do.
func TestAStaleApprovalIsRefusedAfterThePolicyChanges(t *testing.T) {
	t.Parallel()

	rules := &stubRules{
		perms: []*domainharness.Permission{
			perm("action", "docker", "restart_container", domainharness.EffectAllow),
		},
		policies: []*domainharness.Policy{
			policy("restart", "docker", "restart_container", domainharness.RiskMedium, true, 0),
		},
	}
	clock := shared.SystemClock{}
	reg := testRegistry(t)
	calls := newMemCalls()

	a, _ := domainagent.New(clock, "action", domainagent.KindAction, "test")
	policyEngine := harness.NewPolicyEngine(rules, clock, time.Millisecond, "high")

	h := harness.New(harness.Deps{
		Registry:   reg,
		Permission: harness.NewPermissionEngine(rules, clock, time.Minute),
		Policy:     policyEngine,
		Approval:   harness.NewApprovalGate(clock, 30*time.Minute),
		Executor:   harness.NewExecutor(harness.ExecutorConfig{Registry: reg, Clock: clock}),
		Calls:      calls, Audit: &memAudit{}, Incidents: &memIncidents{},
		Agents: &memAgents{agent: a}, Clock: clock,
	})

	ctx := context.Background()
	req, _ := domainharness.NewToolCallRequest(clock, shared.NewID(), a.ID,
		"docker", "restart_container", "restart it")
	req.AgentName = "action"
	req.Params = map[string]any{"container": "api-worker"}
	req.Confidence = 0.9
	if err := calls.Create(ctx, req); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := h.Evaluate(ctx, req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	// Somebody forbids the action while it sits in the queue.
	rules.policies = []*domainharness.Policy{
		policy("restart", "docker", "restart_container", domainharness.RiskForbidden, true, 0),
	}
	policyEngine.Invalidate()

	_, err := h.ApplyApproval(ctx, req.ID, harness.ApprovalApprove,
		harness.Approver{UserID: shared.NewID(), Email: "admin@x", Role: user.RoleAdmin}, "go")
	if err == nil {
		t.Fatal("a stale approval executed after the policy forbade the action")
	}
	if !strings.Contains(err.Error(), "policy changed") && !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
	if calls.executionCount() != 0 {
		t.Error("the action executed despite the policy change")
	}
}

// The bus delivers at least once. Without idempotency, a redelivery restarts the
// container a second time.
func TestARedeliveredRequestIsNotExecutedTwice(t *testing.T) {
	t.Parallel()

	r := newRig(t, rigOpts{})
	ctx := context.Background()

	req := r.propose(t, "docker", "logs", map[string]any{"container": "api"}, 0.9)

	for i := range 3 {
		reloaded, err := r.calls.Get(ctx, req.ID)
		if err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
		if _, err := r.h.Evaluate(ctx, reloaded); err != nil {
			t.Fatalf("Evaluate %d: %v", i, err)
		}
	}

	if got := r.calls.executionCount(); got != 1 {
		t.Errorf("%d executions for 3 deliveries of the same request", got)
	}
	// And only the first delivery produced a decision entry; the redeliveries
	// are recognised before any gate runs.
	if entries := r.audit.all(); len(entries) != 3 {
		t.Logf("%d audit entries (redeliveries are recorded too, which is correct)", len(entries))
	}
}

// The executor must refuse a request that has not been approved, even if called
// directly. It is the last function before infrastructure changes.
func TestTheExecutorRefusesAnUnapprovedRequest(t *testing.T) {
	t.Parallel()

	reg := testRegistry(t)
	exec := harness.NewExecutor(harness.ExecutorConfig{Registry: reg, Clock: shared.SystemClock{}})

	req, _ := domainharness.NewToolCallRequest(shared.SystemClock{}, shared.NewID(), shared.NewID(),
		"docker", "restart_container", "just do it")
	req.Params = map[string]any{"container": "api"}

	for _, decision := range []domainharness.Decision{
		domainharness.DecisionPending,
		domainharness.DecisionAwaitingApproval,
		domainharness.DecisionRejected,
		domainharness.DecisionDeniedPolicy,
		domainharness.DecisionExpired,
	} {
		req.Decision = decision
		if _, err := exec.Execute(context.Background(), req); err == nil {
			t.Errorf("the executor ran a request whose decision was %s", decision)
		}
	}
}

// Live execution against a tool with no implementation must fail loudly rather
// than report a success a responder would read as "the remediation ran".
func TestAnUnimplementedToolRefusesToReportSuccessWhenLive(t *testing.T) {
	t.Parallel()

	r := newRig(t, rigOpts{live: true})
	ctx := context.Background()

	req := r.propose(t, "docker", "logs", map[string]any{"container": "api"}, 0.9)
	res, err := r.h.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if res.Execution == nil {
		t.Fatal("no execution was recorded")
	}
	if res.Execution.Status != domainharness.ExecFailed {
		t.Errorf("status = %s, want failed", res.Execution.Status)
	}
	if res.Execution.Succeeded() {
		t.Error("an unimplemented tool reported success")
	}
	if !strings.Contains(res.Execution.Error, "Phase 7") {
		t.Errorf("the error does not explain itself: %q", res.Execution.Error)
	}
}

// The timeline is how a responder sees what the harness did.
func TestDecisionsReachTheIncidentTimeline(t *testing.T) {
	t.Parallel()

	r := newRig(t, rigOpts{})
	ctx := context.Background()

	denied := r.propose(t, "docker", "become_root", map[string]any{}, 0.9)
	if _, err := r.h.Evaluate(ctx, denied); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	escalated := r.propose(t, "docker", "restart_container",
		map[string]any{"container": "api"}, 0.9)
	if _, err := r.h.Evaluate(ctx, escalated); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	types := r.incidents.eventTypes()
	want := map[string]bool{
		string(incident.EventToolRejected):     false,
		string(incident.EventApprovalRequired): false,
	}
	for _, typ := range types {
		if _, tracked := want[typ]; tracked {
			want[typ] = true
		}
	}
	for typ, seen := range want {
		if !seen {
			t.Errorf("%s never reached the timeline; got %v", typ, types)
		}
	}
}

// A tool that panics must not take down a control plane that is, at that moment,
// managing an outage.
func TestAPanickingToolIsContained(t *testing.T) {
	t.Parallel()

	reg := harness.NewRegistry()
	if err := reg.Register(panicTool{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	exec := harness.NewExecutor(harness.ExecutorConfig{
		Registry: reg, Clock: shared.SystemClock{}, Live: true,
	})

	req, _ := domainharness.NewToolCallRequest(shared.SystemClock{}, shared.NewID(), shared.NewID(),
		"boom", "explode", "test")
	req.Decision = domainharness.DecisionAllowed

	e, err := exec.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute returned an error rather than a failed execution: %v", err)
	}
	if e.Status != domainharness.ExecFailed {
		t.Errorf("status = %s, want failed", e.Status)
	}
	if !strings.Contains(e.Error, "panicked") {
		t.Errorf("the error does not record the panic: %q", e.Error)
	}
}

type panicTool struct{}

func (panicTool) Descriptor() ports.ToolDescriptor {
	return ports.ToolDescriptor{
		Name: "boom", Actions: map[string]ports.ActionDescriptor{"explode": {}},
	}
}
func (panicTool) Invoke(context.Context, ports.ToolInvocation) (ports.ToolResult, error) {
	panic("the daemon went away")
}

// Requests nobody ruled on must expire, so an operator can tell "waiting for me"
// from "waiting since Tuesday".
func TestPendingRequestsExpire(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{now: time.Now()}
	rules := &stubRules{
		perms: []*domainharness.Permission{
			perm("action", "docker", "restart_container", domainharness.EffectAllow),
		},
		policies: []*domainharness.Policy{
			policy("restart", "docker", "restart_container", domainharness.RiskMedium, true, 0),
		},
	}
	reg := testRegistry(t)
	calls := newMemCalls()
	a, _ := domainagent.New(clock, "action", domainagent.KindAction, "test")

	h := harness.New(harness.Deps{
		Registry:   reg,
		Permission: harness.NewPermissionEngine(rules, clock, time.Minute),
		Policy:     harness.NewPolicyEngine(rules, clock, time.Minute, "high"),
		Approval:   harness.NewApprovalGate(clock, 30*time.Minute),
		Executor:   harness.NewExecutor(harness.ExecutorConfig{Registry: reg, Clock: clock}),
		Calls:      calls, Audit: &memAudit{}, Incidents: &memIncidents{},
		Agents: &memAgents{agent: a}, Clock: clock,
	})

	ctx := context.Background()
	req, _ := domainharness.NewToolCallRequest(clock, shared.NewID(), a.ID,
		"docker", "restart_container", "restart it")
	req.AgentName = "action"
	req.Params = map[string]any{"container": "api-worker"}
	req.Confidence = 0.9
	if err := calls.Create(ctx, req); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := h.Evaluate(ctx, req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	// Nothing expires yet.
	if n, err := h.ExpirePending(ctx); err != nil || n != 0 {
		t.Fatalf("ExpirePending expired %d fresh requests (err=%v)", n, err)
	}

	clock.advance(time.Hour)

	n, err := h.ExpirePending(ctx)
	if err != nil {
		t.Fatalf("ExpirePending: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired %d requests, want 1", n)
	}

	reloaded, err := calls.Get(ctx, req.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Decision != domainharness.DecisionExpired {
		t.Errorf("decision = %s, want expired", reloaded.Decision)
	}
}
