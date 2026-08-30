//go:build integration

package integration

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	domainagent "github.com/bishal05das/aegisops-ai/internal/domain/agent"
	domainharness "github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/harness"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/repository/postgres"
	"github.com/bishal05das/aegisops-ai/internal/tools"
)

// The unit tests run the harness against in-memory repositories, which proves
// the gates. These prove the parts only the real database can: the seeded
// permission matrix and policy table actually say what the design claims, the
// unique constraint on executions really does make a double execution
// impossible, and the audit ledger really is append-only.

func newHarness(t *testing.T, ctx context.Context, ceiling string, live bool) (*harness.Harness, *postgres.ToolCallRepo, map[domainagent.Kind]shared.ID) {
	t.Helper()

	db := openDB(t)
	policyRepo := postgres.NewPolicyRepo(db)
	callRepo := postgres.NewToolCallRepo(db)
	agentRepo := postgres.NewAgentRepo(db)
	auditRepo := postgres.NewAuditRepo(db)

	reg := harness.NewRegistry()
	for _, desc := range tools.Catalog() {
		if err := reg.Register(harness.NewNoopTool(desc)); err != nil {
			t.Fatalf("register %s: %v", desc.Name, err)
		}
	}

	ids := make(map[domainagent.Kind]shared.ID, len(domainagent.AllKinds))
	for _, kind := range domainagent.AllKinds {
		a, err := domainagent.New(clock, string(kind), kind, "harness integration test")
		if err != nil {
			t.Fatalf("build agent %s: %v", kind, err)
		}
		if err := agentRepo.Upsert(ctx, a); err != nil {
			t.Fatalf("register agent %s: %v", kind, err)
		}
		ids[kind] = a.ID
	}

	h := harness.New(harness.Deps{
		Registry:   reg,
		Permission: harness.NewPermissionEngine(policyRepo, clock, time.Minute),
		Policy:     harness.NewPolicyEngine(policyRepo, clock, time.Minute, ceiling),
		Approval:   harness.NewApprovalGate(clock, 30*time.Minute),
		Executor: harness.NewExecutor(harness.ExecutorConfig{
			Registry: reg, Clock: clock, Live: live,
		}),
		Calls: callRepo, Audit: auditRepo,
		Incidents: postgres.NewIncidentRepo(db), Agents: agentRepo,
		Clock: clock,
	})
	return h, callRepo, ids
}

// seedApprover creates a real user row.
//
// The tool_calls.decided_by foreign key means an approver must actually exist —
// the schema refuses to record a phantom approval, which is exactly the
// property you want on the column that answers "who authorised this?".
func seedApprover(t *testing.T, ctx context.Context, db *sql.DB, role user.Role) *user.User {
	t.Helper()

	u, err := user.New(clock, "approver-"+shared.NewID().String()+"@example.com", "Approver", role)
	if err != nil {
		t.Fatalf("build approver: %v", err)
	}
	u.PasswordHash = []byte("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaA")
	if err := postgres.NewUserRepo(db).Create(ctx, u); err != nil {
		t.Fatalf("create approver: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = db.ExecContext(c, `DELETE FROM users WHERE id = $1`, u.ID)
	})
	return u
}

func propose(t *testing.T, ctx context.Context, repo *postgres.ToolCallRepo, incidentID, agentID shared.ID, name, tool, action string, params map[string]any, confidence float64) *domainharness.ToolCallRequest {
	t.Helper()

	req, err := domainharness.NewToolCallRequest(clock, incidentID, agentID, tool, action,
		"the container is OOMKilling and a restart should clear it")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.AgentName = name
	req.Params = params
	req.Confidence = confidence
	if err := repo.Create(ctx, req); err != nil {
		t.Fatalf("persist request: %v", err)
	}
	return req
}

// TestSeededMatrixEnforcesTheDesign checks the claim the README makes — six of
// seven agents are structurally read-only — against the rows migration 0004
// actually inserted, rather than against a matrix a test invented.
func TestSeededMatrixEnforcesTheDesign(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)
	engine := harness.NewPermissionEngine(postgres.NewPolicyRepo(db), clock, time.Minute)

	mutating := []struct{ tool, action string }{
		{"docker", "restart_container"},
		{"kubernetes", "restart_deployment"},
		{"kubernetes", "scale_deployment"},
		{"kubernetes", "rollback_deployment"},
		{"linux", "restart_service"},
	}

	for _, kind := range domainagent.AllKinds {
		for _, m := range mutating {
			v, err := engine.Check(ctx, string(kind), m.tool, m.action)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			wantAllowed := kind == domainagent.KindAction
			if v.Allowed != wantAllowed {
				t.Errorf("%s may use %s.%s = %v, want %v (%s)",
					kind, m.tool, m.action, v.Allowed, wantAllowed, v.Reason)
			}
		}
	}
}

// No agent, including the one that may mutate, can reach a destructive action.
func TestNoAgentMayReachADestructiveAction(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)
	policyRepo := postgres.NewPolicyRepo(db)
	permissions := harness.NewPermissionEngine(policyRepo, clock, time.Minute)
	policies := harness.NewPolicyEngine(policyRepo, clock, time.Minute, "high")

	destructive := []struct{ tool, action string }{
		{"database", "drop_table"},
		{"database", "delete_database"},
		{"database", "truncate"},
		{"kubernetes", "delete_namespace"},
		{"docker", "delete_volume"},
	}

	for _, d := range destructive {
		// Refused by the permission matrix for every agent…
		for _, kind := range domainagent.AllKinds {
			v, err := permissions.Check(ctx, string(kind), d.tool, d.action)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if v.Allowed {
				t.Errorf("%s is permitted to call %s.%s", kind, d.tool, d.action)
			}
		}

		// …and independently refused by policy, so removing a permission row
		// would not open a path.
		req, err := domainharness.NewToolCallRequest(clock, shared.NewID(), shared.NewID(),
			d.tool, d.action, "test")
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		ruling, err := policies.Evaluate(ctx, req)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if ruling.Risk != domainharness.RiskForbidden {
			t.Errorf("%s.%s is tiered %s, want forbidden", d.tool, d.action, ruling.Risk)
		}
		if ruling.Decision != domainharness.DecisionDeniedPolicy {
			t.Errorf("%s.%s ruling = %s, want denied_policy", d.tool, d.action, ruling.Decision)
		}
	}
}

// The catalog, the permission matrix and the policy table are three sources of
// truth written separately. This is the check that they agree.
func TestCatalogReconcilesWithThePolicyTable(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)

	reg := harness.NewRegistry()
	for _, desc := range tools.Catalog() {
		if err := reg.Register(harness.NewNoopTool(desc)); err != nil {
			t.Fatalf("register %s: %v", desc.Name, err)
		}
	}

	engine := harness.NewPolicyEngine(postgres.NewPolicyRepo(db), clock, time.Minute, "high")
	problems, err := engine.ReconcileTools(ctx, reg)
	if err != nil {
		t.Fatalf("ReconcileTools: %v", err)
	}

	// Zero problems, not "no dangerous ones".
	//
	// An unpoliced action is denied rather than unsafe, so it would be tempting
	// to treat it as a warning. It is asserted here because that is how this
	// migration came to exist: the reconciler reported ten unpoliced actions,
	// which meant the read-only agents could gather no evidence at all. Failing
	// closed is correct; shipping a deployment where the correct behaviour is
	// "nothing works" is not. See migration 0008.
	for _, p := range problems {
		t.Errorf("catalog and policy table disagree: %s", p)
	}
}

// The full pipeline against the real schema, ending in a real approval.
func TestApprovalPipelineEndToEnd(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)
	h, calls, agentIDs := newHarness(t, ctx, "high", false)
	inc := seedIncident(t, ctx, db, postgres.NewIncidentRepo(db), "integration: harness approval")

	req := propose(t, ctx, calls, inc.ID, agentIDs[domainagent.KindAction], "action",
		"docker", "restart_container", map[string]any{"container": "api-worker"}, 0.9)

	res, err := h.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Request.Decision != domainharness.DecisionAwaitingApproval {
		t.Fatalf("decision = %s, want awaiting_approval (%s)", res.Request.Decision, res.Reason)
	}
	if res.Request.Risk != domainharness.RiskMedium {
		t.Errorf("risk = %s, want medium", res.Request.Risk)
	}

	// It appears in the operator's queue, having survived a round trip.
	page, err := calls.List(ctx, ports.ToolCallFilter{PendingApproval: true}, ports.Page{Limit: 100})
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	var queued bool
	for _, r := range page.Items {
		if r.ID == req.ID {
			queued = true
			if r.Reason == "" {
				t.Error("the agent's reasoning did not survive persistence")
			}
		}
	}
	if !queued {
		t.Fatal("the request is not in the pending queue")
	}

	// An operator approves it.
	approver := seedApprover(t, ctx, db, user.RoleOperator)
	res, err = h.ApplyApproval(ctx, req.ID, harness.ApprovalApprove,
		harness.Approver{UserID: approver.ID, Email: approver.Email, Role: approver.Role},
		"the diagnosis matches the metrics")
	if err != nil {
		t.Fatalf("ApplyApproval: %v", err)
	}
	if res.Request.Decision != domainharness.DecisionApproved {
		t.Fatalf("decision = %s, want approved", res.Request.Decision)
	}
	if res.Execution == nil {
		t.Fatal("the approval did not lead to an execution")
	}
	if res.Execution.Status != domainharness.ExecDryRun {
		t.Errorf("status = %s, want dry_run", res.Execution.Status)
	}

	// The execution is durable and the approver is recorded.
	stored, err := calls.GetExecution(ctx, req.ID)
	if err != nil {
		t.Fatalf("load execution: %v", err)
	}
	if !stored.DryRun {
		t.Error("a dry run was recorded as a real execution")
	}
	reloaded, err := calls.Get(ctx, req.ID)
	if err != nil {
		t.Fatalf("reload request: %v", err)
	}
	if reloaded.DecidedBy == nil {
		t.Error("the approving user was not recorded")
	} else if *reloaded.DecidedBy != approver.ID {
		t.Errorf("decided_by = %s, want the approver %s", reloaded.DecidedBy, approver.ID)
	}
	if reloaded.DecisionNote == "" {
		t.Error("the approver's justification was not recorded")
	}
}

// The unique constraint on executions.tool_call_id is doing security work: it
// is what makes a double execution impossible rather than merely unlikely.
func TestTheSchemaMakesADoubleExecutionImpossible(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)
	calls := postgres.NewToolCallRepo(db)
	inc := seedIncident(t, ctx, db, postgres.NewIncidentRepo(db), "integration: double execution")

	agentRepo := postgres.NewAgentRepo(db)
	a, err := domainagent.New(clock, string(domainagent.KindAction), domainagent.KindAction, "test")
	if err != nil {
		t.Fatalf("build agent: %v", err)
	}
	if err := agentRepo.Upsert(ctx, a); err != nil {
		t.Fatalf("register agent: %v", err)
	}

	req := propose(t, ctx, calls, inc.ID, a.ID, "action",
		"docker", "restart_container", map[string]any{"container": "api"}, 0.9)

	first, err := domainharness.NewExecution(clock, req.ID, domainharness.ExecSucceeded, false)
	if err != nil {
		t.Fatalf("build execution: %v", err)
	}
	if err := calls.SaveExecution(ctx, first); err != nil {
		t.Fatalf("first execution: %v", err)
	}

	second, err := domainharness.NewExecution(clock, req.ID, domainharness.ExecSucceeded, false)
	if err != nil {
		t.Fatalf("build execution: %v", err)
	}
	err = calls.SaveExecution(ctx, second)
	if err == nil {
		t.Fatal("the database accepted a second execution for one tool call")
	}
	if !strings.Contains(err.Error(), "already been executed") {
		t.Errorf("the error does not explain itself: %v", err)
	}
}

// Rejections must be recorded as fully as executions. A harness that only logs
// what it ran throws away its most valuable signal.
func TestRefusalsReachTheLedger(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)
	h, calls, agentIDs := newHarness(t, ctx, "high", false)
	auditRepo := postgres.NewAuditRepo(db)
	inc := seedIncident(t, ctx, db, postgres.NewIncidentRepo(db), "integration: refusal ledger")

	// The Action agent asks to drop a table.
	req := propose(t, ctx, calls, inc.ID, agentIDs[domainagent.KindAction], "action",
		"database", "drop_table", map[string]any{"table": "users"}, 1.0)

	res, err := h.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Request.Decision.Permits() {
		t.Fatalf("a table drop was permitted: %s", res.Reason)
	}

	page, err := auditRepo.List(ctx, ports.AuditFilter{IncidentID: &inc.ID}, ports.Page{Limit: 50})
	if err != nil {
		t.Fatalf("read the ledger: %v", err)
	}

	var found *domainharness.AuditEntry
	for _, e := range page.Items {
		if e.ToolCallID != nil && *e.ToolCallID == req.ID {
			found = e
		}
	}
	if found == nil {
		t.Fatal("the refusal is not in the ledger")
	}
	if found.Outcome != domainharness.OutcomeDenied {
		t.Errorf("outcome = %s, want denied", found.Outcome)
	}
	if found.Action != "database.drop_table" {
		t.Errorf("action = %q, want database.drop_table", found.Action)
	}
	if found.Reason == "" {
		t.Error("the ledger records the refusal but not why")
	}
	// The model's own words must be recoverable during a postmortem.
	if found.ActorName != "action" {
		t.Errorf("actor = %q, want the agent that asked", found.ActorName)
	}
	t.Logf("ledger seq %d: %s -> %s (%s)", found.Seq, found.Action, found.Outcome, found.Reason)
}

// The chain must verify over entries the harness itself wrote.
func TestTheLedgerVerifiesAfterHarnessDecisions(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)
	h, calls, agentIDs := newHarness(t, ctx, "high", false)
	auditRepo := postgres.NewAuditRepo(db)
	inc := seedIncident(t, ctx, db, postgres.NewIncidentRepo(db), "integration: chain after decisions")

	before, err := auditRepo.LatestSeq(ctx)
	if err != nil {
		t.Fatalf("LatestSeq: %v", err)
	}

	for _, c := range []struct {
		tool, action string
		params       map[string]any
	}{
		{"docker", "logs", map[string]any{"container": "api"}},
		{"database", "drop_table", map[string]any{"table": "users"}},
		{"docker", "restart_container", map[string]any{"container": "api"}},
	} {
		req := propose(t, ctx, calls, inc.ID, agentIDs[domainagent.KindAction], "action",
			c.tool, c.action, c.params, 0.9)
		if _, err := h.Evaluate(ctx, req); err != nil {
			t.Fatalf("Evaluate %s.%s: %v", c.tool, c.action, err)
		}
	}

	after, err := auditRepo.LatestSeq(ctx)
	if err != nil {
		t.Fatalf("LatestSeq: %v", err)
	}
	if after <= before {
		t.Fatalf("the ledger did not grow: %d -> %d", before, after)
	}

	result, err := auditRepo.VerifyChain(ctx, before+1, after)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !result.Valid {
		t.Errorf("the chain broke at seq %d: %s", result.BrokenAtSeq, result.Reason)
	}
	t.Logf("verified %d entries written by the harness", result.Checked)
}

// A permission granted through the API must take effect without a restart, and
// a revocation must take effect promptly.
func TestPermissionChangesTakeEffect(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)
	repo := postgres.NewPolicyRepo(db)
	engine := harness.NewPermissionEngine(repo, clock, time.Hour)

	// A tool/action pair nothing else in the suite touches.
	const kind, tool, action = "documentation", "git", "integration_probe"

	v, err := engine.Check(ctx, kind, tool, action)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Allowed {
		t.Fatal("an ungranted action was allowed")
	}

	rule := &domainharness.Permission{
		AgentKind: kind, Tool: tool, Action: action, Effect: domainharness.EffectAllow,
	}
	if err := repo.UpsertPermission(ctx, rule); err != nil {
		t.Fatalf("UpsertPermission: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = repo.DeletePermission(cleanupCtx, rule.ID)
	})

	// Without invalidation the hour-long TTL still serves the old matrix, which
	// is why Invalidate exists rather than relying on the TTL.
	engine.Invalidate()

	v, err = engine.Check(ctx, kind, tool, action)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !v.Allowed {
		t.Errorf("the new rule did not take effect: %s", v.Reason)
	}
}

// The database refuses to store a policy that claims a forbidden action needs
// no approval — such a row would read as a path to executing it.
func TestTheSchemaRefusesAForbiddenPolicyWithoutApproval(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)
	repo := postgres.NewPolicyRepo(db)

	err := repo.UpsertPolicy(ctx, &domainharness.Policy{
		Name: "integration-bad-forbidden", Tool: "database", Action: "integration_probe",
		Risk: domainharness.RiskForbidden, RequiresApproval: false, Enabled: true,
	})
	if err == nil {
		t.Fatal("the database stored a forbidden action that requires no approval")
	}
	if !strings.Contains(err.Error(), "forbidden action must require approval") {
		t.Errorf("the error does not explain the constraint: %v", err)
	}
}
