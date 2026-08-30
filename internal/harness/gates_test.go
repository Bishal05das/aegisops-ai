package harness_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domainharness "github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/harness"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/tools"
)

// These tests exercise each gate in isolation. The pipeline that runs them in
// order is tested separately; here the question is whether each gate, on its
// own, refuses what it is supposed to refuse.

// -----------------------------------------------------------------------------
// Gate 1: the registry
// -----------------------------------------------------------------------------

func testRegistry(t *testing.T) *harness.Registry {
	t.Helper()
	reg := harness.NewRegistry()
	for _, desc := range tools.Catalog() {
		if err := reg.Register(harness.NewNoopTool(desc)); err != nil {
			t.Fatalf("register %s: %v", desc.Name, err)
		}
	}
	return reg
}

func TestRegistryRejectsUnknownToolsAndActions(t *testing.T) {
	t.Parallel()
	reg := testRegistry(t)

	if reg.Known("docker", "restart_container") != true {
		t.Error("a declared action is not known")
	}
	if reg.Known("docker", "become_root") {
		t.Error("an invented action is treated as known")
	}
	if reg.Known("kubernetes_but_evil", "get_pods") {
		t.Error("an invented tool is treated as known")
	}
}

// Parameter validation is the gate that runs before any permission question, so
// it has to be strict about the shapes a language model actually produces.
func TestParameterValidation(t *testing.T) {
	t.Parallel()
	reg := testRegistry(t)

	tests := []struct {
		name        string
		tool        string
		action      string
		params      map[string]any
		wantErr     bool
		errFragment string
	}{
		{
			name: "a valid call passes",
			tool: "docker", action: "restart_container",
			params: map[string]any{"container": "api-worker"},
		},
		{
			name: "a missing required parameter is refused",
			tool: "docker", action: "restart_container",
			params:  map[string]any{},
			wantErr: true, errFragment: "required",
		},
		{
			name: "an undeclared parameter is refused, not ignored",
			tool: "docker", action: "restart_container",
			params:  map[string]any{"container": "api", "sudo": true},
			wantErr: true, errFragment: "does not accept",
		},
		{
			name: "a shell metacharacter fails the name pattern",
			tool: "docker", action: "restart_container",
			params:  map[string]any{"container": "api-worker; rm -rf /"},
			wantErr: true, errFragment: "does not match",
		},
		{
			// The control-character check runs before the pattern check, so this
			// is refused for being a control character rather than for failing
			// the name pattern. Either way it never reaches a permission rule.
			name: "a newline in a name is refused",
			tool: "docker", action: "restart_container",
			params:  map[string]any{"container": "api\nworker"},
			wantErr: true, errFragment: "control character",
		},
		{
			name: "a control character in a free-text field is refused",
			tool: "monitoring", action: "query",
			params:  map[string]any{"query": "up{job=\"api\"}\x1b[2J"},
			wantErr: true, errFragment: "control character",
		},
		{
			name: "the wrong type is refused",
			tool: "docker", action: "restart_container",
			params:  map[string]any{"container": 42},
			wantErr: true, errFragment: "must be a string",
		},
		{
			name: "a fractional replica count is refused rather than truncated",
			tool: "kubernetes", action: "scale_deployment",
			params: map[string]any{
				"deployment": "api", "namespace": "default", "replicas": 2.5,
			},
			wantErr: true, errFragment: "whole number",
		},
		{
			name: "a replica count above the bound is refused",
			tool: "kubernetes", action: "scale_deployment",
			params: map[string]any{
				"deployment": "api", "namespace": "default", "replicas": 1e9,
			},
			wantErr: true, errFragment: "between",
		},
		{
			name: "parent traversal fails the path pattern",
			tool: "linux", action: "read_file",
			params:  map[string]any{"path": "/var/log/../../etc/shadow"},
			wantErr: true, errFragment: "does not match",
		},
		{
			name: "a relative path fails the path pattern",
			tool: "linux", action: "read_file",
			params:  map[string]any{"path": "etc/shadow"},
			wantErr: true, errFragment: "does not match",
		},
		{
			name: "a bare parent segment is refused",
			tool: "linux", action: "read_file",
			params:  map[string]any{"path": "/var/log/.."},
			wantErr: true, errFragment: "does not match",
		},
		{
			name: "a single-dot segment is refused",
			tool: "linux", action: "read_file",
			params:  map[string]any{"path": "/var/./log/syslog"},
			wantErr: true, errFragment: "does not match",
		},
		{
			name: "traversal in a repository path is refused",
			tool: "git", action: "read",
			params:  map[string]any{"path": "../../etc/shadow"},
			wantErr: true, errFragment: "does not match",
		},
		{
			name: "a legitimate log path is still accepted",
			tool: "linux", action: "read_file",
			params: map[string]any{"path": "/var/log/api-worker.log"},
		},
		{
			name: "an uppercase Kubernetes name is refused",
			tool: "kubernetes", action: "describe_pod",
			params:  map[string]any{"pod": "API-Worker"},
			wantErr: true, errFragment: "does not match",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := reg.ValidateParams(tc.tool, tc.action, tc.params)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%s.%s accepted %v", tc.tool, tc.action, tc.params)
				}
				if !strings.Contains(err.Error(), tc.errFragment) {
					t.Errorf("error %q does not mention %q", err, tc.errFragment)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid params were refused: %v", err)
			}
		})
	}
}

// Normalisation must not mutate the caller's map: the request's params are what
// a human approved, and they must be identical at execution.
func TestValidationDoesNotMutateTheRequest(t *testing.T) {
	t.Parallel()
	reg := testRegistry(t)

	original := map[string]any{"container": "api-worker"}
	normalised, err := reg.ValidateParams("docker", "restart_container", original)
	if err != nil {
		t.Fatalf("ValidateParams: %v", err)
	}

	if len(original) != 1 {
		t.Errorf("the caller's map gained %d entries", len(original)-1)
	}
	// The default was applied to the copy only.
	if _, ok := normalised["timeout_seconds"]; !ok {
		t.Error("the default was not applied to the normalised set")
	}
	if _, ok := original["timeout_seconds"]; ok {
		t.Error("normalisation leaked a default into the caller's map")
	}
}

// An unanchored pattern matches a substring, which would let "api; rm -rf /"
// satisfy a rule meant to allow only names.
func TestPatternsAreAnchored(t *testing.T) {
	t.Parallel()

	reg := harness.NewRegistry()
	err := reg.Register(harness.NewNoopTool(ports.ToolDescriptor{
		Name: "t", Actions: map[string]ports.ActionDescriptor{
			"a": {Params: map[string]ports.ParamSpec{
				// Deliberately written without ^ or $.
				"name": {Kind: ports.ParamString, Required: true, Pattern: `[a-z]+`},
			}},
		},
	}))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := reg.ValidateParams("t", "a", map[string]any{"name": "abc"}); err != nil {
		t.Fatalf("a valid value was refused: %v", err)
	}
	if _, err := reg.ValidateParams("t", "a", map[string]any{"name": "abc; rm -rf /"}); err == nil {
		t.Fatal("an unanchored pattern accepted a value with a shell metacharacter")
	}
}

// A descriptor that would weaken validation must fail to register, at startup,
// rather than silently accepting everything at 3am.
func TestBadDescriptorsFailToRegister(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		desc ports.ToolDescriptor
	}{
		{"no name", ports.ToolDescriptor{Actions: map[string]ports.ActionDescriptor{"a": {}}}},
		{"no actions", ports.ToolDescriptor{Name: "t"}},
		{
			"uncompilable pattern",
			ports.ToolDescriptor{Name: "t", Actions: map[string]ports.ActionDescriptor{
				"a": {Params: map[string]ports.ParamSpec{
					"p": {Kind: ports.ParamString, Pattern: `[a-z`},
				}},
			}},
		},
		{
			"unknown parameter kind",
			ports.ToolDescriptor{Name: "t", Actions: map[string]ports.ActionDescriptor{
				"a": {Params: map[string]ports.ParamSpec{"p": {Kind: "wibble"}}},
			}},
		},
		{
			"required and defaulted",
			ports.ToolDescriptor{Name: "t", Actions: map[string]ports.ActionDescriptor{
				"a": {Params: map[string]ports.ParamSpec{
					"p": {Kind: ports.ParamString, Required: true, Default: "x"},
				}},
			}},
		},
		{
			"pattern on a non-string",
			ports.ToolDescriptor{Name: "t", Actions: map[string]ports.ActionDescriptor{
				"a": {Params: map[string]ports.ParamSpec{
					"p": {Kind: ports.ParamInt, Pattern: `\d+`},
				}},
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := harness.NewRegistry().Register(harness.NewNoopTool(tc.desc)); err == nil {
				t.Error("a malformed descriptor registered successfully")
			}
		})
	}
}

func TestDuplicateRegistrationIsRefused(t *testing.T) {
	t.Parallel()

	reg := harness.NewRegistry()
	desc := tools.Docker()
	if err := reg.Register(harness.NewNoopTool(desc)); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	// Silent replacement would let a second registration widen what the first
	// allowed — a privilege change disguised as startup ordering.
	if err := reg.Register(harness.NewNoopTool(desc)); err == nil {
		t.Error("a duplicate registration silently replaced the first")
	}
}

// -----------------------------------------------------------------------------
// Gate 2: permissions
// -----------------------------------------------------------------------------

type stubRules struct {
	perms    []*domainharness.Permission
	policies []*domainharness.Policy
	permErr  error
	polErr   error
	permHits int
}

func (s *stubRules) ListPermissions(context.Context) ([]*domainharness.Permission, error) {
	s.permHits++
	if s.permErr != nil {
		return nil, s.permErr
	}
	return s.perms, nil
}

func (s *stubRules) ListPolicies(context.Context) ([]*domainharness.Policy, error) {
	if s.polErr != nil {
		return nil, s.polErr
	}
	return s.policies, nil
}

func (s *stubRules) UpsertPermission(context.Context, *domainharness.Permission) error { return nil }
func (s *stubRules) UpsertPolicy(context.Context, *domainharness.Policy) error         { return nil }
func (s *stubRules) DeletePermission(context.Context, shared.ID) error                 { return nil }
func (s *stubRules) DeletePolicy(context.Context, shared.ID) error                     { return nil }

func perm(kind, tool, action string, effect domainharness.Effect) *domainharness.Permission {
	return &domainharness.Permission{
		ID: shared.NewID(), AgentKind: kind, Tool: tool, Action: action, Effect: effect,
	}
}

// The single most important property in the package.
func TestPermissionsDenyByDefault(t *testing.T) {
	t.Parallel()

	engine := harness.NewPermissionEngine(&stubRules{}, shared.SystemClock{}, time.Minute)
	v, err := engine.Check(context.Background(), "action", "docker", "restart_container")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Allowed {
		t.Fatal("an empty permission matrix allowed an action")
	}
	if !strings.Contains(v.Reason, "denies by default") {
		t.Errorf("the denial does not explain itself: %q", v.Reason)
	}
	if v.Rule != nil {
		t.Error("a default denial named a rule that does not exist")
	}
}

func TestPermissionResolutionOrder(t *testing.T) {
	t.Parallel()

	rules := &stubRules{perms: []*domainharness.Permission{
		// A blanket allow, carved back by a targeted deny.
		perm("monitoring", "docker", "*", domainharness.EffectAllow),
		perm("monitoring", "docker", "restart_container", domainharness.EffectDeny),
		// Equal specificity, conflicting effects: deny must win.
		perm("action", "docker", "start_container", domainharness.EffectAllow),
		perm("action", "docker", "start_container", domainharness.EffectDeny),
	}}
	engine := harness.NewPermissionEngine(rules, shared.SystemClock{}, time.Minute)

	tests := []struct {
		kind, tool, action string
		want               bool
		why                string
	}{
		{"monitoring", "docker", "logs", true, "the blanket allow applies"},
		{"monitoring", "docker", "restart_container", false, "the specific deny beats the blanket allow"},
		{"action", "docker", "start_container", false, "an explicit deny beats an equally specific allow"},
		{"documentation", "docker", "logs", false, "no rule exists for this agent"},
	}

	for _, tc := range tests {
		v, err := engine.Check(context.Background(), tc.kind, tc.tool, tc.action)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if v.Allowed != tc.want {
			t.Errorf("%s:%s.%s = %v, want %v (%s)",
				tc.kind, tc.tool, tc.action, v.Allowed, tc.want, tc.why)
		}
	}
}

// A matrix that cannot be loaded is not an excuse to proceed.
func TestPermissionEngineFailsClosedOnAColdCache(t *testing.T) {
	t.Parallel()

	rules := &stubRules{permErr: context.DeadlineExceeded}
	engine := harness.NewPermissionEngine(rules, shared.SystemClock{}, time.Minute)

	if _, err := engine.Check(context.Background(), "action", "docker", "restart_container"); err == nil {
		t.Fatal("the engine returned a verdict without being able to read the rules")
	}
}

// A warm cache is different: stale-but-real beats failing an investigation that
// is already permitted.
func TestPermissionEngineServesStaleRulesWhenTheDatabaseIsDown(t *testing.T) {
	t.Parallel()

	rules := &stubRules{perms: []*domainharness.Permission{
		perm("action", "docker", "restart_container", domainharness.EffectAllow),
	}}
	clock := &fakeClock{now: time.Now()}
	engine := harness.NewPermissionEngine(rules, clock, time.Minute)

	if v, err := engine.Check(context.Background(), "action", "docker", "restart_container"); err != nil || !v.Allowed {
		t.Fatalf("warm-up failed: allowed=%v err=%v", v.Allowed, err)
	}

	// The database goes away, and the cache expires.
	rules.permErr = context.DeadlineExceeded
	clock.advance(2 * time.Minute)

	v, err := engine.Check(context.Background(), "action", "docker", "restart_container")
	if err != nil {
		t.Fatalf("the engine failed rather than serving the last known matrix: %v", err)
	}
	if !v.Allowed {
		t.Error("the stale matrix produced a different verdict")
	}
}

func TestPermissionCacheIsInvalidatedOnDemand(t *testing.T) {
	t.Parallel()

	rules := &stubRules{}
	engine := harness.NewPermissionEngine(rules, shared.SystemClock{}, time.Hour)

	if _, err := engine.Check(context.Background(), "action", "docker", "x"); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := engine.Check(context.Background(), "action", "docker", "x"); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rules.permHits != 1 {
		t.Errorf("the matrix was loaded %d times; the cache is not working", rules.permHits)
	}

	// Waiting out an hour-long TTL after revoking a permission would leave the
	// revocation written but unenforced.
	engine.Invalidate()
	if _, err := engine.Check(context.Background(), "action", "docker", "x"); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rules.permHits != 2 {
		t.Error("Invalidate did not force a reload")
	}
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// -----------------------------------------------------------------------------
// Gate 3: policy
// -----------------------------------------------------------------------------

func policy(name, tool, action string, risk domainharness.Risk, approval bool, minConf float64) *domainharness.Policy {
	return &domainharness.Policy{
		ID: shared.NewID(), Name: name, Tool: tool, Action: action,
		Risk: risk, RequiresApproval: approval, MinConfidence: minConf, Enabled: true,
	}
}

func request(tool, action string, confidence float64) *domainharness.ToolCallRequest {
	req, err := domainharness.NewToolCallRequest(shared.SystemClock{},
		shared.NewID(), shared.NewID(), tool, action, "because the test says so")
	if err != nil {
		panic(err)
	}
	req.Confidence = confidence
	return req
}

func TestPolicyRulings(t *testing.T) {
	t.Parallel()

	rules := &stubRules{policies: []*domainharness.Policy{
		policy("logs", "docker", "logs", domainharness.RiskLow, false, 0),
		policy("restart", "docker", "restart_container", domainharness.RiskMedium, true, 0.7),
		policy("rollback", "kubernetes", "rollback_deployment", domainharness.RiskHigh, true, 0.85),
		policy("drop", "database", "drop_table", domainharness.RiskForbidden, true, 1),
		// Low risk, no approval, but a confidence floor.
		policy("query", "monitoring", "query", domainharness.RiskLow, false, 0.5),
	}}

	tests := []struct {
		name         string
		ceiling      string
		tool, action string
		confidence   float64
		wantDecision domainharness.Decision
		reasonHas    string
	}{
		{
			name:    "a read-only action executes automatically",
			ceiling: "low", tool: "docker", action: "logs", confidence: 0.9,
			wantDecision: domainharness.DecisionAllowed,
		},
		{
			name:    "a policy demanding approval escalates",
			ceiling: "high", tool: "docker", action: "restart_container", confidence: 0.9,
			wantDecision: domainharness.DecisionAwaitingApproval,
			reasonHas:    "requires a human",
		},
		{
			name:    "an action above the ceiling escalates rather than being refused",
			ceiling: "low", tool: "kubernetes", action: "rollback_deployment", confidence: 0.99,
			wantDecision: domainharness.DecisionAwaitingApproval,
			reasonHas:    "autonomy ceiling",
		},
		{
			name:    "a forbidden action is denied outright",
			ceiling: "high", tool: "database", action: "drop_table", confidence: 1.0,
			wantDecision: domainharness.DecisionDeniedPolicy,
			reasonHas:    "no approval can authorise it",
		},
		{
			name:    "an untiered action is denied rather than assumed safe",
			ceiling: "high", tool: "docker", action: "start_container", confidence: 0.9,
			wantDecision: domainharness.DecisionDeniedPolicy,
			reasonHas:    "no policy governs",
		},
		{
			name:    "a low-confidence agent is sent to a human even for a low-risk action",
			ceiling: "high", tool: "monitoring", action: "query", confidence: 0.2,
			wantDecision: domainharness.DecisionAwaitingApproval,
			reasonHas:    "confidence",
		},
		{
			name:    "max_auto_risk=none escalates even a read",
			ceiling: "none", tool: "docker", action: "logs", confidence: 1.0,
			wantDecision: domainharness.DecisionAwaitingApproval,
			reasonHas:    "no autonomy",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			engine := harness.NewPolicyEngine(rules, shared.SystemClock{}, time.Minute, tc.ceiling)
			ruling, err := engine.Evaluate(context.Background(), request(tc.tool, tc.action, tc.confidence))
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if ruling.Decision != tc.wantDecision {
				t.Errorf("decision = %s, want %s (reason: %s)",
					ruling.Decision, tc.wantDecision, ruling.Reason)
			}
			if tc.reasonHas != "" && !strings.Contains(ruling.Reason, tc.reasonHas) {
				t.Errorf("reason %q does not mention %q", ruling.Reason, tc.reasonHas)
			}
		})
	}
}

// "none" is not a risk tier. Treating it as one would make it fall through
// Risk.Valid() and default to "low", turning the strictest setting into a
// permissive one — silently, and in the dangerous direction.
func TestUnknownCeilingIsTreatedAsNoAutonomy(t *testing.T) {
	t.Parallel()

	rules := &stubRules{policies: []*domainharness.Policy{
		policy("logs", "docker", "logs", domainharness.RiskLow, false, 0),
	}}

	for _, ceiling := range []string{"none", "", "typo", "forbidden"} {
		t.Run(ceiling, func(t *testing.T) {
			t.Parallel()
			engine := harness.NewPolicyEngine(rules, shared.SystemClock{}, time.Minute, ceiling)
			if engine.AutoAllowed() {
				t.Fatalf("ceiling %q granted autonomy", ceiling)
			}
			ruling, err := engine.Evaluate(context.Background(), request("docker", "logs", 1.0))
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if ruling.Decision != domainharness.DecisionAwaitingApproval {
				t.Errorf("ceiling %q let a read execute automatically", ceiling)
			}
		})
	}
}

// No setting of the autonomy dial reaches a forbidden action.
func TestNoCeilingAuthorisesAForbiddenAction(t *testing.T) {
	t.Parallel()

	rules := &stubRules{policies: []*domainharness.Policy{
		policy("drop", "database", "drop_table", domainharness.RiskForbidden, true, 1),
	}}

	for _, ceiling := range []string{"low", "medium", "high", "forbidden"} {
		engine := harness.NewPolicyEngine(rules, shared.SystemClock{}, time.Minute, ceiling)
		ruling, err := engine.Evaluate(context.Background(), request("database", "drop_table", 1.0))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if ruling.Decision != domainharness.DecisionDeniedPolicy {
			t.Errorf("ceiling=%s made a forbidden action %s", ceiling, ruling.Decision)
		}
	}
}

// A mutating action tiered low risk would execute automatically. That mismatch
// is invisible in either the catalog or the policy table alone.
func TestReconcileCatchesAMutatingActionTieredLowRisk(t *testing.T) {
	t.Parallel()

	rules := &stubRules{policies: []*domainharness.Policy{
		policy("oops", "docker", "restart_container", domainharness.RiskLow, false, 0),
	}}
	engine := harness.NewPolicyEngine(rules, shared.SystemClock{}, time.Minute, "high")

	problems, err := engine.ReconcileTools(context.Background(), testRegistry(t))
	if err != nil {
		t.Fatalf("ReconcileTools: %v", err)
	}

	var found bool
	for _, p := range problems {
		if strings.Contains(p, "restart_container") && strings.Contains(p, "no human review") {
			found = true
		}
	}
	if !found {
		t.Errorf("the mismatch was not reported; problems: %v", problems)
	}
}

// -----------------------------------------------------------------------------
// Gate 4: approval
// -----------------------------------------------------------------------------

func pending(risk domainharness.Risk, age time.Duration, clock shared.Clock) *domainharness.ToolCallRequest {
	req := request("docker", "restart_container", 0.9)
	req.Risk = risk
	req.Decision = domainharness.DecisionAwaitingApproval
	req.CreatedAt = clock.Now().Add(-age)
	return req
}

func TestApprovalAuthorityIsCheckedPerRiskTier(t *testing.T) {
	t.Parallel()

	clock := shared.SystemClock{}
	gate := harness.NewApprovalGate(clock, 30*time.Minute)

	tests := []struct {
		role      user.Role
		risk      domainharness.Risk
		wantAllow bool
	}{
		{user.RoleViewer, domainharness.RiskLow, false},
		{user.RoleOperator, domainharness.RiskLow, true},
		{user.RoleOperator, domainharness.RiskMedium, true},
		{user.RoleOperator, domainharness.RiskHigh, false},
		{user.RoleAdmin, domainharness.RiskHigh, true},
		// No role reaches forbidden.
		{user.RoleAdmin, domainharness.RiskForbidden, false},
	}

	for _, tc := range tests {
		req := pending(tc.risk, time.Minute, clock)
		err := gate.Rule(req, harness.ApprovalApprove,
			harness.Approver{UserID: shared.NewID(), Email: "a@b.c", Role: tc.role}, "because")

		if tc.wantAllow && err != nil {
			t.Errorf("%s could not approve %s risk: %v", tc.role, tc.risk, err)
		}
		if !tc.wantAllow && err == nil {
			t.Errorf("%s approved a %s-risk action", tc.role, tc.risk)
		}
	}
}

// Stopping an action is safe; requiring seniority to say "no" would mean a
// junior responder who spots a bad remediation has to go find someone.
func TestAnyoneMayReject(t *testing.T) {
	t.Parallel()

	clock := shared.SystemClock{}
	gate := harness.NewApprovalGate(clock, 30*time.Minute)
	req := pending(domainharness.RiskHigh, time.Minute, clock)

	err := gate.Rule(req, harness.ApprovalReject,
		harness.Approver{UserID: shared.NewID(), Email: "junior@b.c", Role: user.RoleViewer}, "looks wrong")
	if err != nil {
		t.Fatalf("a viewer could not reject a high-risk action: %v", err)
	}
	if req.Decision != domainharness.DecisionRejected {
		t.Errorf("decision = %s, want rejected", req.Decision)
	}
}

func TestExpiredApprovalsCannotBeRuledOn(t *testing.T) {
	t.Parallel()

	clock := shared.SystemClock{}
	gate := harness.NewApprovalGate(clock, 30*time.Minute)
	req := pending(domainharness.RiskMedium, time.Hour, clock)

	err := gate.Rule(req, harness.ApprovalApprove,
		harness.Approver{UserID: shared.NewID(), Email: "a@b.c", Role: user.RoleAdmin}, "go on")
	if err == nil {
		t.Fatal("an approval was applied to a request that had already expired")
	}

	var appErr *harness.ApprovalError
	if !asApprovalError(err, &appErr) || appErr.Code != harness.ErrApprovalExpired {
		t.Errorf("error code = %v, want %s", err, harness.ErrApprovalExpired)
	}

	// And the sweep marks it, so a postmortem can tell "we decided not to" from
	// "nobody looked".
	if !gate.Expire(req) {
		t.Fatal("Expire did not mark a lapsed request")
	}
	if req.Decision != domainharness.DecisionExpired {
		t.Errorf("decision = %s, want expired", req.Decision)
	}
}

func TestAlreadyDecidedRequestsCannotBeReRuled(t *testing.T) {
	t.Parallel()

	clock := shared.SystemClock{}
	gate := harness.NewApprovalGate(clock, 30*time.Minute)
	approver := harness.Approver{UserID: shared.NewID(), Email: "a@b.c", Role: user.RoleAdmin}

	req := pending(domainharness.RiskMedium, time.Minute, clock)
	if err := gate.Rule(req, harness.ApprovalApprove, approver, "yes"); err != nil {
		t.Fatalf("first approval: %v", err)
	}

	// A double-submit, or a replay. Neither should re-run the action.
	err := gate.Rule(req, harness.ApprovalApprove, approver, "yes again")
	if err == nil {
		t.Fatal("an already-approved request was approved a second time")
	}
	var appErr *harness.ApprovalError
	if !asApprovalError(err, &appErr) || appErr.Code != harness.ErrApprovalNotPending {
		t.Errorf("error code = %v, want %s", err, harness.ErrApprovalNotPending)
	}
}

// asApprovalError unwraps to the harness's own refusal type.
//
// errors.As rather than a type assertion: the service layer wraps these, and a
// test that only recognised the unwrapped form would stop catching the thing it
// was written to catch the moment a caller added context.
func asApprovalError(err error, target **harness.ApprovalError) bool {
	return errors.As(err, target)
}
