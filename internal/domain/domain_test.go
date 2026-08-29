package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
)

func fixedClock() shared.Clock {
	return shared.FixedClock{T: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)}
}

// -----------------------------------------------------------------------------
// shared.ID
// -----------------------------------------------------------------------------

func TestIDRoundTrip(t *testing.T) {
	t.Parallel()

	id := shared.NewID()
	s := id.String()

	if len(s) != 36 || strings.Count(s, "-") != 4 {
		t.Fatalf("String() = %q, want canonical 8-4-4-4-12 form", s)
	}
	// RFC 4122 version 4 and the RFC variant.
	if s[14] != '4' {
		t.Errorf("version nibble = %q, want '4'", s[14])
	}
	if !strings.ContainsRune("89ab", rune(s[19])) {
		t.Errorf("variant nibble = %q, want one of 8/9/a/b", s[19])
	}

	back, err := shared.ParseID(s)
	if err != nil || back != id {
		t.Errorf("ParseID(%q) = %v, %v", s, back, err)
	}
	// The unhyphenated form some clients send must also parse.
	if back, err := shared.ParseID(strings.ReplaceAll(s, "-", "")); err != nil || back != id {
		t.Errorf("unhyphenated parse failed: %v", err)
	}
}

func TestIDRejectsMalformed(t *testing.T) {
	t.Parallel()

	bad := []string{
		"", "not-a-uuid", strings.Repeat("z", 36),
		"0197c8f0-1234-4abc-8def",              // too short
		"0197c8f0*1234*4abc*8def*0123456789ab", // wrong separators
	}
	for _, s := range bad {
		if _, err := shared.ParseID(s); !errors.Is(err, shared.ErrInvalidID) {
			t.Errorf("ParseID(%q) error = %v, want ErrInvalidID", s, err)
		}
	}
}

func TestIDValueAndScan(t *testing.T) {
	t.Parallel()

	id := shared.NewID()

	v, err := id.Value()
	if err != nil || v != id.String() {
		t.Errorf("Value() = %v, %v", v, err)
	}
	// A zero ID must become SQL NULL, or an unset optional FK would be stored
	// as an all-zeroes UUID that violates the referencing constraint.
	if v, err := shared.Nil.Value(); err != nil || v != nil {
		t.Errorf("Nil.Value() = %v, %v, want nil", v, err)
	}

	var scanned shared.ID
	for _, src := range []any{id.String(), []byte(id.String()), [16]byte(id)} {
		if err := scanned.Scan(src); err != nil || scanned != id {
			t.Errorf("Scan(%T) = %v, %v", src, scanned, err)
		}
	}
	if err := scanned.Scan(nil); err != nil || !scanned.IsZero() {
		t.Errorf("Scan(nil) = %v, %v", scanned, err)
	}
	if err := scanned.Scan(42); err == nil {
		t.Error("Scan(int) should fail")
	}
}

// -----------------------------------------------------------------------------
// Validation accumulation
// -----------------------------------------------------------------------------

func TestValidatorAccumulatesEveryFailure(t *testing.T) {
	t.Parallel()

	inc := &incident.Incident{} // everything invalid at once
	err := inc.Validate()
	if err == nil {
		t.Fatal("an empty incident validated successfully")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("error does not wrap ErrValidation: %v", err)
	}

	var ve *shared.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error is not a *ValidationError: %T", err)
	}
	// Reporting one field at a time would make fixing a bad payload a
	// round-trip per field.
	if len(ve.Fields) < 5 {
		t.Errorf("got %d field errors, want every invariant reported at once: %v",
			len(ve.Fields), ve.Fields)
	}

	msg := err.Error()
	for _, want := range []string{"id", "title", "severity", "status", "source"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not mention %q: %s", want, msg)
		}
	}
}

// -----------------------------------------------------------------------------
// Incident lifecycle
// -----------------------------------------------------------------------------

func TestIncidentStateMachine(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	inc, err := incident.New(clock, "api is down", "5xx spike", incident.SeverityHigh, incident.SourceAlert)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if inc.Status != incident.StatusDetected || inc.Version != 1 {
		t.Fatalf("new incident = %s v%d, want detected v1", inc.Status, inc.Version)
	}

	// The happy path an investigation actually walks.
	path := []incident.Status{
		incident.StatusInvestigating,
		incident.StatusDiagnosing,
		incident.StatusAwaitingApproval,
		incident.StatusRemediating,
		incident.StatusVerifying,
		incident.StatusResolved,
		incident.StatusClosed,
	}
	for _, next := range path {
		if err := inc.TransitionTo(clock, next); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if inc.ClosedAt == nil || inc.ResolvedAt == nil || inc.AcknowledgedAt == nil {
		t.Error("lifecycle timestamps were not stamped")
	}
}

// The security-relevant property: an incident must not be able to jump straight
// to remediating, skipping the states where approval is decided.
func TestIncidentCannotSkipToRemediating(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	inc, _ := incident.New(clock, "t", "", incident.SeverityLow, incident.SourceAPI)

	err := inc.TransitionTo(clock, incident.StatusRemediating)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("detected -> remediating error = %v, want ErrConflict", err)
	}
	if inc.Status != incident.StatusDetected {
		t.Errorf("status changed to %s despite a rejected transition", inc.Status)
	}
}

func TestIncidentTransitionIsIdempotent(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	inc, _ := incident.New(clock, "t", "", incident.SeverityLow, incident.SourceAPI)
	_ = inc.TransitionTo(clock, incident.StatusInvestigating)

	// The bus delivers at-least-once, so a redelivered status event must not
	// error — it must be a no-op.
	if err := inc.TransitionTo(clock, incident.StatusInvestigating); err != nil {
		t.Errorf("repeating a transition returned %v, want nil", err)
	}
}

func TestIncidentTerminalAndRecoveryPaths(t *testing.T) {
	t.Parallel()

	if !incident.StatusClosed.Terminal() {
		t.Error("closed should be terminal")
	}
	if incident.StatusResolved.Terminal() {
		t.Error("resolved is not terminal; an incident can be reopened")
	}
	// Verification failing must not dead-end the incident: the fix did not
	// work, so it goes back for another diagnosis.
	if !incident.StatusVerifying.CanTransitionTo(incident.StatusDiagnosing) {
		t.Error("a failed verification must be able to return to diagnosing")
	}
	// A denied approval likewise returns for a different proposal.
	if !incident.StatusAwaitingApproval.CanTransitionTo(incident.StatusDiagnosing) {
		t.Error("a denied approval must be able to return to diagnosing")
	}
	for _, s := range []incident.Status{incident.StatusResolved, incident.StatusClosed, incident.StatusFailed} {
		if s.Active() {
			t.Errorf("%s should not be active", s)
		}
	}
}

func TestIncidentDiagnosisValidatesConfidence(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	inc, _ := incident.New(clock, "t", "", incident.SeverityLow, incident.SourceAPI)

	if err := inc.SetDiagnosis(clock, "memory leak in the worker pool", 0.82); err != nil {
		t.Fatalf("SetDiagnosis: %v", err)
	}
	if inc.Confidence != 0.82 {
		t.Errorf("confidence = %v", inc.Confidence)
	}
	// Out-of-range confidence would corrupt the policy engine's decision, so it
	// is rejected at the domain rather than at the column.
	if err := inc.SetDiagnosis(clock, "x", 1.5); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("confidence 1.5 error = %v, want a validation error", err)
	}
	if err := inc.SetDiagnosis(clock, "", 0.5); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty root cause error = %v, want a validation error", err)
	}
}

func TestSeverityRankOrdersCorrectly(t *testing.T) {
	t.Parallel()

	if incident.SeverityCritical.Rank() >= incident.SeverityLow.Rank() {
		t.Error("critical must rank before low")
	}
	// An unknown severity must not panic and must sort last.
	if incident.Severity("bogus").Rank() <= incident.SeverityLow.Rank() {
		t.Error("an unknown severity should rank last")
	}
}

// -----------------------------------------------------------------------------
// Agent tasks
// -----------------------------------------------------------------------------

func TestTaskLifecycle(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	task, err := agent.NewTask(clock, shared.NewID(), shared.NewID(), "collect_metrics")
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}

	if err := task.Start(clock); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if task.Attempts != 1 || task.StartedAt == nil {
		t.Errorf("after Start: attempts=%d started=%v", task.Attempts, task.StartedAt)
	}

	if err := task.Succeed(clock, map[string]any{"cpu": 91.2}); err != nil {
		t.Fatalf("Succeed: %v", err)
	}
	if !task.Status.Terminal() || task.FinishedAt == nil {
		t.Error("a succeeded task should be terminal and finished")
	}

	// Terminal is terminal: a retry creates a NEW task, so each attempt keeps
	// its own record.
	if err := task.Fail(clock, "late failure"); !errors.Is(err, shared.ErrConflict) {
		t.Errorf("failing a succeeded task = %v, want ErrConflict", err)
	}
}

func TestAgentRosterIsClosedAndMostlyReadOnly(t *testing.T) {
	t.Parallel()

	if len(agent.AllKinds) != 7 {
		t.Fatalf("roster has %d kinds, want 7", len(agent.AllKinds))
	}
	if agent.Kind("rogue_agent").Valid() {
		t.Error("an unregistered kind must not validate")
	}

	// The ratio is the design: exactly one agent of seven may propose a
	// mutation, so a reasoning failure in any other cannot reach a mutating
	// tool regardless of what the model emits.
	mutators := 0
	for _, k := range agent.AllKinds {
		if k.CanMutate() {
			mutators++
		}
	}
	if mutators != 1 {
		t.Errorf("%d agent kinds can mutate, want exactly 1", mutators)
	}
	if !agent.KindAction.CanMutate() {
		t.Error("the action agent must be the one that can mutate")
	}
}

// -----------------------------------------------------------------------------
// Harness risk and policy
// -----------------------------------------------------------------------------

// The single most important assertion in the domain: no autonomy ceiling can
// authorise a forbidden action.
func TestForbiddenRiskIsNeverPermitted(t *testing.T) {
	t.Parallel()

	for _, ceiling := range []harness.Risk{
		harness.RiskLow, harness.RiskMedium, harness.RiskHigh, harness.RiskForbidden,
	} {
		if harness.RiskForbidden.AtOrBelow(ceiling) {
			t.Errorf("forbidden was permitted under ceiling %s", ceiling)
		}
	}

	// And no role can approve it, including admin.
	for _, role := range user.AllRoles {
		if role.CanApprove("forbidden") {
			t.Errorf("role %s could approve a forbidden action", role)
		}
	}
}

func TestRiskCeiling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		risk, ceiling harness.Risk
		allowed       bool
	}{
		{harness.RiskLow, harness.RiskLow, true},
		{harness.RiskMedium, harness.RiskLow, false},
		{harness.RiskMedium, harness.RiskMedium, true},
		{harness.RiskHigh, harness.RiskMedium, false},
		{harness.RiskHigh, harness.RiskHigh, true},
	}
	for _, tc := range tests {
		if got := tc.risk.AtOrBelow(tc.ceiling); got != tc.allowed {
			t.Errorf("%s under ceiling %s = %v, want %v", tc.risk, tc.ceiling, got, tc.allowed)
		}
	}
}

// A Decision added in future must default to NOT permitting execution.
func TestDecisionPermitsIsAClosedAllowlist(t *testing.T) {
	t.Parallel()

	permitting := map[harness.Decision]bool{
		harness.DecisionAllowed:  true,
		harness.DecisionApproved: true,
	}
	all := []harness.Decision{
		harness.DecisionPending, harness.DecisionAllowed, harness.DecisionDeniedUnknown,
		harness.DecisionDeniedParams, harness.DecisionDeniedPermission,
		harness.DecisionDeniedPolicy, harness.DecisionAwaitingApproval,
		harness.DecisionApproved, harness.DecisionRejected, harness.DecisionExpired,
	}
	for _, d := range all {
		if got := d.Permits(); got != permitting[d] {
			t.Errorf("%s.Permits() = %v, want %v", d, got, permitting[d])
		}
	}
	// An unrecognised decision must not permit execution.
	if harness.Decision("something_new").Permits() {
		t.Error("an unknown decision permitted execution")
	}
}

func TestToolCallRequiresAReason(t *testing.T) {
	t.Parallel()

	clock := fixedClock()

	// A mutating request with no stated justification is unauditable.
	_, err := harness.NewToolCallRequest(clock, shared.NewID(), shared.NewID(),
		"docker", "restart_container", "")
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a reasonless request was accepted: %v", err)
	}

	req, err := harness.NewToolCallRequest(clock, shared.NewID(), shared.NewID(),
		"docker", "restart_container", "worker pool is deadlocked")
	if err != nil {
		t.Fatalf("NewToolCallRequest: %v", err)
	}
	// An agent must not be able to grade its own homework: risk and decision
	// start unset and are assigned by the harness.
	if req.Risk != "" {
		t.Errorf("a new request carried risk %q; the harness assigns it", req.Risk)
	}
	if req.Decision != harness.DecisionPending {
		t.Errorf("decision = %q, want pending", req.Decision)
	}
	if req.Qualified() != "docker.restart_container" {
		t.Errorf("Qualified() = %q", req.Qualified())
	}
}

func TestPolicyApprovalRules(t *testing.T) {
	t.Parallel()

	auto := &harness.Policy{Risk: harness.RiskLow, RequiresApproval: false, MinConfidence: 0.5, Enabled: true}
	if auto.NeedsApproval(0.9) {
		t.Error("a confident low-risk action should execute automatically")
	}
	// A weak local model reasoning poorly is exactly what this catches.
	if !auto.NeedsApproval(0.2) {
		t.Error("low confidence must route to a human even for a low-risk action")
	}

	forbidden := &harness.Policy{Risk: harness.RiskForbidden, RequiresApproval: true, Enabled: true}
	if !forbidden.NeedsApproval(1.0) {
		t.Error("a forbidden action must never execute automatically")
	}
}

func TestPermissionMatchingAndSpecificity(t *testing.T) {
	t.Parallel()

	exact := &harness.Permission{Tool: "docker", Action: "restart_container", Effect: harness.EffectAllow}
	toolWide := &harness.Permission{Tool: "docker", Action: harness.Wildcard, Effect: harness.EffectAllow}
	blanket := &harness.Permission{Tool: harness.Wildcard, Action: harness.Wildcard, Effect: harness.EffectAllow}

	if !exact.Matches("docker", "restart_container") || exact.Matches("docker", "logs") {
		t.Error("exact rule matched incorrectly")
	}
	if !toolWide.Matches("docker", "anything") || toolWide.Matches("kubernetes", "anything") {
		t.Error("tool wildcard matched incorrectly")
	}
	if !blanket.Matches("anything", "at_all") {
		t.Error("blanket rule should match everything")
	}

	// The most specific rule must win, so a targeted deny can carve back a
	// broad allow.
	if exact.Specificity() <= toolWide.Specificity() || toolWide.Specificity() <= blanket.Specificity() {
		t.Errorf("specificity ordering wrong: %d, %d, %d",
			exact.Specificity(), toolWide.Specificity(), blanket.Specificity())
	}
}

// -----------------------------------------------------------------------------
// Audit hash chain
// -----------------------------------------------------------------------------

func TestAuditChainDetectsTampering(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	var entries []*harness.AuditEntry
	var prev []byte

	for i := 1; i <= 5; i++ {
		e := harness.NewAuditEntry(clock, "agent", "action", "tool.request", harness.OutcomeDenied)
		e.Seq = int64(i)
		e.Reason = "policy forbids this"
		e.PrevHash = prev
		e.Hash = e.ComputeHash(prev)
		prev = e.Hash
		entries = append(entries, e)
	}

	if v := harness.VerifyChain(entries, nil); !v.Valid {
		t.Fatalf("an untampered chain failed verification: %+v", v)
	}

	// Edit one entry's content without recomputing its hash — what a quiet
	// cover-up looks like.
	entries[2].Reason = "actually it was fine"
	v := harness.VerifyChain(entries, nil)
	if v.Valid {
		t.Fatal("verification passed on a tampered entry")
	}
	if v.BrokenAtSeq != 3 {
		t.Errorf("BrokenAtSeq = %d, want 3", v.BrokenAtSeq)
	}
}

func TestAuditChainDetectsRemoval(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	var entries []*harness.AuditEntry
	var prev []byte
	for i := 1; i <= 4; i++ {
		e := harness.NewAuditEntry(clock, "agent", "action", "tool.request", harness.OutcomeDenied)
		e.Seq = int64(i)
		e.PrevHash = prev
		e.Hash = e.ComputeHash(prev)
		prev = e.Hash
		entries = append(entries, e)
	}

	// Delete the middle entry — the single row showing what an agent tried.
	spliced := []*harness.AuditEntry{entries[0], entries[1], entries[3]}
	if v := harness.VerifyChain(spliced, nil); v.Valid {
		t.Fatal("verification passed after a row was removed")
	}
}

// Regression: the hash used to include the timestamp at nanosecond precision,
// but PostgreSQL TIMESTAMPTZ stores microseconds. Every entry then failed
// verification as soon as it was read back — the chain reported tampering on a
// database nobody had touched, which is worse than having no chain.
//
// A hash is only useful if it can be recomputed from what was actually stored.
func TestAuditHashSurvivesMicrosecondStorage(t *testing.T) {
	t.Parallel()

	// A timestamp with sub-microsecond detail, as time.Now() produces.
	precise := time.Date(2026, 8, 29, 12, 0, 0, 123456789, time.UTC)
	// The same instant after a PostgreSQL round trip.
	stored := precise.Truncate(time.Microsecond)

	if precise.Equal(stored) {
		t.Fatal("the fixture lost its sub-microsecond component; the test proves nothing")
	}

	before := harness.NewAuditEntry(shared.FixedClock{T: precise},
		"agent", "action", "tool.request", harness.OutcomeDenied)
	before.Seq = 1

	after := *before // same entry as it comes back from the database
	after.OccurredAt = stored

	if string(before.ComputeHash(nil)) != string(after.ComputeHash(nil)) {
		t.Error("the hash changes across a microsecond-precision round trip, " +
			"so every stored entry would fail verification")
	}
}

// Length-prefixing prevents a concatenation ambiguity: without it, ("ab","c")
// and ("a","bc") would hash identically and a forged entry could collide.
func TestAuditHashIsUnambiguous(t *testing.T) {
	t.Parallel()

	clock := fixedClock()

	a := harness.NewAuditEntry(clock, "agent", "ab", "c", harness.OutcomeDenied)
	a.Seq = 1
	b := harness.NewAuditEntry(clock, "agent", "a", "bc", harness.OutcomeDenied)
	b.Seq = 1
	b.ID = a.ID // isolate the field boundary as the only difference

	if string(a.ComputeHash(nil)) == string(b.ComputeHash(nil)) {
		t.Error("field boundaries are ambiguous: two different entries hash identically")
	}
}

// -----------------------------------------------------------------------------
// Users
// -----------------------------------------------------------------------------

func TestUserRolesAndApproval(t *testing.T) {
	t.Parallel()

	if !user.RoleAdmin.AtLeast(user.RoleOperator) || user.RoleViewer.AtLeast(user.RoleOperator) {
		t.Error("role ordering is wrong")
	}
	// An unknown role must rank lowest — the safe direction.
	if user.Role("superadmin").AtLeast(user.RoleViewer) {
		t.Error("an unknown role was granted privilege")
	}

	if !user.RoleAdmin.CanApprove("high") || user.RoleOperator.CanApprove("high") {
		t.Error("only admins may approve high-risk actions")
	}
	if !user.RoleOperator.CanApprove("medium") || user.RoleViewer.CanApprove("medium") {
		t.Error("operators, not viewers, approve medium-risk actions")
	}
}

func TestUserEmailNormalisation(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	u, err := user.New(clock, "  Alice@Example.COM  ", "Alice", user.RoleOperator)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Without normalisation, "Alice@Example.com" could register alongside
	// "alice@example.com" and the unique index would not stop it.
	if u.Email != "alice@example.com" {
		t.Errorf("email = %q, want normalised", u.Email)
	}

	for _, bad := range []string{"noatsign", "@nolocal.com", "no@domain", "a b@c.com"} {
		if _, err := user.New(clock, bad, "x", user.RoleViewer); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("New(%q) error = %v, want a validation error", bad, err)
		}
	}
}

// -----------------------------------------------------------------------------
// Execution output handling
// -----------------------------------------------------------------------------

func TestExecutionTruncatesOversizedOutput(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	e, err := harness.NewExecution(clock, shared.NewID(), harness.ExecSucceeded, false)
	if err != nil {
		t.Fatalf("NewExecution: %v", err)
	}

	e.CaptureOutput(strings.Repeat("x", harness.MaxOutputLen*2), "")
	if len(e.Stdout) > harness.MaxOutputLen {
		t.Errorf("stdout length %d exceeds the cap", len(e.Stdout))
	}
	// Silently dropping the tail would make a postmortem read a complete log
	// that was not.
	if !e.Truncated {
		t.Error("Truncated was not set after truncation")
	}
	if !strings.Contains(e.Stdout, "truncated") {
		t.Error("the truncation notice is missing from the output")
	}
	if err := e.Validate(); err != nil {
		t.Errorf("a truncated execution failed validation: %v", err)
	}
}

// A dry run must not report success: nothing happened.
func TestDryRunIsNotSuccess(t *testing.T) {
	t.Parallel()

	clock := fixedClock()
	e, _ := harness.NewExecution(clock, shared.NewID(), harness.ExecSucceeded, true)
	if e.Succeeded() {
		t.Error("a dry run reported that infrastructure was changed")
	}

	live, _ := harness.NewExecution(clock, shared.NewID(), harness.ExecSucceeded, false)
	if !live.Succeeded() {
		t.Error("a live successful execution should report success")
	}
}
