package services

import (
	"context"
	"errors"
	"fmt"

	domainharness "github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/harness"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/pkg/errs"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// ApprovalService is the application layer over the harness's approval gate.
//
// Thin on purpose. The decision logic lives in the harness, because it is a
// security control and belongs in the package a reader can point at; this type
// exists to translate between HTTP-shaped inputs and harness-shaped ones, and to
// map the harness's refusals onto the error taxonomy the API renders.
type ApprovalService struct {
	harness *harness.Harness
	calls   ports.ToolCallRepository
	users   ports.UserRepository
}

// NewApprovalService builds the service.
func NewApprovalService(h *harness.Harness, calls ports.ToolCallRepository, users ports.UserRepository) *ApprovalService {
	return &ApprovalService{harness: h, calls: calls, users: users}
}

// Pending returns the operator's work queue.
func (s *ApprovalService) Pending(ctx context.Context, p ports.Page) (ports.PageResult[*domainharness.ToolCallRequest], error) {
	const op = "services.ApprovalService.Pending"

	res, err := s.calls.List(ctx, ports.ToolCallFilter{PendingApproval: true}, p)
	if err != nil {
		return res, errs.E(op, errs.Internal, "list pending approvals", err)
	}
	return res, nil
}

// Get returns one tool call.
func (s *ApprovalService) Get(ctx context.Context, id shared.ID) (*domainharness.ToolCallRequest, error) {
	const op = "services.ApprovalService.Get"

	req, err := s.calls.Get(ctx, id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, errs.E(op, errs.NotFound, "no such tool call")
		}
		return nil, errs.E(op, errs.Internal, "load tool call", err)
	}
	return req, nil
}

// List returns a filtered page of tool calls.
func (s *ApprovalService) List(ctx context.Context, f ports.ToolCallFilter, p ports.Page) (ports.PageResult[*domainharness.ToolCallRequest], error) {
	const op = "services.ApprovalService.List"

	res, err := s.calls.List(ctx, f, p)
	if err != nil {
		return res, errs.E(op, errs.Internal, "list tool calls", err)
	}
	return res, nil
}

// Execution returns a tool call's outcome, or nil when it never ran.
func (s *ApprovalService) Execution(ctx context.Context, id shared.ID) (*domainharness.Execution, error) {
	const op = "services.ApprovalService.Execution"

	exec, err := s.calls.GetExecution(ctx, id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			// Not an error. Most tool calls never execute — they were denied,
			// or they are still waiting — and a 404 here would make the normal
			// case look like a failure.
			return nil, nil
		}
		return nil, errs.E(op, errs.Internal, "load execution", err)
	}
	return exec, nil
}

// Decide applies a human's ruling.
//
// The approver's role is read from the database rather than from the JWT.
//
// That is the security-relevant choice in this file. A token is a snapshot of
// who someone was when it was issued, and access tokens here live for fifteen
// minutes. Reading the role fresh means revoking someone's authority takes
// effect on their next action rather than on their next login — which matters
// most in exactly the case you would want it to: someone whose access is being
// withdrawn while an incident is in progress.
func (s *ApprovalService) Decide(ctx context.Context, id shared.ID, userID shared.ID, decision harness.ApprovalDecision, note string) (harness.Result, error) {
	const op = "services.ApprovalService.Decide"

	u, err := s.users.Get(ctx, userID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return harness.Result{}, errs.E(op, errs.Unauthorized,
				"the approving account no longer exists")
		}
		return harness.Result{}, errs.E(op, errs.Internal, "load the approver", err)
	}
	if !u.Active {
		return harness.Result{}, errs.E(op, errs.Forbidden,
			"a disabled account cannot approve infrastructure changes").
			WithCode("approver_disabled")
	}

	res, err := s.harness.ApplyApproval(ctx, id, decision,
		harness.Approver{UserID: u.ID, Email: u.Email, Role: u.Role}, note)
	if err != nil {
		return res, mapApprovalError(op, err)
	}

	logger.FromContext(ctx).Info("approval decision applied",
		"tool_call_id", id.String(), "approver", u.Email,
		"decision", string(decision), "outcome", string(res.Request.Decision))
	return res, nil
}

// mapApprovalError translates a harness refusal into the API's error taxonomy.
//
// Each refusal gets its own status because they mean different things to the
// caller: 403 says "not you", 409 says "not now", 422 says "not this". Rendering
// all of them as 400 would leave an operator unable to tell whether to find a
// colleague, refresh the page, or give up.
func mapApprovalError(op string, err error) error {
	var appErr *harness.ApprovalError
	if !errors.As(err, &appErr) {
		if errors.Is(err, shared.ErrNotFound) {
			return errs.E(op, errs.NotFound, "no such tool call")
		}
		return errs.E(op, errs.Internal, "apply the approval", err)
	}

	switch appErr.Code {
	case harness.ErrApprovalAuthority:
		return errs.E(op, errs.Forbidden, appErr.Detail).WithCode("insufficient_authority")
	case harness.ErrApprovalForbidden:
		return errs.E(op, errs.Forbidden, appErr.Detail).WithCode("forbidden_action")
	case harness.ErrApprovalExpired:
		return errs.E(op, errs.Conflict, appErr.Detail).WithCode("approval_expired")
	case harness.ErrApprovalNotPending:
		return errs.E(op, errs.Conflict, appErr.Detail).WithCode("not_pending")
	case harness.ErrApprovalStalePolicy:
		return errs.E(op, errs.Conflict, appErr.Detail).WithCode("policy_changed")
	default:
		return errs.E(op, errs.Invalid, appErr.Detail).WithCode(appErr.Code)
	}
}

// RuleService exposes the permission matrix and policy table for reading.
//
// Read-only in Phase 6. Editing rules through the API is a Phase 15 concern:
// the endpoint is easy, but doing it safely needs the audit write, the cache
// invalidation and the "who may widen a permission" question answered together,
// and half of that is worse than none.
type RuleService struct {
	permission *harness.PermissionEngine
	policy     *harness.PolicyEngine
	registry   *harness.Registry
}

// NewRuleService builds the service.
func NewRuleService(p *harness.PermissionEngine, pol *harness.PolicyEngine, reg *harness.Registry) *RuleService {
	return &RuleService{permission: p, policy: pol, registry: reg}
}

// Permissions returns the compiled matrix.
func (s *RuleService) Permissions(ctx context.Context) (*harness.Permissions, error) {
	const op = "services.RuleService.Permissions"

	perms, err := s.permission.Snapshot(ctx)
	if err != nil {
		return nil, errs.E(op, errs.Internal, "load the permission matrix", err)
	}
	return perms, nil
}

// Policies returns the compiled policy set.
func (s *RuleService) Policies(ctx context.Context) (*harness.Policies, error) {
	const op = "services.RuleService.Policies"

	policies, err := s.policy.Snapshot(ctx)
	if err != nil {
		return nil, errs.E(op, errs.Internal, "load policies", err)
	}
	return policies, nil
}

// Tools returns every registered tool descriptor.
func (s *RuleService) Tools() []ports.ToolDescriptor { return s.registry.Tools() }

// Ceiling reports the deployment's autonomy ceiling.
func (s *RuleService) Ceiling() domainharness.Risk { return s.policy.Ceiling() }

// AuditService reads the ledger.
type AuditService struct {
	audit ports.AuditRepository
}

// NewAuditService builds the service.
func NewAuditService(audit ports.AuditRepository) *AuditService {
	return &AuditService{audit: audit}
}

// List returns a page of the ledger.
func (s *AuditService) List(ctx context.Context, f ports.AuditFilter, p ports.Page) (ports.PageResult[*domainharness.AuditEntry], error) {
	const op = "services.AuditService.List"

	res, err := s.audit.List(ctx, f, p)
	if err != nil {
		return res, errs.E(op, errs.Internal, "read the audit ledger", err)
	}
	return res, nil
}

// Verify recomputes the hash chain over a range.
//
// The range is bounded by the caller because verification is O(n) over rows and
// the ledger only grows. An unbounded verify on a year-old deployment would be
// a very effective way to make the database unavailable during an incident.
func (s *AuditService) Verify(ctx context.Context, fromSeq, toSeq int64) (domainharness.ChainVerification, error) {
	const op = "services.AuditService.Verify"

	if fromSeq < 0 || toSeq < 0 {
		return domainharness.ChainVerification{}, errs.E(op, errs.Invalid,
			"sequence numbers cannot be negative").WithCode("invalid_range")
	}
	if toSeq != 0 && toSeq < fromSeq {
		return domainharness.ChainVerification{}, errs.E(op, errs.Invalid,
			"the range ends before it starts").WithCode("invalid_range")
	}
	if toSeq != 0 && toSeq-fromSeq > MaxVerifyRange {
		return domainharness.ChainVerification{}, errs.E(op, errs.Invalid,
			fmt.Sprintf("verify at most %d entries at a time", MaxVerifyRange)).
			WithCode("range_too_large")
	}

	result, err := s.audit.VerifyChain(ctx, fromSeq, toSeq)
	if err != nil {
		return result, errs.E(op, errs.Internal, "verify the audit chain", err)
	}
	return result, nil
}

// MaxVerifyRange bounds one verification request.
const MaxVerifyRange = 10000

// LatestSeq returns the ledger's highest sequence.
func (s *AuditService) LatestSeq(ctx context.Context) (int64, error) {
	const op = "services.AuditService.LatestSeq"

	seq, err := s.audit.LatestSeq(ctx)
	if err != nil {
		return 0, errs.E(op, errs.Internal, "read the ledger head", err)
	}
	return seq, nil
}
