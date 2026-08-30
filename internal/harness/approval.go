package harness

import (
	"fmt"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/security/rbac"
)

// DefaultApprovalTTL is how long a request waits for a human before expiring.
//
// Expiry is a safety control, not tidiness. An approval queue with no expiry
// means a restart proposed during last Tuesday's outage can be approved on
// Friday and executed against a system that has since been fixed, redeployed or
// rolled back — the approver would be authorising an action whose context no
// longer exists. Thirty minutes is roughly the window in which an incident's
// diagnosis is still true.
const DefaultApprovalTTL = 30 * time.Minute

// ApprovalDecision is a human's ruling.
type ApprovalDecision string

// Approval rulings.
const (
	ApprovalApprove ApprovalDecision = "approve"
	ApprovalReject  ApprovalDecision = "reject"
)

// Valid reports whether the ruling is defined.
func (d ApprovalDecision) Valid() bool {
	return d == ApprovalApprove || d == ApprovalReject
}

// Approver is the human ruling on a request.
//
// Carries the role rather than a permission set so the authority check happens
// here, against the same compiled RBAC matrix the HTTP layer uses. Passing a
// pre-computed "may approve" boolean would move the decision to the caller, and
// a caller that computes it wrongly is exactly what this gate exists to catch.
type Approver struct {
	UserID shared.ID
	Email  string
	Role   user.Role
}

// ApprovalError explains why a ruling was refused.
//
// A named type because these are the interesting failures — every one of them
// is an attempt to authorise something that should not be authorised, and they
// need distinct audit outcomes rather than a generic 400.
type ApprovalError struct {
	Code   string
	Detail string
}

// Error implements error.
func (e *ApprovalError) Error() string { return e.Detail }

// Approval error codes.
const (
	ErrApprovalNotPending  = "not_pending"
	ErrApprovalExpired     = "expired"
	ErrApprovalAuthority   = "insufficient_authority"
	ErrApprovalForbidden   = "forbidden_action"
	ErrApprovalStalePolicy = "policy_changed"
)

// ApprovalGate is gate four: it decides whether a human's ruling may be applied.
//
// Deliberately stateless. The pending queue lives in the tool_calls table, which
// means it survives a restart — an approval queue held in memory would silently
// empty on deploy, and an operator would have no way to tell "nothing is
// pending" from "the daemon restarted and forgot".
type ApprovalGate struct {
	clock shared.Clock
	ttl   time.Duration
}

// NewApprovalGate builds the gate.
func NewApprovalGate(clock shared.Clock, ttl time.Duration) *ApprovalGate {
	if ttl <= 0 {
		ttl = DefaultApprovalTTL
	}
	return &ApprovalGate{clock: clock, ttl: ttl}
}

// TTL reports how long a request may wait.
func (g *ApprovalGate) TTL() time.Duration { return g.ttl }

// Expired reports whether a pending request has outlived its window.
func (g *ApprovalGate) Expired(req *harness.ToolCallRequest) bool {
	if req.Decision != harness.DecisionAwaitingApproval {
		return false
	}
	return g.clock.Now().Sub(req.CreatedAt) > g.ttl
}

// ExpiresAt reports when a pending request lapses.
func (g *ApprovalGate) ExpiresAt(req *harness.ToolCallRequest) time.Time {
	return req.CreatedAt.Add(g.ttl)
}

// Rule applies a human's decision to a pending request.
//
// Every check here is a refusal to trust something that looks like authority but
// is not, and the order runs from cheapest to most surprising:
//
//  1. the request must still be awaiting a ruling. Approving an already-executed
//     call is either a double-submit or a replay, and neither should re-run it.
//  2. it must not have expired.
//  3. a forbidden action cannot be approved by anyone. This is checked even
//     though the policy engine refuses it earlier, because a policy edited
//     between proposal and approval could have moved the action into the
//     forbidden tier, and the last check before execution has to be the one
//     that holds.
//  4. the approver's role must carry authority for *this risk tier*. An
//     operator may approve a container restart and may not approve a database
//     rollback; both arrive at the same endpoint.
//
// On success the request is mutated in place to Approved or Rejected. Persisting
// it is the caller's job, inside a transaction with the audit write.
func (g *ApprovalGate) Rule(req *harness.ToolCallRequest, decision ApprovalDecision, by Approver, note string) error {
	if !decision.Valid() {
		return &ApprovalError{Code: ErrApprovalNotPending,
			Detail: fmt.Sprintf("%q is not a valid ruling", decision)}
	}

	if req.Decision != harness.DecisionAwaitingApproval {
		return &ApprovalError{
			Code: ErrApprovalNotPending,
			Detail: fmt.Sprintf(
				"this request is %s, not awaiting approval; it cannot be ruled on again",
				req.Decision),
		}
	}

	if g.Expired(req) {
		return &ApprovalError{
			Code: ErrApprovalExpired,
			Detail: fmt.Sprintf(
				"this request expired after %s; the incident it was proposed for has moved on, "+
					"so it must be re-proposed rather than approved late", g.ttl),
		}
	}

	// A rejection is always permitted, for anyone who can see the queue.
	//
	// The asymmetry is the point: stopping an action is safe, and requiring a
	// specific authority to say "no" would mean a junior responder who spots a
	// bad remediation has to find someone senior while it sits in the queue.
	// Approving is what needs authority.
	if decision == ApprovalReject {
		req.Decision = harness.DecisionRejected
		now := g.clock.Now()
		req.DecidedBy = &by.UserID
		req.DecidedAt = &now
		req.DecisionNote = note
		return nil
	}

	if req.Risk == harness.RiskForbidden {
		return &ApprovalError{
			Code: ErrApprovalForbidden,
			Detail: "this action is forbidden; there is no approval that authorises it. " +
				"If it genuinely must happen, it happens at a terminal, outside this system",
		}
	}

	// Forbidden is already refused above; this catches an unrecognised tier,
	// which means the row was written by something that did not understand the
	// schema. rbac.ApprovalPermissionFor returns ok=false for both, so the
	// second line of defence needs no special case for forbidden.
	needed, representable := rbac.ApprovalPermissionFor(string(req.Risk))
	if !representable {
		return &ApprovalError{
			Code:   ErrApprovalAuthority,
			Detail: fmt.Sprintf("this request carries an unapprovable risk tier %q", req.Risk),
		}
	}
	if !rbac.Can(by.Role, needed) {
		return &ApprovalError{
			Code: ErrApprovalAuthority,
			Detail: fmt.Sprintf(
				"approving a %s-risk action requires %s, which the %s role does not grant",
				req.Risk, needed, by.Role),
		}
	}

	req.Approve(g.clock, by.UserID, note)
	return nil
}

// Expire marks a lapsed request, returning false when it was not eligible.
//
// Separate from Rule because expiry is not a human decision — it happens to
// requests nobody ruled on, and it must be recorded as its own outcome so a
// postmortem can distinguish "we decided not to" from "nobody looked".
func (g *ApprovalGate) Expire(req *harness.ToolCallRequest) bool {
	if !g.Expired(req) {
		return false
	}
	req.Deny(g.clock, harness.DecisionExpired,
		fmt.Sprintf("no human ruled on this request within %s", g.ttl))
	return true
}
