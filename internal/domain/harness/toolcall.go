// Package harness models the security boundary between what an agent *wants*
// and what actually happens to infrastructure.
//
// Read the types here with one question in mind: what can an agent do with them?
// The answer is nothing. ToolCallRequest is pure data — no methods that act, no
// client, no credentials, no network. An agent's most powerful possible output
// is a description of an action. Turning that description into an effect is the
// harness's job, behind five gates, and the agent has no way to reach past them.
//
// See docs/adr/0006-harness-as-security-boundary.md.
package harness

import (
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// Risk tiers the blast radius of an action and therefore how much autonomy it
// is granted.
type Risk string

// Risk tiers, ascending.
const (
	// RiskLow is read-only: metrics, logs, listings. Executed automatically.
	RiskLow Risk = "low"
	// RiskMedium is a reversible mutation: restart a container, scale a
	// deployment. Requires approval.
	RiskMedium Risk = "medium"
	// RiskHigh is a disruptive mutation: restart a database, roll back a
	// release, change a firewall. Requires approval with justification.
	RiskHigh Risk = "high"
	// RiskForbidden is not reachable through this system by any agent, with any
	// approval. Dropping a table, deleting a volume, deleting a namespace.
	//
	// This is not "needs a very senior approver" — there is deliberately no
	// path. Some actions should require a human at a terminal, outside the
	// automation entirely.
	RiskForbidden Risk = "forbidden"
)

// Valid reports whether the tier is defined.
func (r Risk) Valid() bool {
	switch r {
	case RiskLow, RiskMedium, RiskHigh, RiskForbidden:
		return true
	default:
		return false
	}
}

// Rank orders tiers so a policy ceiling can be compared numerically.
// An unrecognised tier ranks as forbidden — the safe direction to fail.
func (r Risk) Rank() int {
	switch r {
	case RiskLow:
		return 0
	case RiskMedium:
		return 1
	case RiskHigh:
		return 2
	default:
		return 3
	}
}

// AtOrBelow reports whether r is no riskier than ceiling.
//
// Forbidden is never at or below anything, including itself: no ceiling setting
// can authorise it. That asymmetry is the point of the tier existing.
func (r Risk) AtOrBelow(ceiling Risk) bool {
	if r == RiskForbidden {
		return false
	}
	return r.Rank() <= ceiling.Rank()
}

// Decision is the harness's verdict on a request.
type Decision string

// Verdicts. Every one of these is written to the audit log, including — in fact
// especially — the rejections.
const (
	DecisionPending          Decision = "pending"
	DecisionAllowed          Decision = "allowed"
	DecisionDeniedUnknown    Decision = "denied_unknown_tool"
	DecisionDeniedParams     Decision = "denied_invalid_params"
	DecisionDeniedPermission Decision = "denied_permission"
	DecisionDeniedPolicy     Decision = "denied_policy"
	DecisionAwaitingApproval Decision = "awaiting_approval"
	DecisionApproved         Decision = "approved"
	DecisionRejected         Decision = "rejected"
	DecisionExpired          Decision = "expired"
)

// Valid reports whether the decision is defined.
func (d Decision) Valid() bool {
	switch d {
	case DecisionPending, DecisionAllowed, DecisionDeniedUnknown, DecisionDeniedParams,
		DecisionDeniedPermission, DecisionDeniedPolicy, DecisionAwaitingApproval,
		DecisionApproved, DecisionRejected, DecisionExpired:
		return true
	default:
		return false
	}
}

// Permits reports whether this decision allows execution to proceed.
//
// Deliberately a closed allowlist rather than "not denied": a decision added in
// future defaults to *not* permitting execution, which is the correct direction
// for a function that gates infrastructure changes.
func (d Decision) Permits() bool {
	return d == DecisionAllowed || d == DecisionApproved
}

// Terminal reports whether the decision is final.
func (d Decision) Terminal() bool {
	return d != DecisionPending && d != DecisionAwaitingApproval
}

// Field limits.
const (
	MaxToolLen   = 100
	MaxActionLen = 100
	MaxReasonLen = 10000
)

// ToolCallRequest is an agent's *intent* to act.
//
// This struct is the entire attack surface an agent presents. If the model
// hallucinates Action "delete_all_volumes", the result is a row with
// Decision=denied_permission and an audit entry — not an outage.
type ToolCallRequest struct {
	ID         shared.ID
	IncidentID shared.ID
	TaskID     *shared.ID
	AgentID    shared.ID
	AgentName  string

	Tool   string
	Action string
	Params map[string]any

	// Reason is the model's own justification, stored verbatim and never
	// summarised. During a postmortem, "what did the AI think it was doing" is
	// answerable only if this was captured exactly as generated.
	Reason string

	// Confidence is the agent's self-reported certainty. The policy engine can
	// route a low-confidence request to a human even when the action itself is
	// low risk.
	Confidence float64

	Risk     Risk
	Decision Decision

	// DecidedBy is the approving or rejecting user, when a human was involved.
	DecidedBy    *shared.ID
	DecidedAt    *time.Time
	DecisionNote string

	// IdempotencyKey makes a retried request a no-op rather than a second
	// restart. The bus delivers at-least-once, so without this a redelivered
	// ToolRequested event would execute the action twice.
	IdempotencyKey string

	CreatedAt time.Time
}

// NewToolCallRequest builds a validated request in the Pending state.
//
// Risk and Decision are assigned by the harness, not by the caller: an agent
// proposing its own risk tier would be grading its own homework.
func NewToolCallRequest(clock shared.Clock, incidentID, agentID shared.ID, tool, action, reason string) (*ToolCallRequest, error) {
	r := &ToolCallRequest{
		ID:         shared.NewID(),
		IncidentID: incidentID,
		AgentID:    agentID,
		Tool:       tool,
		Action:     action,
		Params:     map[string]any{},
		Reason:     reason,
		Decision:   DecisionPending,
		CreatedAt:  clock.Now(),
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request's invariants.
func (r *ToolCallRequest) Validate() error {
	v := shared.NewValidator("tool_call")
	v.NotZeroID(r.ID, "id")
	v.NotZeroID(r.IncidentID, "incident_id")
	v.NotZeroID(r.AgentID, "agent_id")
	v.Required(r.Tool, "tool")
	v.MaxLen(r.Tool, "tool", MaxToolLen)
	v.Required(r.Action, "action")
	v.MaxLen(r.Action, "action", MaxActionLen)
	// A mutating request with no stated reason is unauditable, so the reason is
	// mandatory rather than nice-to-have.
	v.Required(r.Reason, "reason")
	v.MaxLen(r.Reason, "reason", MaxReasonLen)
	v.InRange(r.Confidence, "confidence", 0, 1)
	v.Check(r.Decision.Valid(), "decision", "is not a known decision")
	v.Check(r.Risk == "" || r.Risk.Valid(), "risk", "is not a known risk tier")
	return v.Err()
}

// Qualified returns the "tool.action" pair used as the permission subject.
func (r *ToolCallRequest) Qualified() string { return r.Tool + "." + r.Action }

// Deny records a terminal rejection with its reason.
func (r *ToolCallRequest) Deny(clock shared.Clock, d Decision, note string) {
	now := clock.Now()
	r.Decision = d
	r.DecisionNote = note
	r.DecidedAt = &now
}

// Approve records a human's approval.
func (r *ToolCallRequest) Approve(clock shared.Clock, by shared.ID, note string) {
	now := clock.Now()
	r.Decision = DecisionApproved
	r.DecidedBy = &by
	r.DecisionNote = note
	r.DecidedAt = &now
}
