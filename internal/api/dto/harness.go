package dto

import (
	"time"

	domainharness "github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/pkg/validate"
)

// DecideRequest is the body of POST /api/v1/approvals/{id}/decide.
type DecideRequest struct {
	Decision string `json:"decision"`
	Note     string `json:"note"`
}

// Validate checks the payload.
//
// A note is required to approve and optional to reject, and the asymmetry is
// deliberate. Approving is authorising an infrastructure change; the one
// artefact a postmortem needs is why a human thought it was the right call, and
// nobody will write it down later. Rejecting needs no defence.
func (r DecideRequest) Validate() error {
	v := validate.New()

	v.Required(r.Decision, "decision")
	v.OneOf(r.Decision, "decision", "approve", "reject")

	if r.Decision == "approve" {
		v.Required(r.Note, "note")
		v.Length(r.Note, "note", 3, MaxDecisionNoteLen)
	}
	v.MaxLength(r.Note, "note", MaxDecisionNoteLen)
	// The note is rendered in operator terminals and stored in the ledger, so
	// it gets the same control-character guard as an incident description.
	v.NoControlChars(r.Note, "note")
	return v.Err()
}

// MaxDecisionNoteLen bounds an approver's justification.
const MaxDecisionNoteLen = 2000

// ToolCallView is a tool call as the API exposes it.
type ToolCallView struct {
	ID         string  `json:"id"`
	IncidentID string  `json:"incident_id"`
	TaskID     *string `json:"task_id,omitempty"`
	AgentID    string  `json:"agent_id"`
	AgentName  string  `json:"agent_name"`

	Tool   string         `json:"tool"`
	Action string         `json:"action"`
	Call   string         `json:"call"`
	Params map[string]any `json:"params"`

	// Reason is the model's own words, never summarised. An approver deciding
	// whether to allow a restart is deciding on this text.
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`

	Risk     string `json:"risk,omitempty"`
	Decision string `json:"decision"`
	// Mutating tells a UI to style this differently without having to know the
	// risk taxonomy.
	Mutating bool `json:"mutating"`

	DecidedBy    *string    `json:"decided_by,omitempty"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	DecisionNote string     `json:"decision_note,omitempty"`

	// ExpiresAt is present only while a request is waiting, so an operator can
	// see how long they have.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	Execution *ExecutionView `json:"execution,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// NewToolCallView maps a request onto the wire type.
func NewToolCallView(req *domainharness.ToolCallRequest) ToolCallView {
	view := ToolCallView{
		ID:           req.ID.String(),
		IncidentID:   req.IncidentID.String(),
		AgentID:      req.AgentID.String(),
		AgentName:    req.AgentName,
		Tool:         req.Tool,
		Action:       req.Action,
		Call:         req.Qualified(),
		Params:       req.Params,
		Reason:       req.Reason,
		Confidence:   req.Confidence,
		Risk:         string(req.Risk),
		Decision:     string(req.Decision),
		Mutating:     req.Risk != "" && req.Risk != domainharness.RiskLow,
		DecidedAt:    req.DecidedAt,
		DecisionNote: req.DecisionNote,
		CreatedAt:    req.CreatedAt,
	}
	if req.TaskID != nil {
		s := req.TaskID.String()
		view.TaskID = &s
	}
	if req.DecidedBy != nil {
		s := req.DecidedBy.String()
		view.DecidedBy = &s
	}
	return view
}

// WithExpiry stamps the deadline on a pending request.
func (v ToolCallView) WithExpiry(at time.Time) ToolCallView {
	if v.Decision == string(domainharness.DecisionAwaitingApproval) {
		v.ExpiresAt = &at
	}
	return v
}

// ExecutionView is what happened when a tool ran.
type ExecutionView struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	// DryRun is separate from Status so a client can tell "this deployment
	// never executes anything" from "this call was skipped".
	DryRun     bool      `json:"dry_run"`
	ExitCode   *int      `json:"exit_code,omitempty"`
	Stdout     string    `json:"stdout,omitempty"`
	Stderr     string    `json:"stderr,omitempty"`
	Truncated  bool      `json:"truncated"`
	Error      string    `json:"error,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// NewExecutionView maps an execution onto the wire type.
func NewExecutionView(e *domainharness.Execution) *ExecutionView {
	if e == nil {
		return nil
	}
	return &ExecutionView{
		ID: e.ID.String(), Status: string(e.Status), DryRun: e.DryRun,
		ExitCode: e.ExitCode, Stdout: e.Stdout, Stderr: e.Stderr,
		Truncated: e.Truncated, Error: e.Error, DurationMS: e.DurationMS,
		StartedAt: e.StartedAt, FinishedAt: e.FinishedAt,
	}
}

// ToolCallListResponse is a page of tool calls.
type ToolCallListResponse struct {
	ToolCalls  []ToolCallView `json:"tool_calls"`
	NextCursor string         `json:"next_cursor,omitempty"`
	HasMore    bool           `json:"has_more"`
	Count      int            `json:"count"`
}

// DecideResponse is the result of a human's ruling.
type DecideResponse struct {
	ToolCall ToolCallView `json:"tool_call"`
	// Executed says whether the approval led straight to execution, so a UI
	// does not have to infer it from the decision plus the presence of a record.
	Executed bool   `json:"executed"`
	Message  string `json:"message"`
}

// AuditEntryView is one ledger row.
type AuditEntryView struct {
	ID         string    `json:"id"`
	Seq        int64     `json:"seq"`
	OccurredAt time.Time `json:"occurred_at"`

	ActorType string `json:"actor_type"`
	ActorID   string `json:"actor_id,omitempty"`
	ActorName string `json:"actor_name,omitempty"`

	Action       string `json:"action"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`

	IncidentID *string `json:"incident_id,omitempty"`
	ToolCallID *string `json:"tool_call_id,omitempty"`

	Outcome string         `json:"outcome"`
	Reason  string         `json:"reason,omitempty"`
	Params  map[string]any `json:"params,omitempty"`
	Result  map[string]any `json:"result,omitempty"`
	Error   string         `json:"error,omitempty"`

	RequestID    string `json:"request_id,omitempty"`
	BuildVersion string `json:"build_version,omitempty"`

	// Hash is the chain hash, so a caller can pin a known-good point and
	// verify forward from it later.
	Hash string `json:"hash"`
}

// NewAuditEntryView maps a ledger row onto the wire type.
func NewAuditEntryView(e *domainharness.AuditEntry) AuditEntryView {
	view := AuditEntryView{
		ID: e.ID.String(), Seq: e.Seq, OccurredAt: e.OccurredAt,
		ActorType: e.ActorType, ActorName: e.ActorName,
		Action: e.Action, ResourceType: e.ResourceType, ResourceID: e.ResourceID,
		Outcome: string(e.Outcome), Reason: e.Reason,
		Params: e.Params, Result: e.Result, Error: e.Error,
		RequestID: e.RequestID, BuildVersion: e.BuildVersion,
		Hash: e.HashHex(),
	}
	if !e.ActorID.IsZero() {
		view.ActorID = e.ActorID.String()
	}
	if e.IncidentID != nil {
		s := e.IncidentID.String()
		view.IncidentID = &s
	}
	if e.ToolCallID != nil {
		s := e.ToolCallID.String()
		view.ToolCallID = &s
	}
	return view
}

// AuditListResponse is a page of the ledger.
type AuditListResponse struct {
	Entries    []AuditEntryView `json:"entries"`
	NextCursor string           `json:"next_cursor,omitempty"`
	HasMore    bool             `json:"has_more"`
	LatestSeq  int64            `json:"latest_seq"`
}

// ChainVerificationResponse reports whether the ledger is intact.
type ChainVerificationResponse struct {
	Checked     int    `json:"checked"`
	Valid       bool   `json:"valid"`
	BrokenAtSeq int64  `json:"broken_at_seq,omitempty"`
	Reason      string `json:"reason,omitempty"`
	FromSeq     int64  `json:"from_seq"`
	ToSeq       int64  `json:"to_seq"`
}

// PermissionView is one rule of the matrix.
type PermissionView struct {
	ID        string `json:"id"`
	AgentKind string `json:"agent_kind"`
	Tool      string `json:"tool"`
	Action    string `json:"action"`
	Effect    string `json:"effect"`
	// Specificity is exposed because resolution order is otherwise invisible,
	// and "which rule won?" is the question an operator asks after a surprising
	// denial.
	Specificity int `json:"specificity"`
}

// PolicyView is one policy.
type PolicyView struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	Description      string  `json:"description,omitempty"`
	Tool             string  `json:"tool"`
	Action           string  `json:"action"`
	Risk             string  `json:"risk"`
	RequiresApproval bool    `json:"requires_approval"`
	MinConfidence    float64 `json:"min_confidence"`
	Priority         int     `json:"priority"`
	Enabled          bool    `json:"enabled"`
	// Reachable is false for an action this deployment will never execute —
	// forbidden, or above the autonomy ceiling. Computed rather than stored,
	// because it depends on configuration the policy row knows nothing about.
	Reachable bool `json:"reachable"`
}

// RulesResponse is the whole decision surface in one document.
//
// Returned together on purpose: "why was this denied?" is rarely answerable
// from the permission matrix or the policy table alone, and making an operator
// join two endpoints during an incident is how they end up guessing.
type RulesResponse struct {
	AutonomyCeiling string           `json:"autonomy_ceiling"`
	DryRun          bool             `json:"dry_run"`
	Permissions     []PermissionView `json:"permissions"`
	Policies        []PolicyView     `json:"policies"`
	Tools           []ToolView       `json:"tools"`
}

// ToolView is a registered tool.
type ToolView struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Actions     []ActionView `json:"actions"`
}

// ActionView is one action a tool exposes.
type ActionView struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Mutating    bool                 `json:"mutating"`
	Params      map[string]ParamView `json:"params,omitempty"`
	Policy      *ActionPolicySummary `json:"policy,omitempty"`
}

// ParamView describes one parameter's contract.
type ParamView struct {
	Kind        string   `json:"kind"`
	Required    bool     `json:"required"`
	Description string   `json:"description,omitempty"`
	Default     any      `json:"default,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
}

// ActionPolicySummary is the policy governing an action, inlined so a client
// listing tools can show what each one would cost.
type ActionPolicySummary struct {
	Risk             string  `json:"risk"`
	RequiresApproval bool    `json:"requires_approval"`
	MinConfidence    float64 `json:"min_confidence"`
	Reachable        bool    `json:"reachable"`
}

// NewToolView maps a descriptor onto the wire type.
func NewToolView(d ports.ToolDescriptor, policyFor func(tool, action string) *ActionPolicySummary) ToolView {
	view := ToolView{Name: d.Name, Description: d.Description}
	for name, ad := range d.Actions {
		av := ActionView{
			Name: name, Description: ad.Description, Mutating: ad.Mutating,
			Params: make(map[string]ParamView, len(ad.Params)),
		}
		for pname, spec := range ad.Params {
			av.Params[pname] = ParamView{
				Kind: string(spec.Kind), Required: spec.Required,
				Description: spec.Description, Default: spec.Default,
				Enum: spec.Enum, Pattern: spec.Pattern,
			}
		}
		if policyFor != nil {
			av.Policy = policyFor(d.Name, name)
		}
		view.Actions = append(view.Actions, av)
	}
	return view
}
