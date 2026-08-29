package dto

import (
	"time"

	domainagent "github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/pkg/validate"
)

// CreateIncidentRequest is the body of POST /api/v1/incidents.
type CreateIncidentRequest struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Source      string            `json:"source"`
	Service     string            `json:"service"`
	Environment string            `json:"environment"`
	Labels      map[string]string `json:"labels"`
}

// Validate checks the payload.
//
// Title and description reach an LLM prompt and an operator's terminal, so both
// are checked for control characters. An incident description containing an ANSI
// escape can rewrite what an operator sees while they decide whether to approve
// a remediation, and one containing a newline plus fabricated JSON can forge
// entries in a log aggregator.
func (r CreateIncidentRequest) Validate() error {
	v := validate.New()

	v.Required(r.Title, "title")
	v.Length(r.Title, "title", 1, incident.MaxTitleLen)
	v.SingleLine(r.Title, "title")

	v.MaxLength(r.Description, "description", incident.MaxDescriptionLen)
	v.NoControlChars(r.Description, "description")

	v.Required(r.Severity, "severity")
	v.OneOf(r.Severity, "severity", "critical", "high", "medium", "low")

	// Source defaults to "api" when omitted, which is what a direct POST is.
	if r.Source != "" {
		v.OneOf(r.Source, "source", "alert", "api", "manual", "agent")
	}

	v.MaxLength(r.Service, "service", incident.MaxServiceLen)
	v.SingleLine(r.Service, "service")
	v.MaxLength(r.Environment, "environment", 100)
	v.SingleLine(r.Environment, "environment")

	// Labels come from alert payloads, so both halves are bounded and checked.
	// An unbounded label map would let one alert write megabytes into JSONB.
	if len(r.Labels) > MaxLabels {
		v.Add("labels", "must contain at most "+itoa(MaxLabels)+" entries")
	}
	for k, val := range r.Labels {
		v.MaxLength(k, "labels."+k, 200)
		v.MaxLength(val, "labels."+k, 1000)
		v.SingleLine(val, "labels."+k)
	}

	return v.Err()
}

// MaxLabels bounds how many labels one incident may carry.
const MaxLabels = 50

// CloseIncidentRequest is the body of POST /api/v1/incidents/{id}/close.
type CloseIncidentRequest struct {
	Reason string `json:"reason"`
}

// Validate checks the payload.
func (r CloseIncidentRequest) Validate() error {
	v := validate.New()
	// A reason is mandatory. "Closed" with no explanation is the entry a
	// postmortem cannot use, and this is a human's only chance to record why.
	v.Required(r.Reason, "reason")
	v.MaxLength(r.Reason, "reason", 2000)
	v.NoControlChars(r.Reason, "reason")
	return v.Err()
}

// IncidentView is an incident as the API exposes it.
type IncidentView struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Severity    string            `json:"severity"`
	Status      string            `json:"status"`
	Source      string            `json:"source"`
	Service     string            `json:"service,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	RootCause  string  `json:"root_cause,omitempty"`
	Confidence float64 `json:"confidence"`

	DetectedAt     time.Time  `json:"detected_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ClosedAt       *time.Time `json:"closed_at,omitempty"`

	// TimeToResolveSeconds is present only once resolved, so a client can
	// compute MTTR without re-deriving it from timestamps.
	TimeToResolveSeconds *float64 `json:"time_to_resolve_seconds,omitempty"`

	// Active tells a UI whether agents are still working this incident,
	// without it having to know the state machine.
	Active bool `json:"active"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Version is exposed so a client can detect that an incident changed
	// under them — the same optimistic-locking signal the repository uses.
	Version int `json:"version"`
}

// NewIncidentView maps a domain incident onto the wire type.
func NewIncidentView(inc *incident.Incident) IncidentView {
	view := IncidentView{
		ID:             inc.ID.String(),
		Title:          inc.Title,
		Description:    inc.Description,
		Severity:       string(inc.Severity),
		Status:         string(inc.Status),
		Source:         string(inc.Source),
		Service:        inc.Service,
		Environment:    inc.Environment,
		Labels:         inc.Labels,
		RootCause:      inc.RootCause,
		Confidence:     inc.Confidence,
		DetectedAt:     inc.DetectedAt,
		AcknowledgedAt: inc.AcknowledgedAt,
		ResolvedAt:     inc.ResolvedAt,
		ClosedAt:       inc.ClosedAt,
		Active:         inc.Status.Active(),
		CreatedAt:      inc.CreatedAt,
		UpdatedAt:      inc.UpdatedAt,
		Version:        inc.Version,
	}
	if d, ok := inc.TimeToResolve(); ok {
		seconds := d.Seconds()
		view.TimeToResolveSeconds = &seconds
	}
	return view
}

// IncidentListResponse is a page of incidents.
type IncidentListResponse struct {
	Incidents  []IncidentView `json:"incidents"`
	NextCursor string         `json:"next_cursor,omitempty"`
	HasMore    bool           `json:"has_more"`
	Total      *int64         `json:"total,omitempty"`
}

// EventView is one entry on an incident's timeline.
type EventView struct {
	ID         string         `json:"id"`
	Seq        int64          `json:"seq"`
	Type       string         `json:"type"`
	ActorType  string         `json:"actor_type"`
	ActorName  string         `json:"actor_name,omitempty"`
	Message    string         `json:"message,omitempty"`
	Payload    map[string]any `json:"payload,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
}

// NewEventView maps a timeline entry onto the wire type.
func NewEventView(e *incident.Event) EventView {
	return EventView{
		ID:         e.ID.String(),
		Seq:        e.Seq,
		Type:       string(e.Type),
		ActorType:  string(e.ActorType),
		ActorName:  e.ActorName,
		Message:    e.Message,
		Payload:    e.Payload,
		OccurredAt: e.OccurredAt,
	}
}

// TimelineResponse is a page of timeline entries.
type TimelineResponse struct {
	IncidentID string      `json:"incident_id"`
	Events     []EventView `json:"events"`
	NextCursor string      `json:"next_cursor,omitempty"`
	HasMore    bool        `json:"has_more"`
}

// TaskView is one unit of agent work.
type TaskView struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Status     string         `json:"status"`
	Error      string         `json:"error,omitempty"`
	Attempts   int            `json:"attempts"`
	Output     map[string]any `json:"output,omitempty"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	DurationMS *int64         `json:"duration_ms,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

// NewTaskView maps a task onto the wire type.
func NewTaskView(t *domainagent.Task) TaskView {
	view := TaskView{
		ID:         t.ID.String(),
		Type:       t.Type,
		Status:     string(t.Status),
		Error:      t.Error,
		Attempts:   t.Attempts,
		Output:     t.Output,
		StartedAt:  t.StartedAt,
		FinishedAt: t.FinishedAt,
		CreatedAt:  t.CreatedAt,
	}
	if d, ok := t.Duration(); ok {
		ms := d.Milliseconds()
		view.DurationMS = &ms
	}
	return view
}

// TasksResponse is a page of agent tasks.
type TasksResponse struct {
	IncidentID string     `json:"incident_id"`
	Tasks      []TaskView `json:"tasks"`
	NextCursor string     `json:"next_cursor,omitempty"`
	HasMore    bool       `json:"has_more"`
}

// AgentView describes a registered agent.
type AgentView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	// CanMutate makes the central ratio visible: six of seven agents are
	// read-only, and a UI should show which one is not.
	CanMutate bool      `json:"can_mutate"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewAgentView maps a registered agent onto the wire type.
func NewAgentView(a *domainagent.Agent) AgentView {
	return AgentView{
		ID:          a.ID.String(),
		Name:        a.Name,
		Kind:        string(a.Kind),
		Description: a.Description,
		Enabled:     a.Enabled,
		CanMutate:   a.Kind.CanMutate(),
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}
}

// AgentsResponse is the roster.
type AgentsResponse struct {
	Agents []AgentView `json:"agents"`
	Count  int         `json:"count"`
}

// itoa avoids importing strconv for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
