// Package incident models the entity the whole platform exists to process.
//
// An Incident is the aggregate root: its timeline of events, the agent tasks
// spawned for it, the tool calls proposed against it and the executions that
// resulted all hang off one incident and share its lifecycle.
package incident

import (
	"fmt"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// ID identifies an incident.
type ID = shared.ID

// Severity is the operational impact, set at detection and rarely changed.
type Severity string

// Severity levels, ordered from most to least impactful.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Valid reports whether the severity is one of the defined levels.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

// Rank orders severities for sorting and for policy comparisons, most severe
// first. An unknown severity ranks last rather than panicking, so a row written
// by a future version cannot crash an older reader.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}

// Status is the incident's position in the investigation lifecycle.
type Status string

// The lifecycle. Transitions are constrained by CanTransitionTo.
const (
	StatusDetected         Status = "detected"
	StatusInvestigating    Status = "investigating"
	StatusDiagnosing       Status = "diagnosing"
	StatusAwaitingApproval Status = "awaiting_approval"
	StatusRemediating      Status = "remediating"
	StatusVerifying        Status = "verifying"
	StatusResolved         Status = "resolved"
	StatusClosed           Status = "closed"
	StatusFailed           Status = "failed"
)

// transitions is the allowed state graph.
//
// Encoding it as data rather than as a chain of if-statements makes the machine
// reviewable at a glance and testable exhaustively — and this machine is
// security-relevant: an incident must not reach Remediating without having
// passed through AwaitingApproval when policy demanded it.
var transitions = map[Status][]Status{
	StatusDetected:      {StatusInvestigating, StatusFailed, StatusClosed},
	StatusInvestigating: {StatusDiagnosing, StatusResolved, StatusFailed, StatusClosed},
	StatusDiagnosing:    {StatusAwaitingApproval, StatusRemediating, StatusResolved, StatusFailed, StatusClosed},
	// A denied or expired approval sends the incident back to diagnosing so the
	// agents can propose something else, rather than dead-ending it.
	StatusAwaitingApproval: {StatusRemediating, StatusDiagnosing, StatusFailed, StatusClosed},
	StatusRemediating:      {StatusVerifying, StatusFailed, StatusClosed},
	// Verification failing is the common case that must not be a dead end: the
	// fix did not work, so go back and diagnose again.
	StatusVerifying: {StatusResolved, StatusDiagnosing, StatusFailed, StatusClosed},
	StatusResolved:  {StatusClosed, StatusInvestigating}, // reopened
	StatusFailed:    {StatusInvestigating, StatusClosed},
	StatusClosed:    {}, // terminal
}

// Valid reports whether the status is defined.
func (s Status) Valid() bool {
	_, ok := transitions[s]
	return ok
}

// Terminal reports whether no further transition is possible.
func (s Status) Terminal() bool { return s == StatusClosed }

// Active reports whether agents should still be working the incident.
func (s Status) Active() bool {
	switch s {
	case StatusResolved, StatusClosed, StatusFailed:
		return false
	default:
		return true
	}
}

// CanTransitionTo reports whether moving to next is permitted.
func (s Status) CanTransitionTo(next Status) bool {
	for _, allowed := range transitions[s] {
		if allowed == next {
			return true
		}
	}
	return false
}

// Source records how the incident entered the system.
type Source string

// Incident sources.
const (
	SourceAlert  Source = "alert"  // an external monitoring system
	SourceAPI    Source = "api"    // POST /api/v1/incidents
	SourceManual Source = "manual" // a human filed it
	SourceAgent  Source = "agent"  // the Monitoring Agent detected it
)

// Valid reports whether the source is defined.
func (s Source) Valid() bool {
	switch s {
	case SourceAlert, SourceAPI, SourceManual, SourceAgent:
		return true
	default:
		return false
	}
}

// Field length limits. These mirror the database constraints; validating here
// means a caller gets a useful field-level error instead of a driver error.
const (
	MaxTitleLen       = 500
	MaxDescriptionLen = 20000
	MaxServiceLen     = 200
	MaxRootCauseLen   = 20000
)

// Incident is the aggregate root.
type Incident struct {
	ID          ID
	Title       string
	Description string
	Severity    Severity
	Status      Status
	Source      Source

	// Service and Environment scope the blast radius and drive which tools the
	// harness will permit.
	Service     string
	Environment string

	// Labels carry arbitrary alert metadata (alertname, cluster, pod...).
	Labels map[string]string

	// RootCause and Confidence are written by the Diagnosis Agent. Confidence is
	// load-bearing: the policy engine routes a low-confidence diagnosis to a
	// human rather than to an action.
	RootCause  string
	Confidence float64

	DetectedAt     time.Time
	AcknowledgedAt *time.Time
	ResolvedAt     *time.Time
	ClosedAt       *time.Time

	CreatedBy shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time

	// Version implements optimistic locking. Seven agents mutate one incident
	// concurrently; without this, two agents reading the same row and writing
	// back would silently lose one of the updates.
	Version int
}

// New builds a validated incident in the Detected state.
func New(clock shared.Clock, title, description string, sev Severity, src Source) (*Incident, error) {
	now := clock.Now()
	inc := &Incident{
		ID:          shared.NewID(),
		Title:       title,
		Description: description,
		Severity:    sev,
		Status:      StatusDetected,
		Source:      src,
		Labels:      map[string]string{},
		DetectedAt:  now,
		CreatedAt:   now,
		UpdatedAt:   now,
		Version:     1,
	}
	if err := inc.Validate(); err != nil {
		return nil, err
	}
	return inc, nil
}

// Validate checks every invariant at once.
func (i *Incident) Validate() error {
	v := shared.NewValidator("incident")
	v.NotZeroID(i.ID, "id")
	v.Required(i.Title, "title")
	v.MaxLen(i.Title, "title", MaxTitleLen)
	v.MaxLen(i.Description, "description", MaxDescriptionLen)
	v.MaxLen(i.Service, "service", MaxServiceLen)
	v.MaxLen(i.RootCause, "root_cause", MaxRootCauseLen)
	v.Check(i.Severity.Valid(), "severity",
		"must be one of: critical, high, medium, low")
	v.Check(i.Status.Valid(), "status", "is not a known lifecycle state")
	v.Check(i.Source.Valid(), "source", "must be one of: alert, api, manual, agent")
	v.InRange(i.Confidence, "confidence", 0, 1)
	v.Check(!i.DetectedAt.IsZero(), "detected_at", "is required")
	return v.Err()
}

// TransitionTo moves the incident to next, enforcing the state machine and
// stamping the timestamp that state implies.
//
// Returns shared.ErrConflict for a disallowed transition: from the caller's
// perspective the incident was not in the state they believed, which is a
// concurrency problem, not bad input.
func (i *Incident) TransitionTo(clock shared.Clock, next Status) error {
	if !next.Valid() {
		return &shared.ValidationError{Entity: "incident", Fields: []shared.FieldError{
			{Field: "status", Message: "unknown state " + string(next)},
		}}
	}
	if i.Status == next {
		return nil // idempotent; re-delivering an event must not fail
	}
	if !i.Status.CanTransitionTo(next) {
		return fmt.Errorf("%w: cannot move incident from %s to %s",
			shared.ErrConflict, i.Status, next)
	}

	now := clock.Now()
	i.Status = next
	i.UpdatedAt = now

	switch next {
	case StatusInvestigating:
		if i.AcknowledgedAt == nil {
			i.AcknowledgedAt = &now
		}
	case StatusResolved:
		if i.ResolvedAt == nil {
			i.ResolvedAt = &now
		}
	case StatusClosed:
		if i.ClosedAt == nil {
			i.ClosedAt = &now
		}
	}
	return nil
}

// SetDiagnosis records the Diagnosis Agent's conclusion.
func (i *Incident) SetDiagnosis(clock shared.Clock, rootCause string, confidence float64) error {
	v := shared.NewValidator("incident")
	v.Required(rootCause, "root_cause")
	v.MaxLen(rootCause, "root_cause", MaxRootCauseLen)
	v.InRange(confidence, "confidence", 0, 1)
	if err := v.Err(); err != nil {
		return err
	}
	i.RootCause = rootCause
	i.Confidence = confidence
	i.UpdatedAt = clock.Now()
	return nil
}

// SetLabel attaches or replaces one label.
func (i *Incident) SetLabel(key, value string) {
	if i.Labels == nil {
		i.Labels = map[string]string{}
	}
	i.Labels[key] = value
}

// TimeToResolve reports how long the incident took, or false if unresolved.
func (i *Incident) TimeToResolve() (time.Duration, bool) {
	if i.ResolvedAt == nil {
		return 0, false
	}
	return i.ResolvedAt.Sub(i.DetectedAt), true
}
