package incident

import (
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// EventType names a fact that occurred during an incident.
//
// Past tense throughout, deliberately: these are records of what happened, not
// commands. Nothing subscribes to a component; components subscribe to facts.
type EventType string

// The event catalogue. These are the same names carried on the event bus, so a
// row in incident_events and a message on the wire describe the same fact.
const (
	EventDetected         EventType = "incident.detected"
	EventAcknowledged     EventType = "incident.acknowledged"
	EventStatusChanged    EventType = "incident.status_changed"
	EventAgentStarted     EventType = "agent.started"
	EventAgentCompleted   EventType = "agent.completed"
	EventAgentFailed      EventType = "agent.failed"
	EventTaskCreated      EventType = "task.created"
	EventDiagnosisReached EventType = "incident.diagnosed"
	EventToolRequested    EventType = "tool.requested"
	EventToolExecuted     EventType = "tool.executed"
	EventToolRejected     EventType = "tool.rejected"
	EventApprovalRequired EventType = "approval.required"
	EventApprovalGranted  EventType = "approval.granted"
	EventApprovalDenied   EventType = "approval.denied"
	EventResolved         EventType = "incident.resolved"
	EventClosed           EventType = "incident.closed"
	EventNoteAdded        EventType = "incident.note_added"
)

// Valid reports whether the type is in the catalogue.
func (e EventType) Valid() bool {
	switch e {
	case EventDetected, EventAcknowledged, EventStatusChanged,
		EventAgentStarted, EventAgentCompleted, EventAgentFailed,
		EventTaskCreated, EventDiagnosisReached,
		EventToolRequested, EventToolExecuted, EventToolRejected,
		EventApprovalRequired, EventApprovalGranted, EventApprovalDenied,
		EventResolved, EventClosed, EventNoteAdded:
		return true
	default:
		return false
	}
}

// ActorType distinguishes who caused an event, which is the first question any
// postmortem asks: did a human do this, or did the AI?
type ActorType string

// Actor types.
const (
	ActorAgent  ActorType = "agent"
	ActorUser   ActorType = "user"
	ActorSystem ActorType = "system"
)

// Valid reports whether the actor type is defined.
func (a ActorType) Valid() bool {
	switch a {
	case ActorAgent, ActorUser, ActorSystem:
		return true
	default:
		return false
	}
}

// Event is one immutable entry on an incident's timeline.
//
// The timeline is append-only. Reconstructing "what did the system believe, and
// when" during a postmortem depends on nothing ever rewriting history — so
// there is deliberately no Update method and no mutating setter.
type Event struct {
	ID         shared.ID
	IncidentID ID

	// Seq orders events within one incident. Timestamps are not sufficient:
	// several agents run concurrently and can produce identical microsecond
	// stamps, and clocks are not guaranteed monotonic across processes.
	// A unique (incident_id, seq) index makes the ordering total.
	Seq int64

	Type      EventType
	ActorType ActorType
	ActorID   shared.ID
	ActorName string

	// Message is human-readable; Payload is the machine-readable detail.
	Message string
	Payload map[string]any

	OccurredAt time.Time
}

// MaxEventMessageLen bounds the human-readable summary.
const MaxEventMessageLen = 2000

// NewEvent builds a validated timeline entry.
//
// Seq is assigned by the repository inside the same transaction as the insert,
// so it is deliberately not a parameter here — computing it in application code
// would race between concurrent agents.
func NewEvent(clock shared.Clock, incidentID ID, typ EventType, actor ActorType, msg string) (*Event, error) {
	ev := &Event{
		ID:         shared.NewID(),
		IncidentID: incidentID,
		Type:       typ,
		ActorType:  actor,
		Message:    msg,
		Payload:    map[string]any{},
		OccurredAt: clock.Now(),
	}
	if err := ev.Validate(); err != nil {
		return nil, err
	}
	return ev, nil
}

// WithActor attaches the identity that caused the event.
func (e *Event) WithActor(id shared.ID, name string) *Event {
	e.ActorID = id
	e.ActorName = name
	return e
}

// WithPayload attaches one machine-readable detail.
func (e *Event) WithPayload(key string, value any) *Event {
	if e.Payload == nil {
		e.Payload = map[string]any{}
	}
	e.Payload[key] = value
	return e
}

// Validate checks the event's invariants.
func (e *Event) Validate() error {
	v := shared.NewValidator("incident_event")
	v.NotZeroID(e.ID, "id")
	v.NotZeroID(e.IncidentID, "incident_id")
	v.Check(e.Type.Valid(), "type", "is not a known event type")
	v.Check(e.ActorType.Valid(), "actor_type", "must be one of: agent, user, system")
	v.MaxLen(e.Message, "message", MaxEventMessageLen)
	v.Check(!e.OccurredAt.IsZero(), "occurred_at", "is required")
	return v.Err()
}
