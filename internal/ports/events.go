package ports

import (
	"context"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// Event is a fact that occurred, published for anyone who cares.
//
// Past tense, always. Components publish facts; they do not send commands to
// each other. That is what keeps seven agents, a harness and an approval
// workflow from becoming an N×N coupling problem — nothing subscribes to a
// component, everything subscribes to a fact.
type Event struct {
	ID string
	// Type is the routing key, e.g. "incident.detected". Dotted segments so a
	// subscriber can match a family with "incident.*" or everything with "#".
	Type string
	// IncidentID correlates every event in one investigation. Present on
	// nearly all of them, which is what makes an investigation reconstructable.
	IncidentID shared.ID

	ActorType string // agent | user | system
	ActorID   shared.ID
	ActorName string

	Payload map[string]any

	// RequestID and TraceID carry correlation across the bus, so a log line
	// emitted by a subscriber can be tied to the HTTP request that caused it.
	RequestID string
	TraceID   string

	OccurredAt time.Time

	// Attempt counts delivery attempts, set by the bus. A handler uses it to
	// decide when to stop retrying and dead-letter instead.
	Attempt int
}

// EventHandler processes one event.
//
// Returning an error requests redelivery. Handlers must therefore be idempotent:
// every bus worth using delivers at least once, and a handler that restarts a
// container on each delivery restarts it twice when the ack is lost.
type EventHandler func(ctx context.Context, e Event) error

// Subscription is a live subscription that can be cancelled.
type Subscription interface {
	// Topic is the pattern this subscription matches.
	Topic() string
	// Unsubscribe stops delivery and waits for in-flight handlers to finish.
	Unsubscribe(ctx context.Context) error
}

// EventBus publishes and delivers events.
//
// Two implementations exist: an in-process bus for tests and single-node
// development, and RabbitMQ for production. Selected by AEGIS_EVENTBUS_DRIVER.
// Because both satisfy this interface, no service, agent or handler knows which
// is wired in — see docs/adr/0004.
type EventBus interface {
	// Publish delivers an event to every matching subscriber.
	//
	// Returns when the event is accepted by the bus, not when it is handled.
	// A caller that needs to know the work completed must wait for the
	// resulting fact, not for this call.
	Publish(ctx context.Context, e Event) error

	// Subscribe registers a handler for a topic pattern.
	//
	// Patterns use AMQP topic syntax: "*" matches exactly one segment, "#"
	// matches zero or more. "incident.*" matches incident.detected;
	// "#" matches everything, which is how the audit ledger observes the whole
	// bus without any publisher knowing it exists.
	Subscribe(ctx context.Context, pattern string, h EventHandler) (Subscription, error)

	// Close stops the bus and waits for in-flight handlers.
	Close(ctx context.Context) error
}

// Event type constants.
//
// These are the same names written to incident_events, so a row in the timeline
// and a message on the wire describe the same fact — an investigation can be
// reconstructed from either.
const (
	TopicIncidentDetected      = "incident.detected"
	TopicIncidentAcknowledged  = "incident.acknowledged"
	TopicIncidentStatusChanged = "incident.status_changed"
	TopicIncidentDiagnosed     = "incident.diagnosed"
	TopicIncidentResolved      = "incident.resolved"
	TopicIncidentClosed        = "incident.closed"

	TopicAgentStarted   = "agent.started"
	TopicAgentCompleted = "agent.completed"
	TopicAgentFailed    = "agent.failed"

	TopicTaskCreated = "task.created"

	TopicToolRequested = "tool.requested"
	TopicToolExecuted  = "tool.executed"
	TopicToolRejected  = "tool.rejected"

	TopicApprovalRequired = "approval.required"
	TopicApprovalGranted  = "approval.granted"
	TopicApprovalDenied   = "approval.denied"
)

// Common subscription patterns.
const (
	// PatternAll matches every event. The audit ledger binds here.
	PatternAll = "#"
	// PatternIncident matches the incident lifecycle.
	PatternIncident = "incident.*"
	// PatternAgent matches agent lifecycle events.
	PatternAgent = "agent.*"
	// PatternTool matches tool requests and outcomes.
	PatternTool = "tool.*"
	// PatternApproval matches the human approval workflow.
	PatternApproval = "approval.*"
)
