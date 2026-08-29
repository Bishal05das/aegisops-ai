package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/pkg/errs"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// IncidentService is the use-case layer for incidents.
//
// It knows nothing about HTTP and nothing about which agents exist. Creating an
// incident publishes a fact; whether anything investigates it is not this
// service's concern, which is what lets the orchestrator be scaled, restarted or
// switched off without the API noticing.
type IncidentService struct {
	incidents ports.IncidentRepository
	tasks     ports.TaskRepository
	audit     ports.AuditRepository
	bus       ports.EventBus
	tx        ports.TxManager
	clock     shared.Clock
	log       *slog.Logger
}

// IncidentDeps are the collaborators the service needs.
type IncidentDeps struct {
	Incidents ports.IncidentRepository
	Tasks     ports.TaskRepository
	Audit     ports.AuditRepository
	Bus       ports.EventBus
	Tx        ports.TxManager
	Clock     shared.Clock
	Logger    *slog.Logger
}

// NewIncidentService builds the service.
func NewIncidentService(d IncidentDeps) *IncidentService {
	clock := d.Clock
	if clock == nil {
		clock = shared.SystemClock{}
	}
	log := d.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &IncidentService{
		incidents: d.Incidents, tasks: d.Tasks, audit: d.Audit,
		bus: d.Bus, tx: d.Tx, clock: clock, log: log,
	}
}

// CreateIncidentInput is a request to open an incident.
type CreateIncidentInput struct {
	Title       string
	Description string
	Severity    incident.Severity
	Source      incident.Source
	Service     string
	Environment string
	Labels      map[string]string
	CreatedBy   user.ID
	RequestID   string
}

// Create opens an incident and announces it.
//
// The write and its audit row commit together — an incident that exists with no
// record of who filed it is exactly the gap a postmortem cannot fill. The event
// is published *after* the commit, deliberately: publishing inside the
// transaction would announce an incident that a rollback then un-created, and
// the orchestrator would investigate a row that does not exist.
func (s *IncidentService) Create(ctx context.Context, in CreateIncidentInput) (*incident.Incident, error) {
	const op = "services.IncidentService.Create"

	inc, buildErr := incident.New(s.clock, in.Title, in.Description, in.Severity, in.Source)
	if buildErr != nil {
		return nil, errs.E(op, errs.Invalid, "the incident is not valid", buildErr).
			WithCode("invalid_incident")
	}
	inc.Service = in.Service
	inc.Environment = in.Environment
	inc.CreatedBy = in.CreatedBy
	for k, v := range in.Labels {
		inc.SetLabel(k, v)
	}
	if err := inc.Validate(); err != nil {
		return nil, errs.E(op, errs.Invalid, "the incident is not valid", err).
			WithCode("invalid_incident")
	}

	commit := func(ctx context.Context) error {
		if err := s.incidents.Create(ctx, inc); err != nil {
			return err
		}

		ev, evErr := incident.NewEvent(s.clock, inc.ID, incident.EventDetected,
			incident.ActorUser, "incident opened: "+inc.Title)
		if evErr != nil {
			return evErr
		}
		ev.ActorID = in.CreatedBy
		if err := s.incidents.AppendEvent(ctx, ev); err != nil {
			return err
		}

		return s.appendAudit(ctx, auditRecord{
			actorID: in.CreatedBy, action: "incident.create",
			outcome: harness.OutcomeExecuted, requestID: in.RequestID,
			params: map[string]any{
				"incident_id": inc.ID.String(),
				"severity":    string(inc.Severity),
				"service":     inc.Service,
			},
		})
	}

	var err error
	if s.tx != nil {
		err = s.tx.WithinTx(ctx, commit)
	} else {
		err = commit(ctx)
	}
	if err != nil {
		if errors.Is(err, shared.ErrValidation) {
			return nil, errs.E(op, errs.Invalid, "the incident is not valid", err)
		}
		return nil, errs.E(op, errs.Internal, "create incident", err)
	}

	s.announce(ctx, inc, in.RequestID)

	logger.FromContext(ctx).Info("incident opened",
		"incident_id", inc.ID.String(), "severity", string(inc.Severity),
		"service", inc.Service, "source", string(inc.Source))

	return inc, nil
}

// announce publishes incident.detected, which is what starts an investigation.
//
// A failure here is logged, not returned. The incident is real and committed;
// refusing to acknowledge it because the bus was unavailable would be worse than
// an investigation that has to be triggered manually.
func (s *IncidentService) announce(ctx context.Context, inc *incident.Incident, requestID string) {
	if s.bus == nil {
		return
	}
	err := s.bus.Publish(ctx, ports.Event{
		Type:       ports.TopicIncidentDetected,
		IncidentID: inc.ID,
		ActorType:  "user",
		ActorID:    inc.CreatedBy,
		RequestID:  requestID,
		OccurredAt: s.clock.Now(),
		Payload: map[string]any{
			"title":    inc.Title,
			"severity": string(inc.Severity),
			"service":  inc.Service,
			"source":   string(inc.Source),
		},
	})
	if err != nil {
		logger.FromContext(ctx).Error(
			"the incident was created but could not be announced; no investigation will start",
			"incident_id", inc.ID.String(), "error", err)
	}
}

// Get returns one incident.
func (s *IncidentService) Get(ctx context.Context, id incident.ID) (*incident.Incident, error) {
	const op = "services.IncidentService.Get"

	inc, err := s.incidents.Get(ctx, id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, errs.E(op, errs.NotFound, "incident not found").
				WithCode("incident_not_found").
				WithField("incident_id", id.String())
		}
		return nil, errs.E(op, errs.Internal, "load incident", err)
	}
	return inc, nil
}

// List returns a filtered page of incidents.
func (s *IncidentService) List(ctx context.Context, f ports.IncidentFilter, p ports.Page) (ports.PageResult[*incident.Incident], error) {
	const op = "services.IncidentService.List"

	res, err := s.incidents.List(ctx, f, p)
	if err != nil {
		return res, errs.E(op, errs.Internal, "list incidents", err)
	}
	return res, nil
}

// Count returns how many incidents match a filter.
//
// Separate from List rather than folded into it: counting a large filtered set
// is a second full scan, so callers paging through results should not pay for it
// unless they asked.
func (s *IncidentService) Count(ctx context.Context, f ports.IncidentFilter) (int64, error) {
	const op = "services.IncidentService.Count"

	n, err := s.incidents.Count(ctx, f)
	if err != nil {
		return 0, errs.E(op, errs.Internal, "count incidents", err)
	}
	return n, nil
}

// Timeline returns an incident's events.
func (s *IncidentService) Timeline(ctx context.Context, id incident.ID, p ports.Page) (ports.PageResult[*incident.Event], error) {
	const op = "services.IncidentService.Timeline"
	var zero ports.PageResult[*incident.Event]

	// Confirms the incident exists first, so a bad ID returns 404 rather than
	// an empty list that reads as "this incident has no history".
	if _, err := s.Get(ctx, id); err != nil {
		return zero, err
	}

	res, err := s.incidents.Events(ctx, id, p)
	if err != nil {
		return zero, errs.E(op, errs.Internal, "load timeline", err)
	}
	return res, nil
}

// Tasks returns the agent work done for an incident.
func (s *IncidentService) Tasks(ctx context.Context, id incident.ID, p ports.Page) (ports.PageResult[*agent.Task], error) {
	const op = "services.IncidentService.Tasks"
	var zero ports.PageResult[*agent.Task]

	if s.tasks == nil {
		return zero, errs.E(op, errs.NotImplemented, "task history is not available")
	}
	if _, err := s.Get(ctx, id); err != nil {
		return zero, err
	}

	res, err := s.tasks.List(ctx, ports.TaskFilter{IncidentID: &id}, p)
	if err != nil {
		return zero, errs.E(op, errs.Internal, "list tasks", err)
	}
	return res, nil
}

// Close moves an incident to closed.
func (s *IncidentService) Close(ctx context.Context, id incident.ID, by user.ID, reason, requestID string) (*incident.Incident, error) {
	const op = "services.IncidentService.Close"

	inc, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if err := inc.TransitionTo(s.clock, incident.StatusClosed); err != nil {
		if errors.Is(err, shared.ErrConflict) {
			return nil, errs.E(op, errs.Conflict,
				fmt.Sprintf("an incident in state %q cannot be closed", inc.Status)).
				WithCode("invalid_transition")
		}
		return nil, errs.E(op, errs.Internal, "close incident", err)
	}

	if err := s.incidents.Update(ctx, inc); err != nil {
		if errors.Is(err, shared.ErrConflict) {
			// Optimistic locking caught a concurrent writer. Reported rather
			// than retried: the caller decided to close based on what they
			// read, and that has changed underneath them.
			return nil, errs.E(op, errs.Conflict,
				"the incident was modified concurrently; re-read it and try again").
				WithCode("concurrent_modification")
		}
		return nil, errs.E(op, errs.Internal, "persist closure", err)
	}

	s.appendTimeline(ctx, inc, incident.EventClosed, by, "incident closed: "+reason)
	_ = s.appendAudit(ctx, auditRecord{
		actorID: by, action: "incident.close",
		outcome: harness.OutcomeExecuted, reason: reason, requestID: requestID,
		params: map[string]any{"incident_id": inc.ID.String()},
	})

	if s.bus != nil {
		_ = s.bus.Publish(ctx, ports.Event{
			Type: ports.TopicIncidentClosed, IncidentID: inc.ID,
			ActorType: "user", ActorID: by, RequestID: requestID,
			Payload: map[string]any{"reason": reason},
		})
	}
	return inc, nil
}

// appendTimeline adds an entry, logging rather than failing on error.
func (s *IncidentService) appendTimeline(ctx context.Context, inc *incident.Incident, typ incident.EventType, actor user.ID, message string) {
	ev, err := incident.NewEvent(s.clock, inc.ID, typ, incident.ActorUser, message)
	if err != nil {
		logger.FromContext(ctx).Warn("could not build a timeline event", "error", err)
		return
	}
	ev.ActorID = actor
	if err := s.incidents.AppendEvent(ctx, ev); err != nil {
		logger.FromContext(ctx).Warn("could not append to the timeline", "error", err)
	}
}

// appendAudit writes to the ledger. Unlike the auth service's version this one
// returns its error, because callers here run inside a transaction where an
// audit failure must roll the whole thing back.
func (s *IncidentService) appendAudit(ctx context.Context, r auditRecord) error {
	if s.audit == nil {
		return nil
	}
	entry := harness.NewAuditEntry(s.clock, "user", r.actorName, r.action, r.outcome)
	entry.ActorID = r.actorID
	entry.Reason = r.reason
	entry.RequestID = r.requestID
	entry.ResourceType = "incident"
	if r.params != nil {
		entry.Params = logger.RedactMap(r.params)
		if id, ok := r.params["incident_id"].(string); ok {
			if parsed, err := shared.ParseID(id); err == nil {
				entry.IncidentID = &parsed
			}
		}
	}
	return s.audit.Append(ctx, entry)
}
