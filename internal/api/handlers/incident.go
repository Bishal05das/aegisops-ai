package handlers

import (
	"net/http"
	"strconv"

	"github.com/bishal05das/aegisops-ai/internal/api/dto"
	"github.com/bishal05das/aegisops-ai/internal/api/middleware"
	"github.com/bishal05das/aegisops-ai/internal/api/render"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/services"
	"github.com/bishal05das/aegisops-ai/pkg/errs"
	"github.com/bishal05das/aegisops-ai/pkg/httpx"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// Incidents serves the incident endpoints.
type Incidents struct {
	svc          *services.IncidentService
	agents       ports.AgentRepository
	maxBodyBytes int64
}

// NewIncidents builds the handler.
func NewIncidents(svc *services.IncidentService, agents ports.AgentRepository, maxBody int64) *Incidents {
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	return &Incidents{svc: svc, agents: agents, maxBodyBytes: maxBody}
}

// Create handles POST /api/v1/incidents.
//
// Returns 202 Accepted rather than 201 Created, and the distinction is real: the
// incident row exists, but the investigation it triggers has not happened yet.
// 201 would imply the work is done. A client polls the timeline to watch the
// agents work.
func (h *Incidents) Create(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Incidents.Create"
	ctx := r.Context()
	principal := middleware.MustPrincipal(ctx)

	var req dto.CreateIncidentRequest
	if err := httpx.Decode(w, r, &req, h.maxBodyBytes); err != nil {
		render.WriteError(w, r, err)
		return
	}
	if err := req.Validate(); err != nil {
		render.WriteError(w, r, validationError(op, err))
		return
	}

	source := incident.Source(req.Source)
	if source == "" {
		source = incident.SourceAPI
	}

	inc, err := h.svc.Create(ctx, services.CreateIncidentInput{
		Title:       req.Title,
		Description: req.Description,
		Severity:    incident.Severity(req.Severity),
		Source:      source,
		Service:     req.Service,
		Environment: req.Environment,
		Labels:      req.Labels,
		CreatedBy:   principal.UserID,
		RequestID:   logger.RequestID(ctx),
	})
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	w.Header().Set("Location", "/api/v1/incidents/"+inc.ID.String())
	render.WriteJSON(w, r, http.StatusAccepted, dto.NewIncidentView(inc))
}

// Get handles GET /api/v1/incidents/{id}.
func (h *Incidents) Get(w http.ResponseWriter, r *http.Request) {
	id, err := incidentID(r)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	inc, err := h.svc.Get(r.Context(), id)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}
	render.WriteJSON(w, r, http.StatusOK, dto.NewIncidentView(inc))
}

// List handles GET /api/v1/incidents.
func (h *Incidents) List(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Incidents.List"
	ctx := r.Context()

	filter, err := incidentFilter(r)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}
	page := pageFrom(r)

	res, err := h.svc.List(ctx, filter, page)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	out := dto.IncidentListResponse{
		Incidents:  make([]dto.IncidentView, len(res.Items)),
		NextCursor: res.NextCursor,
		HasMore:    res.HasMore,
	}
	for i, inc := range res.Items {
		out.Incidents[i] = dto.NewIncidentView(inc)
	}

	// A total is only computed when asked for. Counting a large filtered set is
	// a second full scan, and most callers paging through a list do not need it
	// — making it opt-in keeps the common request cheap.
	if r.URL.Query().Get("include_total") == "true" {
		if total, err := h.svc.Count(ctx, filter); err == nil {
			out.Total = &total
		} else {
			logger.FromContext(ctx).Warn("could not count incidents", "error", err, "op", op)
		}
	}

	render.WriteJSON(w, r, http.StatusOK, out)
}

// Timeline handles GET /api/v1/incidents/{id}/timeline.
//
// This is how a client watches an investigation happen: the orchestrator appends
// an entry as each agent starts, finishes, or requests a tool, so polling this
// shows the agents working in order.
func (h *Incidents) Timeline(w http.ResponseWriter, r *http.Request) {
	id, err := incidentID(r)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	res, err := h.svc.Timeline(r.Context(), id, pageFrom(r))
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	out := dto.TimelineResponse{
		IncidentID: id.String(),
		Events:     make([]dto.EventView, len(res.Items)),
		NextCursor: res.NextCursor,
		HasMore:    res.HasMore,
	}
	for i, e := range res.Items {
		out.Events[i] = dto.NewEventView(e)
	}
	render.WriteJSON(w, r, http.StatusOK, out)
}

// Tasks handles GET /api/v1/incidents/{id}/tasks.
func (h *Incidents) Tasks(w http.ResponseWriter, r *http.Request) {
	id, err := incidentID(r)
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	res, err := h.svc.Tasks(r.Context(), id, pageFrom(r))
	if err != nil {
		render.WriteError(w, r, err)
		return
	}

	out := dto.TasksResponse{
		IncidentID: id.String(),
		Tasks:      make([]dto.TaskView, len(res.Items)),
		NextCursor: res.NextCursor,
		HasMore:    res.HasMore,
	}
	for i, t := range res.Items {
		out.Tasks[i] = dto.NewTaskView(t)
	}
	render.WriteJSON(w, r, http.StatusOK, out)
}

// Close handles POST /api/v1/incidents/{id}/close.
func (h *Incidents) Close(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Incidents.Close"
	ctx := r.Context()
	principal := middleware.MustPrincipal(ctx)

	id, idErr := incidentID(r)
	if idErr != nil {
		render.WriteError(w, r, idErr)
		return
	}

	var req dto.CloseIncidentRequest
	if err := httpx.Decode(w, r, &req, h.maxBodyBytes); err != nil {
		render.WriteError(w, r, err)
		return
	}
	if err := req.Validate(); err != nil {
		render.WriteError(w, r, validationError(op, err))
		return
	}

	inc, err := h.svc.Close(ctx, id, principal.UserID, req.Reason, logger.RequestID(ctx))
	if err != nil {
		render.WriteError(w, r, err)
		return
	}
	render.WriteJSON(w, r, http.StatusOK, dto.NewIncidentView(inc))
}

// ListAgents handles GET /api/v1/agents.
func (h *Incidents) ListAgents(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Incidents.ListAgents"

	if h.agents == nil {
		render.WriteError(w, r, errs.E(op, errs.NotImplemented, "the agent roster is not available"))
		return
	}

	list, err := h.agents.List(r.Context())
	if err != nil {
		render.WriteError(w, r, errs.E(op, errs.Internal, "list agents", err))
		return
	}

	out := dto.AgentsResponse{Agents: make([]dto.AgentView, len(list)), Count: len(list)}
	for i, a := range list {
		out.Agents[i] = dto.NewAgentView(a)
	}
	render.WriteJSON(w, r, http.StatusOK, out)
}

// incidentID extracts and validates the {id} path parameter.
func incidentID(r *http.Request) (incident.ID, error) {
	raw := r.PathValue("id")
	id, err := shared.ParseID(raw)
	if err != nil {
		// A 400, not a 404. The client sent something that is not an
		// identifier at all, which is a different mistake from asking for one
		// that does not exist — and the fix is different too.
		return shared.Nil, errs.E("handlers.incidentID", errs.Invalid,
			"the incident id is not a valid UUID").
			WithCode("invalid_incident_id")
	}
	return id, nil
}

// pageFrom reads pagination parameters.
//
// A bad limit is clamped rather than rejected: `?limit=abc` is a client bug, but
// failing the whole request over it is unhelpful when the sensible default is
// obvious. A bad cursor IS rejected, because silently returning page one when
// the caller asked for page five would look like data loss.
func pageFrom(r *http.Request) ports.Page {
	q := r.URL.Query()
	p := ports.Page{Cursor: q.Get("cursor")}
	if raw := q.Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			p.Limit = n
		}
	}
	return p.Normalise()
}

// incidentFilter reads query parameters into a repository filter.
func incidentFilter(r *http.Request) (ports.IncidentFilter, error) {
	const op = "handlers.incidentFilter"
	q := r.URL.Query()
	var f ports.IncidentFilter

	for _, s := range q["status"] {
		st := incident.Status(s)
		if !st.Valid() {
			return f, errs.E(op, errs.Invalid, "unknown status "+s).
				WithCode("invalid_status")
		}
		f.Statuses = append(f.Statuses, st)
	}
	for _, s := range q["severity"] {
		sev := incident.Severity(s)
		if !sev.Valid() {
			return f, errs.E(op, errs.Invalid, "unknown severity "+s).
				WithCode("invalid_severity")
		}
		f.Severities = append(f.Severities, sev)
	}

	f.Service = q.Get("service")
	f.Environment = q.Get("environment")
	f.ActiveOnly = q.Get("active") == "true"

	if search := q.Get("search"); search != "" {
		// Bounded: an unbounded search term becomes an unbounded ILIKE pattern.
		if len(search) > 200 {
			return f, errs.E(op, errs.Invalid, "the search term is too long").
				WithCode("search_too_long")
		}
		f.Search = search
	}
	return f, nil
}
