// Package handlers implements the HTTP endpoints of the AegisOps API.
package handlers

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/api/render"
	"github.com/bishal05das/aegisops-ai/internal/preflight"
	"github.com/bishal05das/aegisops-ai/internal/version"
)

// Health serves liveness, readiness and version endpoints.
//
// The liveness/readiness distinction is not ceremony — Kubernetes acts on them
// very differently, and conflating them causes outages:
//
//   - **Liveness** answers "is this process wedged?" A failure gets the container
//     *killed*. It must therefore depend on nothing external: if Postgres blips
//     and liveness fails, Kubernetes restarts every replica simultaneously,
//     turning a recoverable dependency hiccup into a full outage.
//   - **Readiness** answers "should traffic reach me?" A failure removes the pod
//     from the load balancer but leaves it running to recover. This one *does*
//     check dependencies.
type Health struct {
	checks []preflight.Check

	// Dependency probes are cached because readiness is polled every few seconds
	// per replica. Without this, a rolling deploy would open a new connection to
	// Postgres, Redis and RabbitMQ several times a second — the health check
	// itself becoming the load that fails it.
	ttl  time.Duration
	mu   sync.Mutex
	last *cachedReport
}

type cachedReport struct {
	report preflight.Report
	at     time.Time
}

// HealthOption configures a Health handler.
type HealthOption func(*Health)

// WithChecks supplies the dependency probes used by readiness.
func WithChecks(checks ...preflight.Check) HealthOption {
	return func(h *Health) { h.checks = checks }
}

// WithCacheTTL overrides how long a readiness result is reused.
func WithCacheTTL(d time.Duration) HealthOption {
	return func(h *Health) { h.ttl = d }
}

// NewHealth builds the health handler.
func NewHealth(opts ...HealthOption) *Health {
	h := &Health{ttl: 5 * time.Second}
	for _, o := range opts {
		o(h)
	}
	return h
}

// livenessResponse is intentionally minimal — anything more would create the
// dependency this endpoint exists to avoid.
type livenessResponse struct {
	Status string `json:"status"`
}

// Live handles GET /healthz.
//
// Reaching this handler already proves everything it needs to: the process is
// scheduled, the listener is accepting, and the middleware chain runs.
func (h *Health) Live(w http.ResponseWriter, r *http.Request) {
	render.WriteJSON(w, r, http.StatusOK, livenessResponse{Status: "ok"})
}

// readinessResponse reports per-dependency status.
type readinessResponse struct {
	Status  string                     `json:"status"`
	Checks  map[string]readinessDetail `json:"checks,omitempty"`
	Version string                     `json:"version"`
	Cached  bool                       `json:"cached"`
}

type readinessDetail struct {
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Error    string `json:"error,omitempty"`
	Duration int64  `json:"duration_ms"`
}

// Ready handles GET /readyz.
//
// Returns 200 when every required dependency answered, 503 otherwise. The body
// is populated in both cases: an operator debugging a pod stuck out of rotation
// needs to know *which* dependency is failing, and a bare status code does not
// tell them.
func (h *Health) Ready(w http.ResponseWriter, r *http.Request) {
	report, cached := h.probe(r.Context())

	resp := readinessResponse{
		Status:  "ready",
		Version: version.Get().Version,
		Cached:  cached,
		Checks:  make(map[string]readinessDetail, len(report.Results)),
	}
	for _, res := range report.Results {
		resp.Checks[res.Name] = readinessDetail{
			Status:   string(res.Status),
			Detail:   res.Detail,
			Error:    res.Error,
			Duration: res.Millis,
		}
	}

	status := http.StatusOK
	if !report.Healthy {
		resp.Status = "not_ready"
		status = http.StatusServiceUnavailable
	}
	render.WriteJSON(w, r, status, resp)
}

// probe returns a dependency report, reusing a recent one when available.
func (h *Health) probe(ctx context.Context) (preflight.Report, bool) {
	if len(h.checks) == 0 {
		// No dependencies wired yet (Phase 2). Ready means "process is serving".
		return preflight.Report{Healthy: true}, false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.last != nil && time.Since(h.last.at) < h.ttl {
		return h.last.report, true
	}

	// Readiness must answer fast even when a dependency is hanging: a probe that
	// blocks past the kubelet's timeout is indistinguishable from a failure, but
	// takes a connection slot with it.
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	report := preflight.Runner{Timeout: 2 * time.Second}.Run(pctx, h.checks)
	h.last = &cachedReport{report: report, at: time.Now()}
	return report, false
}

// Version handles GET /api/v1/version.
func (h *Health) Version(w http.ResponseWriter, r *http.Request) {
	render.WriteJSON(w, r, http.StatusOK, version.Get())
}
