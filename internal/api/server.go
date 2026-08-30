// Package api is the HTTP driving adapter: it turns HTTP requests into calls on
// application services and application errors into HTTP responses.
//
// Nothing below this package knows HTTP exists. That is what makes the same use
// cases reachable from the CLI, the event bus or a future gRPC transport without
// duplication.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/api/handlers"
	"github.com/bishal05das/aegisops-ai/internal/api/middleware"
	"github.com/bishal05das/aegisops-ai/internal/api/render"
	"github.com/bishal05das/aegisops-ai/internal/config"
	"github.com/bishal05das/aegisops-ai/internal/security/ratelimit"
	"github.com/bishal05das/aegisops-ai/internal/security/rbac"
	"github.com/bishal05das/aegisops-ai/pkg/errs"
	"github.com/bishal05das/aegisops-ai/pkg/httpx"
)

// Server owns the HTTP listener and its lifecycle.
type Server struct {
	cfg    config.HTTPConfig
	log    *slog.Logger
	http   *http.Server
	router *httpx.Router
}

// Deps are the collaborators the API layer needs. Later phases extend this
// struct rather than the Server constructor's signature, so wiring stays a
// single readable literal in main.
type Deps struct {
	Config *config.Config
	Logger *slog.Logger
	Health *handlers.Health

	// Auth is nil until Phase 4 wiring is present; the auth routes are then
	// simply not registered, so a partially-composed server still serves its
	// health endpoints rather than panicking at startup.
	Auth *handlers.Auth
	// TokenVerifier gates authenticated routes.
	TokenVerifier middleware.TokenVerifier
	// RateLimiter throttles the API globally, keyed by principal.
	RateLimiter *ratelimit.Limiter

	// Incidents serves the incident and agent endpoints.
	Incidents *handlers.Incidents

	// Harness serves the approval queue, the rule surface and the ledger.
	Harness *handlers.Harness
}

// NewServer assembles the router, middleware stack and http.Server.
func NewServer(deps Deps) *Server {
	cfg := deps.Config.HTTP
	log := deps.Logger

	s := &Server{cfg: cfg, log: log}
	s.router = s.buildRouter(deps)

	s.http = &http.Server{
		Addr:    cfg.Addr,
		Handler: s.router,

		// Each of these bounds a specific failure. Leaving any at Go's zero
		// value means "no limit", which is how a service accumulates stuck
		// connections until it runs out of file descriptors.
		ReadHeaderTimeout: cfg.ReadHeaderTimeout, // Slowloris
		ReadTimeout:       cfg.ReadTimeout,       // slow body
		WriteTimeout:      cfg.WriteTimeout,      // slow consumer
		IdleTimeout:       cfg.IdleTimeout,       // idle keep-alives

		// 1 MiB of headers is already generous; beyond it, someone is probing.
		MaxHeaderBytes: 1 << 20,

		// Route net/http's own errors into the structured logger instead of the
		// global standard logger, so they carry service context and are JSON in
		// production like everything else.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),

		// BaseContext is deliberately left nil (net/http defaults it to
		// context.Background()).
		//
		// The tempting alternative is to root it at Run's context so SIGTERM
		// propagates into request contexts. That would be actively harmful: it
		// cancels every in-flight request the instant the signal arrives, so a
		// handler part-way through an approved remediation is aborted rather
		// than allowed to finish. Shutdown already gives in-flight work its
		// grace period *without* cancelling it — that separation is precisely
		// what makes the drain graceful, and ShutdownGrace is the bound.
		//
		// If a future long-running handler needs to know a shutdown has begun so
		// it can wind down early, that wants a distinct "draining" signal, not
		// cancellation of the request it is serving.
	}
	return s
}

// buildRouter registers middleware and routes.
//
// The middleware order here is the contract described in the middleware package
// doc comment; changing it changes behaviour in ways that are not locally
// obvious, so each position carries its reason.
func (s *Server) buildRouter(deps Deps) *httpx.Router {
	cfg := deps.Config

	r := httpx.NewRouter()
	r.Use(
		// Outermost: everything below resolves its logger from the context.
		middleware.InjectLogger(deps.Logger),
		// Before anything that logs or renders an error, so every line and
		// every response body carries the same correlation ID.
		middleware.RequestID(),
		// Before AccessLog and rate limiting, both of which record the client.
		middleware.RealIP(nil),
		// Above Recovery on purpose: Recovery turns a panic into an ordinary 500
		// response, so AccessLog observes and records it. Reversed, a panic would
		// unwind past AccessLog and vanish from the access log.
		middleware.AccessLog(middleware.LoggerOptions{
			SkipPaths: map[string]bool{"/healthz": true, "/readyz": true},
		}),
		// Not outermost — see the middleware package doc. net/http already keeps
		// the process alive; this exists to produce a *correlated* JSON 500,
		// which requires the request ID established above.
		middleware.Recovery(),
		middleware.SecurityHeaders(),
		// Above Timeout: a preflight does no work and must never be delayed.
		middleware.CORS(middleware.CORSOptions{AllowedOrigins: cfg.HTTP.CORSOrigins}),
		middleware.Timeout(cfg.HTTP.RequestTimeout),
		middleware.MaxBody(cfg.HTTP.MaxBodyBytes),
		// Below Timeout so a throttled request is not also counted against the
		// request budget, and applied to authenticated and anonymous traffic
		// alike — it keys on the principal when there is one and on the client
		// address otherwise.
		middleware.RateLimit(middleware.RateLimitOptions{
			Limiter:   deps.RateLimiter,
			SkipPaths: map[string]bool{"/healthz": true, "/readyz": true},
		}),
	)

	health := deps.Health
	if health == nil {
		health = handlers.NewHealth()
	}

	// Kubernetes probe endpoints live outside /api so they are never versioned,
	// never require authentication and are never rate limited — a throttled
	// readiness check reads to Kubernetes as an unhealthy pod, so the limiter
	// would cause the outage it exists to prevent.
	r.Get("/healthz", health.Live)
	r.Get("/readyz", health.Ready)

	v1 := r.Group("/api/v1")
	v1.Get("/version", health.Version)

	if deps.Auth != nil {
		// Unauthenticated by necessity: login has no credential yet, and
		// refresh exists precisely for when the access token has expired.
		// Requiring auth on either would make them unreachable.
		v1.Post("/auth/login", deps.Auth.Login)
		v1.Post("/auth/refresh", deps.Auth.Refresh)

		// Everything else sits behind authentication. RequireAuth is applied as
		// route middleware rather than to a group, so adding a route without it
		// is visible in the diff rather than silently inheriting a group's
		// protection — or silently missing it.
		if deps.TokenVerifier != nil {
			authed := middleware.RequireAuth(deps.TokenVerifier)
			v1.Post("/auth/logout", deps.Auth.Logout, authed)
			v1.Get("/auth/me", deps.Auth.Me, authed)
		}
	}

	if deps.Incidents != nil && deps.TokenVerifier != nil {
		authed := middleware.RequireAuth(deps.TokenVerifier)

		// Permission is attached per route rather than per group. A new route
		// then has to name what it requires, which is visible in a diff —
		// whereas inheriting a group's protection makes an unprotected route
		// look identical to a protected one.
		v1.Post("/incidents", deps.Incidents.Create,
			authed, middleware.RequirePermission(rbac.PermIncidentCreate))
		v1.Get("/incidents", deps.Incidents.List,
			authed, middleware.RequirePermission(rbac.PermIncidentRead))
		v1.Get("/incidents/{id}", deps.Incidents.Get,
			authed, middleware.RequirePermission(rbac.PermIncidentRead))
		v1.Get("/incidents/{id}/timeline", deps.Incidents.Timeline,
			authed, middleware.RequirePermission(rbac.PermIncidentRead))
		v1.Get("/incidents/{id}/tasks", deps.Incidents.Tasks,
			authed, middleware.RequirePermission(rbac.PermIncidentRead))
		v1.Post("/incidents/{id}/close", deps.Incidents.Close,
			authed, middleware.RequirePermission(rbac.PermIncidentClose))

		v1.Get("/agents", deps.Incidents.ListAgents,
			authed, middleware.RequirePermission(rbac.PermAgentRead))
	}

	if deps.Harness != nil && deps.TokenVerifier != nil {
		authed := middleware.RequireAuth(deps.TokenVerifier)

		// The approval queue. Reading it needs approval:read; ruling on an entry
		// needs authority for that entry's *risk tier*, which cannot be
		// expressed as a route-level permission — a route cannot know whether
		// the request behind {id} is medium or high risk. So the route requires
		// only the ability to see the queue, and the harness performs the real
		// authority check against the loaded request. See ADR 0011.
		v1.Get("/approvals", deps.Harness.ListPending,
			authed, middleware.RequirePermission(rbac.PermApprovalRead))
		v1.Post("/approvals/{id}/decide", deps.Harness.Decide,
			authed, middleware.RequirePermission(rbac.PermApprovalRead))

		v1.Get("/tool-calls", deps.Harness.ListToolCalls,
			authed, middleware.RequirePermission(rbac.PermApprovalRead))
		v1.Get("/tool-calls/{id}", deps.Harness.GetToolCall,
			authed, middleware.RequirePermission(rbac.PermApprovalRead))

		v1.Get("/harness/rules", deps.Harness.Rules,
			authed, middleware.RequirePermission(rbac.PermPolicyRead))

		v1.Get("/audit", deps.Harness.ListAudit,
			authed, middleware.RequirePermission(rbac.PermAuditRead))
		v1.Get("/audit/verify", deps.Harness.VerifyAudit,
			authed, middleware.RequirePermission(rbac.PermAuditVerify))
	}

	// JSON for 404 and 405 rather than net/http's text defaults, so clients
	// parse one error shape for every response the API can produce.
	r.NotFound(http.HandlerFunc(s.notFound))
	r.MethodNotAllowed(http.HandlerFunc(s.methodNotAllowed))

	return r
}

// notFound renders an unmatched route in the standard error envelope.
func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	render.WriteError(w, r, errs.E("api.notFound", errs.NotFound,
		"no route matches "+r.Method+" "+r.URL.Path).
		WithCode("route_not_found"))
}

// methodNotAllowed renders a verb mismatch, naming the verbs that would work.
// The Allow header has already been set by the router from ServeMux's decision.
func (s *Server) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	msg := "method " + r.Method + " is not allowed on " + r.URL.Path
	if allow := w.Header().Get("Allow"); allow != "" {
		msg += "; try: " + allow
	}
	render.WriteError(w, r, errs.E("api.methodNotAllowed", errs.MethodNotAllowed, msg).
		WithCode("method_not_allowed"))
}

// Handler exposes the fully-wrapped handler for testing with httptest.
func (s *Server) Handler() http.Handler { return s.router }

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.cfg.Addr }

// Run serves until ctx is cancelled, then shuts down gracefully.
//
// The sequence matters:
//
//  1. ctx is cancelled (SIGTERM, or a sibling component failing)
//  2. Shutdown stops accepting new connections and closes idle keep-alives
//  3. In-flight requests are given ShutdownGrace to finish
//  4. If the grace expires, remaining connections are severed
//
// Step 3 is why a deploy does not sever an approval mid-execution; step 4 is why
// a wedged handler cannot block a rollout forever.
func (s *Server) Run(ctx context.Context) error {
	const op = "api.Server.Run"

	// Bind explicitly rather than via ListenAndServe so that a port conflict is
	// reported synchronously, before anything announces itself as started.
	//
	// ListenConfig rather than net.Listen so the bind itself honours ctx — a
	// SIGTERM arriving during startup aborts cleanly instead of binding a port
	// the process is about to abandon.
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Addr)
	if err != nil {
		return errs.E(op, errs.Unavailable, "bind "+s.cfg.Addr, err)
	}

	serveErr := make(chan error, 1)
	go func() {
		s.log.Info("http server listening",
			"addr", ln.Addr().String(),
			"read_timeout", s.cfg.ReadTimeout.String(),
			"write_timeout", s.cfg.WriteTimeout.String(),
			"request_timeout", s.cfg.RequestTimeout.String(),
			"max_body_bytes", s.cfg.MaxBodyBytes,
		)
		// ErrServerClosed is the expected result of a graceful Shutdown.
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			return errs.E(op, errs.Internal, "http server failed", err)
		}
		return nil

	case <-ctx.Done():
		s.log.Info("shutting down http server", "grace", s.cfg.ShutdownGrace.String())

		// ctx is *already* cancelled — that is what got us here — so deriving
		// the shutdown budget from it directly would give Shutdown zero time and
		// sever in-flight requests immediately: the precise opposite of a
		// graceful drain.
		//
		// WithoutCancel rather than context.Background(): it drops the
		// cancellation but keeps the context's values, so any trace or request
		// scope attached upstream survives into the drain. Background() would
		// silently discard them.
		shutdownCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), s.cfg.ShutdownGrace)
		defer cancel()

		start := time.Now()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			s.log.Warn("graceful shutdown incomplete; forcing close",
				"error", err, "elapsed", time.Since(start).String())
			// Sever what remains rather than leaking the listener.
			if closeErr := s.http.Close(); closeErr != nil {
				return errs.E(op, errs.Internal, "force close", closeErr)
			}
			return errs.E(op, errs.Timeout, "graceful shutdown exceeded grace period", err)
		}

		s.log.Info("http server stopped cleanly", "elapsed", time.Since(start).String())
		return nil
	}
}
