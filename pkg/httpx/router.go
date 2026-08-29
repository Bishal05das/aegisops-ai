// Package httpx provides the HTTP primitives AegisOps builds its API on:
// routing, middleware composition, JSON handling and a response recorder.
//
// It is domain-free — nothing here knows about incidents, agents or the harness
// — which is why it lives in pkg/ and can be tested in isolation.
//
// No web framework. Go 1.22's ServeMux gained method-aware patterns with path
// wildcards ("POST /api/v1/incidents/{id}"), which removes the last functional
// reason to import a router. See docs/adr/0001-raw-go-no-framework.md.
package httpx

import (
	"net/http"
	"strings"
	"sync"
)

// Middleware wraps a handler with additional behaviour.
//
// The signature is the standard one, so anything written for the wider Go
// ecosystem composes with this router unmodified.
type Middleware func(http.Handler) http.Handler

// Router registers routes and composes middleware around them.
//
// It wraps http.ServeMux rather than reimplementing matching: the standard mux
// already handles method matching, path wildcards, longest-pattern precedence
// and 405 responses. Reimplementing that would be effort spent reproducing
// behaviour rather than demonstrating understanding of it.
type Router struct {
	mux    *http.ServeMux
	global []Middleware
	prefix string

	// notFound and methodNotAllowed render unmatched requests in the API's JSON
	// error shape instead of net/http's plain text.
	notFound         http.Handler
	methodNotAllowed http.Handler

	// fallback is the middleware-wrapped unmatched-request handler, built once.
	fallbackOnce sync.Once
	fallback     http.Handler
}

// NewRouter creates an empty router.
func NewRouter() *Router {
	return &Router{mux: http.NewServeMux()}
}

// Use appends middleware applied to every route registered afterwards.
//
// Order is outermost-first: Use(A, B) means A wraps B wraps the handler, so a
// request passes A → B → handler. Recovery and request-ID must therefore be
// registered first, since they need to observe everything inside them.
func (r *Router) Use(mw ...Middleware) *Router {
	r.global = append(r.global, mw...)
	return r
}

// Group returns a router sharing the same mux but with an added path prefix and
// its own middleware stack, for versioned or authenticated sections of the API.
func (r *Router) Group(prefix string, mw ...Middleware) *Router {
	global := make([]Middleware, 0, len(r.global)+len(mw))
	global = append(global, r.global...)
	global = append(global, mw...)
	return &Router{
		mux:      r.mux,
		global:   global,
		prefix:   joinPath(r.prefix, prefix),
		notFound: r.notFound,
	}
}

// Handle registers a handler for a method and path pattern.
//
//	r.Handle(http.MethodGet, "/api/v1/incidents/{id}", h)
//
// Route-specific middleware is applied inside the router's global stack.
func (r *Router) Handle(method, pattern string, h http.Handler, mw ...Middleware) {
	full := joinPath(r.prefix, pattern)

	// Route middleware wraps the handler first (innermost), then the global
	// stack wraps that — so a per-route auth check runs after recovery and
	// logging have already been established.
	wrapped := Chain(h, mw...)
	wrapped = Chain(wrapped, r.global...)

	if method == "" {
		r.mux.Handle(full, wrapped)
		return
	}
	r.mux.Handle(method+" "+full, wrapped)
}

// HandleFunc is Handle for a plain function.
func (r *Router) HandleFunc(method, pattern string, h http.HandlerFunc, mw ...Middleware) {
	r.Handle(method, pattern, h, mw...)
}

// Convenience registrars for the verbs this API uses.
func (r *Router) Get(p string, h http.HandlerFunc, mw ...Middleware) {
	r.Handle(http.MethodGet, p, h, mw...)
}
func (r *Router) Post(p string, h http.HandlerFunc, mw ...Middleware) {
	r.Handle(http.MethodPost, p, h, mw...)
}
func (r *Router) Put(p string, h http.HandlerFunc, mw ...Middleware) {
	r.Handle(http.MethodPut, p, h, mw...)
}
func (r *Router) Patch(p string, h http.HandlerFunc, mw ...Middleware) {
	r.Handle(http.MethodPatch, p, h, mw...)
}
func (r *Router) Delete(p string, h http.HandlerFunc, mw ...Middleware) {
	r.Handle(http.MethodDelete, p, h, mw...)
}

// NotFound sets the handler for requests matching no route.
func (r *Router) NotFound(h http.Handler) { r.notFound = h }

// MethodNotAllowed sets the handler for a path that exists under a different
// method. The Allow header determined by ServeMux is copied onto the response
// before the handler runs, so the 405 stays RFC-compliant.
func (r *Router) MethodNotAllowed(h http.Handler) { r.methodNotAllowed = h }

// ServeHTTP implements http.Handler.
//
// Matched routes go straight to the mux. Unmatched ones take the fallback path,
// which distinguishes 404 from 405 — a distinction that is easy to lose.
//
// The obvious implementation, registering the not-found handler at "/", quietly
// destroys it: "/" matches every path, so POST to a GET-only route matches "/"
// and renders 404 instead of 405. The client is then told the endpoint does not
// exist when in fact they used the wrong verb.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if _, pattern := r.mux.Handler(req); pattern != "" {
		r.mux.ServeHTTP(w, req)
		return
	}
	r.fallbackHandler().ServeHTTP(w, req)
}

// fallbackHandler builds the unmatched-request handler, wrapped in the global
// middleware stack so a 404 still gets a request ID and an access-log line.
// Traffic hitting wrong URLs is exactly what you want visible during an
// integration, and dropping it out of the logs hides it.
func (r *Router) fallbackHandler() http.Handler {
	r.fallbackOnce.Do(func() {
		r.fallback = Chain(http.HandlerFunc(r.dispatchUnmatched), r.global...)
	})
	return r.fallback
}

// dispatchUnmatched decides between 404, 405 and a mux-issued redirect.
//
// ServeMux reports pattern=="" for all three, but its *response* differs: a 405
// carries an Allow header and a trailing-slash mismatch is a 301. Replaying the
// mux against a discarding writer reads that decision without committing any
// bytes to the real client.
func (r *Router) dispatchUnmatched(w http.ResponseWriter, req *http.Request) {
	probe := &headerProbe{header: make(http.Header)}
	r.mux.ServeHTTP(probe, req)

	switch {
	case probe.status == http.StatusMethodNotAllowed:
		if allow := probe.header.Get("Allow"); allow != "" {
			w.Header().Set("Allow", allow)
		}
		if r.methodNotAllowed != nil {
			r.methodNotAllowed.ServeHTTP(w, req)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

	case probe.status == http.StatusNotFound:
		if r.notFound != nil {
			r.notFound.ServeHTTP(w, req)
			return
		}
		http.NotFound(w, req)

	default:
		// A redirect (trailing-slash or path-cleaning). Let the mux answer for
		// real rather than second-guessing it.
		r.mux.ServeHTTP(w, req)
	}
}

// headerProbe is a ResponseWriter that records the status and headers while
// discarding the body. It exists only to read ServeMux's routing decision.
type headerProbe struct {
	header http.Header
	status int
}

func (p *headerProbe) Header() http.Header { return p.header }

func (p *headerProbe) WriteHeader(status int) {
	if p.status == 0 {
		p.status = status
	}
}

func (p *headerProbe) Write(b []byte) (int, error) {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	return len(b), nil
}

// Chain applies middleware to a handler, outermost first.
//
// Chain(h, A, B, C) yields A(B(C(h))): a request traverses A → B → C → h, and
// the response unwinds h → C → B → A.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		if mw[i] != nil {
			h = mw[i](h)
		}
	}
	return h
}

// joinPath concatenates a prefix and pattern into a single clean path.
func joinPath(prefix, pattern string) string {
	switch {
	case prefix == "":
		return pattern
	case pattern == "" || pattern == "/":
		return prefix
	}
	return strings.TrimSuffix(prefix, "/") + "/" + strings.TrimPrefix(pattern, "/")
}
