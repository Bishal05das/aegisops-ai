// Package middleware implements the cross-cutting concerns of the HTTP layer.
//
// Ordering is the load-bearing decision in this package. The stack applied by
// internal/api.Server is, outermost first:
//
//	InjectLogger    — everything below resolves its logger from the context
//	RequestID       — must precede anything that logs or renders an error
//	RealIP          — AccessLog and rate limiting need the true client address
//	AccessLog       — outside Recovery, so a panic is still recorded as a 500
//	Recovery        — turns a panic into a correlated JSON 500
//	SecurityHeaders — cheap, unconditional, applies even to error responses
//	CORS            — must precede Timeout so preflights are never delayed
//	Timeout         — bounds the handler, not the middleware above it
//	MaxBody         — innermost; only handlers that read a body care
//
// # Why Recovery is not outermost
//
// The intuitive placement is outermost, "so nothing escapes". That is wrong here
// for two reasons.
//
// First, it is unnecessary: net/http already recovers panics per connection in
// (*conn).serve, so a panicking handler cannot kill the process. It closes the
// connection and logs through Server.ErrorLog — which this service points at the
// structured logger. Recovery's real job is narrower and more useful: convert
// the panic into a *well-formed JSON 500 carrying a request ID*.
//
// Second, outermost placement actively defeats that job. Middleware receives the
// *http.Request as it entered, so a Recovery above RequestID and InjectLogger
// holds a context with neither. Its deferred handler then falls back to the
// default logger and emits a 500 with no request_id — precisely the response
// nobody can correlate, produced for precisely the failure that most needs it.
//
// AccessLog sits above Recovery for a related reason: Recovery converts the
// panic into a normal 500 response, so AccessLog observes and records it. Were
// the order reversed, the panic would unwind past AccessLog and the request
// would be missing from the access log entirely.
package middleware

import (
	"net/http"

	"github.com/bishal05das/aegisops-ai/pkg/httpx"
)

// Middleware is re-exported so callers need only import this package.
type Middleware = httpx.Middleware

// wrap adapts a plain function into a Middleware.
func wrap(fn func(http.ResponseWriter, *http.Request, http.Handler)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fn(w, r, next)
		})
	}
}
