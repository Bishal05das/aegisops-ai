package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/bishal05das/aegisops-ai/internal/api/dto"
	"github.com/bishal05das/aegisops-ai/pkg/httpx"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// Recovery converts a panic into a correlated JSON 500.
//
// Note what it is *not* for: net/http already recovers panics per connection in
// (*conn).serve, so the process survives regardless. What the standard library
// does on its own is close the connection and log a stack trace with no request
// context — leaving the client with a dropped connection rather than a response
// they can act on, and the operator with a trace they cannot tie to anything.
//
// This middleware supplies both halves: an error envelope carrying the request
// ID, and a structured log line correlated to it. That requirement is why it
// sits *below* RequestID and InjectLogger rather than outermost — see the
// package documentation.
//
// Two subtleties this handles that naive implementations do not:
//
//   - **http.ErrAbortHandler is re-panicked.** The standard library uses it as a
//     deliberate signal to abandon a response without logging. Swallowing it
//     would convert an intentional abort into a spurious 500.
//   - **A partially-written response cannot be rewritten.** If the handler
//     already sent a status line, the bytes are gone. Writing an error envelope
//     after that appends garbage to a response the client is already parsing, so
//     the connection is closed instead.
func Recovery() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := httpx.NewResponseRecorder(w)

			// contextcheck cannot see that r is the request handed to this
			// closure, so it reports a false positive on the r.Context() below.
			defer func() { //nolint:contextcheck // ctx is inherited from r
				p := recover()
				if p == nil {
					return
				}
				// recover() yields `any`, so this must type-assert before
				// comparing. errors.Is rather than == because a handler may
				// legitimately wrap the sentinel before re-panicking.
				if err, ok := p.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(p) // deliberate abort; let net/http handle it
				}

				ctx := r.Context()
				logger.FromContext(ctx).Error("panic recovered in handler",
					"panic", fmt.Sprint(p),
					"method", r.Method,
					"path", r.URL.Path,
					"stack", string(debug.Stack()),
				)

				if rec.Wrote() {
					// Response already begun. Anything appended now corrupts it;
					// severing the connection is the only honest signal, and
					// ErrAbortHandler is how net/http is told to do that.
					panic(http.ErrAbortHandler)
				}

				body := dto.NewError("internal_error", "an internal error occurred",
					logger.RequestID(ctx))
				_ = httpx.Respond(rec, http.StatusInternalServerError, body)
			}()

			next.ServeHTTP(rec, r)
		})
	}
}
