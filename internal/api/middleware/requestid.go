package middleware

import (
	"log/slog"
	"net/http"

	"github.com/bishal05das/aegisops-ai/pkg/id"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// HeaderRequestID is the header carrying the correlation identifier.
const HeaderRequestID = "X-Request-ID"

// RequestID assigns every request a correlation identifier and puts it on the
// context, the response headers and every log line beneath it.
//
// Inbound values are honoured so a trace survives across service hops — but only
// after validation. An inbound header is attacker-controlled, and echoing an
// arbitrary string into a log line is a log-injection vector: a value containing
// a newline and a fabricated JSON object can forge log entries in any aggregator
// that parses line-delimited JSON. id.Valid constrains the value to 26
// characters of Crockford base32, which makes that impossible.
func RequestID() Middleware {
	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		rid := r.Header.Get(HeaderRequestID)
		if !id.Valid(rid) {
			rid = id.New()
		}

		ctx := logger.WithRequestID(r.Context(), rid)

		// Set on the response before calling the handler: a handler that panics
		// or hijacks the connection must still have surfaced the ID.
		w.Header().Set(HeaderRequestID, rid)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// InjectLogger places a base logger on the request context so downstream code
// can retrieve it with logger.FromContext.
//
// The logger itself needs no request fields attached: the contextHandler in
// pkg/logger lifts request_id, trace_id, incident_id, agent_id and user_id off
// the context at log time. Adding them here would duplicate them.
func InjectLogger(base *slog.Logger) Middleware {
	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		next.ServeHTTP(w, r.WithContext(logger.WithLogger(r.Context(), base)))
	})
}
