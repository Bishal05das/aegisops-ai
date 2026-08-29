package logger

import (
	"context"
	"log/slog"
)

// ctxKey is an unexported type so no other package can collide with these keys
// or read them without going through this API.
type ctxKey int

const (
	keyLogger ctxKey = iota
	keyRequestID
	keyTraceID
	keyIncidentID
	keyAgentID
	keyUserID
)

// contextKeys declares which context values are lifted into every log record.
// Adding a correlation dimension is a one-line change here; no call site moves.
var contextKeys = []struct {
	ctxKey ctxKey
	attr   string
}{
	{keyRequestID, "request_id"},
	{keyTraceID, "trace_id"},
	{keyIncidentID, "incident_id"},
	{keyAgentID, "agent_id"},
	{keyUserID, "user_id"},
}

// WithLogger stores a logger on the context.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, keyLogger, l)
}

// FromContext retrieves the logger from ctx.
//
// It never returns nil. A missing logger falls back to slog's default rather
// than panicking: losing a log line is bad, but crashing a remediation because
// logging was misconfigured is worse.
func FromContext(ctx context.Context) *slog.Logger {
	if ctx != nil {
		if l, ok := ctx.Value(keyLogger).(*slog.Logger); ok && l != nil {
			return l
		}
	}
	return slog.Default()
}

// WithRequestID tags the context with an HTTP request identifier.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyRequestID, id)
}

// RequestID returns the request identifier, or "" if unset.
func RequestID(ctx context.Context) string { return stringValue(ctx, keyRequestID) }

// WithTraceID tags the context with a distributed trace identifier.
func WithTraceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyTraceID, id)
}

// TraceID returns the trace identifier, or "" if unset.
func TraceID(ctx context.Context) string { return stringValue(ctx, keyTraceID) }

// WithIncidentID tags the context with the incident being worked on. Every log
// line emitted anywhere beneath this point becomes filterable by incident,
// which is what makes a multi-agent investigation readable after the fact.
func WithIncidentID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyIncidentID, id)
}

// IncidentID returns the incident identifier, or "" if unset.
func IncidentID(ctx context.Context) string { return stringValue(ctx, keyIncidentID) }

// WithAgentID tags the context with the acting agent.
func WithAgentID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyAgentID, id)
}

// AgentID returns the agent identifier, or "" if unset.
func AgentID(ctx context.Context) string { return stringValue(ctx, keyAgentID) }

// WithUserID tags the context with the authenticated principal.
func WithUserID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyUserID, id)
}

// UserID returns the authenticated principal, or "" if unset.
func UserID(ctx context.Context) string { return stringValue(ctx, keyUserID) }

func stringValue(ctx context.Context, k ctxKey) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(k).(string)
	return s
}
