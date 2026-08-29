// Package render is the single exit point for HTTP responses.
//
// It exists as its own package for a structural reason, not a stylistic one:
// both internal/api (which renders 404s and panics) and internal/api/handlers
// (which renders everything else) need it, and putting it in either would create
// an import cycle. Extracting it also makes the guarantee enforceable — any
// handler writing directly to the ResponseWriter instead of calling through here
// is visible in review as a missing render import.
package render

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/bishal05das/aegisops-ai/internal/api/dto"
	"github.com/bishal05das/aegisops-ai/pkg/errs"
	"github.com/bishal05das/aegisops-ai/pkg/httpx"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// statusClientClosed mirrors nginx's non-standard 499. It is recorded for
// metrics but never sent, because by definition nobody is listening.
const statusClientClosed = 499

// WriteError is the single exit point for every failing request.
//
// Centralising it enforces four properties that are impossible to guarantee when
// handlers write their own errors:
//
//  1. **One envelope shape** for every endpoint.
//  2. **No detail leaks.** Only errs.Error.Public crosses the boundary, so an
//     internal error can never carry a driver message or a query to the client.
//  3. **Every error is logged once**, with the full internal chain, at a level
//     that matches whether it was our fault or the caller's.
//  4. **Every response carries a request ID**, so a user report maps to a log
//     line without guesswork.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	ctx := r.Context()
	status := errs.StatusOf(err)

	// Log before writing: if the client has already hung up the write fails, but
	// the diagnostic must survive regardless.
	logError(ctx, r, err, status)

	if status == statusClientClosed {
		// The client is gone. Nothing can be delivered; just close out.
		return
	}

	code, message := publicOf(err)
	body := dto.NewError(code, message, logger.RequestID(ctx))
	if details := fieldErrors(err); len(details) > 0 {
		body = body.WithDetails(details...)
	}

	if writeErr := httpx.Respond(w, status, body); writeErr != nil {
		// Encoding the envelope itself failed — a bug, not a client problem.
		// Fall back to a hand-written body so the client still gets valid JSON.
		logger.FromContext(ctx).Error("failed to encode error response", "error", writeErr)
		w.Header().Set("Content-Type", httpx.ContentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"internal_error","message":"an internal error occurred"}}` + "\n"))
	}
}

// publicOf extracts the client-safe code and message from any error.
func publicOf(err error) (code, message string) {
	var e *errs.Error
	if errors.As(err, &e) {
		return e.Public()
	}
	// Unclassified errors, including raw context errors, are rendered from their
	// kind alone — never from their text, which may hold internal detail.
	kind := errs.KindOf(err)
	if ce := errs.FromContextError("api", err); ce != nil {
		kind = ce.Kind
	}
	return errs.E("", kind).Public()
}

// ValidationKey is the errs field under which handlers attach per-field
// validation failures destined for the client. Every other field in the error
// chain is treated as log-only context and is never echoed back, because those
// values routinely hold internal identifiers.
const ValidationKey = "validation"

// fieldErrors lifts per-field validation failures out of the error chain.
func fieldErrors(err error) []dto.FieldError {
	fields := errs.Fields(err)
	if len(fields) == 0 {
		return nil
	}
	raw, ok := fields[ValidationKey]
	if !ok {
		return nil
	}
	details, ok := raw.([]dto.FieldError)
	if !ok {
		return nil
	}
	return details
}

// logError records the failure at a level matching who is at fault.
//
// Client mistakes are normal traffic and log at debug; auth failures are
// security-relevant and log at warn; server faults log at error. Logging a 404
// at error level is precisely how an error dashboard becomes noise that
// operators learn to ignore.
func logError(ctx context.Context, r *http.Request, err error, status int) {
	log := logger.FromContext(ctx)

	attrs := []slog.Attr{
		slog.String("error", err.Error()),
		slog.Int("status", status),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	}
	if ops := errs.Ops(err); len(ops) > 0 {
		attrs = append(attrs, slog.Any("ops", ops))
	}
	for k, v := range errs.Fields(err) {
		if k == ValidationKey {
			continue
		}
		attrs = append(attrs, slog.Any(k, v))
	}

	switch {
	case status >= 500 || errs.ShouldLogAsError(err):
		log.LogAttrs(ctx, slog.LevelError, "request failed", attrs...)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		log.LogAttrs(ctx, slog.LevelWarn, "request denied", attrs...)
	default:
		log.LogAttrs(ctx, slog.LevelDebug, "request rejected", attrs...)
	}
}

// WriteJSON writes a successful JSON response, converting an encoding failure
// into the standard error envelope.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	if err := httpx.Respond(w, status, v); err != nil {
		WriteError(w, r, err)
	}
}
