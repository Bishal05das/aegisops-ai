// Package logger provides structured logging for AegisOps on top of log/slog.
//
// Three things it adds over bare slog:
//
//  1. **Context-aware attributes.** A [contextHandler] pulls the request ID,
//     trace ID, incident ID and agent ID off the context at log time. Call sites
//     write log.Info("starting investigation") and correlation happens for free.
//     Threading those values through every signature by hand is how they end up
//     missing from the one line you needed.
//
//  2. **Redaction.** Attribute keys that look like secrets are replaced before
//     they reach a handler. This is defence in depth behind config.Secret, not a
//     substitute for it.
//
//  3. **Environment-appropriate output.** JSON in production for ingestion;
//     human-readable text with source locations in development.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format selects the output encoding.
type Format string

const (
	// FormatJSON emits one JSON object per line, for log aggregation.
	FormatJSON Format = "json"
	// FormatText emits human-readable key=value lines, for a terminal.
	FormatText Format = "text"
)

// Options configures a logger.
type Options struct {
	// Level is the minimum severity emitted.
	Level slog.Level
	// Format selects JSON or text. Defaults to JSON.
	Format Format
	// Output defaults to os.Stdout. Logs go to stdout, not stderr: in a
	// container both are captured, and keeping one stream preserves ordering.
	Output io.Writer
	// AddSource attaches file:line. Useful in development, costly under load.
	AddSource bool
	// Base attributes attached to every record — service, version, environment.
	Base []slog.Attr
}

// New builds a *slog.Logger from Options.
func New(opts Options) *slog.Logger {
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}

	handlerOpts := &slog.HandlerOptions{
		Level:       opts.Level,
		AddSource:   opts.AddSource,
		ReplaceAttr: replaceAttr,
	}

	var h slog.Handler
	if opts.Format == FormatText {
		h = slog.NewTextHandler(out, handlerOpts)
	} else {
		h = slog.NewJSONHandler(out, handlerOpts)
	}

	// Base attributes are applied to the encoder *before* the context wrapper,
	// so they cost nothing per record and never appear in the replay list below.
	if len(opts.Base) > 0 {
		h = h.WithAttrs(opts.Base)
	}

	return slog.New(newContextHandler(h))
}

// Discard returns a logger that writes nowhere. Tests use it to keep output
// clean while still exercising every log call site.
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError + 1,
	}))
}

// ParseLevel converts a configured level name into a slog.Level.
// Unrecognised input yields info and reports ok=false, letting config surface a
// validation error rather than silently running at the wrong verbosity.
func ParseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "info", "":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

// ParseFormat converts a configured format name into a Format.
func ParseFormat(s string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json", "":
		return FormatJSON, true
	case "text", "console":
		return FormatText, true
	default:
		return FormatJSON, false
	}
}

// replaceAttr normalises and redacts attributes before encoding.
//
// Redaction applies at every depth, not just the top level. Grouping is a
// presentation choice; it says nothing about how sensitive a value is. An
// earlier version of this function skipped grouped attributes on the theory
// that callers would redact their own maps first — which meant
// `log.WithGroup("db").Info(..., "password", pw)` wrote the credential straight
// to the log. Redacting twice costs nothing; missing once costs a rotation.
func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	if isSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}

	// slog renders errors via fmt, which loses structure. Errors are attached
	// deliberately by the API error handler, so leave the value but ensure the
	// key is consistent for querying.
	if a.Value.Kind() == slog.KindAny {
		if err, ok := a.Value.Any().(error); ok {
			return slog.String(a.Key, err.Error())
		}
	}
	return a
}

// contextHandler injects correlation identifiers carried on the context.
//
// The obvious implementation — embed a handler and call Record.AddAttrs in
// Handle — is subtly wrong once anyone calls WithGroup. Record attributes land
// inside the open group, so `log.WithGroup("tool").Info(...)` emits
// `{"tool":{"request_id":"..."}}` and every query filtering on a top-level
// request_id silently stops matching that logger's output. Correlation IDs must
// be at the root, always, regardless of grouping.
//
// So the handler keeps the ungrouped root and replays the WithAttrs/WithGroup
// operations applied to it. Context attributes go onto the root; everything else
// is layered on top afterwards.
//
// Cost: when no group or derived attribute is in play — the overwhelmingly
// common case — ops is empty and this is one WithAttrs call per record, the same
// as the naive version.
type contextHandler struct {
	root    slog.Handler // ungrouped; context attributes attach here
	derived slog.Handler // root with ops already applied; the no-context path
	ops     []handlerOp  // replayed on top of root when context attrs exist
}

// handlerOp records one WithAttrs or WithGroup call, so it can be replayed.
type handlerOp struct {
	group string      // non-empty for WithGroup
	attrs []slog.Attr // non-nil for WithAttrs
}

func newContextHandler(h slog.Handler) *contextHandler {
	return &contextHandler{root: h, derived: h}
}

// Enabled implements slog.Handler.
func (h *contextHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.derived.Enabled(ctx, l)
}

// Handle implements slog.Handler.
func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := contextAttrs(ctx)
	if len(attrs) == 0 {
		return h.derived.Handle(ctx, r)
	}

	// Attach at the root so the keys are top-level, then replay.
	target := h.root.WithAttrs(attrs)
	for _, op := range h.ops {
		if op.group != "" {
			target = target.WithGroup(op.group)
			continue
		}
		target = target.WithAttrs(op.attrs)
	}
	return target.Handle(ctx, r)
}

// contextAttrs lifts the correlation identifiers off ctx.
func contextAttrs(ctx context.Context) []slog.Attr {
	if ctx == nil {
		return nil
	}
	var attrs []slog.Attr
	for _, k := range contextKeys {
		if v, ok := ctx.Value(k.ctxKey).(string); ok && v != "" {
			attrs = append(attrs, slog.String(k.attr, v))
		}
	}
	return attrs
}

// WithAttrs implements slog.Handler.
func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return &contextHandler{
		root:    h.root,
		derived: h.derived.WithAttrs(attrs),
		ops:     appendOp(h.ops, handlerOp{attrs: attrs}),
	}
}

// WithGroup implements slog.Handler.
func (h *contextHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &contextHandler{
		root:    h.root,
		derived: h.derived.WithGroup(name),
		ops:     appendOp(h.ops, handlerOp{group: name}),
	}
}

// appendOp copies before appending. Handlers are shared across goroutines and
// must be immutable; appending in place could let two derived loggers alias the
// same backing array and overwrite each other's operations.
func appendOp(ops []handlerOp, op handlerOp) []handlerOp {
	out := make([]handlerOp, len(ops), len(ops)+1)
	copy(out, ops)
	return append(out, op)
}
