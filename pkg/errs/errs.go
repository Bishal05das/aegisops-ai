// Package errs defines the error taxonomy used across AegisOps.
//
// The design solves one specific problem: an error travelling out of a
// repository, through a service, through the harness and into an HTTP response
// has two audiences with opposite needs.
//
//   - The **operator** needs the whole truth: the failing operation, the driver
//     error, the parameters, the incident it belongs to.
//   - The **caller** needs a stable machine-readable code, a message that is
//     safe to show, and a correlation ID to quote in a bug report.
//
// Returning `pq: relation "incidents" does not exist` to an API client leaks
// schema details and tells them nothing useful. Returning a bare "internal
// error" to the log tells the operator nothing at all. So an Error carries both,
// and only [Error.Public] crosses the boundary.
//
// Usage:
//
//	const op = "postgres.IncidentRepo.Get"
//	if errors.Is(err, sql.ErrNoRows) {
//	    return errs.E(op, errs.NotFound, "incident not found").
//	        WithCode("incident_not_found").
//	        WithField("incident_id", id)
//	}
//	return errs.E(op, errs.Internal, "query incidents", err)
package errs

import (
	"errors"
	"fmt"
	"strings"
)

// Kind classifies an error by what the caller should do about it. It is the
// only input to the HTTP status mapping, which keeps that mapping total and
// testable — see [Kind.HTTPStatus].
type Kind uint8

const (
	// Internal is an unexpected failure. Its details are never shown to callers.
	// This is the zero value on purpose: an error whose kind was never set must
	// default to the most conservative disclosure, not the least.
	Internal Kind = iota
	// Invalid means the request was malformed or failed validation.
	Invalid
	// Unauthorized means authentication is missing or bad.
	Unauthorized
	// Forbidden means the caller is authenticated but not permitted. This is
	// also what the harness permission engine returns.
	Forbidden
	// NotFound means the addressed resource does not exist.
	NotFound
	// MethodNotAllowed means the path exists but not under this verb. Kept
	// distinct from NotFound because telling a client "no such endpoint" when
	// they merely used GET instead of POST sends them debugging the wrong thing.
	MethodNotAllowed
	// Conflict means the request collides with current state.
	Conflict
	// Exists means the resource already exists.
	Exists
	// RateLimited means the caller exceeded a quota.
	RateLimited
	// Timeout means the operation exceeded its deadline.
	Timeout
	// Canceled means the operation was cancelled, usually by the client hanging
	// up or by an incident being resolved mid-investigation.
	Canceled
	// Unavailable means a dependency is down. Retrying later may succeed.
	Unavailable
	// NotImplemented means the capability is not built yet.
	NotImplemented
)

// String implements fmt.Stringer.
func (k Kind) String() string {
	switch k {
	case Invalid:
		return "invalid"
	case Unauthorized:
		return "unauthorized"
	case Forbidden:
		return "forbidden"
	case NotFound:
		return "not_found"
	case MethodNotAllowed:
		return "method_not_allowed"
	case Conflict:
		return "conflict"
	case Exists:
		return "exists"
	case RateLimited:
		return "rate_limited"
	case Timeout:
		return "timeout"
	case Canceled:
		return "canceled"
	case Unavailable:
		return "unavailable"
	case NotImplemented:
		return "not_implemented"
	default:
		return "internal"
	}
}

// Error is a structured error carrying everything needed to log it fully and
// render it safely.
type Error struct {
	// Op is the operation that failed, in "package.Type.Method" form. Nested
	// Errors form a call chain without the cost of stack capture.
	Op string
	// Kind drives the HTTP status and the retry decision.
	Kind Kind
	// Code is a stable machine-readable identifier that clients may branch on,
	// e.g. "incident_not_found". Defaults to Kind.String() when unset.
	Code string
	// Message is safe to show to a caller. For Internal it is replaced by a
	// generic string before it leaves the process — see Public.
	Message string
	// Err is the wrapped cause. Never exposed to callers.
	Err error
	// Fields carry structured context for logs. Must not hold secrets.
	Fields map[string]any
}

// E builds an Error.
//
// The variadic tail accepts a message string and/or a wrapped error, in either
// order, so the common cases read naturally:
//
//	errs.E(op, errs.NotFound, "incident not found")
//	errs.E(op, errs.Internal, "load incident", err)
//	errs.E(op, errs.Internal, err)
func E(op string, kind Kind, args ...any) *Error {
	e := &Error{Op: op, Kind: kind}
	for _, a := range args {
		switch v := a.(type) {
		case string:
			e.Message = v
		case error:
			e.Err = v
		case map[string]any:
			e.Fields = v
		default:
			// Silently dropping a misused argument would hide a bug at the exact
			// moment someone is debugging one.
			e.Message = strings.TrimSpace(e.Message + fmt.Sprintf(" [errs: unsupported arg %T]", v))
		}
	}
	return e
}

// Error implements the error interface, rendering the full internal chain.
// This string is for logs only; it may contain details unsafe to expose.
func (e *Error) Error() string {
	var b strings.Builder
	if e.Op != "" {
		b.WriteString(e.Op)
		b.WriteString(": ")
	}
	if e.Message != "" {
		b.WriteString(e.Message)
	} else {
		b.WriteString(e.Kind.String())
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

// Unwrap supports errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.Err }

// WithCode sets the stable client-facing code and returns e for chaining.
func (e *Error) WithCode(code string) *Error { e.Code = code; return e }

// WithField attaches structured log context and returns e for chaining.
func (e *Error) WithField(key string, val any) *Error {
	if e.Fields == nil {
		e.Fields = make(map[string]any, 4)
	}
	e.Fields[key] = val
	return e
}

// WithMessage overrides the client-facing message and returns e for chaining.
func (e *Error) WithMessage(msg string) *Error { e.Message = msg; return e }

// ErrorCode returns the stable code, falling back to the kind.
func (e *Error) ErrorCode() string {
	if e.Code != "" {
		return e.Code
	}
	return e.Kind.String()
}

// genericInternalMessage is what callers see instead of internal detail.
const genericInternalMessage = "an internal error occurred"

// Public returns the code and message safe to send to a caller.
//
// The whole point of the package is this method: for every kind except Internal
// the message was written for a human caller and is returned as-is; for Internal
// it is replaced wholesale, because an Internal message may embed a driver
// error, a file path or a query.
func (e *Error) Public() (code, message string) {
	if e.Kind == Internal {
		code = e.Code
		if code == "" {
			code = "internal_error"
		}
		return code, genericInternalMessage
	}
	msg := e.Message
	if msg == "" {
		msg = defaultMessage(e.Kind)
	}
	return e.ErrorCode(), msg
}

func defaultMessage(k Kind) string {
	switch k {
	case Invalid:
		return "the request was invalid"
	case Unauthorized:
		return "authentication required"
	case Forbidden:
		return "you are not permitted to perform this action"
	case NotFound:
		return "the requested resource was not found"
	case MethodNotAllowed:
		return "that HTTP method is not allowed on this endpoint"
	case Conflict:
		return "the request conflicts with the current state"
	case Exists:
		return "the resource already exists"
	case RateLimited:
		return "too many requests"
	case Timeout:
		return "the request timed out"
	case Canceled:
		return "the request was cancelled"
	case Unavailable:
		return "a required service is unavailable"
	case NotImplemented:
		return "this capability is not implemented"
	default:
		return genericInternalMessage
	}
}

// -----------------------------------------------------------------------------
// Inspection
// -----------------------------------------------------------------------------

// KindOf reports the Kind of any error, walking the wrap chain.
//
// A plain error that never passed through this package is Internal — the
// conservative default, so an unclassified error never accidentally renders as
// a 400 with its raw text.
func KindOf(err error) Kind {
	if err == nil {
		return Internal
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Internal
}

// Is reports whether err has the given Kind anywhere in its chain.
func Is(err error, kind Kind) bool { return KindOf(err) == kind }

// Ops returns the operation chain, outermost first. This reconstructs the call
// path — "api.CreateIncident: service.Create: postgres.Insert" — at a fraction
// of the cost of capturing a stack trace on every error.
func Ops(err error) []string {
	var ops []string
	for err != nil {
		var e *Error
		if !errors.As(err, &e) {
			break
		}
		if e.Op != "" {
			ops = append(ops, e.Op)
		}
		err = e.Err
	}
	return ops
}

// Fields merges the structured context from every Error in the chain.
// Outer errors win, since they have the most specific context.
func Fields(err error) map[string]any {
	var out map[string]any
	// Collect innermost-first so that outer values overwrite inner ones.
	var chain []*Error
	for err != nil {
		var e *Error
		if !errors.As(err, &e) {
			break
		}
		chain = append(chain, e)
		err = e.Err
	}
	for i := len(chain) - 1; i >= 0; i-- {
		for k, v := range chain[i].Fields {
			if out == nil {
				out = make(map[string]any, 4)
			}
			out[k] = v
		}
	}
	return out
}

// Retryable reports whether retrying the operation could plausibly succeed.
// The harness consults this to decide whether a failed tool execution should be
// re-attempted with backoff or parked in the dead-letter queue.
func Retryable(err error) bool {
	switch KindOf(err) {
	case Timeout, Unavailable, RateLimited:
		return true
	default:
		return false
	}
}
