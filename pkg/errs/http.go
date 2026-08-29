package errs

import (
	"context"
	"errors"
	"net/http"
)

// HTTPStatus maps a Kind to its HTTP status code.
//
// Keeping this a total function over a closed enum — rather than a lookup that
// can miss — means an unmapped error can never escape as a 200.
func (k Kind) HTTPStatus() int {
	switch k {
	case Invalid:
		return http.StatusBadRequest
	case Unauthorized:
		return http.StatusUnauthorized
	case Forbidden:
		return http.StatusForbidden
	case NotFound:
		return http.StatusNotFound
	case MethodNotAllowed:
		return http.StatusMethodNotAllowed
	case Conflict, Exists:
		return http.StatusConflict
	case RateLimited:
		return http.StatusTooManyRequests
	case Timeout:
		return http.StatusGatewayTimeout
	case Canceled:
		// 499 is nginx's non-standard "client closed request". It is not in the
		// IANA registry, but recording it distinguishes "the client hung up"
		// from "we failed", which matters when reading latency percentiles.
		return statusClientClosedRequest
	case Unavailable:
		return http.StatusServiceUnavailable
	case NotImplemented:
		return http.StatusNotImplemented
	default:
		return http.StatusInternalServerError
	}
}

// statusClientClosedRequest is nginx's 499.
const statusClientClosedRequest = 499

// StatusOf returns the HTTP status for any error.
//
// Context errors are translated explicitly because they arrive from deep inside
// the standard library without ever passing through E, and misclassifying a
// cancelled request as a 500 pollutes the error rate that pages an on-call.
func StatusOf(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	case errors.Is(err, context.Canceled):
		return statusClientClosedRequest
	default:
		return KindOf(err).HTTPStatus()
	}
}

// FromContextError converts a context error into a classified Error. Returns
// nil for any other error, so callers can use it as a first-chance conversion.
func FromContextError(op string, err error) *Error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return E(op, Timeout, "the operation exceeded its deadline", err)
	case errors.Is(err, context.Canceled):
		return E(op, Canceled, "the operation was cancelled", err)
	default:
		return nil
	}
}

// ShouldLogAsError reports whether a failure represents a server fault worth an
// error-level log line and an alert.
//
// Client mistakes — a bad payload, a missing token, a 404 — are normal traffic.
// Logging them at error level trains operators to ignore error logs, which is
// how a real fault gets missed.
func ShouldLogAsError(err error) bool {
	switch KindOf(err) {
	case Internal, Unavailable, NotImplemented:
		return true
	default:
		return errors.Is(err, context.DeadlineExceeded)
	}
}
