// Package dto holds the wire-format types of the HTTP API.
//
// They are deliberately separate from domain entities. The two shapes drift
// apart over time — a field is renamed in the domain, a legacy alias must stay
// on the wire — and conflating them makes an HTTP field name capable of forcing
// a database migration.
package dto

// ErrorResponse is the single error envelope every failing endpoint returns.
//
// A uniform shape means a client writes one error handler, not one per route.
//
//	{
//	  "error": {
//	    "code":       "incident_not_found",
//	    "message":    "the requested resource was not found",
//	    "request_id": "01JQ8XKPT4Z9F2HN6M3VB7CDEG",
//	    "details":    [{"field": "severity", "message": "must be one of: low, medium, high"}]
//	  }
//	}
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody is the payload of an ErrorResponse.
type ErrorBody struct {
	// Code is a stable machine-readable identifier. Clients branch on this,
	// never on Message, which is prose and may be reworded at any time.
	Code string `json:"code"`
	// Message is safe to display. For internal failures it is intentionally
	// generic — the detail is in the server log, keyed by RequestID.
	Message string `json:"message"`
	// RequestID correlates this response with the server-side log entry. It is
	// the single most useful field in the envelope: it turns "it broke" into a
	// one-line log query.
	RequestID string `json:"request_id,omitempty"`
	// Details carries per-field validation failures.
	Details []FieldError `json:"details,omitempty"`
}

// FieldError describes one validation failure.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// NewError builds an error envelope.
func NewError(code, message, requestID string) ErrorResponse {
	return ErrorResponse{Error: ErrorBody{
		Code:      code,
		Message:   message,
		RequestID: requestID,
	}}
}

// WithDetails attaches field-level validation failures.
func (e ErrorResponse) WithDetails(details ...FieldError) ErrorResponse {
	e.Error.Details = append(e.Error.Details, details...)
	return e
}
