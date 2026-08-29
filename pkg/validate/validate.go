// Package validate checks inbound request payloads.
//
// Distinct from the domain's own validation, and both are needed. The domain
// enforces invariants an *entity* must satisfy however it was constructed —
// including from a repository read or an agent. This package enforces what a
// *request* must look like, and reports failures per-field so a client can fix
// them all in one round trip rather than discovering them one at a time.
//
// Nothing here is security by itself: rejecting a bad field does not make a good
// one safe. It bounds what reaches the layers below, so a handler never passes
// an unbounded string to a query or a negative page size to a limit.
package validate

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FieldError names one invalid field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (f FieldError) Error() string { return f.Field + " " + f.Message }

// Errors is a set of field failures.
type Errors []FieldError

// Error implements error.
func (e Errors) Error() string {
	parts := make([]string, len(e))
	for i, f := range e {
		parts[i] = f.Error()
	}
	return "validation failed: " + strings.Join(parts, "; ")
}

// Any reports whether anything failed.
func (e Errors) Any() bool { return len(e) > 0 }

// Validator accumulates field failures for one payload.
//
// Accumulating rather than returning on the first failure, for the same reason
// config does: telling a client about one bad field, then another after they fix
// it, turns one request into five.
type Validator struct {
	errs Errors
}

// New starts a validation pass.
func New() *Validator { return &Validator{} }

// Add records a failure directly.
func (v *Validator) Add(field, message string) *Validator {
	v.errs = append(v.errs, FieldError{Field: field, Message: message})
	return v
}

// Check records a failure when cond is false.
func (v *Validator) Check(cond bool, field, message string) *Validator {
	if !cond {
		return v.Add(field, message)
	}
	return v
}

// Required rejects an empty or whitespace-only value.
func (v *Validator) Required(value, field string) *Validator {
	return v.Check(strings.TrimSpace(value) != "", field, "is required")
}

// Length bounds a string by RUNE count, not bytes.
//
// The distinction is user-visible: a 40-character name in Bengali or Japanese
// can exceed 100 bytes, and a byte-based limit would reject it while accepting a
// far longer ASCII one. Storage limits are separately enforced in bytes by the
// database.
func (v *Validator) Length(value, field string, minLen, maxLen int) *Validator {
	n := utf8.RuneCountInString(value)
	switch {
	case n < minLen:
		return v.Add(field, fmt.Sprintf("must be at least %d characters", minLen))
	case n > maxLen:
		return v.Add(field, fmt.Sprintf("must be at most %d characters", maxLen))
	default:
		return v
	}
}

// MaxLength bounds a string's rune count from above only.
func (v *Validator) MaxLength(value, field string, maxLen int) *Validator {
	return v.Length(value, field, 0, maxLen)
}

// OneOf constrains a value to a set, naming the alternatives on failure.
func (v *Validator) OneOf(value, field string, allowed ...string) *Validator {
	for _, a := range allowed {
		if value == a {
			return v
		}
	}
	return v.Add(field, "must be one of: "+strings.Join(allowed, ", "))
}

// Range bounds an integer inclusively.
func (v *Validator) Range(value int, field string, low, high int) *Validator {
	return v.Check(value >= low && value <= high, field,
		fmt.Sprintf("must be between %d and %d", low, high))
}

// Email applies a deliberately shallow address check.
//
// Full RFC 5322 validation by regular expression is a well-known dead end — the
// grammar permits comments, quoted local parts and nested folding — and the only
// real proof an address works is delivering to it. This rejects the obviously
// wrong so a typo is caught at the boundary, and nothing more.
func (v *Validator) Email(value, field string) *Validator {
	value = strings.TrimSpace(value)
	if value == "" {
		return v.Add(field, "is required")
	}
	if utf8.RuneCountInString(value) > 320 {
		return v.Add(field, "is too long")
	}
	local, domain, found := strings.Cut(value, "@")
	if !found || local == "" || domain == "" {
		return v.Add(field, "must contain a local part and a domain")
	}
	if strings.Contains(domain, "@") {
		return v.Add(field, "contains more than one @")
	}
	if dot := strings.LastIndex(domain, "."); dot <= 0 || dot == len(domain)-1 {
		return v.Add(field, "domain must contain a dot")
	}
	if strings.ContainsFunc(value, unicode.IsSpace) {
		return v.Add(field, "must not contain whitespace")
	}
	return v
}

// NoControlChars rejects control characters other than tab, newline and
// carriage return.
//
// This is a log-injection and terminal-escape guard. A description containing a
// newline plus fabricated JSON can forge entries in any aggregator that parses
// line-delimited JSON, and an ANSI escape sequence can rewrite what an operator
// sees in a terminal — which matters when the text being displayed is an
// incident an agent is about to act on.
func (v *Validator) NoControlChars(value, field string) *Validator {
	for _, r := range value {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if unicode.IsControl(r) {
			return v.Add(field, "must not contain control characters")
		}
	}
	return v
}

// SingleLine rejects any line break, for fields rendered inline.
func (v *Validator) SingleLine(value, field string) *Validator {
	if strings.ContainsAny(value, "\r\n") {
		return v.Add(field, "must be a single line")
	}
	return v.NoControlChars(value, field)
}

// Err returns the accumulated failures, or nil when everything passed.
func (v *Validator) Err() error {
	if len(v.errs) == 0 {
		return nil
	}
	return v.errs
}

// Fields returns the accumulated failures for rendering into an error envelope.
func (v *Validator) Fields() Errors { return v.errs }
