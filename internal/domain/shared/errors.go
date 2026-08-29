package shared

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Domain-level sentinels. Adapters translate these into transport concerns —
// pkg/errs maps them to HTTP status codes — so the domain never mentions HTTP.
var (
	// ErrNotFound means the addressed entity does not exist.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists means a uniqueness constraint would be violated.
	ErrAlreadyExists = errors.New("already exists")
	// ErrConflict means the write collided with concurrent state. For entities
	// carrying a version, this is a failed optimistic-locking check.
	ErrConflict = errors.New("conflict")
	// ErrValidation means the entity violates an invariant.
	ErrValidation = errors.New("validation failed")
	// ErrForbidden means the actor may not perform this operation. The harness
	// permission engine returns this.
	ErrForbidden = errors.New("forbidden")
)

// FieldError names one invalid field and why.
type FieldError struct {
	Field   string
	Message string
}

func (f FieldError) Error() string { return f.Field + ": " + f.Message }

// ValidationError collects every invariant an entity violated.
//
// Entities validate wholesale rather than returning on the first failure, for
// the same reason config does: telling an operator about one bad field, then
// another after they fix it, is a hostile loop.
type ValidationError struct {
	Entity string
	Fields []FieldError
}

// Error implements error.
func (v *ValidationError) Error() string {
	if len(v.Fields) == 0 {
		return v.Entity + ": validation failed"
	}
	parts := make([]string, 0, len(v.Fields))
	for _, f := range v.Fields {
		parts = append(parts, f.Error())
	}
	return fmt.Sprintf("%s: %s", v.Entity, strings.Join(parts, "; "))
}

// Unwrap lets errors.Is(err, ErrValidation) succeed for any ValidationError.
func (v *ValidationError) Unwrap() error { return ErrValidation }

// Validator accumulates field errors for one entity.
type Validator struct {
	entity string
	fields []FieldError
}

// NewValidator starts validating the named entity.
func NewValidator(entity string) *Validator { return &Validator{entity: entity} }

// Check records a failure when cond is false.
func (v *Validator) Check(cond bool, field, message string) *Validator {
	if !cond {
		v.fields = append(v.fields, FieldError{Field: field, Message: message})
	}
	return v
}

// Required records a failure when a string is empty after trimming.
func (v *Validator) Required(value, field string) *Validator {
	return v.Check(strings.TrimSpace(value) != "", field, "is required")
}

// MaxLen guards against unbounded text reaching a column. Values here come from
// an LLM or an alert payload, neither of which respects a length budget.
func (v *Validator) MaxLen(value, field string, maxLen int) *Validator {
	return v.Check(len(value) <= maxLen,
		field, fmt.Sprintf("must be at most %d characters, got %d", maxLen, len(value)))
}

// InRange guards a float, used for confidence scores.
func (v *Validator) InRange(value float64, field string, low, high float64) *Validator {
	return v.Check(value >= low && value <= high,
		field, fmt.Sprintf("must be between %v and %v, got %v", low, high, value))
}

// NotZeroID records a failure when a required identifier is unset.
func (v *Validator) NotZeroID(id ID, field string) *Validator {
	return v.Check(!id.IsZero(), field, "is required")
}

// Err returns the accumulated error, or nil when everything passed.
func (v *Validator) Err() error {
	if len(v.fields) == 0 {
		return nil
	}
	return &ValidationError{Entity: v.entity, Fields: v.fields}
}

// Clock abstracts time so entity behaviour is testable without sleeping.
//
// It is a port in the hexagonal sense: the domain declares what it needs, and
// the composition root supplies a real clock. Tests supply a fixed one, which is
// what makes "resolved 4 minutes after detection" assertable.
type Clock interface {
	Now() time.Time
}

// SystemClock reads the wall clock.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// FixedClock returns a constant time. Test-only, but it lives here because the
// Clock contract does.
type FixedClock struct{ T time.Time }

// Now implements Clock.
func (f FixedClock) Now() time.Time { return f.T }
