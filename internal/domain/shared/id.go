// Package shared holds the value objects and errors every other domain package
// depends on.
//
// Like the rest of internal/domain it imports nothing outside the standard
// library — no driver, no HTTP, no logger. That constraint is what keeps the
// core testable without infrastructure and is enforced by an import-graph test.
package shared

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ID is a UUIDv4 identifier for a persisted entity.
//
// Two reasons this is a distinct type rather than a bare string:
//
//   - **Type safety at the boundary.** Passing an AgentID where an IncidentID
//     is expected becomes a compile error once the aliases below are used, which
//     matters in a system that threads four different identifiers through every
//     call.
//   - **Validation happens once.** Parse rejects malformed input at the edge, so
//     nothing downstream re-checks, and a malformed ID can never reach a query.
//
// Postgres generates these with gen_random_uuid() for rows it creates, but the
// application generates them too: knowing an entity's ID *before* inserting lets
// a service build a whole object graph — an incident, its first event, its audit
// entry — and commit it in one transaction.
type ID [16]byte

// Nil is the zero identifier. It is never valid for a persisted entity.
var Nil ID

// NewID returns a random UUIDv4.
//
// It panics only if the system CSPRNG fails, which on Linux means the machine is
// in a state where continuing would be unsafe regardless.
func NewID() ID {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		panic("shared: crypto/rand unavailable: " + err.Error())
	}
	// RFC 4122 §4.4: set version to 4 and the variant to RFC 4122.
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

// ErrInvalidID reports a malformed identifier.
var ErrInvalidID = errors.New("invalid identifier")

// ParseID decodes the canonical 8-4-4-4-12 hyphenated form, and also accepts the
// unhyphenated 32-character form that some clients send.
func ParseID(s string) (ID, error) {
	var id ID

	switch len(s) {
	case 36:
		if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return Nil, fmt.Errorf("%w: %q is not a hyphenated UUID", ErrInvalidID, s)
		}
		s = s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	case 32:
		// Accepted as-is.
	default:
		return Nil, fmt.Errorf("%w: %q has length %d, want 32 or 36", ErrInvalidID, s, len(s))
	}

	if _, err := hex.Decode(id[:], []byte(strings.ToLower(s))); err != nil {
		return Nil, fmt.Errorf("%w: %q is not hexadecimal", ErrInvalidID, s)
	}
	return id, nil
}

// MustParseID is ParseID for compile-time constants and test fixtures.
func MustParseID(s string) ID {
	id, err := ParseID(s)
	if err != nil {
		panic(err)
	}
	return id
}

// IsZero reports whether the identifier is unset.
func (id ID) IsZero() bool { return id == Nil }

// String renders the canonical hyphenated form.
func (id ID) String() string {
	var b [36]byte
	hex.Encode(b[0:8], id[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], id[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], id[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], id[8:10])
	b[23] = '-'
	hex.Encode(b[24:36], id[10:16])
	return string(b[:])
}

// MarshalText implements encoding.TextMarshaler, which also covers JSON.
func (id ID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *ID) UnmarshalText(b []byte) error {
	parsed, err := ParseID(string(b))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// Value implements driver.Valuer so an ID can be passed straight to a query.
//
// The string form is used rather than the raw bytes: it is what Postgres's uuid
// type accepts unambiguously, and it keeps query logs readable.
func (id ID) Value() (driver.Value, error) {
	if id.IsZero() {
		return nil, nil
	}
	return id.String(), nil
}

// Scan implements sql.Scanner, accepting the text and 16-byte binary forms a
// driver may return.
func (id *ID) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*id = Nil
		return nil
	case string:
		parsed, err := ParseID(v)
		if err != nil {
			return err
		}
		*id = parsed
		return nil
	case []byte:
		if len(v) == 16 {
			copy(id[:], v)
			return nil
		}
		parsed, err := ParseID(string(v))
		if err != nil {
			return err
		}
		*id = parsed
		return nil
	case [16]byte:
		*id = v
		return nil
	default:
		return fmt.Errorf("%w: cannot scan %T into ID", ErrInvalidID, src)
	}
}
