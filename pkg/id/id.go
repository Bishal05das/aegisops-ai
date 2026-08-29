// Package id generates lexicographically sortable unique identifiers.
//
// The format is ULID: a 48-bit millisecond timestamp followed by 80 bits of
// cryptographic randomness, rendered as 26 characters of Crockford base32.
//
// Sortability is the reason this exists rather than a bare random string.
// AegisOps correlates work across seven agents, an event bus and an append-only
// audit ledger; being able to order request IDs and audit entries by their
// identifier alone — without a join, and without trusting a clock column that
// may have been written by a different process — is worth the 40 lines.
//
// Crockford base32 excludes I, L, O and U, so an identifier read aloud from a
// pager or copied out of a screenshot cannot be transcribed ambiguously.
package id

import (
	"crypto/rand"
	"errors"
	"strings"
	"time"
)

// Length is the character count of an encoded identifier.
const Length = 26

// crockford is base32 with I, L, O and U removed to avoid transcription errors.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// timeChars encodes the 48-bit timestamp; randChars encodes the 80-bit suffix.
const (
	timeChars = 10
	randChars = 16
	randBytes = 10
)

// New returns a new identifier built from the current wall-clock time.
//
// It panics only if the system CSPRNG fails, which on Linux means the kernel is
// in a state where continuing would be unsafe anyway.
func New() string {
	s, err := newAt(time.Now())
	if err != nil {
		panic("id: crypto/rand unavailable: " + err.Error())
	}
	return s
}

// NewAt is New with an explicit timestamp. Tests use it to assert ordering.
func NewAt(t time.Time) (string, error) { return newAt(t) }

func newAt(t time.Time) (string, error) {
	ms := uint64(t.UnixMilli())

	entropy := make([]byte, randBytes)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}

	var b [Length]byte

	// Timestamp: 48 bits into 10 characters, most-significant first. The top
	// two bits of the 50-bit encoding space are always zero, which is what keeps
	// the encoding monotonic with time.
	for i := timeChars - 1; i >= 0; i-- {
		b[i] = crockford[ms&0x1f]
		ms >>= 5
	}

	// Randomness: 80 bits into exactly 16 characters, MSB-first across the byte
	// stream. 80 is divisible by 5, so this needs no padding.
	var acc uint16
	var bits uint8
	pos := timeChars
	for _, by := range entropy {
		acc = acc<<8 | uint16(by)
		bits += 8
		for bits >= 5 {
			bits -= 5
			b[pos] = crockford[(acc>>bits)&0x1f]
			pos++
		}
	}

	return string(b[:]), nil
}

// ErrInvalid reports an identifier that is not well-formed.
var ErrInvalid = errors.New("id: malformed identifier")

// Valid reports whether s is a well-formed identifier.
//
// Inbound X-Request-ID headers are attacker-controlled, so anything echoed into
// a log line or a response header is validated through here first. An
// unvalidated header is a log-injection vector.
func Valid(s string) bool {
	if len(s) != Length {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(crockford, upper(s[i])) < 0 {
			return false
		}
	}
	return true
}

// Time extracts the creation timestamp encoded in the identifier.
func Time(s string) (time.Time, error) {
	if !Valid(s) {
		return time.Time{}, ErrInvalid
	}
	var ms uint64
	for i := 0; i < timeChars; i++ {
		ms = ms<<5 | uint64(strings.IndexByte(crockford, upper(s[i])))
	}
	return time.UnixMilli(int64(ms)), nil
}

// upper folds an ASCII byte to uppercase so lowercase input decodes too.
func upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}
