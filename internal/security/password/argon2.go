// Package password hashes and verifies user passwords.
//
// argon2id, not the stdlib's PBKDF2. That is a deliberate second dependency and
// the reasoning is quantitative rather than aesthetic: PBKDF2 is not
// memory-hard, so it parallelises almost perfectly onto GPUs. At equal
// wall-clock cost to the server, a leaked PBKDF2-SHA256 hash falls to offline
// attack roughly two to three orders of magnitude faster than argon2id, which
// forces each guess to allocate 19 MiB and defeats that parallelism.
//
// The people whose passwords these are can authorise the destruction of
// production infrastructure. The difference is worth one module from
// golang.org/x, maintained by the Go team.
//
// PBKDF2 remains a drop-in: [Hasher] is an interface, and crypto/pbkdf2 entered
// the standard library in Go 1.24 should the dependency ever need to go.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Hasher hashes and verifies passwords.
//
// An interface rather than package functions so the algorithm can be swapped,
// and so tests can substitute a fast stub — argon2id is deliberately slow, and
// a suite that hashes on every fixture would take minutes.
type Hasher interface {
	// Hash returns an encoded digest carrying its own parameters.
	Hash(plaintext string) (string, error)
	// Verify reports whether plaintext matches encoded. It must run in time
	// independent of how much of the digest matched.
	Verify(plaintext, encoded string) (bool, error)
	// NeedsRehash reports whether a digest was produced with weaker parameters
	// than the current policy, so it can be upgraded at next login.
	NeedsRehash(encoded string) bool
}

// Params configures argon2id.
//
// Defaults follow the OWASP Password Storage Cheat Sheet's argon2id baseline:
// m=19456 KiB (19 MiB), t=2, p=1. Memory is the parameter that matters most —
// it is what an attacker cannot trade away — so raise Memory before Time.
type Params struct {
	// Memory in KiB.
	Memory uint32
	// Time is the number of passes.
	Time uint32
	// Parallelism is the number of lanes.
	Parallelism uint8
	// SaltLength in bytes. 16 is the RFC 9106 recommendation.
	SaltLength uint32
	// KeyLength in bytes. 32 gives a 256-bit digest.
	KeyLength uint32
}

// DefaultParams is the OWASP argon2id baseline.
var DefaultParams = Params{
	Memory:      19 * 1024,
	Time:        2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// Errors returned by this package.
var (
	// ErrInvalidHash means the encoded digest is not a well-formed PHC string.
	ErrInvalidHash = errors.New("password: hash is not in the expected format")
	// ErrIncompatibleVersion means the digest was produced by a different
	// argon2 version than this build links against.
	ErrIncompatibleVersion = errors.New("password: incompatible argon2 version")
	// ErrPasswordTooLong means the input exceeds MaxPasswordLen.
	ErrPasswordTooLong = errors.New("password: exceeds the maximum length")
	// ErrPasswordTooShort means the input is below MinPasswordLen.
	ErrPasswordTooShort = errors.New("password: is too short")
)

// Length bounds.
//
// The maximum is a denial-of-service control, not a security policy: argon2
// hashes its input before the memory-hard phase, so a long password costs no
// more than a short one — but accepting a 10 MB "password" means reading and
// buffering it on every login attempt.
//
// The minimum is deliberately a length floor and nothing else. Composition
// rules ("one uppercase, one digit, one symbol") measurably reduce entropy by
// funnelling users into predictable patterns; NIST SP 800-63B recommends
// against them and recommends length instead.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 1024
)

// Argon2Hasher implements Hasher with argon2id.
type Argon2Hasher struct {
	params Params

	// decoyHash is a digest of an unguessable value, used by BurnTime to make
	// an unknown-user login cost the same as a real one. Built lazily; see
	// (*Argon2Hasher).decoy.
	decoyOnce sync.Once
	decoyHash string
}

// NewArgon2Hasher builds a hasher. Zero-valued params fall back to the defaults.
func NewArgon2Hasher(p Params) *Argon2Hasher {
	if p.Memory == 0 {
		p.Memory = DefaultParams.Memory
	}
	if p.Time == 0 {
		p.Time = DefaultParams.Time
	}
	if p.Parallelism == 0 {
		p.Parallelism = DefaultParams.Parallelism
	}
	if p.SaltLength == 0 {
		p.SaltLength = DefaultParams.SaltLength
	}
	if p.KeyLength == 0 {
		p.KeyLength = DefaultParams.KeyLength
	}
	return &Argon2Hasher{params: p}
}

var _ Hasher = (*Argon2Hasher)(nil)

// Validate checks a plaintext password against the length policy.
func Validate(plaintext string) error {
	switch {
	case len(plaintext) < MinPasswordLen:
		return fmt.Errorf("%w: must be at least %d characters", ErrPasswordTooShort, MinPasswordLen)
	case len(plaintext) > MaxPasswordLen:
		return fmt.Errorf("%w: must be at most %d characters", ErrPasswordTooLong, MaxPasswordLen)
	default:
		return nil
	}
}

// Hash derives a digest and encodes it in PHC string format.
//
// The parameters travel *with* the digest rather than living in configuration.
// That is what makes raising the cost factor safe: an old hash still carries the
// parameters it was made with, so it verifies correctly, and NeedsRehash then
// flags it for upgrade at the user's next successful login. Storing parameters
// separately would invalidate every existing password the moment they changed.
func (h *Argon2Hasher) Hash(plaintext string) (string, error) {
	const op = "password.Argon2Hasher.Hash"

	if err := Validate(plaintext); err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("%s: read salt: %w", op, err)
	}

	digest := argon2.IDKey([]byte(plaintext), salt,
		h.params.Time, h.params.Memory, h.params.Parallelism, h.params.KeyLength)

	return encode(h.params, salt, digest), nil
}

// Verify reports whether plaintext produces encoded.
//
// Two properties matter here:
//
//   - The comparison uses subtle.ConstantTimeCompare. A byte-wise comparison
//     that returns early leaks, through timing, how many leading bytes matched,
//     which turns an offline problem into an online one.
//   - It re-derives using the parameters stored *in the digest*, not the
//     hasher's current ones, so raising the cost factor does not lock out every
//     existing user.
func (h *Argon2Hasher) Verify(plaintext, encoded string) (bool, error) {
	const op = "password.Argon2Hasher.Verify"

	params, salt, want, err := decode(encoded)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	// Bound the work an attacker can request. Without this, a login attempt
	// with a 10 MB body still allocates and copies it before the length check.
	if len(plaintext) > MaxPasswordLen {
		return false, fmt.Errorf("%s: %w", op, ErrPasswordTooLong)
	}

	// len() is non-negative and `want` came from decode(), which bounds it by
	// the digest actually stored — never near uint32 overflow.
	got := argon2.IDKey([]byte(plaintext), salt,
		params.Time, params.Memory, params.Parallelism, uint32(len(want))) //nolint:gosec // bounded by the decoded digest length

	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether a digest is weaker than current policy.
func (h *Argon2Hasher) NeedsRehash(encoded string) bool {
	params, _, digest, err := decode(encoded)
	if err != nil {
		// Unparseable means it cannot be verified either; treat it as needing
		// replacement rather than silently accepting it forever.
		return true
	}
	return params.Memory < h.params.Memory ||
		params.Time < h.params.Time ||
		uint32(len(digest)) < h.params.KeyLength //nolint:gosec // digest length is bounded by decode()
}

// phcPrefix identifies the algorithm in the PHC string.
const phcPrefix = "$argon2id$"

// encode renders a digest in PHC string format:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<base64 salt>$<base64 hash>
//
// A standard, self-describing format rather than a bespoke one, so the stored
// value is intelligible to any tool that understands PHC — including whatever
// replaces this code.
func encode(p Params, salt, digest []byte) string {
	return fmt.Sprintf("%sv=%d$m=%d,t=%d,p=%d$%s$%s",
		phcPrefix, argon2.Version, p.Memory, p.Time, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest))
}

// decode parses a PHC string.
func decode(encoded string) (Params, []byte, []byte, error) {
	var p Params

	if !strings.HasPrefix(encoded, phcPrefix) {
		return p, nil, nil, ErrInvalidHash
	}

	// "$argon2id$v=19$m=...,t=...,p=...$salt$hash" splits into six parts, the
	// first empty because the string starts with a separator.
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return p, nil, nil, fmt.Errorf("%w: expected 6 fields, got %d", ErrInvalidHash, len(parts))
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, fmt.Errorf("%w: unreadable version field", ErrInvalidHash)
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("%w: digest is v%d, this build is v%d",
			ErrIncompatibleVersion, version, argon2.Version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Parallelism); err != nil {
		return p, nil, nil, fmt.Errorf("%w: unreadable parameter field", ErrInvalidHash)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, fmt.Errorf("%w: salt is not valid base64", ErrInvalidHash)
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, fmt.Errorf("%w: digest is not valid base64", ErrInvalidHash)
	}

	// Both are base64-decoded from a PHC string whose length the caller already
	// bounded; neither can approach uint32 overflow.
	p.SaltLength = uint32(len(salt))  //nolint:gosec // bounded by the decoded segment
	p.KeyLength = uint32(len(digest)) //nolint:gosec // bounded by the decoded segment
	return p, salt, digest, nil
}

// BurnTime performs a hash comparison that always fails, at the same cost as a
// real one, so an unknown-user login is indistinguishable from a wrong password.
//
// Why this is needed: when a login arrives for an address that does not exist,
// the natural implementation returns immediately. That makes the response
// measurably faster than one where a hash was actually computed — roughly 40 ms
// against under a millisecond — and that difference is a user-enumeration
// oracle. An attacker learns which addresses are registered without ever
// guessing a password, which is the reconnaissance step before a targeted
// credential-stuffing run.
//
// The decoy digest is derived from *this hasher's own parameters* rather than
// being a hardcoded constant. That distinction matters: with a fixed constant,
// an operator raising Memory to harden the real path would make every genuine
// verification more expensive while the decoy stayed cheap — silently reopening
// the oracle that the decoy exists to close. Deriving it keeps the two costs
// equal by construction.
//
// The result is deliberately discarded; callers use this for its duration.
func (h *Argon2Hasher) BurnTime(plaintext string) {
	_, _ = h.Verify(plaintext, h.decoy())
}

// decoy returns a digest of an unguessable value, computed once per hasher.
//
// Built lazily rather than in the constructor so that constructing a hasher
// stays cheap — a process that never serves a failed login for an unknown user
// never pays for it.
func (h *Argon2Hasher) decoy() string {
	h.decoyOnce.Do(func() {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			// Unreachable short of the kernel CSPRNG failing. Fall back to a
			// fixed value: a decoy nobody can match is still a decoy, and
			// failing the login path over this would be worse.
			secret = []byte("aegisops-decoy-fallback-value-32b")
		}
		salt := make([]byte, h.params.SaltLength)
		_, _ = rand.Read(salt)

		digest := argon2.IDKey(secret, salt,
			h.params.Time, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
		h.decoyHash = encode(h.params, salt, digest)
	})
	return h.decoyHash
}
