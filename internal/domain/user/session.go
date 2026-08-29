package user

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// RefreshTokenBytes is the entropy of an opaque refresh token.
//
// 32 bytes is 256 bits — beyond any brute-force reach, and matching the SHA-256
// digest width so the hash neither wastes nor truncates entropy.
const RefreshTokenBytes = 32

// RefreshToken is a stored, hashed refresh credential.
//
// The plaintext exists only twice: once in the response that issues it, and once
// in the request that redeems it. Nothing persists it, and there is deliberately
// no field to hold it — a struct with a plaintext field eventually gets logged.
type RefreshToken struct {
	ID     shared.ID
	UserID ID

	// TokenHash is SHA-256 of the opaque token.
	TokenHash []byte

	// FamilyID groups every token descended from one login, so a detected
	// replay can revoke the whole lineage rather than one link of it.
	FamilyID shared.ID

	RotatedTo *shared.ID
	RotatedAt *time.Time

	RevokedAt     *time.Time
	RevokedReason string

	IssuedIP  string
	UserAgent string

	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewRefreshToken mints a token, returning the plaintext to hand to the client
// and the record to persist.
//
// The plaintext is returned separately and never stored on the struct, so there
// is no path by which persisting the record could persist the secret.
func NewRefreshToken(clock shared.Clock, userID ID, familyID shared.ID, ttl time.Duration) (plaintext string, rec *RefreshToken, err error) {
	raw := make([]byte, RefreshTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("user: generate refresh token: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(raw)

	if familyID.IsZero() {
		familyID = shared.NewID()
	}
	now := clock.Now()

	return plaintext, &RefreshToken{
		ID:        shared.NewID(),
		UserID:    userID,
		TokenHash: HashRefreshToken(plaintext),
		FamilyID:  familyID,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}, nil
}

// HashRefreshToken derives the stored digest.
//
// A bare SHA-256, not argon2. The input is a 256-bit random value, so there is
// no dictionary to defend against and nothing for a memory-hard function to
// slow down that matters; using one would only make every refresh cost 40 ms of
// CPU for no security gain — a self-inflicted denial of service.
func HashRefreshToken(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

// MatchesHash compares a plaintext against a stored digest in constant time.
//
// The lookup is by hash and therefore already exact, so this is belt and braces
// — but a comparison that short-circuits is never the right one to leave in an
// authentication path where the next change might make it load-bearing.
func MatchesHash(plaintext string, stored []byte) bool {
	got := HashRefreshToken(plaintext)
	return subtle.ConstantTimeCompare(got, stored) == 1
}

// Refresh-token state errors.
var (
	// ErrTokenExpired means the token is past its expiry.
	ErrTokenExpired = errors.New("refresh token has expired")
	// ErrTokenRevoked means the token was explicitly revoked.
	ErrTokenRevoked = errors.New("refresh token has been revoked")
	// ErrTokenReplayed means an already-rotated token was presented again.
	// This is treated as a compromise, not a mistake — see Usable.
	ErrTokenReplayed = errors.New("refresh token was already used")
)

// Usable reports whether the token may be redeemed, or why not.
//
// The ordering matters. Replay is checked before expiry so that a stolen token
// replayed after it expired is still reported as a replay: the caller escalates
// on replay by revoking the family, and an "expired" answer would let a real
// compromise pass as routine.
func (t *RefreshToken) Usable(now time.Time) error {
	switch {
	case t.RotatedAt != nil:
		return ErrTokenReplayed
	case t.RevokedAt != nil:
		return fmt.Errorf("%w: %s", ErrTokenRevoked, t.RevokedReason)
	case now.After(t.ExpiresAt):
		return ErrTokenExpired
	default:
		return nil
	}
}

// Validate checks the record's invariants.
func (t *RefreshToken) Validate() error {
	v := shared.NewValidator("refresh_token")
	v.NotZeroID(t.ID, "id")
	v.NotZeroID(t.UserID, "user_id")
	v.NotZeroID(t.FamilyID, "family_id")
	v.Check(len(t.TokenHash) == sha256.Size, "token_hash",
		fmt.Sprintf("must be %d bytes", sha256.Size))
	v.Check(t.ExpiresAt.After(t.CreatedAt), "expires_at", "must be after created_at")
	// Both rotation columns must move together, or "has this been rotated?"
	// has two answers depending which is consulted.
	v.Check((t.RotatedTo == nil) == (t.RotatedAt == nil), "rotated_to",
		"rotated_to and rotated_at must be set together")
	return v.Err()
}
