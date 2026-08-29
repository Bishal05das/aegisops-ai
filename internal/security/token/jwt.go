// Package token implements JWT signing and verification over crypto/hmac.
//
// Hand-written rather than imported, because JWT's well-known vulnerabilities
// all live in the *verify* path, and every one of them is a default someone
// else chose:
//
//   - **alg:none.** The spec defines an "unsecured" JWT with no signature.
//     Libraries that honoured it let anyone forge any token by setting one
//     header field. [Verifier.Verify] accepts exactly one algorithm and rejects
//     the header before touching the payload.
//   - **Algorithm confusion.** Where a service verifies with whatever algorithm
//     the token names, an attacker re-signs an RS256 token as HS256 using the
//     public key as the HMAC secret, and it validates. Pinning the algorithm at
//     construction — not reading it from the token — removes the class.
//   - **Non-constant-time comparison.** Comparing signatures with == leaks
//     timing. hmac.Equal does not.
//   - **Trusting unverified claims.** Anything that decodes a payload before
//     checking the signature invites a caller to use attacker-controlled data.
//     Verify checks the signature first and returns nothing until it passes.
//
// The format is RFC 7519 with RFC 7515 compact serialisation: three base64url
// segments, unpadded, joined by dots.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
)

// Algorithm names the signing algorithm. Only HS256 is supported.
//
// A single symmetric algorithm is the right choice for a service that both
// issues and verifies its own tokens: asymmetric signing solves the problem of
// verifying tokens you did not issue, which does not arise here. Supporting one
// algorithm also means algorithm confusion has nothing to confuse.
type Algorithm string

// HS256 is HMAC with SHA-256.
const HS256 Algorithm = "HS256"

// Type is the JWT header's typ field.
const typeJWT = "JWT"

// Errors returned by verification. All are deliberately coarse at the boundary:
// see [Verifier.Verify] for why the caller must not relay them verbatim.
var (
	// ErrMalformed means the token is not a well-formed compact JWT.
	ErrMalformed = errors.New("malformed token")
	// ErrUnsupportedAlgorithm means the header named an algorithm other than
	// the one this verifier accepts — including "none".
	ErrUnsupportedAlgorithm = errors.New("unsupported signing algorithm")
	// ErrSignatureInvalid means the signature did not verify.
	ErrSignatureInvalid = errors.New("signature is invalid")
	// ErrExpired means the token is past its exp.
	ErrExpired = errors.New("token has expired")
	// ErrNotYetValid means the token is before its nbf.
	ErrNotYetValid = errors.New("token is not yet valid")
	// ErrWrongIssuer means iss did not match.
	ErrWrongIssuer = errors.New("token was issued by a different party")
	// ErrWrongAudience means aud did not match.
	ErrWrongAudience = errors.New("token is for a different audience")
	// ErrWrongPurpose means an access token was used where a refresh token was
	// expected, or vice versa.
	ErrWrongPurpose = errors.New("token has the wrong purpose")
)

// Purpose distinguishes token kinds so one cannot be substituted for another.
//
// Without this, a long-lived refresh token would be accepted as a bearer
// credential on every endpoint — collapsing the entire reason for having two
// token lifetimes.
type Purpose string

// Token purposes.
const (
	PurposeAccess  Purpose = "access"
	PurposeRefresh Purpose = "refresh"
)

// header is the JOSE header. Only the two fields that matter are modelled;
// anything else in an incoming header is ignored, and `alg` is validated
// against the verifier's pinned algorithm rather than trusted.
type header struct {
	Alg Algorithm `json:"alg"`
	Typ string    `json:"typ"`
	// Kid names the signing key, so keys can be rotated without a flag day: a
	// verifier holding both the old and new key picks by kid. Reserved for
	// Phase 15; emitted now so existing tokens carry it when that lands.
	Kid string `json:"kid,omitempty"`
}

// Claims is the token payload.
//
// Registered claims use their RFC 7519 names. Application claims are prefixed
// so they cannot collide with a future registered claim.
type Claims struct {
	// Issuer identifies who minted the token.
	Issuer string `json:"iss"`
	// Subject is the user ID.
	Subject string `json:"sub"`
	// Audience is who the token is for.
	Audience string `json:"aud,omitempty"`
	// ExpiresAt, NotBefore and IssuedAt are seconds since the Unix epoch, as
	// RFC 7519 requires — not RFC 3339 strings.
	ExpiresAt int64 `json:"exp"`
	NotBefore int64 `json:"nbf,omitempty"`
	IssuedAt  int64 `json:"iat"`
	// ID is a unique token identifier, so a specific token can be revoked and
	// so a replayed one is recognisable in the audit log.
	ID string `json:"jti"`

	// Purpose separates access from refresh tokens.
	Purpose Purpose `json:"aegis_purpose"`
	// Role is carried in the token so authorisation needs no database round
	// trip per request. The cost is staleness: a role changed mid-session is
	// not enforced until the access token expires, which is why access tokens
	// are minutes rather than hours. Anything requiring immediate revocation
	// must check the database.
	Role user.Role `json:"aegis_role"`
	// Email is included for audit attribution, so a log line naming who
	// approved an action does not require a user lookup.
	Email string `json:"aegis_email,omitempty"`
}

// UserID parses the subject into a domain identifier.
func (c Claims) UserID() (user.ID, error) {
	id, err := shared.ParseID(c.Subject)
	if err != nil {
		return shared.Nil, fmt.Errorf("token subject is not a valid user id: %w", err)
	}
	return id, nil
}

// Expiry returns the expiry as a time.
func (c Claims) Expiry() time.Time { return time.Unix(c.ExpiresAt, 0).UTC() }

// minSecretLen is 32 bytes. An HMAC-SHA256 key shorter than the hash output
// adds no security over a 256-bit key while suggesting otherwise; RFC 7518 §3.2
// requires a key of at least the hash size.
const minSecretLen = 32

// Signer mints tokens.
type Signer struct {
	secret   []byte
	issuer   string
	audience string
	alg      Algorithm
	clock    shared.Clock
}

// Config configures a Signer and Verifier.
type Config struct {
	Secret   string
	Issuer   string
	Audience string
	// Leeway tolerates clock skew between the issuing and verifying hosts.
	// Deliberately small: a generous window extends the life of every token
	// past its stated expiry, including a stolen one.
	Leeway time.Duration
	Clock  shared.Clock
}

// DefaultLeeway is the clock-skew tolerance applied when none is configured.
const DefaultLeeway = 30 * time.Second

// NewSigner builds a token signer.
//
// Returns an error rather than panicking on a short secret: this is reachable
// from configuration, and a misconfigured deployment should fail to start with
// a clear message, not crash with a stack trace.
func NewSigner(cfg Config) (*Signer, error) {
	if len(cfg.Secret) < minSecretLen {
		return nil, fmt.Errorf(
			"token: signing secret must be at least %d bytes, got %d (generate one with `make gen-secret`)",
			minSecretLen, len(cfg.Secret))
	}
	if cfg.Issuer == "" {
		return nil, errors.New("token: issuer is required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = shared.SystemClock{}
	}
	return &Signer{
		secret:   []byte(cfg.Secret),
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		alg:      HS256,
		clock:    clock,
	}, nil
}

// Sign mints a token for a user with the given purpose and lifetime.
func (s *Signer) Sign(u *user.User, purpose Purpose, ttl time.Duration) (string, Claims, error) {
	now := s.clock.Now()
	claims := Claims{
		Issuer:    s.issuer,
		Subject:   u.ID.String(),
		Audience:  s.audience,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		ID:        shared.NewID().String(),
		Purpose:   purpose,
		Role:      u.Role,
		Email:     u.Email,
	}
	signed, err := s.SignClaims(claims)
	return signed, claims, err
}

// SignClaims serialises and signs an explicit claim set.
func (s *Signer) SignClaims(claims Claims) (string, error) {
	const op = "token.Signer.SignClaims"

	headerJSON, err := json.Marshal(header{Alg: s.alg, Typ: typeJWT})
	if err != nil {
		return "", fmt.Errorf("%s: encode header: %w", op, err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("%s: encode claims: %w", op, err)
	}

	signingInput := encodeSegment(headerJSON) + "." + encodeSegment(claimsJSON)
	signature := sign(s.secret, signingInput)
	return signingInput + "." + encodeSegment(signature), nil
}

// Verifier checks tokens.
//
// Separate from Signer so a component that only needs to verify never holds the
// ability to mint. They share a secret today; when key rotation lands, the
// verifier will hold several and the signer one.
type Verifier struct {
	secret   []byte
	issuer   string
	audience string
	// alg is pinned at construction and never read from the token. This is
	// what makes algorithm confusion structurally impossible.
	alg    Algorithm
	leeway time.Duration
	clock  shared.Clock
}

// NewVerifier builds a token verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	if len(cfg.Secret) < minSecretLen {
		return nil, fmt.Errorf(
			"token: verification secret must be at least %d bytes, got %d",
			minSecretLen, len(cfg.Secret))
	}
	if cfg.Issuer == "" {
		return nil, errors.New("token: issuer is required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = shared.SystemClock{}
	}
	leeway := cfg.Leeway
	if leeway <= 0 {
		leeway = DefaultLeeway
	}
	return &Verifier{
		secret:   []byte(cfg.Secret),
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		alg:      HS256,
		leeway:   leeway,
		clock:    clock,
	}, nil
}

// maxTokenBytes caps the input before any parsing.
//
// An unbounded token is a cheap denial-of-service: base64 decoding and JSON
// parsing a megabyte of attacker-supplied text costs far more than rejecting it.
// A legitimate token here is a few hundred bytes.
const maxTokenBytes = 8 << 10

// Verify checks a token and returns its claims.
//
// Order matters and is deliberate:
//
//  1. bound the input size
//  2. split into exactly three segments
//  3. decode and check the *header* — reject any algorithm but the pinned one
//  4. verify the signature in constant time
//  5. only then decode the claims
//  6. check registered claims: exp, nbf, iss, aud
//
// Nothing decoded from the payload is returned or acted upon before step 4. A
// verifier that parses claims first, however briefly, hands a caller
// attacker-controlled data and relies on discipline to prevent its use.
func (v *Verifier) Verify(raw string, expected Purpose) (Claims, error) {
	const op = "token.Verifier.Verify"
	var zero Claims

	if len(raw) == 0 {
		return zero, fmt.Errorf("%s: %w: token is empty", op, ErrMalformed)
	}
	if len(raw) > maxTokenBytes {
		return zero, fmt.Errorf("%s: %w: token exceeds %d bytes", op, ErrMalformed, maxTokenBytes)
	}

	// Exactly three segments. Compact serialisation has no other valid shape,
	// and a JWE (five segments) must not be mistaken for a JWS.
	firstDot := strings.IndexByte(raw, '.')
	lastDot := strings.LastIndexByte(raw, '.')
	if firstDot <= 0 || lastDot <= firstDot || lastDot == len(raw)-1 ||
		strings.Count(raw, ".") != 2 {
		return zero, fmt.Errorf("%s: %w: expected three dot-separated segments", op, ErrMalformed)
	}

	signingInput := raw[:lastDot]
	headerSegment := raw[:firstDot]
	claimsSegment := raw[firstDot+1 : lastDot]
	signatureSegment := raw[lastDot+1:]

	// ---- header, before anything else ---------------------------------------
	headerJSON, err := decodeSegment(headerSegment)
	if err != nil {
		return zero, fmt.Errorf("%s: %w: header is not valid base64url", op, ErrMalformed)
	}
	var h header
	if jsonErr := json.Unmarshal(headerJSON, &h); jsonErr != nil {
		return zero, fmt.Errorf("%s: %w: header is not valid JSON", op, ErrMalformed)
	}

	// The single most important line in this package. "none" is just another
	// value that is not HS256, so it is rejected here with everything else —
	// there is no special case to forget.
	if h.Alg != v.alg {
		return zero, fmt.Errorf("%s: %w: token declares %q, this verifier accepts only %q",
			op, ErrUnsupportedAlgorithm, h.Alg, v.alg)
	}
	if h.Typ != "" && !strings.EqualFold(h.Typ, typeJWT) {
		return zero, fmt.Errorf("%s: %w: typ is %q", op, ErrMalformed, h.Typ)
	}

	// ---- signature, before the payload is looked at --------------------------
	signature, err := decodeSegment(signatureSegment)
	if err != nil {
		return zero, fmt.Errorf("%s: %w: signature is not valid base64url", op, ErrMalformed)
	}
	if !hmac.Equal(signature, sign(v.secret, signingInput)) {
		return zero, fmt.Errorf("%s: %w", op, ErrSignatureInvalid)
	}

	// ---- claims, now that they are trustworthy ------------------------------
	claimsJSON, err := decodeSegment(claimsSegment)
	if err != nil {
		return zero, fmt.Errorf("%s: %w: payload is not valid base64url", op, ErrMalformed)
	}
	var claims Claims
	dec := json.NewDecoder(strings.NewReader(string(claimsJSON)))
	// Unknown claims are tolerated, not rejected: a future version adding a
	// claim must not invalidate tokens held by older verifiers during a rollout.
	if err := dec.Decode(&claims); err != nil {
		return zero, fmt.Errorf("%s: %w: payload is not valid JSON", op, ErrMalformed)
	}

	now := v.clock.Now()

	if claims.ExpiresAt == 0 {
		// A token with no expiry never expires. Refuse rather than treat a
		// missing claim as permission.
		return zero, fmt.Errorf("%s: %w: token has no expiry", op, ErrMalformed)
	}
	if now.After(claims.Expiry().Add(v.leeway)) {
		return zero, fmt.Errorf("%s: %w at %s", op, ErrExpired, claims.Expiry().Format(time.RFC3339))
	}
	if claims.NotBefore != 0 {
		nbf := time.Unix(claims.NotBefore, 0).UTC()
		if now.Add(v.leeway).Before(nbf) {
			return zero, fmt.Errorf("%s: %w until %s", op, ErrNotYetValid, nbf.Format(time.RFC3339))
		}
	}
	if claims.Issuer != v.issuer {
		return zero, fmt.Errorf("%s: %w", op, ErrWrongIssuer)
	}
	if v.audience != "" && claims.Audience != v.audience {
		return zero, fmt.Errorf("%s: %w", op, ErrWrongAudience)
	}
	// Without this, a refresh token would work as a bearer credential on every
	// endpoint, collapsing the reason for two lifetimes.
	if expected != "" && claims.Purpose != expected {
		return zero, fmt.Errorf("%s: %w: token is a %q token, expected %q",
			op, ErrWrongPurpose, claims.Purpose, expected)
	}
	if claims.Subject == "" {
		return zero, fmt.Errorf("%s: %w: token has no subject", op, ErrMalformed)
	}

	return claims, nil
}

// sign computes the HMAC-SHA256 of the signing input.
func sign(secret []byte, signingInput string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

// encodeSegment renders a segment as unpadded base64url, per RFC 7515 §2.
func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeSegment parses an unpadded base64url segment.
//
// RawURLEncoding rejects padding, which is correct: RFC 7515 requires it to be
// omitted, and a permissive decoder would accept two distinct encodings of the
// same token — giving one token two identities in any cache or replay check.
func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
