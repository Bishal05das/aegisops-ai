package security_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/security/password"
	"github.com/bishal05das/aegisops-ai/internal/security/ratelimit"
	"github.com/bishal05das/aegisops-ai/internal/security/rbac"
	"github.com/bishal05das/aegisops-ai/internal/security/token"
)

const testSecret = "test-signing-secret-at-least-32-bytes-long"

func testUser(role user.Role) *user.User {
	return &user.User{
		ID:    shared.NewID(),
		Email: "test@example.com",
		Role:  role,
	}
}

func newSignerVerifier(t *testing.T, clock shared.Clock) (*token.Signer, *token.Verifier) {
	t.Helper()
	cfg := token.Config{Secret: testSecret, Issuer: "aegisops-test", Audience: "aegisops-test", Clock: clock}
	s, err := token.NewSigner(cfg)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	v, err := token.NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return s, v
}

// -----------------------------------------------------------------------------
// JWT — the attack vectors
// -----------------------------------------------------------------------------

func TestJWTRoundTrip(t *testing.T) {
	t.Parallel()

	clock := shared.FixedClock{T: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)}
	signer, verifier := newSignerVerifier(t, clock)
	u := testUser(user.RoleOperator)

	raw, claims, err := signer.Sign(u, token.PurposeAccess, 15*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if strings.Count(raw, ".") != 2 {
		t.Fatalf("token is not compact serialisation: %q", raw)
	}

	got, err := verifier.Verify(raw, token.PurposeAccess)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != u.ID.String() || got.Role != u.Role || got.ID != claims.ID {
		t.Errorf("claims did not round trip: %+v", got)
	}
	if uid, err := got.UserID(); err != nil || uid != u.ID {
		t.Errorf("UserID() = %v, %v", uid, err)
	}
}

// The single most important test in this package: a token declaring "none" must
// be rejected. Libraries that honoured the unsecured JWT let anyone forge any
// token by editing one header field.
func TestJWTRejectsAlgNone(t *testing.T) {
	t.Parallel()

	clock := shared.FixedClock{T: time.Now().UTC()}
	signer, verifier := newSignerVerifier(t, clock)
	raw, _, _ := signer.Sign(testUser(user.RoleViewer), token.PurposeAccess, time.Hour)

	payload := strings.Split(raw, ".")[1]

	for _, alg := range []string{"none", "None", "NONE", "nOnE"} {
		header := b64(t, `{"alg":"`+alg+`","typ":"JWT"}`)
		// The classic unsecured JWT: an empty signature segment.
		forged := header + "." + payload + "."

		if _, err := verifier.Verify(forged, token.PurposeAccess); err == nil {
			t.Fatalf("alg=%q was accepted — anyone could forge any token", alg)
		} else if !errors.Is(err, token.ErrUnsupportedAlgorithm) && !errors.Is(err, token.ErrMalformed) {
			t.Errorf("alg=%q rejected for the wrong reason: %v", alg, err)
		}
	}
}

// Algorithm confusion: a verifier that trusts the token's own `alg` can be
// tricked into verifying an asymmetric token with a symmetric key. Pinning the
// algorithm at construction removes the class entirely.
func TestJWTRejectsAlgorithmSubstitution(t *testing.T) {
	t.Parallel()

	clock := shared.FixedClock{T: time.Now().UTC()}
	signer, verifier := newSignerVerifier(t, clock)
	raw, _, _ := signer.Sign(testUser(user.RoleAdmin), token.PurposeAccess, time.Hour)

	parts := strings.Split(raw, ".")
	for _, alg := range []string{"RS256", "ES256", "HS512", "HS384", "PS256"} {
		forged := b64(t, `{"alg":"`+alg+`","typ":"JWT"}`) + "." + parts[1] + "." + parts[2]
		if _, err := verifier.Verify(forged, token.PurposeAccess); !errors.Is(err, token.ErrUnsupportedAlgorithm) {
			t.Errorf("alg=%q error = %v, want ErrUnsupportedAlgorithm", alg, err)
		}
	}
}

// Privilege escalation by editing the payload. This is what a stolen viewer
// token plus a text editor looks like.
func TestJWTRejectsTamperedClaims(t *testing.T) {
	t.Parallel()

	clock := shared.FixedClock{T: time.Now().UTC()}
	signer, verifier := newSignerVerifier(t, clock)
	raw, _, _ := signer.Sign(testUser(user.RoleViewer), token.PurposeAccess, time.Hour)

	parts := strings.Split(raw, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims["aegis_role"] != string(user.RoleViewer) {
		t.Fatalf("fixture is wrong: role is %v", claims["aegis_role"])
	}

	claims["aegis_role"] = string(user.RoleAdmin)
	forgedPayload, _ := json.Marshal(claims)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forgedPayload) + "." + parts[2]

	if _, err := verifier.Verify(forged, token.PurposeAccess); !errors.Is(err, token.ErrSignatureInvalid) {
		t.Errorf("escalated token error = %v, want ErrSignatureInvalid", err)
	}
}

func TestJWTRejectsWrongSecret(t *testing.T) {
	t.Parallel()

	clock := shared.FixedClock{T: time.Now().UTC()}
	signer, _ := newSignerVerifier(t, clock)
	raw, _, _ := signer.Sign(testUser(user.RoleAdmin), token.PurposeAccess, time.Hour)

	other, err := token.NewVerifier(token.Config{
		Secret: "a-completely-different-secret-32-bytes!!",
		Issuer: "aegisops-test", Audience: "aegisops-test", Clock: clock,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := other.Verify(raw, token.PurposeAccess); !errors.Is(err, token.ErrSignatureInvalid) {
		t.Errorf("error = %v, want ErrSignatureInvalid", err)
	}
}

// A refresh token must not work as a bearer credential, or the two lifetimes
// collapse into one and a long-lived token becomes an access token.
func TestJWTPurposeSeparation(t *testing.T) {
	t.Parallel()

	clock := shared.FixedClock{T: time.Now().UTC()}
	signer, verifier := newSignerVerifier(t, clock)
	u := testUser(user.RoleAdmin)

	refresh, _, _ := signer.Sign(u, token.PurposeRefresh, 24*time.Hour)
	if _, err := verifier.Verify(refresh, token.PurposeAccess); !errors.Is(err, token.ErrWrongPurpose) {
		t.Errorf("refresh-as-access error = %v, want ErrWrongPurpose", err)
	}

	access, _, _ := signer.Sign(u, token.PurposeAccess, time.Minute)
	if _, err := verifier.Verify(access, token.PurposeRefresh); !errors.Is(err, token.ErrWrongPurpose) {
		t.Errorf("access-as-refresh error = %v, want ErrWrongPurpose", err)
	}
}

func TestJWTExpiryAndNotBefore(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	signer, _ := newSignerVerifier(t, shared.FixedClock{T: base})
	raw, _, _ := signer.Sign(testUser(user.RoleViewer), token.PurposeAccess, 15*time.Minute)

	// Well past expiry, beyond the leeway.
	late, err := token.NewVerifier(token.Config{
		Secret: testSecret, Issuer: "aegisops-test", Audience: "aegisops-test",
		Clock: shared.FixedClock{T: base.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := late.Verify(raw, token.PurposeAccess); !errors.Is(err, token.ErrExpired) {
		t.Errorf("expired token error = %v, want ErrExpired", err)
	}

	// Just inside the leeway must still pass: a few seconds of clock skew
	// between hosts is normal and must not log everyone out.
	edge, edgeErr := token.NewVerifier(token.Config{
		Secret: testSecret, Issuer: "aegisops-test", Audience: "aegisops-test",
		Leeway: 30 * time.Second,
		Clock:  shared.FixedClock{T: base.Add(15*time.Minute + 10*time.Second)},
	})
	if edgeErr != nil {
		t.Fatal(edgeErr)
	}
	if _, err := edge.Verify(raw, token.PurposeAccess); err != nil {
		t.Errorf("token 10s past expiry with 30s leeway was rejected: %v", err)
	}
}

func TestJWTRejectsWrongIssuerAndAudience(t *testing.T) {
	t.Parallel()

	clock := shared.FixedClock{T: time.Now().UTC()}
	signer, _ := newSignerVerifier(t, clock)
	raw, _, _ := signer.Sign(testUser(user.RoleViewer), token.PurposeAccess, time.Hour)

	wrongIssuer, _ := token.NewVerifier(token.Config{
		Secret: testSecret, Issuer: "somebody-else", Audience: "aegisops-test", Clock: clock,
	})
	if _, err := wrongIssuer.Verify(raw, token.PurposeAccess); !errors.Is(err, token.ErrWrongIssuer) {
		t.Errorf("error = %v, want ErrWrongIssuer", err)
	}

	wrongAudience, _ := token.NewVerifier(token.Config{
		Secret: testSecret, Issuer: "aegisops-test", Audience: "another-service", Clock: clock,
	})
	if _, err := wrongAudience.Verify(raw, token.PurposeAccess); !errors.Is(err, token.ErrWrongAudience) {
		t.Errorf("error = %v, want ErrWrongAudience", err)
	}
}

func TestJWTRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	clock := shared.FixedClock{T: time.Now().UTC()}
	_, verifier := newSignerVerifier(t, clock)

	cases := map[string]string{
		"empty":               "",
		"no dots":             "notatoken",
		"one dot":             "header.payload",
		"four segments":       "a.b.c.d",
		"five segments (JWE)": "a.b.c.d.e",
		"empty signature":     "a.b.",
		"leading dot":         ".b.c",
		"not base64":          "!!!.###.$$$",
		"oversized":           strings.Repeat("a", 9000) + ".b.c",
	}
	for name, raw := range cases {
		if _, err := verifier.Verify(raw, token.PurposeAccess); err == nil {
			t.Errorf("%s: accepted %q", name, truncateForLog(raw))
		}
	}
}

// A token with no exp would never expire. A missing claim must not be read as
// permission.
func TestJWTRejectsMissingExpiry(t *testing.T) {
	t.Parallel()

	clock := shared.FixedClock{T: time.Now().UTC()}
	signer, verifier := newSignerVerifier(t, clock)

	// Sign a claim set with exp deliberately zeroed, so it is correctly signed
	// and still invalid — proving the check is on the claim, not the signature.
	raw, err := signer.SignClaims(token.Claims{
		Issuer: "aegisops-test", Audience: "aegisops-test",
		Subject: shared.NewID().String(), Purpose: token.PurposeAccess,
		Role: user.RoleAdmin, IssuedAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("SignClaims: %v", err)
	}
	if _, err := verifier.Verify(raw, token.PurposeAccess); !errors.Is(err, token.ErrMalformed) {
		t.Errorf("token without exp error = %v, want it refused", err)
	}
}

func TestJWTRejectsShortSecret(t *testing.T) {
	t.Parallel()

	_, err := token.NewSigner(token.Config{Secret: "too-short", Issuer: "x"})
	if err == nil {
		t.Error("a short signing secret was accepted")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("error should state the minimum: %v", err)
	}
}

func b64(t *testing.T, s string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func truncateForLog(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// -----------------------------------------------------------------------------
// Passwords
// -----------------------------------------------------------------------------

func TestPasswordHashAndVerify(t *testing.T) {
	t.Parallel()

	// Minimal cost: this test is about correctness, not about spending 40 ms.
	h := password.NewArgon2Hasher(password.Params{Memory: 8 * 1024, Time: 1})

	const plaintext = "correct-horse-battery-staple"
	encoded, err := h.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Errorf("digest is not in PHC format: %q", encoded)
	}

	ok, err := h.Verify(plaintext, encoded)
	if err != nil || !ok {
		t.Errorf("Verify(correct) = %v, %v", ok, err)
	}
	ok, err = h.Verify("wrong-password", encoded)
	if err != nil || ok {
		t.Errorf("Verify(wrong) = %v, %v", ok, err)
	}
}

// Two users with the same password must not share a digest, or one cracked hash
// reveals every account using that password.
func TestPasswordHashesAreSalted(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2Hasher(password.Params{Memory: 8 * 1024, Time: 1})
	const same = "identical-password-value"

	a, _ := h.Hash(same)
	b, _ := h.Hash(same)
	if a == b {
		t.Error("identical passwords produced identical digests; the salt is not random")
	}
	// Both must still verify.
	for i, enc := range []string{a, b} {
		if ok, _ := h.Verify(same, enc); !ok {
			t.Errorf("digest %d did not verify", i)
		}
	}
}

func TestPasswordLengthPolicy(t *testing.T) {
	t.Parallel()

	if err := password.Validate("short"); !errors.Is(err, password.ErrPasswordTooShort) {
		t.Errorf("short password error = %v", err)
	}
	if err := password.Validate(strings.Repeat("x", 2000)); !errors.Is(err, password.ErrPasswordTooLong) {
		t.Errorf("long password error = %v", err)
	}
	if err := password.Validate("a-perfectly-fine-password"); err != nil {
		t.Errorf("valid password rejected: %v", err)
	}
}

// The parameters travel with the digest, so raising the cost factor must not
// invalidate existing passwords — it must flag them for upgrade instead.
func TestPasswordRehashOnParameterIncrease(t *testing.T) {
	t.Parallel()

	weak := password.NewArgon2Hasher(password.Params{Memory: 8 * 1024, Time: 1})
	strong := password.NewArgon2Hasher(password.Params{Memory: 32 * 1024, Time: 3})

	const plaintext = "a-users-existing-password"
	old, err := weak.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	// The stronger hasher must still verify the old digest.
	if ok, err := strong.Verify(plaintext, old); err != nil || !ok {
		t.Fatalf("raising the cost factor locked out an existing user: %v, %v", ok, err)
	}
	if !strong.NeedsRehash(old) {
		t.Error("a weaker digest was not flagged for rehashing")
	}
	if weak.NeedsRehash(old) {
		t.Error("a digest at current parameters was flagged for rehashing")
	}
}

func TestPasswordRejectsCorruptDigest(t *testing.T) {
	t.Parallel()

	h := password.NewArgon2Hasher(password.Params{Memory: 8 * 1024, Time: 1})
	for _, bad := range []string{
		"", "not-a-hash", "$argon2id$", "$argon2id$v=19$m=8,t=1,p=1$notbase64!$x",
		"$bcrypt$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA",
	} {
		if _, err := h.Verify("anything", bad); err == nil {
			t.Errorf("corrupt digest %q was accepted", bad)
		}
		if !h.NeedsRehash(bad) {
			t.Errorf("corrupt digest %q was not flagged for rehashing", bad)
		}
	}
}

// -----------------------------------------------------------------------------
// RBAC
// -----------------------------------------------------------------------------

// The most important RBAC assertion: no role approves a forbidden action.
func TestRBACNobodyApprovesForbidden(t *testing.T) {
	t.Parallel()

	for _, role := range append(user.AllRoles, user.Role("superuser"), user.Role("")) {
		if rbac.CanApproveRisk(role, "forbidden") {
			t.Errorf("role %q could approve a forbidden action", role)
		}
	}
	// And it is unrepresentable, not merely unassigned: there is no permission
	// to accidentally add to the admin list while tidying the matrix.
	if _, representable := rbac.ApprovalPermissionFor("forbidden"); representable {
		t.Error("a permission exists for forbidden approvals; it must be unrepresentable")
	}
}

func TestRBACApprovalTiers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		role  user.Role
		risk  string
		allow bool
	}{
		{user.RoleViewer, "low", false},
		{user.RoleViewer, "medium", false},
		{user.RoleViewer, "high", false},
		{user.RoleOperator, "low", true},
		{user.RoleOperator, "medium", true},
		{user.RoleOperator, "high", false}, // the escalation boundary
		{user.RoleAdmin, "low", true},
		{user.RoleAdmin, "medium", true},
		{user.RoleAdmin, "high", true},
	}
	for _, tc := range tests {
		if got := rbac.CanApproveRisk(tc.role, tc.risk); got != tc.allow {
			t.Errorf("CanApproveRisk(%s, %s) = %v, want %v", tc.role, tc.risk, got, tc.allow)
		}
	}
}

func TestRBACDeniesUnknownRole(t *testing.T) {
	t.Parallel()

	// A token minted by a newer build can carry a role this one does not know,
	// and during a rolling deploy it will. It must grant nothing.
	unknown := user.Role("future_superadmin")
	for _, perm := range rbac.AllPermissions() {
		if rbac.Can(unknown, perm) {
			t.Errorf("unknown role was granted %s", perm)
		}
	}
	if len(rbac.Permissions(unknown)) != 0 {
		t.Error("unknown role reports permissions")
	}
}

func TestRBACViewerIsReadOnly(t *testing.T) {
	t.Parallel()

	// Anything that changes state must be denied to a viewer. Listed explicitly
	// rather than derived, so adding a write permission without considering the
	// viewer fails here.
	mutating := []rbac.Permission{
		rbac.PermIncidentCreate, rbac.PermIncidentUpdate, rbac.PermIncidentClose,
		rbac.PermAgentUpdate, rbac.PermAgentDisable,
		rbac.PermApproveLow, rbac.PermApproveMedium, rbac.PermApproveHigh,
		rbac.PermApprovalReject, rbac.PermPolicyWrite,
		rbac.PermUserWrite, rbac.PermUserDelete,
	}
	for _, perm := range mutating {
		if rbac.Can(user.RoleViewer, perm) {
			t.Errorf("viewer holds the mutating permission %s", perm)
		}
	}
	if !rbac.Can(user.RoleViewer, rbac.PermIncidentRead) {
		t.Error("viewer cannot read incidents, which is its entire purpose")
	}
}

func TestRBACOperatorCannotManageUsersOrPolicy(t *testing.T) {
	t.Parallel()

	// The separation that keeps an operator from granting themselves more:
	// editing users or the policy matrix is how a role becomes self-escalating.
	for _, perm := range []rbac.Permission{
		rbac.PermUserWrite, rbac.PermUserDelete, rbac.PermPolicyWrite,
	} {
		if rbac.Can(user.RoleOperator, perm) {
			t.Errorf("operator holds %s, which allows self-escalation", perm)
		}
	}
}

func TestRBACAnyAndAll(t *testing.T) {
	t.Parallel()

	if !rbac.CanAll(user.RoleAdmin, rbac.PermUserRead, rbac.PermUserWrite) {
		t.Error("admin should hold both user permissions")
	}
	if rbac.CanAll(user.RoleOperator, rbac.PermIncidentRead, rbac.PermUserWrite) {
		t.Error("CanAll returned true when one permission is missing")
	}
	if !rbac.CanAny(user.RoleOperator, rbac.PermUserWrite, rbac.PermIncidentRead) {
		t.Error("CanAny returned false when one permission is held")
	}
}

// -----------------------------------------------------------------------------
// Rate limiting
// -----------------------------------------------------------------------------

// movableClock lets a test advance time without sleeping.
type movableClock struct{ t time.Time }

func (c *movableClock) Now() time.Time          { return c.t }
func (c *movableClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func TestRateLimiterBurstThenRefill(t *testing.T) {
	t.Parallel()

	clock := &movableClock{t: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)}
	l := ratelimit.New(ratelimit.Config{Rate: 1, Burst: 3, Clock: clock})

	for i := 1; i <= 3; i++ {
		if d := l.Allow("k"); !d.Allowed {
			t.Fatalf("request %d was refused inside the burst", i)
		}
	}
	d := l.Allow("k")
	if d.Allowed {
		t.Fatal("the fourth request was allowed past a burst of 3")
	}
	if d.RetryAfter <= 0 {
		t.Error("a refusal must carry a positive Retry-After, or clients retry immediately")
	}

	// One token per second.
	clock.Advance(time.Second)
	if d := l.Allow("k"); !d.Allowed {
		t.Error("a token did not refill after one second")
	}
	if d := l.Allow("k"); d.Allowed {
		t.Error("two tokens refilled in one second at a rate of 1/s")
	}
}

// Peek exists because AllowN(key, 0) cannot fail: `tokens < 0` is never true,
// so a zero-cost call reports Allowed even on an empty bucket. That looked like
// a peek and silently disabled the login throttle.
func TestRateLimiterPeekDoesNotConsumeButCanRefuse(t *testing.T) {
	t.Parallel()

	clock := &movableClock{t: time.Now().UTC()}
	l := ratelimit.New(ratelimit.Config{Rate: 1, Burst: 2, Clock: clock})

	// Peeking repeatedly must not drain the bucket.
	for i := 0; i < 10; i++ {
		if d := l.Peek("k"); !d.Allowed {
			t.Fatalf("peek %d refused a full bucket", i)
		}
	}
	if d := l.Peek("k"); d.Remaining != 2 {
		t.Errorf("remaining = %d after 10 peeks, want 2", d.Remaining)
	}

	// Drain it, then peek must refuse.
	l.Allow("k")
	l.Allow("k")
	if d := l.Peek("k"); d.Allowed {
		t.Error("peek allowed on an empty bucket — the login throttle would never fire")
	}

	// The regression itself: a zero-cost AllowN would have said yes here.
	if d := l.AllowN("k", 0); !d.Allowed {
		t.Log("AllowN(key,0) refuses on an empty bucket")
	} else {
		t.Log("AllowN(key,0) allows on an empty bucket — which is exactly why Peek exists")
	}
}

func TestRateLimiterKeysAreIndependent(t *testing.T) {
	t.Parallel()

	clock := &movableClock{t: time.Now().UTC()}
	l := ratelimit.New(ratelimit.Config{Rate: 1, Burst: 1, Clock: clock})

	if !l.Allow("user:a").Allowed || l.Allow("user:a").Allowed {
		t.Fatal("bucket a did not behave as a burst of 1")
	}
	// Exhausting one principal must not affect another, or one busy client
	// throttles everyone behind the same NAT.
	if !l.Allow("user:b").Allowed {
		t.Error("exhausting one key refused another")
	}
}

func TestRateLimiterResetRestoresAllowance(t *testing.T) {
	t.Parallel()

	clock := &movableClock{t: time.Now().UTC()}
	l := ratelimit.New(ratelimit.Config{Rate: 1, Burst: 2, Clock: clock})

	l.Allow("k")
	l.Allow("k")
	if l.Allow("k").Allowed {
		t.Fatal("bucket was not exhausted")
	}

	// A successful login clears the failure budget.
	l.Reset("k")
	if !l.Allow("k").Allowed {
		t.Error("Reset did not restore the allowance")
	}
}

// Keying by IP means an attacker can mint a new key per request. A map that only
// grows is a memory-exhaustion vector — the limiter becoming the outage.
func TestRateLimiterEvictsIdleBuckets(t *testing.T) {
	t.Parallel()

	clock := &movableClock{t: time.Now().UTC()}
	l := ratelimit.New(ratelimit.Config{Rate: 10, Burst: 10, TTL: time.Minute, Clock: clock})

	for i := 0; i < 500; i++ {
		l.Allow("ip:" + string(rune('a'+i%26)) + itoa(i))
	}
	if l.Len() < 400 {
		t.Fatalf("only %d buckets tracked; the fixture is not exercising growth", l.Len())
	}

	// Past the TTL, and past the sweep interval so a sweep actually runs.
	clock.Advance(2 * time.Minute)
	l.Allow("trigger-the-sweep")

	if l.Len() > 5 {
		t.Errorf("%d buckets survived eviction, want them reclaimed", l.Len())
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
