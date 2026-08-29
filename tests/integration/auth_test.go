//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/repository/postgres"
	"github.com/bishal05das/aegisops-ai/internal/security/password"
	"github.com/bishal05das/aegisops-ai/internal/security/token"
	"github.com/bishal05das/aegisops-ai/internal/services"
)

// fastHasher keeps the suite quick. argon2id at production parameters costs
// ~40 ms per verification, and a suite that hashes on every fixture would spend
// minutes doing it. Correctness of the hashing itself is covered by unit tests.
func fastHasher() password.Hasher {
	return password.NewArgon2Hasher(password.Params{Memory: 8 * 1024, Time: 1})
}

func newAuthService(t *testing.T, db *sql.DB) (*services.AuthService, password.Hasher) {
	t.Helper()

	cfg := token.Config{
		Secret:   "integration-test-signing-secret-32b+",
		Issuer:   "aegisops-test",
		Audience: "aegisops-test",
	}
	signer, err := token.NewSigner(cfg)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := token.NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	hasher := fastHasher()
	svc := services.NewAuthService(services.AuthDeps{
		Users:    postgres.NewUserRepo(db),
		Sessions: postgres.NewSessionRepo(db),
		Audit:    postgres.NewAuditRepo(db),
		Tx:       postgres.NewTxManager(db),
		Hasher:   hasher,
		Signer:   signer,
		Verifier: verifier,
		Config: services.AuthConfig{
			AccessTTL:  15 * time.Minute,
			RefreshTTL: 24 * time.Hour,
		},
	})
	return svc, hasher
}

// seedUser creates a user with a known password and removes it afterwards.
func seedUser(t *testing.T, ctx context.Context, db *sql.DB, hasher password.Hasher, role user.Role, plaintext string) *user.User {
	t.Helper()

	email := "auth-" + shared.NewID().String() + "@example.com"
	u, err := user.New(shared.SystemClock{}, email, "Auth Test", role)
	if err != nil {
		t.Fatalf("build user: %v", err)
	}
	hashed, err := hasher.Hash(plaintext)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u.PasswordHash = []byte(hashed)

	if err := postgres.NewUserRepo(db).Create(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = db.ExecContext(c, `DELETE FROM users WHERE id = $1`, u.ID)
	})
	return u
}

const testPassword = "a-perfectly-good-test-password"

func TestLoginIssuesUsableTokens(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	svc, hasher := newAuthService(t, db)
	u := seedUser(t, ctx, db, hasher, user.RoleOperator, testPassword)

	creds, err := svc.Login(ctx, services.LoginRequest{
		Email: u.Email, Password: testPassword, IP: "203.0.113.10", UserAgent: "go-test",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if creds.AccessToken == "" || creds.RefreshToken == "" {
		t.Fatal("login returned an empty token")
	}
	if creds.AccessToken == creds.RefreshToken {
		t.Error("access and refresh tokens are identical")
	}

	claims, err := svc.VerifyAccessToken(creds.AccessToken)
	if err != nil {
		t.Fatalf("the issued access token does not verify: %v", err)
	}
	if claims.Role != user.RoleOperator {
		t.Errorf("role = %q, want operator", claims.Role)
	}
	if id, err := claims.UserID(); err != nil || id != u.ID {
		t.Errorf("subject = %v, want %v", id, u.ID)
	}
}

// Every failure mode must be indistinguishable to the caller, or the API becomes
// an oracle for which addresses are registered.
func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	svc, hasher := newAuthService(t, db)

	active := seedUser(t, ctx, db, hasher, user.RoleViewer, testPassword)

	disabled := seedUser(t, ctx, db, hasher, user.RoleViewer, testPassword)
	disabled.Active = false
	if err := postgres.NewUserRepo(db).Update(ctx, disabled); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	cases := map[string]services.LoginRequest{
		"unknown address":  {Email: "nobody-" + shared.NewID().String() + "@example.com", Password: testPassword},
		"wrong password":   {Email: active.Email, Password: "definitely-not-the-password"},
		"disabled account": {Email: disabled.Email, Password: testPassword},
	}

	var messages []string
	for name, req := range cases {
		_, err := svc.Login(ctx, req)
		if err == nil {
			t.Fatalf("%s: login succeeded", name)
		}
		messages = append(messages, err.Error())
	}

	// The wrapped operation differs, but the client-facing text must not. Assert
	// on the message the caller actually sees.
	for i := 1; i < len(messages); i++ {
		if extractPublic(messages[0]) != extractPublic(messages[i]) {
			t.Errorf("failure messages differ between causes:\n  %q\n  %q",
				messages[0], messages[i])
		}
	}
}

// extractPublic pulls the client-facing sentence out of a wrapped error.
func extractPublic(msg string) string {
	const marker = services.ErrInvalidCredentialsText
	if idx := indexOf(msg, marker); idx >= 0 {
		return marker
	}
	return msg
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// The core session-security property.
func TestRefreshRotatesAndDetectsReplay(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	svc, hasher := newAuthService(t, db)
	u := seedUser(t, ctx, db, hasher, user.RoleOperator, testPassword)

	first, err := svc.Login(ctx, services.LoginRequest{Email: u.Email, Password: testPassword})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	r1 := first.RefreshToken

	second, err := svc.Refresh(ctx, r1, "203.0.113.10", "go-test", "req-1")
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	r2 := second.RefreshToken
	if r1 == r2 {
		t.Fatal("refresh returned the same token; rotation is not happening")
	}

	third, err := svc.Refresh(ctx, r2, "203.0.113.10", "go-test", "req-2")
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	r3 := third.RefreshToken

	// The attack: R1 was captured before rotation and is presented now.
	if _, err := svc.Refresh(ctx, r1, "198.51.100.7", "attacker", "req-3"); err == nil {
		t.Fatal("a replayed refresh token was accepted")
	}

	// The whole family must be dead, including the legitimate client's R3.
	// Losing the honest session is the correct trade: a live token is known to
	// be in someone else's hands, and there is no way to tell which holder is
	// which.
	if _, err := svc.Refresh(ctx, r3, "203.0.113.10", "go-test", "req-4"); err == nil {
		t.Error("the token family survived a detected replay")
	}
}

// Two clients refreshing the same token concurrently must not both succeed, or
// rotation is decorative and two live lineages exist from one credential.
func TestConcurrentRefreshHasExactlyOneWinner(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	svc, hasher := newAuthService(t, db)
	u := seedUser(t, ctx, db, hasher, user.RoleOperator, testPassword)

	creds, err := svc.Login(ctx, services.LoginRequest{Email: u.Email, Password: testPassword})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	const racers = 6
	results := make(chan error, racers)
	for i := 0; i < racers; i++ {
		go func() {
			_, err := svc.Refresh(ctx, creds.RefreshToken, "203.0.113.10", "go-test", "race")
			results <- err
		}()
	}

	var succeeded, failed int
	for i := 0; i < racers; i++ {
		if err := <-results; err == nil {
			succeeded++
		} else {
			failed++
		}
	}

	if succeeded != 1 {
		t.Errorf("%d of %d concurrent refreshes succeeded, want exactly 1", succeeded, racers)
	}
	t.Logf("%d succeeded, %d correctly refused", succeeded, failed)
}

// A user deactivated mid-session must not refresh their way to a fresh access
// token — that is the entire point of a short access lifetime.
func TestDeactivatedUserCannotRefresh(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	svc, hasher := newAuthService(t, db)
	u := seedUser(t, ctx, db, hasher, user.RoleOperator, testPassword)

	creds, err := svc.Login(ctx, services.LoginRequest{Email: u.Email, Password: testPassword})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	u.Active = false
	if err := postgres.NewUserRepo(db).Update(ctx, u); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	if _, err := svc.Refresh(ctx, creds.RefreshToken, "203.0.113.10", "go-test", "req"); err == nil {
		t.Error("a deactivated user refreshed their session")
	}
}

func TestLogoutRevokesTheToken(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	svc, hasher := newAuthService(t, db)
	u := seedUser(t, ctx, db, hasher, user.RoleViewer, testPassword)

	creds, err := svc.Login(ctx, services.LoginRequest{Email: u.Email, Password: testPassword})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := svc.Logout(ctx, creds.RefreshToken, "req"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := svc.Refresh(ctx, creds.RefreshToken, "", "", "req"); err == nil {
		t.Error("a revoked token still refreshed")
	}

	// Idempotent: logging out twice is not an error, and an unknown token must
	// not reveal that it is unknown.
	if err := svc.Logout(ctx, creds.RefreshToken, "req"); err != nil {
		t.Errorf("second logout returned %v, want nil", err)
	}
	if err := svc.Logout(ctx, "a-token-that-never-existed", "req"); err != nil {
		t.Errorf("logout with an unknown token returned %v, want nil", err)
	}
}

func TestLogoutAllEndsEverySession(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	svc, hasher := newAuthService(t, db)
	u := seedUser(t, ctx, db, hasher, user.RoleOperator, testPassword)

	var tokens []string
	for i := 0; i < 3; i++ {
		creds, err := svc.Login(ctx, services.LoginRequest{Email: u.Email, Password: testPassword})
		if err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
		tokens = append(tokens, creds.RefreshToken)
	}

	n, err := svc.LogoutAll(ctx, u.ID, "test", "req")
	if err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	if n < 3 {
		t.Errorf("revoked %d sessions, want at least 3", n)
	}
	for i, tok := range tokens {
		if _, err := svc.Refresh(ctx, tok, "", "", "req"); err == nil {
			t.Errorf("session %d survived logout-all", i)
		}
	}
}

// The login path must record failures as fully as successes: a run of them from
// one address distinguishes a forgotten password from a credential-stuffing run,
// and that signal only exists if the write is unconditional.
func TestFailedLoginIsAudited(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	svc, hasher := newAuthService(t, db)
	u := seedUser(t, ctx, db, hasher, user.RoleViewer, testPassword)

	audits := postgres.NewAuditRepo(db)
	before, err := audits.LatestSeq(ctx)
	if err != nil {
		t.Fatalf("LatestSeq: %v", err)
	}

	if _, err := svc.Login(ctx, services.LoginRequest{
		Email: u.Email, Password: "wrong", IP: "198.51.100.9",
	}); err == nil {
		t.Fatal("login with a wrong password succeeded")
	}

	after, err := audits.LatestSeq(ctx)
	if err != nil {
		t.Fatalf("LatestSeq: %v", err)
	}
	if after <= before {
		t.Fatal("a failed login wrote nothing to the audit ledger")
	}

	page, err := audits.List(ctx, ports.AuditFilter{Action: "auth.login"}, ports.Page{Limit: 5})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var foundDenied bool
	for _, e := range page.Items {
		if e.Outcome == "denied" {
			foundDenied = true
			break
		}
	}
	if !foundDenied {
		t.Error("no denied auth.login entry in the ledger")
	}
}

// A weaker digest must be transparently upgraded at next login, and the upgrade
// must not break the login it happens during.
func TestPasswordHashUpgradedOnLogin(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)

	weak := password.NewArgon2Hasher(password.Params{Memory: 8 * 1024, Time: 1})
	u := seedUser(t, ctx, db, weak, user.RoleViewer, testPassword)
	original := string(u.PasswordHash)

	// A service configured with stronger parameters.
	cfg := token.Config{Secret: "integration-test-signing-secret-32b+", Issuer: "aegisops-test"}
	signer, _ := token.NewSigner(cfg)
	verifier, _ := token.NewVerifier(cfg)
	strong := password.NewArgon2Hasher(password.Params{Memory: 16 * 1024, Time: 2})

	svc := services.NewAuthService(services.AuthDeps{
		Users:    postgres.NewUserRepo(db),
		Sessions: postgres.NewSessionRepo(db),
		Audit:    postgres.NewAuditRepo(db),
		Hasher:   strong, Signer: signer, Verifier: verifier,
		Config: services.AuthConfig{AccessTTL: time.Minute, RefreshTTL: time.Hour},
	})

	if _, err := svc.Login(ctx, services.LoginRequest{Email: u.Email, Password: testPassword}); err != nil {
		t.Fatalf("login with a weak digest failed: %v", err)
	}

	reloaded, err := postgres.NewUserRepo(db).Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(reloaded.PasswordHash) == original {
		t.Error("the weak digest was not upgraded on login")
	}
	// And the upgraded digest must still verify the same password.
	if ok, err := strong.Verify(testPassword, string(reloaded.PasswordHash)); err != nil || !ok {
		t.Errorf("the upgraded digest does not verify: %v, %v", ok, err)
	}
}

func TestSessionRepositoryRevokeFamily(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	sessions := postgres.NewSessionRepo(db)
	hasher := fastHasher()
	u := seedUser(t, ctx, db, hasher, user.RoleViewer, testPassword)

	family := shared.NewID()
	for i := 0; i < 3; i++ {
		_, rec, err := user.NewRefreshToken(shared.SystemClock{}, u.ID, family, time.Hour)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if err := sessions.Create(ctx, rec); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	n, err := sessions.RevokeFamily(ctx, family, "test revocation", time.Now().UTC())
	if err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if n != 3 {
		t.Errorf("revoked %d tokens, want 3", n)
	}

	live, err := sessions.ListForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("%d sessions still live after revoking the family", len(live))
	}
}

func TestRefreshTokenNotFoundIsOpaque(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)

	_, err := postgres.NewSessionRepo(db).GetByPlaintext(ctx, "a-token-that-was-never-issued")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	// The error must not echo the presented value back into a log line.
	if indexOf(err.Error(), "a-token-that-was-never-issued") >= 0 {
		t.Errorf("the error echoed the token: %v", err)
	}
}
