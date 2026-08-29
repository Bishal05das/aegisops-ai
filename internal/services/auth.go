// Package services holds the application use cases.
//
// Services depend on the domain and on ports, never on adapters. That is what
// makes every use case here testable with in-memory fakes and no infrastructure.
package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/security/password"
	"github.com/bishal05das/aegisops-ai/internal/security/token"
	"github.com/bishal05das/aegisops-ai/pkg/errs"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// AuthConfig configures the authentication service.
type AuthConfig struct {
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// AuthService issues and redeems credentials.
type AuthService struct {
	users    ports.UserRepository
	sessions ports.SessionRepository
	audit    ports.AuditRepository
	tx       ports.TxManager

	hasher   password.Hasher
	signer   *token.Signer
	verifier *token.Verifier

	cfg   AuthConfig
	clock shared.Clock
	log   *slog.Logger
}

// AuthDeps are the collaborators the service needs.
type AuthDeps struct {
	Users    ports.UserRepository
	Sessions ports.SessionRepository
	Audit    ports.AuditRepository
	Tx       ports.TxManager
	Hasher   password.Hasher
	Signer   *token.Signer
	Verifier *token.Verifier
	Config   AuthConfig
	Clock    shared.Clock
	Logger   *slog.Logger
}

// NewAuthService builds the service.
func NewAuthService(d AuthDeps) *AuthService {
	clock := d.Clock
	if clock == nil {
		clock = shared.SystemClock{}
	}
	log := d.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &AuthService{
		users: d.Users, sessions: d.Sessions, audit: d.Audit, tx: d.Tx,
		hasher: d.Hasher, signer: d.Signer, verifier: d.Verifier,
		cfg: d.Config, clock: clock, log: log,
	}
}

// Credentials carries the tokens issued to a client.
type Credentials struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	TokenType    string
	User         *user.User
}

// LoginRequest is one authentication attempt.
type LoginRequest struct {
	Email    string
	Password string
	// IP and UserAgent are recorded on the session for the audit trail: a
	// session appearing from a new address is what a compromise looks like.
	IP        string
	UserAgent string
	RequestID string
}

// ErrInvalidCredentials is returned for every failed login.
//
// One error for every cause — no such user, wrong password, disabled account —
// because distinguishing them tells an attacker which addresses are registered.
// The specific reason is logged server-side, where it is useful and not
// disclosed.
var ErrInvalidCredentials = errors.New(ErrInvalidCredentialsText)

// ErrInvalidCredentialsText is the exact sentence every failed login returns.
//
// Exported so tests can assert that no failure mode produces a different one —
// duplicating the literal in a test would let the two drift, and the property
// under test is precisely that they are identical.
const ErrInvalidCredentialsText = "invalid email or password"

// Login authenticates a user and issues a token pair.
//
// The security-relevant property is that every failure path costs the same. An
// unknown address burns an argon2 verification against a decoy digest, so the
// response time does not reveal whether the account exists — otherwise an
// attacker enumerates valid addresses without ever guessing a password, which is
// the reconnaissance step before targeted credential stuffing.
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*Credentials, error) {
	const op = "services.AuthService.Login"

	email := user.NormaliseEmail(req.Email)
	log := logger.FromContext(ctx)

	u, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			// Spend the same time a real verification would.
			s.burn(req.Password)
			s.recordFailure(ctx, email, req, "no such user")
			log.Warn("login failed", "reason", "unknown_user", "email", email)
			return nil, errs.E(op, errs.Unauthorized, ErrInvalidCredentials.Error()).
				WithCode("invalid_credentials")
		}
		return nil, errs.E(op, errs.Internal, "look up user", err)
	}

	ok, err := s.hasher.Verify(req.Password, string(u.PasswordHash))
	if err != nil {
		// A malformed stored hash is an operator problem, not a caller one, so
		// it logs as an error — but the caller still learns nothing.
		log.Error("stored password hash could not be verified",
			"error", err, "user_id", u.ID.String())
		s.recordFailure(ctx, email, req, "unverifiable stored hash")
		return nil, errs.E(op, errs.Unauthorized, ErrInvalidCredentials.Error()).
			WithCode("invalid_credentials")
	}
	if !ok {
		s.recordFailure(ctx, email, req, "wrong password")
		log.Warn("login failed", "reason", "wrong_password", "user_id", u.ID.String())
		return nil, errs.E(op, errs.Unauthorized, ErrInvalidCredentials.Error()).
			WithCode("invalid_credentials")
	}

	// Checked after the password, deliberately. Reporting "account disabled"
	// before verifying the password would confirm the address exists to anyone
	// who guesses it.
	if !u.Active {
		s.recordFailure(ctx, email, req, "account is disabled")
		log.Warn("login refused", "reason", "inactive_account", "user_id", u.ID.String())
		return nil, errs.E(op, errs.Unauthorized, ErrInvalidCredentials.Error()).
			WithCode("invalid_credentials")
	}

	// Transparently upgrade a digest made with weaker parameters. The plaintext
	// is in hand exactly once per login, so this is the only opportunity.
	s.rehashIfNeeded(ctx, u, req.Password)

	issued, err := s.issue(ctx, u, shared.Nil, req.IP, req.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := s.users.RecordLogin(ctx, u.ID, s.clock.Now()); err != nil {
		// Non-fatal: the login succeeded, and refusing it because a timestamp
		// did not update would be the wrong trade.
		log.Warn("failed to record login timestamp", "error", err, "user_id", u.ID.String())
	}

	s.recordAudit(ctx, auditRecord{
		actorID: u.ID, actorName: u.Email, action: "auth.login",
		outcome: harness.OutcomeExecuted, requestID: req.RequestID,
		params: map[string]any{"ip": req.IP, "user_agent": req.UserAgent},
	})
	log.Info("login succeeded", "user_id", u.ID.String(), "role", string(u.Role))

	return issued.Credentials, nil
}

// Refresh exchanges a refresh token for a new pair, rotating the old one.
//
// Rotation with reuse detection: every refresh invalidates the token presented
// and issues a new one. If a token that has already been rotated is presented
// again, either it was stolen after the legitimate client rotated it, or the
// client is racing itself. Those are indistinguishable from here and only one is
// benign, so the entire family is revoked and the user re-authenticates.
// Choosing the benign interpretation would leave a thief holding a live session.
func (s *AuthService) Refresh(ctx context.Context, plaintext, ip, userAgent, requestID string) (*Credentials, error) {
	const op = "services.AuthService.Refresh"
	log := logger.FromContext(ctx)

	rec, err := s.sessions.GetByPlaintext(ctx, plaintext)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			log.Warn("refresh failed", "reason", "unknown_token", "ip", ip)
			return nil, errs.E(op, errs.Unauthorized, "refresh token is not valid").
				WithCode("invalid_refresh_token")
		}
		return nil, errs.E(op, errs.Internal, "look up refresh token", err)
	}

	now := s.clock.Now()
	if stateErr := rec.Usable(now); stateErr != nil {
		if errors.Is(stateErr, user.ErrTokenReplayed) {
			// The important branch. Revoke everything descended from this login.
			revoked, revErr := s.sessions.RevokeFamily(ctx, rec.FamilyID,
				"a rotated refresh token was replayed", now)
			if revErr != nil {
				log.Error("failed to revoke a compromised token family",
					"error", revErr, "family_id", rec.FamilyID.String())
			}
			log.Warn("refresh token replay detected; family revoked",
				"user_id", rec.UserID.String(),
				"family_id", rec.FamilyID.String(),
				"tokens_revoked", revoked,
				"ip", ip)
			s.recordAudit(ctx, auditRecord{
				actorID: rec.UserID, actorName: "", action: "auth.token_replay_detected",
				outcome: harness.OutcomeDenied, requestID: requestID,
				reason: "a rotated refresh token was presented again; the token family was revoked",
				params: map[string]any{"ip": ip, "tokens_revoked": revoked},
			})
		}
		// Every state failure looks the same to the caller.
		return nil, errs.E(op, errs.Unauthorized, "refresh token is not valid").
			WithCode("invalid_refresh_token")
	}

	u, err := s.users.Get(ctx, rec.UserID)
	if err != nil {
		return nil, errs.E(op, errs.Unauthorized, "refresh token is not valid").
			WithCode("invalid_refresh_token")
	}
	// A user deactivated mid-session must not be able to refresh their way to a
	// fresh access token — that is the whole point of short access lifetimes.
	if !u.Active {
		_, _ = s.sessions.RevokeAllForUser(ctx, u.ID, "account deactivated", now)
		return nil, errs.E(op, errs.Unauthorized, "refresh token is not valid").
			WithCode("invalid_refresh_token")
	}

	creds, err := s.issue(ctx, u, rec.FamilyID, ip, userAgent)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Rotate last: the replacement must already exist, and Rotate fails with a
	// conflict if another request rotated the same token first.
	if err := s.sessions.Rotate(ctx, rec.ID, creds.session); err != nil {
		if errors.Is(err, shared.ErrConflict) {
			log.Warn("concurrent refresh lost the rotation race", "user_id", u.ID.String())
			return nil, errs.E(op, errs.Unauthorized, "refresh token is not valid").
				WithCode("invalid_refresh_token")
		}
		return nil, errs.E(op, errs.Internal, "rotate refresh token", err)
	}

	log.Info("refreshed session", "user_id", u.ID.String())
	return creds.Credentials, nil
}

// Logout revokes one refresh token.
//
// Access tokens are not revoked, and cannot be: they are stateless and valid
// until they expire. That is the cost of not checking the database on every
// request, and it is why the access TTL is minutes. A client that needs
// immediate revocation must also discard its access token, which every sane
// client does on logout anyway.
func (s *AuthService) Logout(ctx context.Context, plaintext, requestID string) error {
	const op = "services.AuthService.Logout"

	rec, err := s.sessions.GetByPlaintext(ctx, plaintext)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			// Idempotent: logging out with an unknown token is not an error,
			// and reporting one would tell a caller which tokens exist.
			return nil
		}
		return errs.E(op, errs.Internal, "look up refresh token", err)
	}

	if err := s.sessions.Revoke(ctx, rec.ID, "logout", s.clock.Now()); err != nil {
		return errs.E(op, errs.Internal, "revoke refresh token", err)
	}

	s.recordAudit(ctx, auditRecord{
		actorID: rec.UserID, action: "auth.logout",
		outcome: harness.OutcomeExecuted, requestID: requestID,
	})
	return nil
}

// LogoutAll revokes every session a user holds.
func (s *AuthService) LogoutAll(ctx context.Context, userID user.ID, reason, requestID string) (int64, error) {
	const op = "services.AuthService.LogoutAll"

	n, err := s.sessions.RevokeAllForUser(ctx, userID, reason, s.clock.Now())
	if err != nil {
		return 0, errs.E(op, errs.Internal, "revoke sessions", err)
	}
	s.recordAudit(ctx, auditRecord{
		actorID: userID, action: "auth.logout_all",
		outcome: harness.OutcomeExecuted, requestID: requestID,
		params: map[string]any{"sessions_revoked": n, "reason": reason},
	})
	return n, nil
}

// VerifyAccessToken checks a bearer token and returns its claims.
func (s *AuthService) VerifyAccessToken(raw string) (token.Claims, error) {
	return s.verifier.Verify(raw, token.PurposeAccess)
}

// issuedCredentials pairs the client-facing credentials with the session record
// the caller still has to persist or rotate.
type issuedCredentials struct {
	*Credentials
	session *user.RefreshToken
}

// issue mints an access/refresh pair.
//
// familyID is zero for a fresh login and inherited on refresh, which is what
// keeps a whole lineage revocable together.
func (s *AuthService) issue(ctx context.Context, u *user.User, familyID shared.ID, ip, userAgent string) (issuedCredentials, error) {
	var zero issuedCredentials

	access, claims, err := s.signer.Sign(u, token.PurposeAccess, s.cfg.AccessTTL)
	if err != nil {
		return zero, fmt.Errorf("sign access token: %w", err)
	}

	plaintext, rec, err := user.NewRefreshToken(s.clock, u.ID, familyID, s.cfg.RefreshTTL)
	if err != nil {
		return zero, fmt.Errorf("mint refresh token: %w", err)
	}
	rec.IssuedIP = ip
	rec.UserAgent = truncate(userAgent, 500)

	creds := &Credentials{
		AccessToken:  access,
		RefreshToken: plaintext,
		ExpiresAt:    claims.Expiry(),
		TokenType:    "Bearer",
		User:         u,
	}

	// On a fresh login there is nothing to rotate, so the record is stored here.
	// On refresh the caller passes it to Rotate, which must insert it and mark
	// the old one used in one transaction.
	if familyID.IsZero() {
		if err := s.sessions.Create(ctx, rec); err != nil {
			return zero, fmt.Errorf("store refresh token: %w", err)
		}
	}
	return issuedCredentials{Credentials: creds, session: rec}, nil
}

// burn spends the time a real password verification would.
func (s *AuthService) burn(plaintext string) {
	type burner interface{ BurnTime(string) }
	if b, ok := s.hasher.(burner); ok {
		b.BurnTime(plaintext)
	}
}

// rehashIfNeeded upgrades a digest made with weaker parameters.
func (s *AuthService) rehashIfNeeded(ctx context.Context, u *user.User, plaintext string) {
	if !s.hasher.NeedsRehash(string(u.PasswordHash)) {
		return
	}
	log := logger.FromContext(ctx)

	upgraded, err := s.hasher.Hash(plaintext)
	if err != nil {
		log.Warn("failed to upgrade a password hash", "error", err, "user_id", u.ID.String())
		return
	}
	u.PasswordHash = []byte(upgraded)
	u.UpdatedAt = s.clock.Now()
	if err := s.users.Update(ctx, u); err != nil {
		// Non-fatal: the user authenticated correctly, and failing their login
		// because an optimisation did not persist would be absurd.
		log.Warn("failed to persist an upgraded password hash", "error", err, "user_id", u.ID.String())
		return
	}
	log.Info("upgraded a password hash to current parameters", "user_id", u.ID.String())
}

// recordFailure writes a failed authentication to the ledger.
//
// Failures are recorded as fully as successes. A run of them from one address is
// the signal that distinguishes a forgotten password from a credential-stuffing
// campaign, and it only exists if the write is unconditional.
func (s *AuthService) recordFailure(ctx context.Context, email string, req LoginRequest, reason string) {
	s.recordAudit(ctx, auditRecord{
		actorName: email,
		action:    "auth.login",
		outcome:   harness.OutcomeDenied,
		reason:    reason,
		requestID: req.RequestID,
		params:    map[string]any{"ip": req.IP, "user_agent": req.UserAgent},
	})
}

// auditRecord is the internal shape passed to recordAudit.
type auditRecord struct {
	actorID   shared.ID
	actorName string
	action    string
	outcome   harness.Outcome
	reason    string
	requestID string
	params    map[string]any
}

// recordAudit appends to the ledger, never failing the caller.
//
// An audit write that fails must not fail the operation it describes — refusing
// a correct login because a log row would not insert is the wrong trade. It is
// logged at error level so the gap is visible.
func (s *AuthService) recordAudit(ctx context.Context, r auditRecord) {
	if s.audit == nil {
		return
	}
	entry := harness.NewAuditEntry(s.clock, "user", r.actorName, r.action, r.outcome)
	entry.ActorID = r.actorID
	entry.Reason = r.reason
	entry.RequestID = r.requestID
	entry.ResourceType = "session"
	if r.params != nil {
		entry.Params = logger.RedactMap(r.params)
	}

	if err := s.audit.Append(ctx, entry); err != nil {
		logger.FromContext(ctx).Error("failed to write an audit entry",
			"error", err, "action", r.action)
	}
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
