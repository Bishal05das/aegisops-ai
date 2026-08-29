package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/api/dto"
	"github.com/bishal05das/aegisops-ai/internal/api/middleware"
	"github.com/bishal05das/aegisops-ai/internal/api/render"
	"github.com/bishal05das/aegisops-ai/internal/security/ratelimit"
	"github.com/bishal05das/aegisops-ai/internal/services"
	"github.com/bishal05das/aegisops-ai/pkg/errs"
	"github.com/bishal05das/aegisops-ai/pkg/httpx"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
	"github.com/bishal05das/aegisops-ai/pkg/validate"
)

// Auth serves the authentication endpoints.
type Auth struct {
	svc *services.AuthService
	// loginLimiter is separate from the global limiter and far tighter.
	// Credential guessing is a fundamentally different traffic shape from
	// ordinary API use: a handful of attempts per minute is generous for a
	// human and useless for a brute-force run.
	loginLimiter *ratelimit.Limiter
	maxBodyBytes int64
}

// AuthOption configures the handler.
type AuthOption func(*Auth)

// WithLoginLimiter sets the per-identity login throttle.
func WithLoginLimiter(l *ratelimit.Limiter) AuthOption {
	return func(a *Auth) { a.loginLimiter = l }
}

// WithMaxBodyBytes bounds request bodies.
func WithMaxBodyBytes(n int64) AuthOption {
	return func(a *Auth) { a.maxBodyBytes = n }
}

// NewAuth builds the handler.
func NewAuth(svc *services.AuthService, opts ...AuthOption) *Auth {
	a := &Auth{svc: svc, maxBodyBytes: 1 << 20}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Login handles POST /api/v1/auth/login.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Auth.Login"
	ctx := r.Context()

	var req dto.LoginRequest
	if err := httpx.Decode(w, r, &req, a.maxBodyBytes); err != nil {
		render.WriteError(w, r, err)
		return
	}
	if err := req.Validate(); err != nil {
		render.WriteError(w, r, validationError(op, err))
		return
	}

	// Throttled by email as well as by address. IP-only limiting is defeated by
	// a botnet spreading guesses for one account across many hosts — the
	// password-spraying pattern — and email-only limiting lets one attacker
	// lock out an account they do not own by exhausting its budget. Both keys
	// are checked, and the account key is only *consumed* on failure below, so
	// an attacker cannot deny service to a user who is logging in successfully.
	emailKey := "login:email:" + req.Email
	if a.loginLimiter != nil {
		// Peek, not AllowN(key, 0): a zero-cost call can never fail its own
		// budget check, so it would silently allow everything. Peek reports
		// whether one token is available without consuming it, which is what
		// lets the refusal happen before any argon2 work is done.
		if d := a.loginLimiter.Peek(emailKey); !d.Allowed {
			a.rejectRateLimited(w, r, d)
			return
		}
	}

	creds, err := a.svc.Login(ctx, services.LoginRequest{
		Email:     req.Email,
		Password:  req.Password,
		IP:        middleware.ClientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: logger.RequestID(ctx),
	})
	if err != nil {
		// Charge the account budget only for failures. A user logging in
		// correctly all day is never throttled; an attacker guessing is.
		if a.loginLimiter != nil && errs.Is(err, errs.Unauthorized) {
			a.loginLimiter.Allow(emailKey)
		}
		render.WriteError(w, r, err)
		return
	}

	// A successful login clears the account's failure budget, so a user who
	// mistyped twice before getting it right is not throttled afterwards.
	if a.loginLimiter != nil {
		a.loginLimiter.Reset(emailKey)
	}

	render.WriteJSON(w, r, http.StatusOK, tokenResponse(creds))
}

// Refresh handles POST /api/v1/auth/refresh.
//
// Unauthenticated by design: the whole point is to obtain a new access token
// when the current one has expired, so requiring a valid access token would make
// the endpoint unreachable exactly when it is needed. The refresh token is the
// credential.
func (a *Auth) Refresh(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Auth.Refresh"
	ctx := r.Context()

	var req dto.RefreshRequest
	if err := httpx.Decode(w, r, &req, a.maxBodyBytes); err != nil {
		render.WriteError(w, r, err)
		return
	}
	if err := req.Validate(); err != nil {
		render.WriteError(w, r, validationError(op, err))
		return
	}

	creds, err := a.svc.Refresh(ctx, req.RefreshToken,
		middleware.ClientIP(r), r.UserAgent(), logger.RequestID(ctx))
	if err != nil {
		render.WriteError(w, r, err)
		return
	}
	render.WriteJSON(w, r, http.StatusOK, tokenResponse(creds))
}

// Logout handles POST /api/v1/auth/logout.
//
// Requires authentication so that "log out everywhere" can be attributed, and
// so a stolen refresh token alone cannot be used to end a victim's other
// sessions — a nuisance-denial-of-service that costs an attacker nothing.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	const op = "handlers.Auth.Logout"
	ctx := r.Context()
	principal := middleware.MustPrincipal(ctx)

	var req dto.LogoutRequest
	if err := httpx.Decode(w, r, &req, a.maxBodyBytes); err != nil {
		render.WriteError(w, r, err)
		return
	}
	if err := req.Validate(); err != nil {
		render.WriteError(w, r, validationError(op, err))
		return
	}

	if req.AllSessions {
		n, err := a.svc.LogoutAll(ctx, principal.UserID,
			"user requested logout from all sessions", logger.RequestID(ctx))
		if err != nil {
			render.WriteError(w, r, err)
			return
		}
		render.WriteJSON(w, r, http.StatusOK, map[string]any{
			"logged_out":       true,
			"sessions_revoked": n,
		})
		return
	}

	if err := a.svc.Logout(ctx, req.RefreshToken, logger.RequestID(ctx)); err != nil {
		render.WriteError(w, r, err)
		return
	}
	render.WriteJSON(w, r, http.StatusOK, map[string]any{"logged_out": true})
}

// Me handles GET /api/v1/auth/me.
//
// Answers from the *token*, not the database. That is deliberate and has a
// consequence worth stating: a role changed mid-session is not reflected here
// until the access token expires. The alternative — a database read on an
// endpoint clients poll — buys freshness that the authorisation path does not
// have anyway, since every other endpoint also authorises from the token.
// Access tokens are minutes long precisely so this window stays small.
func (a *Auth) Me(w http.ResponseWriter, r *http.Request) {
	principal := middleware.MustPrincipal(r.Context())

	perms := principal.Permissions()
	out := make([]string, len(perms))
	for i, p := range perms {
		out[i] = string(p)
	}

	render.WriteJSON(w, r, http.StatusOK, map[string]any{
		"id":          principal.UserID.String(),
		"email":       principal.Email,
		"role":        string(principal.Role),
		"permissions": out,
		"token_id":    principal.TokenID,
	})
}

// tokenResponse maps service credentials onto the wire type.
func tokenResponse(c *services.Credentials) dto.TokenResponse {
	return dto.TokenResponse{
		AccessToken:  c.AccessToken,
		RefreshToken: c.RefreshToken,
		TokenType:    c.TokenType,
		ExpiresIn:    int(time.Until(c.ExpiresAt).Seconds()),
		ExpiresAt:    c.ExpiresAt,
		User:         dto.NewUserView(c.User, true),
	}
}

// rejectRateLimited renders a 429 with retry guidance.
func (a *Auth) rejectRateLimited(w http.ResponseWriter, r *http.Request, d ratelimit.Decision) {
	retryAfter := int(d.RetryAfter.Round(time.Second) / time.Second)
	if retryAfter < 1 {
		retryAfter = 1
	}
	w.Header().Set("Retry-After", itoa(retryAfter))

	logger.FromContext(r.Context()).Warn("login throttled",
		"remote_ip", middleware.ClientIP(r), "retry_after_s", retryAfter)

	render.WriteError(w, r, errs.E("handlers.Auth.Login", errs.RateLimited,
		"too many login attempts; retry in "+itoa(retryAfter)+"s").
		WithCode("login_throttled").
		WithField("retry_after_seconds", retryAfter))
}

// validationError converts field failures into the API error envelope.
//
// The per-field detail is attached under render.ValidationKey, which is the one
// error field the renderer echoes to the client — everything else in an error
// chain is log-only context that may hold internal identifiers.
func validationError(op string, err error) error {
	e := errs.E(op, errs.Invalid, "the request payload is not valid").
		WithCode("validation_failed")

	var fields validate.Errors
	if errors.As(err, &fields) {
		details := make([]dto.FieldError, len(fields))
		for i, f := range fields {
			details[i] = dto.FieldError{Field: f.Field, Message: f.Message}
		}
		e = e.WithField(render.ValidationKey, details)
	}
	return e
}

// itoa avoids importing strconv for two call sites.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
