package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/bishal05das/aegisops-ai/internal/api/render"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/security/rbac"
	"github.com/bishal05das/aegisops-ai/internal/security/token"
	"github.com/bishal05das/aegisops-ai/pkg/errs"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// Principal is the authenticated caller.
//
// Built only from claims that have already passed signature verification, so
// nothing here is attacker-controlled by the time a handler reads it.
type Principal struct {
	UserID user.ID
	Email  string
	Role   user.Role
	// TokenID is the jti, carried so an action can be traced to the exact
	// credential that authorised it.
	TokenID string
}

// Can reports whether the principal holds a permission.
func (p Principal) Can(perm rbac.Permission) bool { return rbac.Can(p.Role, perm) }

// Permissions returns every grant the principal's role carries, so a client can
// hide actions it cannot perform rather than offering them and rendering a 403.
func (p Principal) Permissions() []rbac.Permission { return rbac.Permissions(p.Role) }

// ctxKeyPrincipal is unexported, so no package outside this one can forge a
// principal onto a context. That matters: if any package could write this key,
// authorisation could be bypassed by a handler that set it.
type ctxKeyPrincipal struct{}

// PrincipalFrom returns the authenticated caller, if any.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKeyPrincipal{}).(Principal)
	return p, ok
}

// MustPrincipal returns the caller, panicking if the route was not
// authenticated.
//
// The panic is deliberate and is a wiring assertion, not an input check: a
// handler calling this on a route without RequireAuth is a routing mistake that
// must fail loudly in development rather than serve unauthenticated traffic.
// Recovery converts it to a 500, so a mistake is an error page, never an
// authorisation bypass.
func MustPrincipal(ctx context.Context) Principal {
	p, ok := PrincipalFrom(ctx)
	if !ok {
		panic("middleware: MustPrincipal called on a route that is not behind RequireAuth")
	}
	return p
}

// TokenVerifier is the subset of the token package the middleware needs.
//
// An interface rather than *token.Verifier so tests can substitute one without
// a real signing key.
type TokenVerifier interface {
	Verify(raw string, expected token.Purpose) (token.Claims, error)
}

const (
	headerAuthorization = "Authorization"
	bearerPrefix        = "Bearer "
)

// RequireAuth rejects requests without a valid access token.
//
// Every failure returns the same 401 with the same body. Distinguishing
// "expired" from "malformed" from "wrong signature" would tell an attacker
// probing with forged tokens which part they got right; the specific reason is
// logged server-side where it is useful and not disclosed.
func RequireAuth(v TokenVerifier) Middleware {
	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		ctx := r.Context()
		log := logger.FromContext(ctx)

		raw, err := bearerToken(r)
		if err != nil {
			log.Debug("authentication failed", "reason", err.Error())
			render.WriteError(w, r, unauthorized("missing or malformed Authorization header"))
			return
		}

		claims, err := v.Verify(raw, token.PurposeAccess)
		if err != nil {
			// Logged with the real reason; the client is told nothing.
			log.Warn("token rejected", "error", err.Error(), "remote_ip", ClientIP(r))
			render.WriteError(w, r, unauthorized("the access token is not valid"))
			return
		}

		userID, err := claims.UserID()
		if err != nil {
			log.Warn("token carries an unusable subject", "error", err.Error())
			render.WriteError(w, r, unauthorized("the access token is not valid"))
			return
		}
		// A role this build does not recognise grants nothing (rbac.Can returns
		// false for unknown roles), but refusing outright is clearer than
		// serving a principal who can do nothing and cannot be told why.
		if !claims.Role.Valid() {
			log.Warn("token carries an unknown role", "role", string(claims.Role))
			render.WriteError(w, r, unauthorized("the access token is not valid"))
			return
		}

		principal := Principal{
			UserID:  userID,
			Email:   claims.Email,
			Role:    claims.Role,
			TokenID: claims.ID,
		}

		ctx = context.WithValue(ctx, ctxKeyPrincipal{}, principal)
		// Put the user on the logging context too, so every line beneath this
		// point is attributable without the handler threading it through.
		ctx = logger.WithUserID(ctx, userID.String())

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuth attaches a principal when a valid token is present and otherwise
// proceeds unauthenticated.
//
// For endpoints whose behaviour differs for a known caller but which do not
// require one. An invalid token is treated as absent rather than rejected: the
// route does not need authentication, so failing it would be stricter than the
// route's own contract.
func OptionalAuth(v TokenVerifier) Middleware {
	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		raw, err := bearerToken(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		claims, err := v.Verify(raw, token.PurposeAccess)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		userID, err := claims.UserID()
		if err != nil || !claims.Role.Valid() {
			next.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyPrincipal{}, Principal{
			UserID: userID, Email: claims.Email, Role: claims.Role, TokenID: claims.ID,
		})
		ctx = logger.WithUserID(ctx, userID.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission rejects a caller lacking every listed permission.
//
// Must be applied inside RequireAuth. Reaching it without a principal is a
// wiring error and returns 401 rather than proceeding — the failure mode of a
// misconfigured route must be "denied", never "allowed".
func RequirePermission(perms ...rbac.Permission) Middleware {
	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		principal, ok := PrincipalFrom(r.Context())
		if !ok {
			logger.FromContext(r.Context()).Error(
				"RequirePermission is applied to a route with no RequireAuth in front of it",
				"path", r.URL.Path)
			render.WriteError(w, r, unauthorized("authentication required"))
			return
		}

		for _, perm := range perms {
			if principal.Can(perm) {
				continue
			}
			logger.FromContext(r.Context()).Warn("authorisation denied",
				"required_permission", string(perm),
				"role", string(principal.Role),
				"path", r.URL.Path)

			// The permission IS named. Unlike authentication, where naming the
			// reason helps an attacker, an authenticated caller already knows
			// their own role — telling them which permission they lack costs
			// nothing and is the difference between a usable API and a guessing
			// game.
			render.WriteError(w, r, errs.E("middleware.RequirePermission", errs.Forbidden,
				"your role does not grant "+string(perm)).
				WithCode("permission_denied").
				WithField("required_permission", string(perm)).
				WithField("role", string(principal.Role)))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireRole rejects a caller below a minimum role.
//
// Prefer RequirePermission: a permission says what the endpoint needs, whereas a
// role says who happens to have it today. This exists for the few checks that
// are genuinely about rank rather than capability.
func RequireRole(minimum user.Role) Middleware {
	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		principal, ok := PrincipalFrom(r.Context())
		if !ok {
			render.WriteError(w, r, unauthorized("authentication required"))
			return
		}
		if !principal.Role.AtLeast(minimum) {
			render.WriteError(w, r, errs.E("middleware.RequireRole", errs.Forbidden,
				"this endpoint requires the "+string(minimum)+" role or higher").
				WithCode("insufficient_role").
				WithField("role", string(principal.Role)))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerToken extracts the credential from the Authorization header.
func bearerToken(r *http.Request) (string, error) {
	header := r.Header.Get(headerAuthorization)
	if header == "" {
		return "", errs.E("middleware.bearerToken", errs.Unauthorized, "no Authorization header")
	}
	// Case-insensitive scheme, per RFC 7235: some clients send "bearer".
	if len(header) < len(bearerPrefix) ||
		!strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return "", errs.E("middleware.bearerToken", errs.Unauthorized,
			"Authorization header is not a Bearer credential")
	}
	raw := strings.TrimSpace(header[len(bearerPrefix):])
	if raw == "" {
		return "", errs.E("middleware.bearerToken", errs.Unauthorized, "Bearer credential is empty")
	}
	return raw, nil
}

// unauthorized builds a 401 with a WWW-Authenticate-appropriate code.
func unauthorized(message string) error {
	return errs.E("middleware.auth", errs.Unauthorized, message).
		WithCode("unauthenticated")
}
