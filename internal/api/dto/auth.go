package dto

import (
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/security/rbac"
	"github.com/bishal05das/aegisops-ai/pkg/validate"
)

// LoginRequest is the body of POST /api/v1/auth/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate checks the payload shape.
//
// Deliberately weak on the password: length and format rules belong at
// *registration*, not at login. Rejecting a login because the submitted password
// is 4 characters tells an attacker their guess was structurally wrong without
// costing them an attempt, and it means a user whose password predates a policy
// change can no longer sign in.
func (r LoginRequest) Validate() error {
	v := validate.New()
	v.Email(r.Email, "email")
	v.Required(r.Password, "password")
	// An upper bound only, as a denial-of-service guard: without it a login
	// body could carry megabytes that must be read before anything rejects it.
	v.MaxLength(r.Password, "password", 1024)
	return v.Err()
}

// RefreshRequest is the body of POST /api/v1/auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Validate checks the payload shape.
func (r RefreshRequest) Validate() error {
	v := validate.New()
	v.Required(r.RefreshToken, "refresh_token")
	v.MaxLength(r.RefreshToken, "refresh_token", 512)
	return v.Err()
}

// LogoutRequest is the body of POST /api/v1/auth/logout.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
	// AllSessions logs the caller out everywhere rather than just here.
	AllSessions bool `json:"all_sessions"`
}

// Validate checks the payload shape.
func (r LogoutRequest) Validate() error {
	v := validate.New()
	// A refresh token is not required when revoking every session: the caller
	// is already authenticated by their access token, and demanding the refresh
	// token would make "log me out everywhere" impossible from a client that
	// has lost it — which is exactly the situation that prompts the request.
	if !r.AllSessions {
		v.Required(r.RefreshToken, "refresh_token")
	}
	v.MaxLength(r.RefreshToken, "refresh_token", 512)
	return v.Err()
}

// TokenResponse is returned by login and refresh.
//
// Field names follow RFC 6749 (OAuth 2.0) so a standard client library can
// consume them without a custom decoder, even though this is not an OAuth flow.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	// RefreshToken is returned in the body rather than a cookie: the primary
	// clients here are the CLI and CI, which have no cookie jar. A browser
	// front-end should store it somewhere a script cannot read, which is a
	// decision for that client, not this API.
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	// ExpiresIn is seconds, per RFC 6749. ExpiresAt is the absolute time,
	// included because a client with a skewed clock can use it to detect the
	// skew rather than silently sending expired tokens.
	ExpiresIn int       `json:"expires_in"`
	ExpiresAt time.Time `json:"expires_at"`
	User      UserView  `json:"user"`
}

// UserView is a user as the API exposes them.
//
// A separate type from user.User on purpose, and the reason is structural: the
// domain entity carries PasswordHash. If handlers serialised the entity
// directly, adding a sensitive field to it would silently start leaking that
// field from every endpoint that returns a user. Mapping through a view means a
// new field is invisible until someone deliberately adds it here.
type UserView struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	Active      bool       `json:"active"`
	Permissions []string   `json:"permissions,omitempty"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// NewUserView maps a domain user onto the wire type.
//
// withPermissions expands the role into its grants, so a UI can hide actions the
// caller cannot perform instead of offering them and rendering a 403.
func NewUserView(u *user.User, withPermissions bool) UserView {
	view := UserView{
		ID:          u.ID.String(),
		Email:       u.Email,
		Name:        u.Name,
		Role:        string(u.Role),
		Active:      u.Active,
		LastLoginAt: u.LastLoginAt,
		CreatedAt:   u.CreatedAt,
	}
	if withPermissions {
		perms := rbac.Permissions(u.Role)
		view.Permissions = make([]string, len(perms))
		for i, p := range perms {
			view.Permissions[i] = string(p)
		}
	}
	return view
}

// SessionView describes one live session for GET /api/v1/auth/sessions.
//
// Carries no token material of any kind — not even a prefix. A session list
// exists so a user can spot a login they do not recognise; it does not need to
// identify the credential, and including any part of it would put token material
// in a response that a browser extension or a proxy log could capture.
type SessionView struct {
	ID        string    `json:"id"`
	IssuedIP  string    `json:"issued_ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Current marks the session making this request, so a user can tell which
	// one they would be ending.
	Current bool `json:"current"`
}

// SessionsResponse is the body of GET /api/v1/auth/sessions.
type SessionsResponse struct {
	Sessions []SessionView `json:"sessions"`
	Count    int           `json:"count"`
}
