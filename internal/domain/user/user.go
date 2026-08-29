// Package user models the humans who approve what the AI proposes.
//
// Phase 4 builds authentication on top of this; Phase 3 establishes the entity
// and its persistence so that an approval has someone to attribute.
package user

import (
	"strings"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// ID identifies a user.
type ID = shared.ID

// Role is the RBAC subject.
type Role string

// Roles, ascending in privilege.
const (
	// RoleViewer may read incidents, agents and the audit log. Nothing else.
	RoleViewer Role = "viewer"
	// RoleOperator may create incidents and approve medium-risk actions.
	RoleOperator Role = "operator"
	// RoleAdmin may additionally approve high-risk actions and edit the
	// permission and policy tables.
	RoleAdmin Role = "admin"
)

// AllRoles is the canonical list, ascending in privilege.
var AllRoles = []Role{RoleViewer, RoleOperator, RoleAdmin}

// Valid reports whether the role is defined.
func (r Role) Valid() bool {
	switch r {
	case RoleViewer, RoleOperator, RoleAdmin:
		return true
	default:
		return false
	}
}

// Rank orders roles for privilege comparison. An unknown role ranks lowest,
// which is the safe direction: a role this build does not recognise gets the
// fewest privileges rather than the most.
func (r Role) Rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

// AtLeast reports whether this role meets a required privilege level.
func (r Role) AtLeast(required Role) bool {
	return r.Rank() >= required.Rank() && r.Valid()
}

// CanApprove reports whether this role may approve an action at the given risk
// tier, expressed as a string to keep the user package independent of harness.
//
// Forbidden actions are approvable by nobody — including admins. That is the
// distinction between "requires a very senior approver" and "there is no path
// through this system", and it must not erode as roles are added.
func (r Role) CanApprove(risk string) bool {
	switch risk {
	case "forbidden":
		return false
	case "high":
		return r == RoleAdmin
	case "medium":
		return r.AtLeast(RoleOperator)
	case "low":
		return r.AtLeast(RoleOperator)
	default:
		return false
	}
}

// Field limits.
const (
	MaxEmailLen = 320 // RFC 5321 maximum
	MaxNameLen  = 200
)

// User is a human principal.
type User struct {
	ID    ID
	Email string
	Name  string
	Role  Role

	// PasswordHash is an argon2id digest, written in Phase 4. It is a []byte
	// rather than a string so it is never accidentally interpolated into a
	// format verb, and it is excluded from every DTO by construction: the API
	// layer maps User to a response type that has no such field.
	PasswordHash []byte

	Active      bool
	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// New builds a validated user. The password hash is set separately by the auth
// service, which owns the hashing parameters.
func New(clock shared.Clock, email, name string, role Role) (*User, error) {
	now := clock.Now()
	u := &User{
		ID:        shared.NewID(),
		Email:     NormaliseEmail(email),
		Name:      name,
		Role:      role,
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := u.Validate(); err != nil {
		return nil, err
	}
	return u, nil
}

// NormaliseEmail lowercases and trims, so uniqueness is case-insensitive and
// "Alice@Example.com" cannot register alongside "alice@example.com".
func NormaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Validate checks the user's invariants.
//
// Email validation is deliberately shallow — a non-empty local part, an @, and a
// dotted domain. Attempting to fully validate an address with a regex is a
// well-known dead end; the only real proof an address works is sending to it.
func (u *User) Validate() error {
	v := shared.NewValidator("user")
	v.NotZeroID(u.ID, "id")
	v.Required(u.Email, "email")
	v.MaxLen(u.Email, "email", MaxEmailLen)
	v.Check(plausibleEmail(u.Email), "email", "is not a plausible address")
	v.MaxLen(u.Name, "name", MaxNameLen)
	v.Check(u.Role.Valid(), "role", "must be one of: viewer, operator, admin")
	return v.Err()
}

func plausibleEmail(s string) bool {
	local, domain, found := strings.Cut(s, "@")
	if !found || local == "" || domain == "" {
		return false
	}
	if strings.Contains(domain, "@") || strings.ContainsAny(s, " \t\n\r") {
		return false
	}
	dot := strings.LastIndex(domain, ".")
	return dot > 0 && dot < len(domain)-1
}
