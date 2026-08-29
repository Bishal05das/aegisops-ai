// Package rbac maps roles to permissions.
//
// Deny by default: a permission with no grant is refused, and there is no
// wildcard that grants everything. Admin is a role with a long list, not a
// bypass — which matters because the one thing nobody may do (approve a
// forbidden action) has to stay impossible for admins too.
//
// The matrix is a package-level table rather than database rows, unlike the
// harness permission matrix in Phase 6. The distinction is deliberate: harness
// permissions govern what an *AI agent* may attempt and must be editable at
// runtime as tools are added, whereas these govern what a *human role* may do
// through the API — a contract that changes only when the API does, and that
// should therefore change under code review with a deploy behind it.
package rbac

import (
	"fmt"
	"sort"

	"github.com/bishal05das/aegisops-ai/internal/domain/user"
)

// Permission names one capability.
//
// The "resource:verb" shape keeps them greppable and makes an over-broad grant
// visible at a glance in the matrix below.
type Permission string

// The permission catalogue.
const (
	// Incidents.
	PermIncidentRead   Permission = "incident:read"
	PermIncidentCreate Permission = "incident:create"
	PermIncidentUpdate Permission = "incident:update"
	PermIncidentClose  Permission = "incident:close"

	// Agents and their work.
	PermAgentRead   Permission = "agent:read"
	PermAgentUpdate Permission = "agent:update"
	// PermAgentDisable is separated from PermAgentUpdate on purpose: disabling
	// an agent is the emergency stop for a misbehaving AI, and an operator
	// needs it without also being able to rewrite an agent's configuration.
	PermAgentDisable Permission = "agent:disable"

	// Approvals. Split by risk tier so authority is granted in proportion to
	// blast radius rather than as a single "may approve" flag.
	PermApprovalRead   Permission = "approval:read"
	PermApproveLow     Permission = "approval:approve:low"
	PermApproveMedium  Permission = "approval:approve:medium"
	PermApproveHigh    Permission = "approval:approve:high"
	PermApprovalReject Permission = "approval:reject"

	// The audit ledger is read-only by construction; there is deliberately no
	// write or delete permission, because no role may amend it.
	PermAuditRead   Permission = "audit:read"
	PermAuditVerify Permission = "audit:verify"

	// Harness rules.
	PermPolicyRead  Permission = "policy:read"
	PermPolicyWrite Permission = "policy:write"

	// Users.
	PermUserRead   Permission = "user:read"
	PermUserWrite  Permission = "user:write"
	PermUserDelete Permission = "user:delete"
)

// matrix maps each role to the permissions it holds.
//
// Roles are cumulative in practice but written out in full rather than layered,
// because "operator inherits viewer" hides what an operator can actually do at
// the moment someone is auditing it. An explicit list is longer and answers the
// question directly.
var matrix = map[user.Role][]Permission{
	user.RoleViewer: {
		PermIncidentRead,
		PermAgentRead,
		PermApprovalRead,
		PermAuditRead,
		PermPolicyRead,
	},
	user.RoleOperator: {
		PermIncidentRead,
		PermIncidentCreate,
		PermIncidentUpdate,
		PermIncidentClose,
		PermAgentRead,
		PermAgentDisable, // the emergency stop, without config rewrite
		PermApprovalRead,
		PermApproveLow,
		PermApproveMedium,
		PermApprovalReject,
		PermAuditRead,
		PermPolicyRead,
	},
	user.RoleAdmin: {
		PermIncidentRead,
		PermIncidentCreate,
		PermIncidentUpdate,
		PermIncidentClose,
		PermAgentRead,
		PermAgentUpdate,
		PermAgentDisable,
		PermApprovalRead,
		PermApproveLow,
		PermApproveMedium,
		PermApproveHigh,
		PermApprovalReject,
		PermAuditRead,
		PermAuditVerify,
		PermPolicyRead,
		PermPolicyWrite,
		PermUserRead,
		PermUserWrite,
		PermUserDelete,
	},
}

// index is the matrix as sets, built once for O(1) lookup.
var index = func() map[user.Role]map[Permission]bool {
	out := make(map[user.Role]map[Permission]bool, len(matrix))
	for role, perms := range matrix {
		set := make(map[Permission]bool, len(perms))
		for _, p := range perms {
			set[p] = true
		}
		out[role] = set
	}
	return out
}()

// Can reports whether a role holds a permission.
//
// An unknown role holds nothing. That is the safe direction and it is not
// hypothetical: a token minted by a newer build could carry a role this binary
// does not know, and during a rolling deploy it will.
func Can(role user.Role, perm Permission) bool {
	perms, known := index[role]
	if !known {
		return false
	}
	return perms[perm]
}

// CanAll reports whether a role holds every listed permission.
func CanAll(role user.Role, perms ...Permission) bool {
	for _, p := range perms {
		if !Can(role, p) {
			return false
		}
	}
	return true
}

// CanAny reports whether a role holds at least one of the listed permissions.
func CanAny(role user.Role, perms ...Permission) bool {
	for _, p := range perms {
		if Can(role, p) {
			return true
		}
	}
	return false
}

// Permissions returns a role's grants, sorted, for display and for the /me
// endpoint so a UI can hide what the user cannot do.
func Permissions(role user.Role) []Permission {
	perms := matrix[role]
	out := make([]Permission, len(perms))
	copy(out, perms)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ApprovalPermissionFor returns the permission needed to approve an action at a
// given risk tier.
//
// Forbidden returns ok=false rather than a permission, because there is no
// permission that grants it — not to admin, not to anyone. Returning a
// permission nobody holds would work today but would silently start granting
// the moment someone added it to the admin list while tidying the matrix.
// Making it unrepresentable is stronger than making it unassigned.
func ApprovalPermissionFor(risk string) (Permission, bool) {
	switch risk {
	case "low":
		return PermApproveLow, true
	case "medium":
		return PermApproveMedium, true
	case "high":
		return PermApproveHigh, true
	default:
		// Covers "forbidden" and any unrecognised tier.
		return "", false
	}
}

// CanApproveRisk reports whether a role may approve an action at a risk tier.
func CanApproveRisk(role user.Role, risk string) bool {
	perm, representable := ApprovalPermissionFor(risk)
	if !representable {
		return false
	}
	return Can(role, perm)
}

// AllPermissions returns every defined permission, sorted. Used by tests to
// assert the matrix stays complete as permissions are added.
func AllPermissions() []Permission {
	seen := map[Permission]bool{}
	for _, perms := range matrix {
		for _, p := range perms {
			seen[p] = true
		}
	}
	out := make([]Permission, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Describe renders a role's grants for an operator inspecting the matrix.
func Describe(role user.Role) string {
	if _, known := index[role]; !known {
		return fmt.Sprintf("%s: unknown role, no permissions", role)
	}
	return fmt.Sprintf("%s: %d permissions: %v", role, len(matrix[role]), Permissions(role))
}
