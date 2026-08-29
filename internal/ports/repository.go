// Package ports declares the interfaces the application core requires of the
// outside world.
//
// This is the inward-facing half of the hexagon. Services depend on these
// interfaces; adapters in internal/repository, internal/events and internal/llm
// implement them. Composition happens once, in cmd/aegisopsd.
//
// The practical payoff is that every use case is testable against an in-memory
// implementation with no database, no broker and no model — which is what makes
// the Phase 12 end-to-end scenarios feasible at all.
package ports

import (
	"context"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
)

// Page describes a slice of a result set.
//
// Keyset pagination, not OFFSET. The audit log and incident list grow without
// bound, and OFFSET makes the database walk and discard every skipped row, so
// page 10,000 costs 10,000 times page 1. A cursor is O(1) regardless of depth
// and, unlike OFFSET, does not skip or duplicate rows when the set changes
// underneath a paging client — which it constantly does here, since incidents
// arrive while an operator is reading.
type Page struct {
	Limit  int
	Cursor string
}

// DefaultPageLimit and MaxPageLimit bound result sizes.
const (
	DefaultPageLimit = 50
	MaxPageLimit     = 500
)

// Normalise clamps the page into range, so a caller passing 0 or 100000 gets
// something sane rather than an error or a table scan.
func (p Page) Normalise() Page {
	if p.Limit <= 0 {
		p.Limit = DefaultPageLimit
	}
	if p.Limit > MaxPageLimit {
		p.Limit = MaxPageLimit
	}
	return p
}

// PageResult carries a page of results and the cursor for the next one.
type PageResult[T any] struct {
	Items      []T
	NextCursor string
	HasMore    bool
}

// IncidentFilter narrows an incident query. Zero-valued fields are ignored, so
// the zero filter means "everything".
type IncidentFilter struct {
	Statuses    []incident.Status
	Severities  []incident.Severity
	Service     string
	Environment string
	Source      incident.Source
	// ActiveOnly restricts to incidents agents should still be working.
	ActiveOnly bool
	Since      *time.Time
	Until      *time.Time
	// Search matches the title and description using a trigram index.
	Search string
}

// IncidentRepository persists incidents and their timelines.
type IncidentRepository interface {
	Create(ctx context.Context, inc *incident.Incident) error

	// Get returns shared.ErrNotFound when the incident does not exist.
	Get(ctx context.Context, id incident.ID) (*incident.Incident, error)

	// Update writes an incident using optimistic locking on Version, returning
	// shared.ErrConflict if another writer got there first. Seven agents mutate
	// one incident concurrently; without this, two agents reading the same row
	// and writing back would silently lose one of the updates.
	//
	// On success the passed incident's Version is advanced in place.
	Update(ctx context.Context, inc *incident.Incident) error

	List(ctx context.Context, f IncidentFilter, p Page) (PageResult[*incident.Incident], error)
	Count(ctx context.Context, f IncidentFilter) (int64, error)

	// AppendEvent adds one entry to the incident's timeline, assigning Seq
	// inside the same transaction. Computing the sequence in application code
	// would race between concurrent agents.
	AppendEvent(ctx context.Context, ev *incident.Event) error

	// Events returns the timeline in ascending sequence order.
	Events(ctx context.Context, id incident.ID, p Page) (PageResult[*incident.Event], error)
}

// AgentRepository persists agent registrations.
type AgentRepository interface {
	Create(ctx context.Context, a *agent.Agent) error
	Get(ctx context.Context, id agent.ID) (*agent.Agent, error)
	GetByName(ctx context.Context, name string) (*agent.Agent, error)
	List(ctx context.Context) ([]*agent.Agent, error)
	Update(ctx context.Context, a *agent.Agent) error

	// Upsert registers an agent or updates it in place, keyed on name. The
	// orchestrator calls this at startup so the roster is reconciled from code
	// rather than requiring a seed migration to stay in step.
	//
	// It reconciles an agent's DEFINITION (kind, description, config) and
	// deliberately leaves its OPERATIONAL STATE alone: an existing agent's
	// `enabled` flag is never overwritten. Disabling an agent is how an operator
	// stops the AI proposing actions, and a restart must not silently re-arm it.
	// Use Update to change that flag.
	Upsert(ctx context.Context, a *agent.Agent) error
}

// TaskFilter narrows a task query.
type TaskFilter struct {
	IncidentID *shared.ID
	AgentID    *shared.ID
	Statuses   []agent.TaskStatus
}

// TaskRepository persists agent tasks.
type TaskRepository interface {
	Create(ctx context.Context, t *agent.Task) error
	Get(ctx context.Context, id shared.ID) (*agent.Task, error)
	Update(ctx context.Context, t *agent.Task) error
	List(ctx context.Context, f TaskFilter, p Page) (PageResult[*agent.Task], error)
}

// UserRepository persists user accounts.
type UserRepository interface {
	Create(ctx context.Context, u *user.User) error
	Get(ctx context.Context, id user.ID) (*user.User, error)

	// GetByEmail is the authentication lookup. Implementations must match on
	// the normalised (lowercased) address.
	GetByEmail(ctx context.Context, email string) (*user.User, error)

	Update(ctx context.Context, u *user.User) error
	List(ctx context.Context, p Page) (PageResult[*user.User], error)
	RecordLogin(ctx context.Context, id user.ID, at time.Time) error
}

// SessionRepository persists refresh tokens.
//
// Refresh tokens are opaque and stored hashed; the plaintext never reaches this
// interface except to be looked up by digest.
type SessionRepository interface {
	Create(ctx context.Context, t *user.RefreshToken) error

	// GetByPlaintext hashes the presented value and looks it up. Returns
	// shared.ErrNotFound for an unrecognised token, saying nothing about
	// whether it ever existed.
	GetByPlaintext(ctx context.Context, plaintext string) (*user.RefreshToken, error)

	// Rotate atomically marks a token used and stores its replacement. It must
	// fail with shared.ErrConflict if the token was already rotated, so two
	// concurrent refreshes cannot both succeed.
	Rotate(ctx context.Context, oldID shared.ID, next *user.RefreshToken) error

	// RevokeFamily invalidates every token descended from one login. Called on
	// replay detection: a rotated token presented again means the lineage is
	// no longer trustworthy.
	RevokeFamily(ctx context.Context, familyID shared.ID, reason string, at time.Time) (int64, error)

	// RevokeAllForUser is logout-everywhere, and the correct response to a
	// password change or a role downgrade.
	RevokeAllForUser(ctx context.Context, userID user.ID, reason string, at time.Time) (int64, error)

	// Revoke invalidates one token. Revoking an already-revoked token is a
	// no-op, because logging out twice is not an error.
	Revoke(ctx context.Context, id shared.ID, reason string, at time.Time) error

	// DeleteExpired is housekeeping: an expired token is already unusable, but
	// every login and every refresh adds a row.
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)

	ListForUser(ctx context.Context, userID user.ID) ([]*user.RefreshToken, error)
}

// ToolCallFilter narrows a tool-call query.
type ToolCallFilter struct {
	IncidentID *shared.ID
	AgentID    *shared.ID
	Decisions  []harness.Decision
	Risks      []harness.Risk
	// PendingApproval selects requests a human still has to rule on — the
	// operator's work queue.
	PendingApproval bool
}

// ToolCallRepository persists agent intents and their execution records.
type ToolCallRepository interface {
	Create(ctx context.Context, r *harness.ToolCallRequest) error
	Get(ctx context.Context, id shared.ID) (*harness.ToolCallRequest, error)

	// GetByIdempotencyKey returns shared.ErrNotFound when the key is unseen.
	// The bus delivers at-least-once, so this is what stops a redelivered
	// ToolRequested event from restarting a container twice.
	GetByIdempotencyKey(ctx context.Context, key string) (*harness.ToolCallRequest, error)

	Update(ctx context.Context, r *harness.ToolCallRequest) error
	List(ctx context.Context, f ToolCallFilter, p Page) (PageResult[*harness.ToolCallRequest], error)

	// SaveExecution records the outcome. One execution per tool call, enforced
	// by a unique constraint, so a duplicate returns shared.ErrAlreadyExists
	// rather than executing again.
	SaveExecution(ctx context.Context, e *harness.Execution) error
	GetExecution(ctx context.Context, toolCallID shared.ID) (*harness.Execution, error)
}

// PolicyRepository serves the rules the harness evaluates.
type PolicyRepository interface {
	ListPermissions(ctx context.Context) ([]*harness.Permission, error)
	ListPolicies(ctx context.Context) ([]*harness.Policy, error)
	UpsertPermission(ctx context.Context, p *harness.Permission) error
	UpsertPolicy(ctx context.Context, p *harness.Policy) error
	DeletePermission(ctx context.Context, id shared.ID) error
	DeletePolicy(ctx context.Context, id shared.ID) error
}

// AuditFilter narrows an audit query.
type AuditFilter struct {
	IncidentID *shared.ID
	ActorID    *shared.ID
	ActorType  string
	Action     string
	Outcomes   []harness.Outcome
	Since      *time.Time
	Until      *time.Time
}

// AuditRepository is the append-only ledger.
//
// There is deliberately no Update and no Delete. The ledger's value comes from
// being immutable, and an interface that cannot express a rewrite is a stronger
// guarantee than a convention that says not to.
type AuditRepository interface {
	// Append assigns Seq and links the hash chain inside the insert
	// transaction, because the chain must be computed against the row that is
	// actually the predecessor — knowable only under the lock the insert holds.
	Append(ctx context.Context, e *harness.AuditEntry) error

	List(ctx context.Context, f AuditFilter, p Page) (PageResult[*harness.AuditEntry], error)

	// VerifyChain recomputes the hash chain over a sequence range, detecting
	// rows that were edited or removed after the fact.
	VerifyChain(ctx context.Context, fromSeq, toSeq int64) (harness.ChainVerification, error)

	// LatestSeq returns the highest assigned sequence, or 0 on an empty ledger.
	LatestSeq(ctx context.Context) (int64, error)
}
