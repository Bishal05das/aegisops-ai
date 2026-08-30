package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// PolicyRepo serves the permission matrix and the policy table.
//
// These two tables are the thing standing between a hallucinated action and
// production. They are read on every tool call, which is why the engines above
// compile and cache them rather than querying per check.
//
// Note what this adapter does *not* offer: no partial update, no "set effect".
// A rule is written whole or not at all. A half-applied permission change is a
// state nobody can reason about, and the tables are small enough that writing
// the whole row costs nothing.
type PolicyRepo struct {
	base
}

// NewPolicyRepo builds the adapter.
func NewPolicyRepo(db *sql.DB) *PolicyRepo { return &PolicyRepo{base{db: db}} }

var _ ports.PolicyRepository = (*PolicyRepo)(nil)

// ListPermissions returns the whole matrix.
//
// Unpaginated on purpose. The matrix is bounded by (agents × tools × actions)
// and is read as a unit by the permission engine — a partial matrix is not a
// smaller answer, it is a wrong one, because a missing deny rule reverses a
// verdict.
func (r *PolicyRepo) ListPermissions(ctx context.Context) ([]*harness.Permission, error) {
	const op = "postgres.PolicyRepo.ListPermissions"

	rows, err := r.exec(ctx).QueryContext(ctx, `
		SELECT id, agent_kind, tool, action, effect, created_at, updated_at
		FROM permissions
		ORDER BY agent_kind, tool, action`)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*harness.Permission
	for rows.Next() {
		var (
			p      harness.Permission
			effect string
		)
		if err := rows.Scan(&p.ID, &p.AgentKind, &p.Tool, &p.Action, &effect,
			&p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		p.Effect = harness.Effect(effect)
		out = append(out, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: iterate: %w", op, err)
	}
	return out, nil
}

// ListPolicies returns every policy, enabled or not.
//
// Disabled ones are included because the compiler needs them: Policy.Matches
// already returns false for a disabled policy, and returning them lets the API
// show an operator the rule that would apply if it were re-enabled.
func (r *PolicyRepo) ListPolicies(ctx context.Context) ([]*harness.Policy, error) {
	const op = "postgres.PolicyRepo.ListPolicies"

	rows, err := r.exec(ctx).QueryContext(ctx, `
		SELECT id, name, description, tool, action, risk, requires_approval,
		       min_confidence, priority, enabled, conditions, created_at, updated_at
		FROM policies
		ORDER BY priority DESC, tool, action`)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*harness.Policy
	for rows.Next() {
		var (
			p          harness.Policy
			risk       string
			conditions []byte
		)
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Tool, &p.Action, &risk,
			&p.RequiresApproval, &p.MinConfidence, &p.Priority, &p.Enabled,
			&conditions, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		p.Risk = harness.Risk(risk)
		if err := unmarshalJSON(conditions, &p.Conditions); err != nil {
			return nil, fmt.Errorf("%s: decode conditions: %w", op, err)
		}
		if p.Conditions == nil {
			p.Conditions = map[string]any{}
		}
		out = append(out, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: iterate: %w", op, err)
	}
	return out, nil
}

// UpsertPermission writes one rule, keyed by (agent_kind, tool, action).
func (r *PolicyRepo) UpsertPermission(ctx context.Context, p *harness.Permission) error {
	const op = "postgres.PolicyRepo.UpsertPermission"

	if p.ID.IsZero() {
		p.ID = shared.NewID()
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	err := r.exec(ctx).QueryRowContext(ctx, `
		INSERT INTO permissions (id, agent_kind, tool, action, effect, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5, now(), now())
		ON CONFLICT (agent_kind, tool, action) DO UPDATE SET
			effect     = EXCLUDED.effect,
			updated_at = now()
		RETURNING id, created_at, updated_at`,
		p.ID, p.AgentKind, p.Tool, p.Action, string(p.Effect),
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if isCheckViolation(err) {
			// The CHECK constraint names the seven agent kinds, so an unknown
			// one is rejected by the database rather than silently stored as a
			// rule that can never match.
			return fmt.Errorf("%s: %w: %q is not a known agent kind, or %q is not "+
				"allow or deny", op, shared.ErrValidation, p.AgentKind, p.Effect)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// UpsertPolicy writes one policy, keyed by (tool, action).
func (r *PolicyRepo) UpsertPolicy(ctx context.Context, p *harness.Policy) error {
	const op = "postgres.PolicyRepo.UpsertPolicy"

	if p.ID.IsZero() {
		p.ID = shared.NewID()
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	conditions, err := marshalJSON(p.Conditions)
	if err != nil {
		return fmt.Errorf("%s: encode conditions: %w", op, err)
	}

	err = r.exec(ctx).QueryRowContext(ctx, `
		INSERT INTO policies (
			id, name, description, tool, action, risk, requires_approval,
			min_confidence, priority, enabled, conditions, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now(), now())
		ON CONFLICT (tool, action) DO UPDATE SET
			name              = EXCLUDED.name,
			description       = EXCLUDED.description,
			risk              = EXCLUDED.risk,
			requires_approval = EXCLUDED.requires_approval,
			min_confidence    = EXCLUDED.min_confidence,
			priority          = EXCLUDED.priority,
			enabled           = EXCLUDED.enabled,
			conditions        = EXCLUDED.conditions,
			updated_at        = now()
		RETURNING id, created_at, updated_at`,
		p.ID, p.Name, p.Description, p.Tool, p.Action, string(p.Risk), p.RequiresApproval,
		p.MinConfidence, p.Priority, p.Enabled, conditions,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if isCheckViolation(err) {
			// policies_forbidden_requires_approval is the one that matters: the
			// database refuses to store a forbidden action that claims not to
			// need approval, because such a row would read as a path to
			// executing it.
			return fmt.Errorf("%s: %w: the policy violates a schema constraint — a "+
				"forbidden action must require approval, risk must be one of "+
				"low/medium/high/forbidden, and min_confidence must be within 0..1",
				op, shared.ErrValidation)
		}
		if isUniqueViolation(err) {
			return fmt.Errorf("%s: %w: a different policy is already named %q",
				op, shared.ErrAlreadyExists, p.Name)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// DeletePermission removes one rule.
//
// Deleting a rule is a *tightening* when the rule was an allow and a *loosening*
// when it was a deny, which is why the API layer requires policy:write for both
// and the audit ledger records either.
func (r *PolicyRepo) DeletePermission(ctx context.Context, id shared.ID) error {
	const op = "postgres.PolicyRepo.DeletePermission"

	res, err := r.exec(ctx).ExecContext(ctx, `DELETE FROM permissions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return requireOneRow(op, res, shared.ErrNotFound, "permission "+id.String())
}

// DeletePolicy removes one policy.
//
// The action it governed becomes untiered, and the policy engine denies untiered
// actions — so deleting a policy disables the action rather than freeing it.
func (r *PolicyRepo) DeletePolicy(ctx context.Context, id shared.ID) error {
	const op = "postgres.PolicyRepo.DeletePolicy"

	res, err := r.exec(ctx).ExecContext(ctx, `DELETE FROM policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return requireOneRow(op, res, shared.ErrNotFound, "policy "+id.String())
}
