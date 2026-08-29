package harness

import (
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// Effect is a permission verdict.
type Effect string

// Permission effects.
const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Valid reports whether the effect is defined.
func (e Effect) Valid() bool { return e == EffectAllow || e == EffectDeny }

// Wildcard matches any tool or action in a permission or policy rule.
const Wildcard = "*"

// Permission is one row of a per-agent allowlist.
//
// The engine that reads these is deny-by-default: an action with no matching
// allow rule is refused. An explicit deny always wins over an allow, so a
// blanket "monitoring may use anything on the docker tool" can still be carved
// back without rewriting the allow rule.
//
// Rules are data, not code, so the permission matrix is reviewable and diffable
// without reading Go — which matters because this table is the thing standing
// between a hallucinated action and production.
type Permission struct {
	ID        shared.ID
	AgentKind string
	Tool      string
	Action    string
	Effect    Effect
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks the permission's invariants.
func (p *Permission) Validate() error {
	v := shared.NewValidator("permission")
	v.NotZeroID(p.ID, "id")
	v.Required(p.AgentKind, "agent_kind")
	v.Required(p.Tool, "tool")
	v.Required(p.Action, "action")
	v.Check(p.Effect.Valid(), "effect", "must be allow or deny")
	return v.Err()
}

// Matches reports whether this rule applies to a tool/action pair, honouring
// wildcards on either side.
func (p *Permission) Matches(tool, action string) bool {
	toolOK := p.Tool == Wildcard || p.Tool == tool
	actionOK := p.Action == Wildcard || p.Action == action
	return toolOK && actionOK
}

// Specificity ranks how precisely a rule matches, so the most specific rule wins
// when several apply. An exact tool+action beats a tool wildcard, which beats a
// blanket rule.
func (p *Permission) Specificity() int {
	score := 0
	if p.Tool != Wildcard {
		score += 2
	}
	if p.Action != Wildcard {
		score++
	}
	return score
}

// Policy assigns a risk tier to a tool/action and decides whether a human must
// approve it.
type Policy struct {
	ID          shared.ID
	Name        string
	Description string

	Tool   string
	Action string

	Risk             Risk
	RequiresApproval bool

	// MinConfidence lets a policy demand human review when the agent is unsure,
	// even for an otherwise-automatic action. A weak local model reasoning
	// poorly is exactly the case this catches.
	MinConfidence float64

	// Priority breaks ties; higher wins. Specificity is used first.
	Priority int
	Enabled  bool

	// Conditions carries future structured predicates (environment, time of
	// day, service tier). Schemaless so adding one needs no migration.
	Conditions map[string]any

	CreatedAt time.Time
	UpdatedAt time.Time
}

// MaxPolicyNameLen bounds the policy name.
const MaxPolicyNameLen = 200

// Validate checks the policy's invariants.
func (p *Policy) Validate() error {
	v := shared.NewValidator("policy")
	v.NotZeroID(p.ID, "id")
	v.Required(p.Name, "name")
	v.MaxLen(p.Name, "name", MaxPolicyNameLen)
	v.Required(p.Tool, "tool")
	v.Required(p.Action, "action")
	v.Check(p.Risk.Valid(), "risk", "must be one of: low, medium, high, forbidden")
	v.InRange(p.MinConfidence, "min_confidence", 0, 1)
	return v.Err()
}

// Matches reports whether this policy governs a tool/action pair.
func (p *Policy) Matches(tool, action string) bool {
	if !p.Enabled {
		return false
	}
	toolOK := p.Tool == Wildcard || p.Tool == tool
	actionOK := p.Action == Wildcard || p.Action == action
	return toolOK && actionOK
}

// Specificity ranks how precisely a policy matches. Same scheme as Permission.
func (p *Policy) Specificity() int {
	score := 0
	if p.Tool != Wildcard {
		score += 2
	}
	if p.Action != Wildcard {
		score++
	}
	return score
}

// NeedsApproval reports whether a request under this policy must be held for a
// human, given the agent's confidence and the deployment's autonomy ceiling.
//
// Three independent reasons to stop, any one sufficient:
//
//   - the action is forbidden outright — no approval can authorise it
//   - the policy demands approval for this action
//   - the agent's confidence is below what the policy requires
//
// The ceiling is checked separately by the caller via Risk.AtOrBelow.
func (p *Policy) NeedsApproval(confidence float64) bool {
	if p.Risk == RiskForbidden {
		return true
	}
	if p.RequiresApproval {
		return true
	}
	return confidence < p.MinConfidence
}
