package harness

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// PolicyEngine is gate three: how dangerous is this, and who has to say yes?
//
// Permission answered *may this agent do this at all*. Policy answers a
// different question — *under what conditions* — and the separation is
// deliberate. Permissions are per-agent and change when an agent's role changes;
// policies are per-action and change when an organisation's risk appetite does.
// Collapsing them into one table would mean re-stating every risk tier once per
// agent, and the first copy to drift would be a silent privilege escalation.
//
// # The autonomy ceiling
//
// AEGIS_HARNESS_MAX_AUTO_RISK names the riskiest action this deployment will
// execute *without* asking a human. Anything above it is not refused — it is
// escalated. That distinction matters: refusing would mean an operator could not
// authorise a rollback even when they want to, which is not what "maximum
// automatic risk" says.
//
// The ceiling is checked in addition to the policy's own requires_approval flag,
// never instead of it, so lowering the ceiling tightens every action at once
// without editing a policy row, and raising it cannot loosen an action whose
// policy demands approval.
//
// "none" is a real setting and means no autonomy at all: every action, including
// reading logs, waits for a human. It is represented as allowAuto=false rather
// than as a Risk value, because "none" is not a tier — treating it as one would
// make it fall through Risk.Valid() and default to "low", turning the strictest
// setting into a permissive one. That failure would be silent and in the
// dangerous direction, which is why it gets its own field.
//
// Forbidden sits outside the ceiling entirely: [harness.Risk.AtOrBelow] returns
// false for forbidden against every ceiling including forbidden itself, so no
// setting of this dial authorises dropping a table.
type PolicyEngine struct {
	repo  ports.PolicyRepository
	clock shared.Clock
	ttl   time.Duration

	ceiling harness.Risk
	// allowAuto is false when the ceiling is "none".
	allowAuto bool

	loading sync.Mutex
	current atomic.Pointer[Policies]
	loadedA atomic.Int64
}

// CeilingNone is the configuration value meaning "grant no autonomy at all".
const CeilingNone = "none"

// NewPolicyEngine builds the gate.
//
// The ceiling is taken as a string rather than a harness.Risk because "none" is
// a valid setting that is deliberately not a risk tier. Anything unrecognised
// becomes "none" — the most restrictive setting — because a misconfigured
// ceiling must never be more permissive than the operator intended.
func NewPolicyEngine(repo ports.PolicyRepository, clock shared.Clock, ttl time.Duration, ceiling string) *PolicyEngine {
	if ttl <= 0 {
		ttl = DefaultRuleCacheTTL
	}

	e := &PolicyEngine{repo: repo, clock: clock, ttl: ttl}
	risk := harness.Risk(ceiling)
	// Forbidden is rejected as a ceiling: it is not a level of autonomy, and
	// accepting it would read as though setting it granted something.
	if risk.Valid() && risk != harness.RiskForbidden {
		e.ceiling, e.allowAuto = risk, true
	}
	return e
}

// Ceiling reports the configured autonomy ceiling, or "none".
func (e *PolicyEngine) Ceiling() harness.Risk {
	if !e.allowAuto {
		return CeilingNone
	}
	return e.ceiling
}

// AutoAllowed reports whether any action may execute without a human.
func (e *PolicyEngine) AutoAllowed() bool { return e.allowAuto }

// Policies is a compiled, immutable policy set.
type Policies struct {
	ordered []*harness.Policy
	builtAt time.Time
}

// CompilePolicies orders policies so the first match is the one that governs.
//
// Specificity first, then priority, so an exact tool+action rule always beats a
// wildcard regardless of the priority numbers someone chose. Priority only
// breaks ties between equally specific rules — otherwise a high priority on a
// broad rule could silently override a narrow one written later.
func CompilePolicies(policies []*harness.Policy, at time.Time) *Policies {
	ordered := make([]*harness.Policy, 0, len(policies))
	ordered = append(ordered, policies...)

	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Specificity() != ordered[j].Specificity() {
			return ordered[i].Specificity() > ordered[j].Specificity()
		}
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority > ordered[j].Priority
		}
		// Final tiebreak: the riskier rule wins, so an ambiguous pair of rules
		// resolves toward caution rather than toward whichever was inserted
		// first.
		return ordered[i].Risk.Rank() > ordered[j].Risk.Rank()
	})
	return &Policies{ordered: ordered, builtAt: at}
}

// For returns the policy governing a tool.action, or nil when none matches.
func (p *Policies) For(tool, action string) *harness.Policy {
	for _, pol := range p.ordered {
		if pol.Matches(tool, action) {
			return pol
		}
	}
	return nil
}

// All returns every compiled policy in resolution order.
func (p *Policies) All() []*harness.Policy {
	out := make([]*harness.Policy, len(p.ordered))
	copy(out, p.ordered)
	return out
}

// Count reports how many policies are compiled.
func (p *Policies) Count() int { return len(p.ordered) }

// BuiltAt reports when the set was compiled.
func (p *Policies) BuiltAt() time.Time { return p.builtAt }

// Ruling is the policy engine's verdict.
type Ruling struct {
	// Risk is the tier assigned to the action. Always set, even on a denial.
	Risk harness.Risk

	// Decision is what the harness should record: allowed, awaiting_approval,
	// or denied_policy.
	Decision harness.Decision

	// RequiresApproval is true when a human must rule before execution.
	RequiresApproval bool

	// Reason explains the verdict in a sentence an operator can act on.
	Reason string

	// Policy is the rule that governed, or nil when none matched.
	Policy *harness.Policy
}

// Evaluate rules on one request.
//
// The order of checks below is the order of severity, and each returns
// immediately: a forbidden action is never additionally described as
// "low confidence", because the first fact is the only one that matters.
func (e *PolicyEngine) Evaluate(ctx context.Context, req *harness.ToolCallRequest) (Ruling, error) {
	policies, err := e.policies(ctx)
	if err != nil {
		return Ruling{}, fmt.Errorf("harness.PolicyEngine.Evaluate: %w", err)
	}

	pol := policies.For(req.Tool, req.Action)
	if pol == nil {
		// No policy governs this action. Deny.
		//
		// The alternative — defaulting an unpoliced action to low risk and
		// running it — would mean that forgetting to write a policy row is
		// indistinguishable from deciding the action is safe. A tool added
		// without a policy is unusable until someone tiers it, which is the
		// same discipline the permission matrix enforces.
		return Ruling{
			Risk:     harness.RiskForbidden,
			Decision: harness.DecisionDeniedPolicy,
			Reason: fmt.Sprintf(
				"no policy governs %s.%s; an untiered action is denied rather than assumed safe",
				req.Tool, req.Action),
		}, nil
	}

	if pol.Risk == harness.RiskForbidden {
		return Ruling{
			Risk:     harness.RiskForbidden,
			Decision: harness.DecisionDeniedPolicy,
			Policy:   pol,
			Reason: fmt.Sprintf(
				"%s.%s is forbidden by policy %q; no approval can authorise it",
				req.Tool, req.Action, pol.Name),
		}, nil
	}

	// The autonomy ceiling. Above it, a human decides — the action is escalated,
	// not refused. Refusing would mean an operator could not authorise a
	// rollback even when they want to, which is not what "maximum automatic
	// risk" means.
	if !e.allowAuto {
		return Ruling{
			Risk:             pol.Risk,
			Decision:         harness.DecisionAwaitingApproval,
			RequiresApproval: true,
			Policy:           pol,
			Reason: fmt.Sprintf(
				"this deployment grants no autonomy (max_auto_risk=none), so %s.%s "+
					"needs a human even though policy %q would allow it",
				req.Tool, req.Action, pol.Name),
		}, nil
	}
	if !pol.Risk.AtOrBelow(e.ceiling) {
		return Ruling{
			Risk:             pol.Risk,
			Decision:         harness.DecisionAwaitingApproval,
			RequiresApproval: true,
			Policy:           pol,
			Reason: fmt.Sprintf(
				"%s.%s is %s risk, above this deployment's %s autonomy ceiling, so a human must approve it",
				req.Tool, req.Action, pol.Risk, e.ceiling),
		}, nil
	}

	if pol.RequiresApproval {
		return Ruling{
			Risk:             pol.Risk,
			Decision:         harness.DecisionAwaitingApproval,
			RequiresApproval: true,
			Policy:           pol,
			Reason: fmt.Sprintf("policy %q requires a human to approve %s-risk %s.%s",
				pol.Name, pol.Risk, req.Tool, req.Action),
		}, nil
	}

	// Confidence floor. Last because it is the only check that depends on the
	// agent rather than on the action: everything above is true regardless of
	// how sure the model claims to be.
	if req.Confidence < pol.MinConfidence {
		return Ruling{
			Risk:             pol.Risk,
			Decision:         harness.DecisionAwaitingApproval,
			RequiresApproval: true,
			Policy:           pol,
			Reason: fmt.Sprintf(
				"the agent reported %.2f confidence; policy %q requires %.2f, so a human must review",
				req.Confidence, pol.Name, pol.MinConfidence),
		}, nil
	}

	return Ruling{
		Risk:     pol.Risk,
		Decision: harness.DecisionAllowed,
		Policy:   pol,
		Reason: fmt.Sprintf("policy %q permits %s-risk %s.%s automatically",
			pol.Name, pol.Risk, req.Tool, req.Action),
	}, nil
}

// Invalidate drops the cached policy set.
func (e *PolicyEngine) Invalidate() {
	e.current.Store(nil)
	e.loadedA.Store(0)
}

// Snapshot returns the compiled policy set, loading it if necessary.
func (e *PolicyEngine) Snapshot(ctx context.Context) (*Policies, error) { return e.policies(ctx) }

func (e *PolicyEngine) policies(ctx context.Context) (*Policies, error) {
	if p := e.current.Load(); p != nil {
		if loaded := e.loadedA.Load(); loaded != 0 && e.clock.Now().Sub(time.Unix(0, loaded)) < e.ttl {
			return p, nil
		}
	}

	e.loading.Lock()
	defer e.loading.Unlock()

	if p := e.current.Load(); p != nil {
		if loaded := e.loadedA.Load(); loaded != 0 && e.clock.Now().Sub(time.Unix(0, loaded)) < e.ttl {
			return p, nil
		}
	}

	rules, err := e.repo.ListPolicies(ctx)
	if err != nil {
		// Same trade as the permission matrix: stale-but-real beats absent, and
		// absent fails closed.
		if p := e.current.Load(); p != nil {
			return p, nil
		}
		return nil, fmt.Errorf("load policies: %w", err)
	}

	compiled := CompilePolicies(rules, e.clock.Now())
	e.current.Store(compiled)
	e.loadedA.Store(e.clock.Now().UnixNano())
	return compiled, nil
}

// ReconcileTools cross-checks registered tools against the policy table.
//
// Two misconfigurations matter, and neither is visible by reading either source
// alone:
//
//   - a mutating action with no policy, or policied as low risk. This is the
//     dangerous one: it would execute automatically. Reported as an error.
//   - a registered action no policy governs. Unusable rather than unsafe, so it
//     is reported as a warning — the action simply cannot run until tiered.
//
// Run at startup so a mismatch stops the daemon instead of surfacing the first
// time an agent proposes the action.
func (e *PolicyEngine) ReconcileTools(ctx context.Context, reg *Registry) (problems []string, err error) {
	policies, err := e.policies(ctx)
	if err != nil {
		return nil, fmt.Errorf("harness.PolicyEngine.ReconcileTools: %w", err)
	}

	for _, desc := range reg.Tools() {
		actions := make([]string, 0, len(desc.Actions))
		for action := range desc.Actions {
			actions = append(actions, action)
		}
		sort.Strings(actions)

		for _, action := range actions {
			ad := desc.Actions[action]
			pol := policies.For(desc.Name, action)
			switch {
			case pol == nil && ad.Mutating:
				problems = append(problems, fmt.Sprintf(
					"%s.%s is a mutating action with no policy: it would be denied, but it "+
						"should be tiered explicitly", desc.Name, action))
			case pol == nil:
				problems = append(problems, fmt.Sprintf(
					"%s.%s has no policy and cannot run until one is added", desc.Name, action))
			case ad.Mutating && pol.Risk == harness.RiskLow:
				problems = append(problems, fmt.Sprintf(
					"%s.%s declares itself mutating but policy %q tiers it low risk, so it "+
						"would execute with no human review", desc.Name, action, pol.Name))
			}
		}
	}
	return problems, nil
}
