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

// PermissionEngine is gate two: may this agent kind use this tool.action?
//
// # Deny by default
//
// An action with no matching allow rule is refused. Not "logged and allowed",
// not "allowed with a warning" — refused. This is the single most important
// property in the package, and it is why the engine is written around
// [Permissions.Allows] returning false for the empty matrix rather than around a
// list of denials.
//
// The consequence worth stating plainly: a tool added in Phase 7 is unusable by
// every agent until someone writes a permission row for it. That is the correct
// direction of failure. The opposite — a new tool being usable until someone
// remembers to restrict it — puts the burden of safety on memory.
//
// # Resolution order
//
// When several rules match, the most specific wins; among equally specific
// rules, an explicit deny beats an allow. So a blanket
// "monitoring may use anything on the docker tool" can be carved back with a
// targeted deny without unpicking the allow.
//
// # Why rules are cached
//
// The matrix is read on every tool call from every concurrent investigation. A
// database round trip per check would make the safety gate the slowest thing in
// the pipeline, which is how people end up wanting to skip it. The cache is
// refreshed on an interval and can be invalidated explicitly when the matrix is
// edited through the API.
type PermissionEngine struct {
	repo    ports.PolicyRepository
	ttl     time.Duration
	clock   shared.Clock
	loading sync.Mutex
	// current holds the compiled matrix. atomic.Pointer so a lookup never
	// blocks on a refresh: the gate must not become a contention point.
	current atomic.Pointer[Permissions]
	loadedA atomic.Int64
}

// DefaultRuleCacheTTL is how long a compiled matrix is served before refresh.
//
// One minute rather than one hour: this table is a security control, and the
// window between revoking an agent's permission and that revocation taking
// effect should be short enough that an operator does not feel the need to
// restart the daemon to be sure.
const DefaultRuleCacheTTL = time.Minute

// NewPermissionEngine builds the gate.
func NewPermissionEngine(repo ports.PolicyRepository, clock shared.Clock, ttl time.Duration) *PermissionEngine {
	if ttl <= 0 {
		ttl = DefaultRuleCacheTTL
	}
	return &PermissionEngine{repo: repo, clock: clock, ttl: ttl}
}

// Permissions is a compiled, immutable permission matrix.
//
// Immutable by construction: it is built once from a snapshot of the table and
// then only read. That is what makes it safe to publish through an atomic
// pointer and share across every concurrent investigation without a lock.
type Permissions struct {
	// byAgent indexes rules by agent kind, so a lookup scans only that agent's
	// rules rather than the whole matrix.
	byAgent map[string][]*harness.Permission
	builtAt time.Time
}

// CompilePermissions sorts rules into the order the engine resolves them.
//
// Sorting happens once here rather than on every lookup: the resolution order is
// a property of the rule set, not of the query.
func CompilePermissions(rules []*harness.Permission, at time.Time) *Permissions {
	byAgent := make(map[string][]*harness.Permission)
	for _, r := range rules {
		byAgent[r.AgentKind] = append(byAgent[r.AgentKind], r)
	}
	for _, rs := range byAgent {
		sort.SliceStable(rs, func(i, j int) bool {
			if rs[i].Specificity() != rs[j].Specificity() {
				return rs[i].Specificity() > rs[j].Specificity()
			}
			// Equal specificity: deny first, so the first match is the denial.
			return rs[i].Effect == harness.EffectDeny && rs[j].Effect != harness.EffectDeny
		})
	}
	return &Permissions{byAgent: byAgent, builtAt: at}
}

// Allows resolves the matrix for one agent and action.
//
// Returns the effect and the rule that produced it, so a denial can name the
// rule responsible. "denied by policy" with no indication of which rule is the
// kind of audit entry that wastes an hour during an incident.
func (p *Permissions) Allows(agentKind, tool, action string) (bool, *harness.Permission) {
	for _, r := range p.byAgent[agentKind] {
		if r.Matches(tool, action) {
			return r.Effect == harness.EffectAllow, r
		}
	}
	// No rule matched. Deny — this is the default that matters.
	return false, nil
}

// Rules returns every rule for an agent kind, most specific first.
func (p *Permissions) Rules(agentKind string) []*harness.Permission {
	out := make([]*harness.Permission, len(p.byAgent[agentKind]))
	copy(out, p.byAgent[agentKind])
	return out
}

// Count reports the total number of compiled rules.
func (p *Permissions) Count() int {
	n := 0
	for _, rs := range p.byAgent {
		n += len(rs)
	}
	return n
}

// BuiltAt reports when the matrix was compiled.
func (p *Permissions) BuiltAt() time.Time { return p.builtAt }

// Check evaluates one request against the matrix.
func (e *PermissionEngine) Check(ctx context.Context, agentKind, tool, action string) (Verdict, error) {
	perms, err := e.matrix(ctx)
	if err != nil {
		// A matrix that cannot be loaded is not an excuse to proceed. Failing
		// closed here means an outage in the rules database stops remediation
		// rather than un-gating it, which is the trade this system exists to
		// make.
		return Verdict{}, fmt.Errorf("harness.PermissionEngine.Check: %w", err)
	}

	allowed, rule := perms.Allows(agentKind, tool, action)
	v := Verdict{Allowed: allowed, Rule: rule}
	switch {
	case allowed:
		v.Reason = fmt.Sprintf("permitted by rule %s:%s.%s=allow",
			rule.AgentKind, rule.Tool, rule.Action)
	case rule != nil:
		v.Reason = fmt.Sprintf("denied by rule %s:%s.%s=deny",
			rule.AgentKind, rule.Tool, rule.Action)
	default:
		v.Reason = fmt.Sprintf(
			"no permission rule grants %s the use of %s.%s; the matrix denies by default",
			agentKind, tool, action)
	}
	return v, nil
}

// Verdict is a permission decision plus the rule that produced it.
type Verdict struct {
	Allowed bool
	Reason  string
	// Rule is nil when the denial came from the default rather than from an
	// explicit rule — a distinction an operator needs, because the fix differs.
	Rule *harness.Permission
}

// Invalidate drops the cached matrix so the next check reloads.
//
// Called when the matrix is edited through the API. Waiting out the TTL after
// revoking a permission would leave a window in which the revocation is written
// but not enforced.
func (e *PermissionEngine) Invalidate() {
	e.current.Store(nil)
	e.loadedA.Store(0)
}

// Snapshot returns the currently compiled matrix, loading it if necessary.
func (e *PermissionEngine) Snapshot(ctx context.Context) (*Permissions, error) {
	return e.matrix(ctx)
}

func (e *PermissionEngine) matrix(ctx context.Context) (*Permissions, error) {
	now := e.clock.Now()
	if p := e.current.Load(); p != nil {
		if loaded := e.loadedA.Load(); loaded != 0 && now.Sub(time.Unix(0, loaded)) < e.ttl {
			return p, nil
		}
	}

	// One loader at a time. Without this, a cold cache under load sends every
	// concurrent tool call to the database at once — a thundering herd against
	// the table the whole system's safety depends on.
	e.loading.Lock()
	defer e.loading.Unlock()

	if p := e.current.Load(); p != nil {
		if loaded := e.loadedA.Load(); loaded != 0 && e.clock.Now().Sub(time.Unix(0, loaded)) < e.ttl {
			return p, nil
		}
	}

	rules, err := e.repo.ListPermissions(ctx)
	if err != nil {
		// Serve a stale matrix rather than failing, but only if one exists.
		//
		// The trade: a brief database outage should not stop an investigation
		// that is already permitted, and the rules change rarely. Note the
		// asymmetry with a cold cache — with nothing to fall back on, the call
		// fails closed. Stale-but-real is safe; absent is not.
		if p := e.current.Load(); p != nil {
			return p, nil
		}
		return nil, fmt.Errorf("load the permission matrix: %w", err)
	}

	compiled := CompilePermissions(rules, e.clock.Now())
	e.current.Store(compiled)
	e.loadedA.Store(e.clock.Now().UnixNano())
	return compiled, nil
}
