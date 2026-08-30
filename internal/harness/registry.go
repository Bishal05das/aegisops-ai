// Package harness implements the security boundary between what an agent wants
// and what happens to infrastructure.
//
// # The five gates
//
// A ToolCallRequest arrives from an agent as an event and passes through, in
// order:
//
//  1. Registry    — is this a real tool.action, and are the parameters valid?
//  2. Permission  — may this agent kind use it? (deny by default)
//  3. Policy      — how risky is it, and does a human have to say yes?
//  4. Approval    — if so, park it until a human with the right authority rules
//  5. Execution   — invoke the tool, bounded and recorded
//
// Every gate can veto, and every outcome — especially a veto — is written to the
// audit ledger. Ordering is load-bearing and is explained at [Harness.Evaluate].
//
// # What this package guarantees
//
// The agent packages cannot reach past it. `internal/agents` holds no tool, no
// executor and no credentials; the only thing it can produce is a
// harness.ToolCallRequest, which is inert data. Everything that can actually
// touch infrastructure lives here, behind the gates above.
//
// See docs/adr/0006-harness-as-security-boundary.md and
// docs/adr/0011-harness-engine.md.
package harness

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// DefaultMaxParamLen bounds any string parameter without its own MaxLen.
//
// Parameters are assembled by a language model and become arguments to
// infrastructure calls. An unbounded string is how a hallucinated response
// becomes a megabyte of argv.
const DefaultMaxParamLen = 4096

// MaxParams bounds how many parameters one call may carry. A model that emits
// hundreds of keys has malfunctioned, and the harness should say so rather than
// validate them one by one.
const MaxParams = 64

// Registry is gate one: the set of tools that exist, and what they accept.
//
// Two jobs, and the second is the security-relevant one:
//
//   - resolve "docker.restart_container" to something invokable
//   - reject a call whose parameters do not match the declared schema
//
// The second runs *before* the permission check on purpose. A malformed call is
// not a permission question, and validating first means a permission rule can
// never be evaluated against parameters that were never coherent.
//
// Safe for concurrent use. Registration happens at startup; lookups happen on
// every tool call from every investigation at once.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]ports.Tool
	// compiled caches each parameter's anchored pattern, so a regex is built at
	// registration rather than on every call.
	compiled map[string]*regexp.Regexp
}

// NewRegistry builds an empty registry.
//
// Empty is the correct starting state: a registry that pre-registered tools
// would make "which tools does this deployment expose?" a question about code
// rather than about composition, and the answer must be visible in one place.
func NewRegistry() *Registry {
	return &Registry{
		tools:    make(map[string]ports.Tool),
		compiled: make(map[string]*regexp.Regexp),
	}
}

// Register adds a tool.
//
// Validation is strict and fails loudly: a tool with a malformed descriptor
// cannot be registered, because the alternative is a parameter pattern that
// silently matches everything. This runs at startup, so a bad descriptor stops
// the daemon rather than surfacing at 3am as an unexpectedly-permitted call.
func (r *Registry) Register(t ports.Tool) error {
	const op = "harness.Registry.Register"

	d := t.Descriptor()
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("%s: the tool has no name", op)
	}
	if len(d.Actions) == 0 {
		return fmt.Errorf("%s: tool %q declares no actions", op, d.Name)
	}

	// Compile every pattern before mutating any state, so a failure leaves the
	// registry exactly as it was.
	patterns := make(map[string]*regexp.Regexp)
	for action, ad := range d.Actions {
		if strings.TrimSpace(action) == "" {
			return fmt.Errorf("%s: tool %q declares an unnamed action", op, d.Name)
		}
		for name, spec := range ad.Params {
			if err := validateSpec(d.Name, action, name, spec); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			if spec.Pattern == "" {
				continue
			}
			// Anchored on both ends. An unanchored pattern matches a substring,
			// so `^[a-z]+$` written as `[a-z]+` would accept
			// "web; rm -rf /" — the exact class of value this is meant to stop.
			re, err := regexp.Compile(anchor(spec.Pattern))
			if err != nil {
				return fmt.Errorf("%s: tool %q action %q param %q: bad pattern %q: %w",
					op, d.Name, action, name, spec.Pattern, err)
			}
			patterns[paramKey(d.Name, action, name)] = re
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tools[d.Name]; exists {
		// Silent replacement would let a second registration widen what the
		// first allowed, which is a privilege change disguised as a startup
		// ordering detail.
		return fmt.Errorf("%s: tool %q is already registered", op, d.Name)
	}
	r.tools[d.Name] = t
	for k, v := range patterns {
		r.compiled[k] = v
	}
	return nil
}

// Lookup returns a registered tool.
func (r *Registry) Lookup(tool string) (ports.Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[tool]
	return t, ok
}

// Known reports whether a tool.action pair exists.
//
// Distinct from "is it permitted": an unknown action and a forbidden one are
// different facts and get different audit outcomes, because they mean different
// things. An unknown action usually means the model invented one; a forbidden
// one means it asked for something real that it may not have.
func (r *Registry) Known(tool, action string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tools[tool]
	if !ok {
		return false
	}
	_, ok = t.Descriptor().Actions[action]
	return ok
}

// Describe returns one action's declaration.
func (r *Registry) Describe(tool, action string) (ports.ActionDescriptor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tools[tool]
	if !ok {
		return ports.ActionDescriptor{}, false
	}
	ad, ok := t.Descriptor().Actions[action]
	return ad, ok
}

// Tools lists every registered descriptor, sorted by name for stable output.
func (r *Registry) Tools() []ports.ToolDescriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]ports.ToolDescriptor, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t.Descriptor())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ValidateParams checks a call's parameters against the declared schema and
// returns the normalised set to execute with.
//
// Returns a *fresh* map rather than mutating the caller's. The request's params
// are what a human sees when approving, and they must not change between
// approval and execution — normalising in place would make the approved values
// and the executed values silently different.
//
// Three rules, all deny-by-default:
//
//   - an undeclared parameter is an error, not something to ignore. Dropping an
//     argument the model meant to pass executes a different action from the one
//     that was reviewed.
//   - a missing required parameter is an error.
//   - a value that fails its constraint is an error, and the message names the
//     parameter so an operator can see what the model got wrong.
func (r *Registry) ValidateParams(tool, action string, params map[string]any) (map[string]any, error) {
	r.mu.RLock()
	t, ok := r.tools[tool]
	if !ok {
		r.mu.RUnlock()
		return nil, &ParamError{Reason: fmt.Sprintf("unknown tool %q", tool)}
	}
	ad, ok := t.Descriptor().Actions[action]
	if !ok {
		r.mu.RUnlock()
		return nil, &ParamError{Reason: fmt.Sprintf("tool %q has no action %q", tool, action)}
	}
	// Copy the compiled patterns out under the lock so validation itself runs
	// unlocked; the regexps are immutable once compiled.
	pats := make(map[string]*regexp.Regexp, len(ad.Params))
	for name := range ad.Params {
		if re, ok := r.compiled[paramKey(tool, action, name)]; ok {
			pats[name] = re
		}
	}
	r.mu.RUnlock()

	if len(params) > MaxParams {
		return nil, &ParamError{Reason: fmt.Sprintf(
			"the call carries %d parameters; the limit is %d", len(params), MaxParams)}
	}

	// Undeclared parameters, reported together and in a stable order so the
	// message is the same on every run.
	var unknown []string
	for name := range params {
		if _, declared := ad.Params[name]; !declared {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, &ParamError{
			Param: unknown[0],
			Reason: fmt.Sprintf("%s.%s does not accept %s",
				tool, action, strings.Join(quoteAll(unknown), ", ")),
		}
	}

	out := make(map[string]any, len(ad.Params))
	for name, spec := range ad.Params {
		raw, present := params[name]
		if !present || raw == nil {
			if spec.Required {
				return nil, &ParamError{Param: name, Reason: "is required"}
			}
			if spec.Default != nil {
				out[name] = spec.Default
			}
			continue
		}
		v, err := coerce(name, spec, raw, pats[name])
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

// ParamError is a schema violation.
//
// A distinct type because the harness maps it to DecisionDeniedParams and to a
// specific audit outcome. Collapsing it into a generic error would lose the
// distinction between "the model asked for something malformed" and "the
// harness broke", which are opposite kinds of problem.
type ParamError struct {
	Param  string
	Reason string
}

// Error implements error.
func (e *ParamError) Error() string {
	if e.Param == "" {
		return e.Reason
	}
	return e.Param + " " + e.Reason
}

// coerce converts and constrains one value.
//
// JSON round-trips every number to float64, so an int parameter arrives as a
// float and has to be checked for integrality rather than assumed. A model
// emitting `{"replicas": 2.5}` must be rejected, not silently truncated to 2.
func coerce(name string, spec ports.ParamSpec, raw any, pat *regexp.Regexp) (any, error) {
	fail := func(format string, args ...any) error {
		return &ParamError{Param: name, Reason: fmt.Sprintf(format, args...)}
	}

	switch spec.Kind {
	case ports.ParamString:
		s, ok := raw.(string)
		if !ok {
			return nil, fail("must be a string, got %T", raw)
		}
		maxLen := spec.MaxLen
		if maxLen <= 0 {
			maxLen = DefaultMaxParamLen
		}
		if len(s) > maxLen {
			return nil, fail("is longer than the %d-character limit", maxLen)
		}
		// Control characters never belong in an infrastructure argument, and
		// they are how a value smuggles a newline into a log line or an escape
		// sequence into an approver's terminal.
		if i := strings.IndexFunc(s, isControl); i >= 0 {
			return nil, fail("contains a control character at byte %d", i)
		}
		if len(spec.Enum) > 0 && !contains(spec.Enum, s) {
			return nil, fail("must be one of: %s", strings.Join(spec.Enum, ", "))
		}
		if pat != nil && !pat.MatchString(s) {
			return nil, fail("does not match the required format %s", spec.Pattern)
		}
		return s, nil

	case ports.ParamInt:
		f, err := toFloat(raw)
		if err != nil {
			return nil, fail("must be an integer, got %T", raw)
		}
		if f != math.Trunc(f) {
			return nil, fail("must be a whole number, got %v", f)
		}
		if err := checkRange(spec, f); err != nil {
			return nil, fail("%s", err.Error())
		}
		return int64(f), nil

	case ports.ParamFloat:
		f, err := toFloat(raw)
		if err != nil {
			return nil, fail("must be a number, got %T", raw)
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fail("must be a finite number")
		}
		if err := checkRange(spec, f); err != nil {
			return nil, fail("%s", err.Error())
		}
		return f, nil

	case ports.ParamBool:
		b, ok := raw.(bool)
		if !ok {
			return nil, fail("must be true or false, got %T", raw)
		}
		return b, nil

	default:
		// An unknown kind means a descriptor the registry does not understand.
		// Rejecting is the safe direction: accepting would let a typo'd kind
		// disable validation for that parameter entirely.
		return nil, fail("has an unsupported parameter kind %q", spec.Kind)
	}
}

func checkRange(spec ports.ParamSpec, f float64) error {
	if spec.Min == 0 && spec.Max == 0 {
		return nil
	}
	if f < spec.Min || f > spec.Max {
		return fmt.Errorf("must be between %v and %v, got %v", spec.Min, spec.Max, f)
	}
	return nil
}

func toFloat(raw any) (float64, error) {
	switch v := raw.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case json.Number:
		return v.Float64()
	default:
		return 0, fmt.Errorf("not numeric")
	}
}

// validateSpec rejects a descriptor that would weaken validation.
func validateSpec(tool, action, name string, spec ports.ParamSpec) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("tool %q action %q declares an unnamed parameter", tool, action)
	}
	switch spec.Kind {
	case ports.ParamString, ports.ParamInt, ports.ParamBool, ports.ParamFloat:
	default:
		return fmt.Errorf("tool %q action %q param %q has unknown kind %q",
			tool, action, name, spec.Kind)
	}
	if spec.Required && spec.Default != nil {
		// Harmless at runtime, but it means one of the two is a mistake, and
		// guessing which one is not the registry's job.
		return fmt.Errorf("tool %q action %q param %q is required and also has a default",
			tool, action, name)
	}
	if len(spec.Enum) > 0 && spec.Kind != ports.ParamString {
		return fmt.Errorf("tool %q action %q param %q: enum applies only to strings",
			tool, action, name)
	}
	if spec.Pattern != "" && spec.Kind != ports.ParamString {
		return fmt.Errorf("tool %q action %q param %q: pattern applies only to strings",
			tool, action, name)
	}
	if spec.Min > spec.Max {
		return fmt.Errorf("tool %q action %q param %q: min %v exceeds max %v",
			tool, action, name, spec.Min, spec.Max)
	}
	return nil
}

// anchor makes a pattern match the whole string.
func anchor(p string) string {
	if !strings.HasPrefix(p, "^") {
		p = "^" + p
	}
	if !strings.HasSuffix(p, "$") {
		p += "$"
	}
	return p
}

func paramKey(tool, action, param string) string { return tool + "." + action + "." + param }

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

func contains(set []string, s string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}
