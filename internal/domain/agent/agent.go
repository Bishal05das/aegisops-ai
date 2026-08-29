// Package agent models the seven specialists and the tasks dispatched to them.
//
// Note what is absent: nothing here can execute anything. An agent is a
// registration record and a permission subject. Its capability to affect the
// world is entirely a function of what the harness will accept from it, which is
// the whole architectural point. See docs/adr/0006.
package agent

import (
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// ID identifies an agent.
type ID = shared.ID

// Kind names one of the seven specialists.
type Kind string

// The roster. Each has a narrow charter and, critically, a narrow permission set.
const (
	KindIncidentManager Kind = "incident_manager"
	KindMonitoring      Kind = "monitoring"
	KindLogAnalysis     Kind = "log_analysis"
	KindDiagnosis       Kind = "diagnosis"
	KindSecurity        Kind = "security"
	KindAction          Kind = "action"
	KindDocumentation   Kind = "documentation"
)

// AllKinds is the canonical roster, in dispatch order.
var AllKinds = []Kind{
	KindIncidentManager,
	KindMonitoring,
	KindLogAnalysis,
	KindDiagnosis,
	KindSecurity,
	KindAction,
	KindDocumentation,
}

// Valid reports whether the kind is one of the seven.
func (k Kind) Valid() bool {
	for _, known := range AllKinds {
		if k == known {
			return true
		}
	}
	return false
}

// CanMutate reports whether this kind is permitted to *propose* an action that
// changes infrastructure.
//
// Exactly one of seven returns true. That ratio is the design: six agents can
// only read, so a reasoning failure in any of them cannot reach a mutating tool
// regardless of what the model emits. This is advisory metadata for the UI and
// for assertions — the binding decision is made by the harness permission
// engine, which is data, not code.
func (k Kind) CanMutate() bool { return k == KindAction }

// Agent is a registered specialist.
type Agent struct {
	ID          ID
	Name        string
	Kind        Kind
	Description string
	Enabled     bool

	// Config holds per-agent tuning: prompt version, model override, timeouts.
	// Deliberately schemaless — each agent reads the keys it understands, so
	// adding one does not require a migration.
	Config map[string]any

	CreatedAt time.Time
	UpdatedAt time.Time
}

// MaxNameLen bounds the agent name.
const MaxNameLen = 100

// New builds a validated agent registration.
func New(clock shared.Clock, name string, kind Kind, description string) (*Agent, error) {
	now := clock.Now()
	a := &Agent{
		ID:          shared.NewID(),
		Name:        name,
		Kind:        kind,
		Description: description,
		Enabled:     true,
		Config:      map[string]any{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return a, nil
}

// Validate checks the agent's invariants.
func (a *Agent) Validate() error {
	v := shared.NewValidator("agent")
	v.NotZeroID(a.ID, "id")
	v.Required(a.Name, "name")
	v.MaxLen(a.Name, "name", MaxNameLen)
	v.Check(a.Kind.Valid(), "kind", "is not one of the seven agent kinds")
	return v.Err()
}
