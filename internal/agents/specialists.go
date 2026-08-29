package agents

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// Deps are the collaborators every agent needs.
type Deps struct {
	// Reasoner is the LLM seam. Phase 8 supplies a local model; until then the
	// scripted implementation makes orchestration deterministic and testable.
	Reasoner ports.Reasoner
	Clock    shared.Clock
	Registry map[agent.Kind]Registration
}

func (d Deps) registration(kind agent.Kind) Registration {
	if r, ok := d.Registry[kind]; ok {
		return r
	}
	// A code-level agent with no database row can still run and reason; it just
	// cannot attribute a tool call, and the harness will refuse an unattributed
	// one. Failing here instead would make the whole investigation depend on
	// registration having completed, which is a worse failure mode.
	return Registration{Name: string(kind), Kind: kind}
}

func newBase(kind agent.Kind, describe string, d Deps) base {
	reg := d.registration(kind)
	return base{kind: kind, describe: describe, clock: d.Clock, id: reg.ID, name: reg.Name}
}

// -----------------------------------------------------------------------------
// Monitoring
// -----------------------------------------------------------------------------

// Monitoring collects the numbers: CPU, memory, disk, network, service health.
//
// Read-only by construction and by permission. Its tool calls are all
// low-risk reads, which the policy engine executes automatically — an
// investigation that needed human approval to look at a dashboard would be
// useless.
type Monitoring struct {
	base
	reasoner ports.Reasoner
}

// NewMonitoring builds the monitoring agent.
func NewMonitoring(d Deps) *Monitoring {
	return &Monitoring{
		base:     newBase(agent.KindMonitoring, "Collects metrics and service health", d),
		reasoner: d.Reasoner,
	}
}

// Execute implements Agent.
func (a *Monitoring) Execute(ctx context.Context, in Input) (Output, error) {
	const op = "agents.Monitoring.Execute"

	calls, err := a.gather(in)
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}

	resp, err := a.reasoner.Reason(ctx, ports.ReasoningRequest{
		Task: "collect_metrics",
		SystemPrompt: "You are a monitoring specialist. Report what the telemetry " +
			"shows. Do not speculate about causes; that is the diagnosis agent's job.",
		Question: fmt.Sprintf("What does the telemetry show for %q on service %q?",
			in.Incident.Title, in.Incident.Service),
		Context: map[string]any{
			"service":     in.Incident.Service,
			"environment": in.Incident.Environment,
			"severity":    string(in.Incident.Severity),
			"labels":      in.Incident.Labels,
		},
		ResponseSchema: `{"summary":string,"metrics":object,"anomalies":[string],"confidence":number}`,
	})
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}

	return Output{
		Summary:    resp.Content,
		Confidence: resp.Confidence,
		Findings: map[string]any{
			"service":     in.Incident.Service,
			"environment": in.Incident.Environment,
			"observed_by": a.Name(),
		},
		ToolCalls: calls,
	}, nil
}

// gather builds the read-only intents this agent wants executed.
func (a *Monitoring) gather(in Input) ([]*harness.ToolCallRequest, error) {
	specs := []struct{ tool, action, reason string }{
		{"monitoring", "query", "read the service's error rate and latency around the incident window"},
		{"docker", "list_containers", "identify which containers are running for the affected service"},
		{"kubernetes", "get_pods", "check pod status and restart counts for the affected workload"},
	}

	out := make([]*harness.ToolCallRequest, 0, len(specs))
	for _, s := range specs {
		req, err := intent(a.clock, in, a.ID(), a.Name(), s.tool, s.action, s.reason)
		if err != nil {
			return nil, err
		}
		req.Params = map[string]any{
			"service":     in.Incident.Service,
			"environment": in.Incident.Environment,
		}
		req.Confidence = 1.0 // reading telemetry is not a judgement call
		out = append(out, req)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Log analysis
// -----------------------------------------------------------------------------

// LogAnalysis reads logs and finds the patterns in them.
type LogAnalysis struct {
	base
	reasoner ports.Reasoner
}

// NewLogAnalysis builds the log analysis agent.
func NewLogAnalysis(d Deps) *LogAnalysis {
	return &LogAnalysis{
		base:     newBase(agent.KindLogAnalysis, "Analyses logs for errors and patterns", d),
		reasoner: d.Reasoner,
	}
}

// Execute implements Agent.
func (a *LogAnalysis) Execute(ctx context.Context, in Input) (Output, error) {
	const op = "agents.LogAnalysis.Execute"

	calls := make([]*harness.ToolCallRequest, 0, 2)
	for _, s := range []struct{ tool, action, reason string }{
		{"docker", "logs", "read container logs from the incident window"},
		{"kubernetes", "logs", "read pod logs, including the previous container if it restarted"},
	} {
		req, err := intent(a.clock, in, a.ID(), a.Name(), s.tool, s.action, s.reason)
		if err != nil {
			return Output{}, fmt.Errorf("%s: %w", op, err)
		}
		req.Params = map[string]any{
			"service": in.Incident.Service,
			// Bounded: an unbounded log fetch is a memory hazard and the
			// executor would truncate it anyway.
			"lines": 1000,
			"since": in.Incident.DetectedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		req.Confidence = 1.0
		calls = append(calls, req)
	}

	resp, err := a.reasoner.Reason(ctx, ports.ReasoningRequest{
		Task: "analyse_logs",
		SystemPrompt: "You are a log analysis specialist. Cluster errors into " +
			"distinct failure modes and report the most frequent. Quote log lines " +
			"rather than paraphrasing them.",
		Question: fmt.Sprintf("What failure patterns appear in the logs for %q?", in.Incident.Title),
		Context: map[string]any{
			"service":     in.Incident.Service,
			"description": in.Incident.Description,
		},
		ResponseSchema: `{"summary":string,"patterns":[{"pattern":string,"count":number}],"confidence":number}`,
	})
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}

	return Output{
		Summary:    resp.Content,
		Confidence: resp.Confidence,
		Findings:   map[string]any{"analysed_by": a.Name()},
		ToolCalls:  calls,
	}, nil
}

// -----------------------------------------------------------------------------
// Security
// -----------------------------------------------------------------------------

// Security looks for whether the incident is an attack rather than a fault.
//
// It runs in the first wave alongside Monitoring and Log Analysis, deliberately:
// "is this a breach?" changes what a safe remediation looks like, and finding
// out after the Action agent has already restarted the compromised container is
// too late.
type Security struct {
	base
	reasoner ports.Reasoner
}

// NewSecurity builds the security agent.
func NewSecurity(d Deps) *Security {
	return &Security{
		base:     newBase(agent.KindSecurity, "Checks for vulnerabilities and misconfiguration", d),
		reasoner: d.Reasoner,
	}
}

// Execute implements Agent.
func (a *Security) Execute(ctx context.Context, in Input) (Output, error) {
	const op = "agents.Security.Execute"

	req, err := intent(a.clock, in, a.ID(), a.Name(), "security", "scan",
		"check the affected workload for known vulnerabilities and configuration drift")
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}
	req.Params = map[string]any{"service": in.Incident.Service, "environment": in.Incident.Environment}
	req.Confidence = 1.0

	resp, err := a.reasoner.Reason(ctx, ports.ReasoningRequest{
		Task: "security_review",
		SystemPrompt: "You are a security specialist. Decide whether this incident " +
			"shows signs of compromise rather than ordinary failure. Say so " +
			"explicitly when it does not — a false alarm costs an investigation.",
		Question: fmt.Sprintf("Does %q show signs of compromise?", in.Incident.Title),
		Context: map[string]any{
			"service":     in.Incident.Service,
			"environment": in.Incident.Environment,
			"description": in.Incident.Description,
		},
		ResponseSchema: `{"summary":string,"compromise_suspected":boolean,"findings":[string],"confidence":number}`,
	})
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}

	return Output{
		Summary:    resp.Content,
		Confidence: resp.Confidence,
		Findings:   map[string]any{"reviewed_by": a.Name()},
		ToolCalls:  []*harness.ToolCallRequest{req},
	}, nil
}

// -----------------------------------------------------------------------------
// Diagnosis
// -----------------------------------------------------------------------------

// Diagnosis reasons over the evidence and names a root cause.
//
// It requests no tools at all. Its input is what the first wave gathered and its
// output is a conclusion — which is why it is the one agent whose confidence
// directly gates whether a remediation may proceed automatically.
type Diagnosis struct {
	base
	reasoner ports.Reasoner
}

// NewDiagnosis builds the diagnosis agent.
func NewDiagnosis(d Deps) *Diagnosis {
	return &Diagnosis{
		base:     newBase(agent.KindDiagnosis, "Determines the root cause and its confidence", d),
		reasoner: d.Reasoner,
	}
}

// DiagnosisResult is what a diagnosis produces, lifted into Findings.
const (
	FindingRootCause  = "root_cause"
	FindingConfidence = "confidence"
	FindingRemediable = "remediable"
)

// Execute implements Agent.
func (a *Diagnosis) Execute(ctx context.Context, in Input) (Output, error) {
	const op = "agents.Diagnosis.Execute"

	if in.Evidence == nil || !in.Evidence.Complete() {
		// Refusing is the correct behaviour. A diagnosis with no telemetry is
		// guesswork, and guesswork is what the confidence score exists to keep
		// away from the Action agent.
		return Output{}, fmt.Errorf("%s: %w: no monitoring evidence to reason over",
			op, shared.ErrValidation)
	}

	resp, err := a.reasoner.Reason(ctx, ports.ReasoningRequest{
		Task: "diagnose",
		SystemPrompt: "You are a diagnosis specialist. Identify the single most " +
			"likely root cause from the evidence. State your confidence honestly: " +
			"a low score routes this to a human, which is the correct outcome when " +
			"the evidence is thin.",
		Question: fmt.Sprintf("What is the root cause of %q?", in.Incident.Title),
		Context: map[string]any{
			"incident": map[string]any{
				"title":       in.Incident.Title,
				"description": in.Incident.Description,
				"severity":    string(in.Incident.Severity),
				"service":     in.Incident.Service,
			},
			"evidence": in.Evidence.Fields(),
		},
		ResponseSchema: `{"root_cause":string,"confidence":number,"remediable":boolean,"reasoning":string}`,
	})
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}

	return Output{
		Summary:    resp.Content,
		Confidence: resp.Confidence,
		Findings: map[string]any{
			FindingRootCause:  resp.Content,
			FindingConfidence: resp.Confidence,
			// Whether a fix is even proposable. A disk that filled because a
			// customer uploaded 400 GB is diagnosable and not remediable by
			// this system.
			FindingRemediable: resp.Confidence >= MinRemediationConfidence,
		},
		NextAgents: []agent.Kind{agent.KindAction},
	}, nil
}

// MinRemediationConfidence is the floor below which no remediation is proposed.
//
// Distinct from the policy engine's threshold and deliberately redundant: this
// stops a bad diagnosis from ever becoming a tool call, and the policy engine
// stops a tool call from executing. Two independent gates, because a single one
// is a single point of failure for the property that matters most.
const MinRemediationConfidence = 0.5

// -----------------------------------------------------------------------------
// Action
// -----------------------------------------------------------------------------

// Action proposes a remediation.
//
// The only agent of the seven that may request a mutating tool, and even then
// only a proposal: every request it emits passes the harness's five gates, and
// the ones that matter require a human. Six of seven agents can only read; that
// ratio is the design, not an accident of which tools exist today.
type Action struct {
	base
	reasoner ports.Reasoner
}

// NewAction builds the action agent.
func NewAction(d Deps) *Action {
	return &Action{
		base:     newBase(agent.KindAction, "Proposes remediations for human approval", d),
		reasoner: d.Reasoner,
	}
}

// Execute implements Agent.
func (a *Action) Execute(ctx context.Context, in Input) (Output, error) {
	const op = "agents.Action.Execute"

	if in.Evidence == nil || !in.Evidence.Has(agent.KindDiagnosis) {
		return Output{}, fmt.Errorf("%s: %w: no diagnosis to remediate",
			op, shared.ErrValidation)
	}

	diagnosis := in.Evidence.Findings[agent.KindDiagnosis]
	confidence, _ := diagnosis[FindingConfidence].(float64)

	// The first of the two independent gates. Below this, no intent is even
	// constructed — there is nothing for the harness to refuse because nothing
	// was proposed.
	if confidence < MinRemediationConfidence {
		return Output{
			Summary: fmt.Sprintf(
				"No remediation proposed: diagnosis confidence %.2f is below the %.2f floor. "+
					"This incident needs a human.", confidence, MinRemediationConfidence),
			Confidence: confidence,
			Findings:   map[string]any{"remediation_proposed": false, "reason": "low_confidence"},
		}, nil
	}

	resp, err := a.reasoner.Reason(ctx, ports.ReasoningRequest{
		Task: "plan_remediation",
		SystemPrompt: "You are a remediation specialist. Propose the smallest " +
			"reversible action that addresses the diagnosed cause. Prefer restarting " +
			"over deleting, and scaling over recreating. Never propose destroying data.",
		Question: fmt.Sprintf("What is the safest remediation for %q?", in.Incident.Title),
		Context: map[string]any{
			"root_cause": diagnosis[FindingRootCause],
			"confidence": confidence,
			"service":    in.Incident.Service,
			"evidence":   in.Evidence.Fields(),
		},
		ResponseSchema: `{"summary":string,"tool":string,"action":string,"params":object,"reason":string,"confidence":number}`,
	})
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}

	plan, err := parseRemediation(resp.Content)
	if err != nil {
		// A reasoner that answered unusably must not become a silent no-op:
		// the incident should show that a remediation was attempted and could
		// not be parsed, so a human knows to look.
		//
		// Returning a successful Output rather than the error is deliberate. An
		// error here would fail the agent's task and read as "the Action agent
		// broke", when what actually happened is that the model produced
		// something unusable — a fact the incident should record, not hide.
		//nolint:nilerr // the parse failure is the finding, not a failure to report
		return Output{
			Summary:    "The remediation plan could not be parsed; escalating to a human.",
			Confidence: 0,
			Findings:   map[string]any{"remediation_proposed": false, "reason": "unparseable_plan"},
		}, nil
	}

	req, err := intent(a.clock, in, a.ID(), a.Name(), plan.Tool, plan.Action, plan.Reason)
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}
	req.Params = plan.Params
	req.Confidence = resp.Confidence

	return Output{
		Summary:    plan.Summary,
		Confidence: resp.Confidence,
		Findings: map[string]any{
			"remediation_proposed": true,
			"proposed_tool":        plan.Tool,
			"proposed_action":      plan.Action,
		},
		ToolCalls: []*harness.ToolCallRequest{req},
	}, nil
}

// -----------------------------------------------------------------------------
// Documentation
// -----------------------------------------------------------------------------

// Documentation writes the postmortem.
//
// Runs last and requests no tools. Its output is embedded into long-term memory
// in Phase 9, which is what "learns from previous incidents" means here:
// retrieval over your own history, not fine-tuning.
type Documentation struct {
	base
	reasoner ports.Reasoner
}

// NewDocumentation builds the documentation agent.
func NewDocumentation(d Deps) *Documentation {
	return &Documentation{
		base:     newBase(agent.KindDocumentation, "Writes the incident report and postmortem", d),
		reasoner: d.Reasoner,
	}
}

// Execute implements Agent.
func (a *Documentation) Execute(ctx context.Context, in Input) (Output, error) {
	const op = "agents.Documentation.Execute"

	resp, err := a.reasoner.Reason(ctx, ports.ReasoningRequest{
		Task: "write_postmortem",
		SystemPrompt: "You are writing a postmortem. State what happened, what " +
			"caused it, what was done, and what would prevent a recurrence. Blameless " +
			"and specific. Where the investigation was uncertain, say so.",
		Question: fmt.Sprintf("Write the postmortem for %q.", in.Incident.Title),
		Context: map[string]any{
			"incident": map[string]any{
				"title":       in.Incident.Title,
				"severity":    string(in.Incident.Severity),
				"service":     in.Incident.Service,
				"root_cause":  in.Incident.RootCause,
				"detected_at": in.Incident.DetectedAt,
			},
			"evidence": in.Evidence.Fields(),
		},
		ResponseSchema: `{"summary":string,"timeline":[string],"root_cause":string,"prevention":[string]}`,
	})
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}

	return Output{
		Summary:    resp.Content,
		Confidence: resp.Confidence,
		Findings:   map[string]any{"postmortem": resp.Content, "written_by": a.Name()},
	}, nil
}

// -----------------------------------------------------------------------------
// Incident manager
// -----------------------------------------------------------------------------

// IncidentManager builds the investigation plan.
//
// Pure coordination: it requests no tools and touches nothing. Its output is a
// plan the orchestrator may follow — advisory, because a manager that could
// dispatch itself could loop, and because the orchestrator owns the dependency
// ordering that makes the phases correct.
type IncidentManager struct {
	base
	reasoner ports.Reasoner
}

// NewIncidentManager builds the coordinating agent.
func NewIncidentManager(d Deps) *IncidentManager {
	return &IncidentManager{
		base:     newBase(agent.KindIncidentManager, "Plans and coordinates the investigation", d),
		reasoner: d.Reasoner,
	}
}

// Execute implements Agent.
func (a *IncidentManager) Execute(ctx context.Context, in Input) (Output, error) {
	const op = "agents.IncidentManager.Execute"

	resp, err := a.reasoner.Reason(ctx, ports.ReasoningRequest{
		Task: "plan_investigation",
		SystemPrompt: "You coordinate an incident investigation. Decide which " +
			"specialists to involve and why. You do not investigate yourself.",
		Question: fmt.Sprintf("How should %q be investigated?", in.Incident.Title),
		Context: map[string]any{
			"title":       in.Incident.Title,
			"description": in.Incident.Description,
			"severity":    string(in.Incident.Severity),
			"source":      string(in.Incident.Source),
			"service":     in.Incident.Service,
		},
		ResponseSchema: `{"summary":string,"agents":[string],"rationale":string}`,
	})
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}

	return Output{
		Summary:    resp.Content,
		Confidence: resp.Confidence,
		Findings:   map[string]any{"planned_by": a.Name()},
		NextAgents: firstWave(),
	}, nil
}

// firstWave is the set of agents that can run without waiting for anyone.
//
// Independent by construction: each reads a different source, none consumes
// another's output, so the orchestrator runs them concurrently. Diagnosis and
// Action are absent precisely because they are not independent.
func firstWave() []agent.Kind {
	return []agent.Kind{
		agent.KindMonitoring,
		agent.KindLogAnalysis,
		agent.KindSecurity,
	}
}

// -----------------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------------

// BuildAll constructs every agent, keyed by kind.
func BuildAll(d Deps) map[agent.Kind]Agent {
	if d.Clock == nil {
		d.Clock = shared.SystemClock{}
	}
	return map[agent.Kind]Agent{
		agent.KindIncidentManager: NewIncidentManager(d),
		agent.KindMonitoring:      NewMonitoring(d),
		agent.KindLogAnalysis:     NewLogAnalysis(d),
		agent.KindSecurity:        NewSecurity(d),
		agent.KindDiagnosis:       NewDiagnosis(d),
		agent.KindAction:          NewAction(d),
		agent.KindDocumentation:   NewDocumentation(d),
	}
}

// Kinds returns the roster in a stable order, for the /agents endpoint.
func Kinds(m map[agent.Kind]Agent) []agent.Kind {
	out := make([]agent.Kind, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// eventTypeFor maps an agent lifecycle moment onto a timeline event type.
func eventTypeFor(started bool) incident.EventType {
	if started {
		return incident.EventAgentStarted
	}
	return incident.EventAgentCompleted
}

// summarise trims an agent summary for a timeline entry, which is bounded.
func summarise(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= incident.MaxEventMessageLen {
		return s
	}
	return s[:incident.MaxEventMessageLen-1] + "…"
}
