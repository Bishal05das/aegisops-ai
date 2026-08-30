package agents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// Orchestrator runs investigations.
//
// # Why phases rather than a flat fan-out
//
// The seven agents are not peers. Monitoring, Log Analysis and Security read
// different sources and depend on nothing, so they run concurrently — three
// reasoner calls in the time of one. Diagnosis cannot start until they finish,
// because reasoning over absent evidence is guesswork. Action cannot start until
// Diagnosis produces a confidence score, because that score is what decides
// whether a remediation may be proposed at all.
//
// That dependency shape is the orchestrator's entire job, and it is why this is
// not a worker pool over a queue of agents.
//
// # What it does not do
//
// It does not execute tool calls. Agents return intents; the orchestrator
// publishes them as tool.requested and the harness decides. Wiring the
// orchestrator directly to a tool would collapse the boundary the whole design
// rests on, so it holds no tool client and imports no tool package.
type Orchestrator struct {
	agents    map[agent.Kind]Agent
	incidents ports.IncidentRepository
	tasks     ports.TaskRepository
	// calls persists an agent's intent before it is announced. Without it the
	// harness receives an event naming a row that does not exist.
	calls ports.ToolCallRepository
	bus   ports.EventBus
	clock shared.Clock
	log   *slog.Logger

	cfg OrchestratorConfig

	// running tracks in-flight investigations so Shutdown can wait for them and
	// so a duplicate IncidentDetected does not start a second one.
	mu      sync.Mutex
	running map[shared.ID]context.CancelFunc

	wg sync.WaitGroup
}

// OrchestratorConfig tunes the engine.
type OrchestratorConfig struct {
	// AgentTimeout bounds one agent's execution. Applied per agent rather than
	// per investigation, so one slow specialist cannot consume the whole budget.
	AgentTimeout time.Duration

	// InvestigationTimeout bounds the whole pipeline.
	InvestigationTimeout time.Duration

	// MaxConcurrentInvestigations bounds how many incidents are worked at once.
	//
	// Necessary because a reasoner is memory-hungry: a 7B model serving twenty
	// concurrent investigations will swap, and every investigation then takes
	// longer than the outage they are meant to shorten.
	MaxConcurrentInvestigations int

	// FailOnAgentError decides whether one agent's failure aborts the
	// investigation. Default false: a cluster that will not serve logs is a
	// common failure mode, and refusing to diagnose because of it would make
	// the system useless exactly when it is needed.
	FailOnAgentError bool
}

// Defaults for OrchestratorConfig.
const (
	DefaultAgentTimeout         = 2 * time.Minute
	DefaultInvestigationTimeout = 15 * time.Minute
	DefaultMaxConcurrent        = 4
)

// OrchestratorDeps are the collaborators the engine needs.
type OrchestratorDeps struct {
	Agents    map[agent.Kind]Agent
	Incidents ports.IncidentRepository
	Tasks     ports.TaskRepository
	Calls     ports.ToolCallRepository
	Bus       ports.EventBus
	Clock     shared.Clock
	Logger    *slog.Logger
	Config    OrchestratorConfig
}

// NewOrchestrator builds the engine.
func NewOrchestrator(d OrchestratorDeps) *Orchestrator {
	cfg := d.Config
	if cfg.AgentTimeout <= 0 {
		cfg.AgentTimeout = DefaultAgentTimeout
	}
	if cfg.InvestigationTimeout <= 0 {
		cfg.InvestigationTimeout = DefaultInvestigationTimeout
	}
	if cfg.MaxConcurrentInvestigations <= 0 {
		cfg.MaxConcurrentInvestigations = DefaultMaxConcurrent
	}
	clock := d.Clock
	if clock == nil {
		clock = shared.SystemClock{}
	}
	log := d.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	return &Orchestrator{
		agents: d.Agents, incidents: d.Incidents, tasks: d.Tasks,
		calls: d.Calls, bus: d.Bus,
		clock: clock, log: log, cfg: cfg,
		running: make(map[shared.ID]context.CancelFunc),
	}
}

// Start subscribes the orchestrator to the events it reacts to.
//
// Event-driven rather than called directly: the API creates an incident and
// publishes a fact. Whether anything investigates it is not the API's concern,
// which is what lets the orchestrator be scaled, restarted or disabled without
// the API knowing.
func (o *Orchestrator) Start(ctx context.Context) error {
	const op = "agents.Orchestrator.Start"

	if _, err := o.bus.Subscribe(ctx, ports.TopicIncidentDetected, o.onIncidentDetected); err != nil {
		return fmt.Errorf("%s: subscribe to %s: %w", op, ports.TopicIncidentDetected, err)
	}

	o.log.Info("orchestrator started",
		"agents", len(o.agents),
		"max_concurrent", o.cfg.MaxConcurrentInvestigations,
		"agent_timeout", o.cfg.AgentTimeout.String())
	return nil
}

// Shutdown cancels in-flight investigations and waits for them to unwind.
func (o *Orchestrator) Shutdown(ctx context.Context) error {
	o.mu.Lock()
	for id, cancel := range o.running {
		o.log.Info("cancelling an in-flight investigation", "incident_id", id.String())
		cancel()
	}
	o.mu.Unlock()

	done := make(chan struct{})
	go func() {
		o.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("agents.Orchestrator.Shutdown: investigations did not stop: %w", ctx.Err())
	}
}

// onIncidentDetected reacts to a new incident.
func (o *Orchestrator) onIncidentDetected(ctx context.Context, e ports.Event) error {
	if e.IncidentID.IsZero() {
		// Nothing to investigate, and returning an error would have the bus
		// retry a message that can never succeed.
		o.log.Warn("incident.detected carried no incident id", "event_id", e.ID)
		return nil
	}

	o.mu.Lock()
	if _, already := o.running[e.IncidentID]; already {
		o.mu.Unlock()
		// The bus delivers at least once, so a redelivery is expected and is
		// not an error. Starting a second investigation would double every
		// reasoner call and race two writers on one incident.
		o.log.Debug("investigation already running; ignoring a redelivery",
			"incident_id", e.IncidentID.String())
		return nil
	}
	if len(o.running) >= o.cfg.MaxConcurrentInvestigations {
		o.mu.Unlock()
		// Returning an error asks the bus to redeliver with backoff, which is
		// exactly right: the work is still wanted, just not now.
		o.log.Warn("at the concurrent investigation limit; deferring",
			"incident_id", e.IncidentID.String(),
			"limit", o.cfg.MaxConcurrentInvestigations)
		return fmt.Errorf("orchestrator is at its concurrency limit")
	}

	// Detached from the bus's delivery context, which is cancelled as soon as
	// the handler returns. An investigation outlives the event that triggered
	// it by minutes, so inheriting that context would kill it immediately.
	// Values are kept so correlation survives; only cancellation is dropped.
	invCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), o.cfg.InvestigationTimeout)
	o.running[e.IncidentID] = cancel
	o.mu.Unlock()

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer func() {
			cancel()
			o.mu.Lock()
			delete(o.running, e.IncidentID)
			o.mu.Unlock()
		}()

		if err := o.Investigate(invCtx, e.IncidentID); err != nil {
			o.log.Error("investigation failed",
				"incident_id", e.IncidentID.String(), "error", err)
		}
	}()

	return nil
}

// Investigate runs the full pipeline for one incident.
//
// Exported so it can be driven directly in tests and, later, triggered manually
// through the API — but the production path is always the event.
func (o *Orchestrator) Investigate(ctx context.Context, incidentID shared.ID) error {
	const op = "agents.Orchestrator.Investigate"

	ctx = logger.WithIncidentID(ctx, incidentID.String())
	log := o.log.With("incident_id", incidentID.String())

	inc, loadErr := o.incidents.Get(ctx, incidentID)
	if loadErr != nil {
		return fmt.Errorf("%s: load incident: %w", op, loadErr)
	}
	if !inc.Status.Active() {
		log.Info("incident is no longer active; not investigating", "status", string(inc.Status))
		return nil
	}

	started := o.clock.Now()
	log.Info("investigation started", "title", inc.Title, "severity", string(inc.Severity))

	evidence := NewEvidence()

	if err := o.transition(ctx, inc, incident.StatusInvestigating); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// ---- plan --------------------------------------------------------------
	// Advisory. The orchestrator owns the dependency ordering because that is
	// what makes the phases correct; a manager that could reorder them could
	// have Diagnosis run before there was anything to diagnose.
	if out, err := o.runAgent(ctx, inc, agent.KindIncidentManager, evidence); err != nil {
		log.Warn("planning failed; proceeding with the standard investigation", "error", err)
	} else {
		evidence.Record(agent.KindIncidentManager, out)
	}

	// ---- wave one: independent evidence gathering, concurrent --------------
	o.runConcurrently(ctx, inc, firstWave(), evidence)

	if !evidence.Complete() {
		// Monitoring is the floor. Without it there is nothing to reason over,
		// and a diagnosis produced anyway would carry unearned confidence.
		log.Warn("no monitoring evidence; escalating instead of diagnosing")
		return o.fail(ctx, inc, "evidence gathering produced no telemetry to reason over")
	}

	// ---- wave two: diagnosis ----------------------------------------------
	if err := o.transition(ctx, inc, incident.StatusDiagnosing); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	diagnosis, err := o.runAgent(ctx, inc, agent.KindDiagnosis, evidence)
	if err != nil {
		log.Error("diagnosis failed", "error", err)
		return o.fail(ctx, inc, "the diagnosis agent could not reach a conclusion")
	}
	evidence.Record(agent.KindDiagnosis, diagnosis)

	if applyErr := o.applyDiagnosis(ctx, inc, diagnosis); applyErr != nil {
		log.Warn("could not persist the diagnosis", "error", applyErr)
	}

	// ---- wave three: remediation proposal ----------------------------------
	remediation, err := o.runAgent(ctx, inc, agent.KindAction, evidence)
	if err != nil {
		log.Error("remediation planning failed", "error", err)
	} else {
		evidence.Record(agent.KindAction, remediation)
	}

	// Every intent goes to the harness. The orchestrator never executes one.
	proposed := o.publishIntents(ctx, inc, remediation.ToolCalls)

	switch {
	case proposed > 0:
		// The harness moves the incident on from here — to awaiting_approval or
		// straight to remediating, depending on risk. The orchestrator's job
		// ends at proposing.
		log.Info("remediation proposed; handing off to the harness", "tool_calls", proposed)
	default:
		log.Info("no remediation proposed; this incident needs a human")
	}

	// ---- wave four: documentation ------------------------------------------
	// Runs regardless of whether a remediation was proposed. An incident that
	// could not be remediated is exactly the one worth writing up.
	if doc, err := o.runAgent(ctx, inc, agent.KindDocumentation, evidence); err != nil {
		log.Warn("documentation failed", "error", err)
	} else {
		evidence.Record(agent.KindDocumentation, doc)
		o.appendEvent(ctx, inc, incident.EventNoteAdded, "documentation",
			summarise(doc.Summary))
	}

	log.Info("investigation complete",
		"duration", time.Since(started).String(),
		"agents_run", evidence.AgentCount(),
		"agents_failed", evidence.FailureCount(),
		"tool_calls_proposed", proposed)

	return nil
}

// runConcurrently runs a set of independent agents at the same time.
//
// Each gets a snapshot of the evidence, so concurrent reads cannot race against
// another agent's write. Results are folded back under a mutex.
func (o *Orchestrator) runConcurrently(ctx context.Context, inc *incident.Incident, kinds []agent.Kind, evidence *Evidence) {
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)

	for _, kind := range kinds {
		wg.Add(1)
		go func(kind agent.Kind) {
			defer wg.Done()

			// A detached snapshot: handing every goroutine the live map would
			// be a data race, and Go maps only sometimes panic on one.
			snapshot := evidence.Snapshot()

			out, err := o.runAgentWithEvidence(ctx, inc, kind, snapshot)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// Recorded rather than discarded: "log analysis could not reach
				// the cluster" is itself evidence, and a diagnosis reached
				// without it should be able to say so.
				evidence.RecordError(kind, err)
				return
			}
			evidence.Record(kind, out)
			o.publishIntents(ctx, inc, out.ToolCalls)
		}(kind)
	}
	wg.Wait()
}

// runAgent runs one agent against the live evidence.
func (o *Orchestrator) runAgent(ctx context.Context, inc *incident.Incident, kind agent.Kind, evidence *Evidence) (Output, error) {
	return o.runAgentWithEvidence(ctx, inc, kind, evidence)
}

// runAgentWithEvidence creates a task, runs the agent, and records the outcome.
func (o *Orchestrator) runAgentWithEvidence(ctx context.Context, inc *incident.Incident, kind agent.Kind, evidence *Evidence) (Output, error) {
	const op = "agents.Orchestrator.runAgent"

	impl, ok := o.agents[kind]
	if !ok {
		return Output{}, fmt.Errorf("%s: no agent registered for kind %q", op, kind)
	}

	task, err := o.createTask(ctx, inc, impl, kind)
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", op, err)
	}

	o.publish(ctx, inc, ports.TopicAgentStarted, string(kind), map[string]any{
		"task_id": task.ID.String(), "agent": string(kind),
	})
	o.appendEvent(ctx, inc, eventTypeFor(true), string(kind),
		fmt.Sprintf("%s started", kind))

	// Per-agent timeout, so one slow specialist cannot consume the whole
	// investigation budget.
	runCtx, cancel := context.WithTimeout(ctx, o.cfg.AgentTimeout)
	defer cancel()

	started := o.clock.Now()
	out, execErr := o.safeExecute(runCtx, impl, Input{
		Incident: inc,
		Task:     task,
		Evidence: evidence,
	})
	elapsed := time.Since(started)

	if execErr != nil {
		o.finishTask(ctx, task, nil, execErr)
		o.publish(ctx, inc, ports.TopicAgentFailed, string(kind), map[string]any{
			"task_id": task.ID.String(), "error": execErr.Error(),
			"duration_ms": elapsed.Milliseconds(),
		})
		o.appendEvent(ctx, inc, incident.EventAgentFailed, string(kind),
			fmt.Sprintf("%s failed: %s", kind, execErr.Error()))
		return Output{}, execErr
	}

	o.finishTask(ctx, task, out.Findings, nil)
	o.publish(ctx, inc, ports.TopicAgentCompleted, string(kind), map[string]any{
		"task_id": task.ID.String(), "confidence": out.Confidence,
		"tool_calls": len(out.ToolCalls), "duration_ms": elapsed.Milliseconds(),
	})
	o.appendEvent(ctx, inc, eventTypeFor(false), string(kind), summarise(out.Summary))

	o.log.Debug("agent completed",
		"agent", string(kind), "confidence", out.Confidence,
		"tool_calls", len(out.ToolCalls), "duration", elapsed.String())

	return out, nil
}

// safeExecute runs an agent, converting a panic into an error.
//
// A panicking agent must not take down the investigation, let alone the process.
// One broken specialist is a failed task; the other six can still contribute.
func (o *Orchestrator) safeExecute(ctx context.Context, impl Agent, in Input) (out Output, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("agent %s panicked: %v", impl.Kind(), p)
			o.log.Error("agent panicked",
				"agent", string(impl.Kind()), "panic", fmt.Sprint(p),
				"incident_id", in.Incident.ID.String())
		}
	}()
	return impl.Execute(ctx, in)
}

// publishIntents persists each tool call and emits it as a tool.requested event.
//
// This is the handoff, and the only thing the orchestrator does with an intent.
// The harness subscribes to tool.requested and decides.
//
// # Persist, then publish
//
// The row is written before the event that names it, for the same reason the
// incident service commits before announcing: an event referencing a row that
// does not exist is unprocessable, and the subscriber can only drop it.
//
// Getting this backwards is exactly the bug this ordering was written to fix.
// Phase 5 published the event and never wrote the row — invisible at the time,
// because nothing subscribed. The moment the harness did, every single intent
// arrived as "tool.requested names a tool call that does not exist" and no
// remediation was ever evaluated.
//
// A crash between the write and the publish leaves a `pending` row with no
// event, which is recoverable by a sweep. The reverse leaves nothing to recover.
func (o *Orchestrator) publishIntents(ctx context.Context, inc *incident.Incident, calls []*harness.ToolCallRequest) int {
	published := 0
	for _, call := range calls {
		if call == nil {
			continue
		}

		if o.calls != nil {
			if err := o.calls.Create(ctx, call); err != nil {
				// Do not publish an event whose row failed to write: the harness
				// would only be able to drop it, and the agent's intent would be
				// lost silently rather than loudly.
				o.log.Error("could not persist a tool call; not publishing it",
					"incident_id", inc.ID.String(), "call", call.Tool+"."+call.Action,
					"agent", call.AgentName, "error", err)
				continue
			}
		}

		o.publish(ctx, inc, ports.TopicToolRequested, call.AgentName, map[string]any{
			"tool_call_id": call.ID.String(),
			"tool":         call.Tool,
			"action":       call.Action,
			"params":       call.Params,
			// Carried verbatim. A postmortem asking "what did the AI think it
			// was doing" is answerable only if this survives unedited.
			"reason":     call.Reason,
			"confidence": call.Confidence,
			"agent_id":   call.AgentID.String(),
		})
		o.appendEvent(ctx, inc, incident.EventToolRequested, call.AgentName,
			fmt.Sprintf("%s requested %s.%s", call.AgentName, call.Tool, call.Action))
		published++
	}
	return published
}

// createTask persists a unit of agent work before it runs.
//
// Written before execution rather than after, so a crash mid-investigation
// leaves a `running` task rather than no record at all — the difference between
// "we know an agent was working and did not finish" and silence.
func (o *Orchestrator) createTask(ctx context.Context, inc *incident.Incident, impl Agent, kind agent.Kind) (*agent.Task, error) {
	agentID := shared.Nil
	if withID, ok := impl.(interface{ ID() shared.ID }); ok {
		agentID = withID.ID()
	}
	// Named explicitly rather than left to NewTask's validator. Every task and
	// every tool call is attributed to an agent row, so an unregistered agent
	// fails here — and "not registered" is a startup reconciliation problem,
	// which a generic "agent_id must not be zero" would send someone hunting for
	// in the wrong place.
	if agentID.IsZero() {
		return nil, fmt.Errorf("agent %s has no registered identity: it is missing "+
			"from the agents table, so its work cannot be attributed", kind)
	}

	task, err := agent.NewTask(o.clock, inc.ID, agentID, string(kind))
	if err != nil {
		return nil, fmt.Errorf("build task: %w", err)
	}
	if err := task.Start(o.clock); err != nil {
		return nil, fmt.Errorf("start task: %w", err)
	}

	if o.tasks != nil {
		if err := o.tasks.Create(ctx, task); err != nil {
			return nil, fmt.Errorf("persist task: %w", err)
		}
	}
	o.publish(ctx, inc, ports.TopicTaskCreated, string(kind), map[string]any{
		"task_id": task.ID.String(), "type": string(kind),
	})
	return task, nil
}

// finishTask records a task's outcome.
func (o *Orchestrator) finishTask(ctx context.Context, task *agent.Task, output map[string]any, execErr error) {
	if o.tasks == nil {
		return
	}

	var domainErr error
	if execErr != nil {
		domainErr = task.Fail(o.clock, execErr.Error())
	} else {
		domainErr = task.Succeed(o.clock, output)
	}
	if domainErr != nil {
		o.log.Warn("could not transition a task", "task_id", task.ID.String(), "error", domainErr)
		return
	}
	if err := o.tasks.Update(ctx, task); err != nil {
		// Non-fatal: the agent's work is done and recorded on the timeline.
		// Failing the investigation because a status column did not update
		// would be the wrong trade.
		o.log.Warn("could not persist a task's outcome",
			"task_id", task.ID.String(), "error", err)
	}
}

// transition moves the incident's lifecycle state and persists it.
func (o *Orchestrator) transition(ctx context.Context, inc *incident.Incident, next incident.Status) error {
	if err := inc.TransitionTo(o.clock, next); err != nil {
		if errors.Is(err, shared.ErrConflict) {
			// Someone else advanced the incident. Not fatal: the state machine
			// refused an invalid move, which is it working.
			o.log.Debug("skipping an invalid transition",
				"from", string(inc.Status), "to", string(next))
			return nil
		}
		return fmt.Errorf("transition to %s: %w", next, err)
	}

	if err := o.incidents.Update(ctx, inc); err != nil {
		if errors.Is(err, shared.ErrConflict) {
			// Optimistic locking caught a concurrent writer. Re-read and let
			// the next step work from current state rather than overwriting.
			o.log.Warn("incident was modified concurrently; re-reading", "status", string(next))
			fresh, getErr := o.incidents.Get(ctx, inc.ID)
			if getErr == nil {
				*inc = *fresh
			}
			return nil
		}
		return fmt.Errorf("persist status %s: %w", next, err)
	}

	o.publish(ctx, inc, ports.TopicIncidentStatusChanged, "orchestrator", map[string]any{
		"status": string(next),
	})
	return nil
}

// applyDiagnosis writes the root cause and confidence onto the incident.
func (o *Orchestrator) applyDiagnosis(ctx context.Context, inc *incident.Incident, out Output) error {
	rootCause, _ := out.Findings[FindingRootCause].(string)
	if rootCause == "" {
		rootCause = out.Summary
	}
	if err := inc.SetDiagnosis(o.clock, rootCause, out.Confidence); err != nil {
		return fmt.Errorf("set diagnosis: %w", err)
	}
	if err := o.incidents.Update(ctx, inc); err != nil {
		return fmt.Errorf("persist diagnosis: %w", err)
	}

	o.publish(ctx, inc, ports.TopicIncidentDiagnosed, "diagnosis", map[string]any{
		"root_cause": rootCause, "confidence": out.Confidence,
	})
	o.appendEvent(ctx, inc, incident.EventDiagnosisReached, "diagnosis", summarise(rootCause))
	return nil
}

// fail moves the incident to failed with a reason.
func (o *Orchestrator) fail(ctx context.Context, inc *incident.Incident, reason string) error {
	o.appendEvent(ctx, inc, incident.EventAgentFailed, "orchestrator", reason)
	if err := o.transition(ctx, inc, incident.StatusFailed); err != nil {
		return err
	}
	return nil
}

// publish emits an event, never failing the caller.
//
// A bus write that fails must not fail the investigation it describes: the work
// is real whether or not anyone was told. Logged at warn so the gap is visible.
func (o *Orchestrator) publish(ctx context.Context, inc *incident.Incident, topic, actor string, payload map[string]any) {
	if o.bus == nil {
		return
	}
	err := o.bus.Publish(ctx, ports.Event{
		Type:       topic,
		IncidentID: inc.ID,
		ActorType:  "agent",
		ActorName:  actor,
		Payload:    payload,
		OccurredAt: o.clock.Now(),
	})
	if err != nil {
		o.log.Warn("could not publish an event", "topic", topic, "error", err)
	}
}

// appendEvent adds an entry to the incident's timeline.
//
// Also never fails the caller, for the same reason — but at warn rather than
// silence, because a timeline with a hole in it is how a postmortem reaches the
// wrong conclusion.
func (o *Orchestrator) appendEvent(ctx context.Context, inc *incident.Incident, typ incident.EventType, actorName, message string) {
	ev, err := incident.NewEvent(o.clock, inc.ID, typ, incident.ActorAgent, message)
	if err != nil {
		o.log.Warn("could not build a timeline event", "type", string(typ), "error", err)
		return
	}
	ev.ActorName = actorName

	if err := o.incidents.AppendEvent(ctx, ev); err != nil {
		o.log.Warn("could not append to the incident timeline",
			"type", string(typ), "error", err)
	}
}

// RunningCount reports how many investigations are in flight, for a metrics
// gauge and for tests asserting the concurrency limit holds.
func (o *Orchestrator) RunningCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.running)
}
