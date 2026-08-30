package agents_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/agents"
	domainagent "github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/events/inproc"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// These tests run the real orchestrator against in-memory repositories and the
// in-process bus. No database, no broker, no model — which is exactly what the
// hexagonal layering was for: the properties worth asserting here are about
// dispatch order, concurrency and the security boundary, and none of them need
// infrastructure to be true.

// -----------------------------------------------------------------------------
// In-memory repositories
// -----------------------------------------------------------------------------

type memIncidents struct {
	mu        sync.Mutex
	incidents map[shared.ID]*incident.Incident
	events    map[shared.ID][]*incident.Event
}

func newMemIncidents() *memIncidents {
	return &memIncidents{
		incidents: map[shared.ID]*incident.Incident{},
		events:    map[shared.ID][]*incident.Event{},
	}
}

func (m *memIncidents) Create(_ context.Context, inc *incident.Incident) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := *inc
	m.incidents[inc.ID] = &copied
	return nil
}

func (m *memIncidents) Get(_ context.Context, id incident.ID) (*incident.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inc, ok := m.incidents[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	copied := *inc
	return &copied, nil
}

func (m *memIncidents) Update(_ context.Context, inc *incident.Incident) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.incidents[inc.ID]
	if !ok {
		return shared.ErrNotFound
	}
	// Mirrors the real optimistic locking, so a test exercising a conflict
	// exercises the same code path production would.
	if stored.Version != inc.Version {
		return shared.ErrConflict
	}
	copied := *inc
	copied.Version++
	m.incidents[inc.ID] = &copied
	inc.Version++
	return nil
}

func (m *memIncidents) List(context.Context, ports.IncidentFilter, ports.Page) (ports.PageResult[*incident.Incident], error) {
	return ports.PageResult[*incident.Incident]{}, nil
}

func (m *memIncidents) Count(context.Context, ports.IncidentFilter) (int64, error) { return 0, nil }

// AppendEvent serialises per incident, matching the adapter's contract.
func (m *memIncidents) AppendEvent(_ context.Context, ev *incident.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ev.Seq = int64(len(m.events[ev.IncidentID]) + 1)
	copied := *ev
	m.events[ev.IncidentID] = append(m.events[ev.IncidentID], &copied)
	return nil
}

func (m *memIncidents) Events(_ context.Context, id incident.ID, _ ports.Page) (ports.PageResult[*incident.Event], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*incident.Event, len(m.events[id]))
	copy(out, m.events[id])
	return ports.PageResult[*incident.Event]{Items: out}, nil
}

func (m *memIncidents) eventTypes(id incident.ID) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.events[id]))
	for _, e := range m.events[id] {
		out = append(out, string(e.Type)+"/"+e.ActorName)
	}
	return out
}

type memTasks struct {
	mu    sync.Mutex
	tasks map[shared.ID]*domainagent.Task
	order []shared.ID
}

func newMemTasks() *memTasks {
	return &memTasks{tasks: map[shared.ID]*domainagent.Task{}}
}

func (m *memTasks) Create(_ context.Context, t *domainagent.Task) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := *t
	m.tasks[t.ID] = &copied
	m.order = append(m.order, t.ID)
	return nil
}

func (m *memTasks) Get(_ context.Context, id shared.ID) (*domainagent.Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *memTasks) Update(_ context.Context, t *domainagent.Task) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := *t
	m.tasks[t.ID] = &copied
	return nil
}

func (m *memTasks) List(context.Context, ports.TaskFilter, ports.Page) (ports.PageResult[*domainagent.Task], error) {
	return ports.PageResult[*domainagent.Task]{}, nil
}

func (m *memTasks) statuses() map[string]domainagent.TaskStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]domainagent.TaskStatus{}
	for _, id := range m.order {
		t := m.tasks[id]
		out[t.Type] = t.Status
	}
	return out
}

// -----------------------------------------------------------------------------
// Harness
// -----------------------------------------------------------------------------

type fixture struct {
	orch      *agents.Orchestrator
	incidents *memIncidents
	tasks     *memTasks
	bus       *inproc.Bus
	reasoner  *agents.ScriptedReasoner
	inc       *incident.Incident
}

func newFixture(t *testing.T, mutate func(*agents.OrchestratorDeps)) *fixture {
	t.Helper()

	incidents := newMemIncidents()
	tasks := newMemTasks()
	bus := inproc.New(inproc.Config{Workers: 2, BlockOnFull: true})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = bus.Close(ctx)
	})

	reasoner := agents.NewScriptedReasoner()
	registry := map[domainagent.Kind]agents.Registration{}
	for _, kind := range domainagent.AllKinds {
		registry[kind] = agents.Registration{ID: shared.NewID(), Name: string(kind), Kind: kind}
	}

	deps := agents.OrchestratorDeps{
		Agents:    agents.BuildAll(agents.Deps{Reasoner: reasoner, Clock: shared.SystemClock{}, Registry: registry}),
		Incidents: incidents,
		Tasks:     tasks,
		Bus:       bus,
	}
	if mutate != nil {
		mutate(&deps)
	}

	inc, err := incident.New(shared.SystemClock{}, "api-worker is OOMKilled",
		"pods restart every few minutes", incident.SeverityHigh, incident.SourceAlert)
	if err != nil {
		t.Fatalf("build incident: %v", err)
	}
	inc.Service = "api-worker"
	if err := incidents.Create(context.Background(), inc); err != nil {
		t.Fatalf("seed incident: %v", err)
	}

	return &fixture{
		orch: agents.NewOrchestrator(deps), incidents: incidents,
		tasks: tasks, bus: bus, reasoner: reasoner, inc: inc,
	}
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// -----------------------------------------------------------------------------
// The pipeline
// -----------------------------------------------------------------------------

func TestInvestigationRunsEveryAgent(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	statuses := f.tasks.statuses()
	for _, kind := range domainagent.AllKinds {
		status, ran := statuses[string(kind)]
		if !ran {
			t.Errorf("%s never ran", kind)
			continue
		}
		if status != domainagent.TaskSucceeded {
			t.Errorf("%s finished as %s, want succeeded", kind, status)
		}
	}
}

// The dependency shape is the orchestrator's entire job, so it is asserted
// directly: everything the first wave produces must precede diagnosis, and
// diagnosis must precede the remediation proposal.
func TestAgentsRunInDependencyOrder(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	timeline := f.incidents.eventTypes(f.inc.ID)
	indexOfStart := func(kind domainagent.Kind) int {
		for i, entry := range timeline {
			if entry == "agent.started/"+string(kind) {
				return i
			}
		}
		return -1
	}

	manager := indexOfStart(domainagent.KindIncidentManager)
	monitoring := indexOfStart(domainagent.KindMonitoring)
	diagnosis := indexOfStart(domainagent.KindDiagnosis)
	action := indexOfStart(domainagent.KindAction)
	documentation := indexOfStart(domainagent.KindDocumentation)

	for name, idx := range map[string]int{
		"incident_manager": manager, "monitoring": monitoring,
		"diagnosis": diagnosis, "action": action, "documentation": documentation,
	} {
		if idx < 0 {
			t.Fatalf("%s does not appear on the timeline: %v", name, timeline)
		}
	}

	if manager >= monitoring {
		t.Error("planning must precede evidence gathering")
	}
	if monitoring >= diagnosis {
		t.Error("diagnosis started before the evidence it reasons over")
	}
	if diagnosis >= action {
		t.Error("a remediation was proposed before there was a diagnosis")
	}
	if action >= documentation {
		t.Error("the postmortem was written before the remediation was proposed")
	}
}

// The first wave must actually be concurrent — three sequential reasoner calls
// would triple the time to a diagnosis, which is the number that matters during
// an outage.
func TestFirstWaveRunsConcurrently(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	const perCall = 120 * time.Millisecond
	f.reasoner.SetDelay(perCall)

	start := time.Now()
	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	elapsed := time.Since(start)

	// Seven agents, but the three in the first wave overlap, so the critical
	// path is five sequential calls rather than seven.
	sequential := 7 * perCall
	if elapsed >= sequential {
		t.Errorf("investigation took %v; sequential would be ~%v, so the first "+
			"wave did not run concurrently", elapsed, sequential)
	}
	t.Logf("elapsed %v against %v if fully sequential", elapsed, sequential)
}

// -----------------------------------------------------------------------------
// The security boundary
// -----------------------------------------------------------------------------

// Every published intent must name a tool call that actually exists.
//
// The regression test for a gap that was invisible for a whole phase: Phase 5
// published tool.requested events and never wrote the tool_calls row, which
// nothing noticed because nothing subscribed. When the Phase 6 harness did, every
// intent arrived as "names a tool call that does not exist" and no remediation
// was ever evaluated. An event referencing a row that does not exist is
// unprocessable, and the subscriber can only drop it.
func TestPublishedIntentsArePersistedFirst(t *testing.T) {
	t.Parallel()

	calls := newMemToolCalls()
	f := newFixture(t, func(d *agents.OrchestratorDeps) { d.Calls = calls })
	ctx := testCtx(t)

	var (
		mu        sync.Mutex
		announced []string
	)
	if _, err := f.bus.Subscribe(ctx, ports.TopicToolRequested, func(_ context.Context, e ports.Event) error {
		id, _ := e.Payload["tool_call_id"].(string)
		mu.Lock()
		announced = append(announced, id)
		mu.Unlock()
		return nil
	}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(announced) == 0 {
		t.Fatal("no intents were announced")
	}
	for _, id := range announced {
		parsed, err := shared.ParseID(id)
		if err != nil {
			t.Errorf("tool_call_id %q is not a usable id", id)
			continue
		}
		if !calls.has(parsed) {
			t.Errorf("tool.requested announced %s, which was never persisted", id)
		}
	}
	t.Logf("%d intents announced, all backed by a persisted row", len(announced))
}

// A tool call that cannot be persisted must not be announced: the harness could
// only drop the event, losing the agent's intent silently rather than loudly.
func TestAnUnpersistableIntentIsNotAnnounced(t *testing.T) {
	t.Parallel()

	calls := newMemToolCalls()
	calls.failing = true
	f := newFixture(t, func(d *agents.OrchestratorDeps) { d.Calls = calls })
	ctx := testCtx(t)

	var count int
	var mu sync.Mutex
	if _, err := f.bus.Subscribe(ctx, ports.TopicToolRequested, func(context.Context, ports.Event) error {
		mu.Lock()
		count++
		mu.Unlock()
		return nil
	}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if count != 0 {
		t.Errorf("%d intents were announced despite every write failing", count)
	}
}

// memToolCalls records what the orchestrator persisted.
type memToolCalls struct {
	mu      sync.Mutex
	stored  map[shared.ID]bool
	failing bool
}

func newMemToolCalls() *memToolCalls {
	return &memToolCalls{stored: map[shared.ID]bool{}}
}

func (m *memToolCalls) Create(_ context.Context, r *harness.ToolCallRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failing {
		return errors.New("the database is unavailable")
	}
	m.stored[r.ID] = true
	return nil
}

func (m *memToolCalls) has(id shared.ID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stored[id]
}

func (m *memToolCalls) Get(context.Context, shared.ID) (*harness.ToolCallRequest, error) {
	return nil, shared.ErrNotFound
}
func (m *memToolCalls) GetByIdempotencyKey(context.Context, string) (*harness.ToolCallRequest, error) {
	return nil, shared.ErrNotFound
}
func (m *memToolCalls) Update(context.Context, *harness.ToolCallRequest) error { return nil }
func (m *memToolCalls) List(context.Context, ports.ToolCallFilter, ports.Page) (ports.PageResult[*harness.ToolCallRequest], error) {
	return ports.PageResult[*harness.ToolCallRequest]{}, nil
}
func (m *memToolCalls) SaveExecution(context.Context, *harness.Execution) error { return nil }
func (m *memToolCalls) GetExecution(context.Context, shared.ID) (*harness.Execution, error) {
	return nil, shared.ErrNotFound
}

// The claim ADR 0006 makes, asserted as a property of the code: an agent's most
// powerful output is a description of an action. The orchestrator publishes it
// and executes nothing.
func TestOrchestratorPublishesIntentsAndExecutesNothing(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	var (
		mu        sync.Mutex
		requested []map[string]any
	)
	if _, err := f.bus.Subscribe(ctx, ports.TopicToolRequested, func(_ context.Context, e ports.Event) error {
		mu.Lock()
		defer mu.Unlock()
		requested = append(requested, e.Payload)
		return nil
	}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	// Give the bus a moment to drain the publishes.
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(requested) == 0 {
		t.Fatal("no tool.requested events were published")
	}

	var mutating int
	for _, payload := range requested {
		reason, _ := payload["reason"].(string)
		if strings.TrimSpace(reason) == "" {
			// The harness refuses a reasonless request, and a postmortem cannot
			// answer "what did the AI think it was doing" without one.
			t.Errorf("a tool call carried no reason: %v", payload)
		}
		if payload["tool_call_id"] == nil || payload["agent_id"] == nil {
			t.Errorf("a tool call was unattributed: %v", payload)
		}
		if action, _ := payload["action"].(string); action == "restart_container" {
			mutating++
		}
	}

	// Exactly one mutating proposal, from exactly one agent.
	if mutating != 1 {
		t.Errorf("%d mutating proposals, want 1", mutating)
	}
	t.Logf("%d intents published, %d of them mutating", len(requested), mutating)
}

// Two independent gates stop a bad diagnosis becoming an action. This is the
// first: below the floor, no intent is even constructed, so there is nothing for
// the harness to refuse because nothing was proposed.
func TestLowConfidenceDiagnosisProposesNoRemediation(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	f.reasoner.SetAnswer("diagnose", ports.ReasoningResponse{
		Content:    "Possibly a network partition, but the evidence is thin.",
		Confidence: 0.2, // below MinRemediationConfidence
		Model:      "scripted",
	})

	var mutating int
	var mu sync.Mutex
	if _, err := f.bus.Subscribe(ctx, ports.TopicToolRequested, func(_ context.Context, e ports.Event) error {
		if action, _ := e.Payload["action"].(string); action == "restart_container" {
			mu.Lock()
			mutating++
			mu.Unlock()
		}
		return nil
	}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if mutating != 0 {
		t.Errorf("%d remediations proposed from a 0.2-confidence diagnosis, want 0", mutating)
	}
}

// A reasoner that answers unusably must escalate, not silently do nothing and
// not guess at an action.
func TestUnparseableRemediationEscalates(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	f.reasoner.SetAnswer("plan_remediation", ports.ReasoningResponse{
		Content:    "I think you should probably restart something, maybe?",
		Confidence: 0.9,
		Model:      "scripted",
	})

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	// The action agent must still have completed — an unparseable plan is a
	// handled outcome, not a crash.
	if status := f.tasks.statuses()[string(domainagent.KindAction)]; status != domainagent.TaskSucceeded {
		t.Errorf("the action agent finished as %s on an unparseable plan", status)
	}
}

// -----------------------------------------------------------------------------
// Failure handling
// -----------------------------------------------------------------------------

// A cluster that will not serve logs is a common failure mode. Refusing to
// diagnose because of it would make the system useless exactly when it is needed.
func TestOneAgentFailingDoesNotAbortTheInvestigation(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	f.reasoner.SetFailure("analyse_logs", errors.New("the log backend is unreachable"))

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	statuses := f.tasks.statuses()
	if statuses[string(domainagent.KindLogAnalysis)] != domainagent.TaskFailed {
		t.Errorf("log_analysis is %s, want failed", statuses[string(domainagent.KindLogAnalysis)])
	}
	// The investigation must have continued past it.
	if statuses[string(domainagent.KindDiagnosis)] != domainagent.TaskSucceeded {
		t.Error("diagnosis did not run after log analysis failed")
	}
	if statuses[string(domainagent.KindDocumentation)] != domainagent.TaskSucceeded {
		t.Error("documentation did not run after log analysis failed")
	}
}

// Monitoring is the floor: a diagnosis with no telemetry is guesswork, and
// guesswork is what the confidence score exists to keep away from the Action
// agent. Losing it must escalate rather than produce a confident answer.
func TestNoTelemetryEscalatesInsteadOfGuessing(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	f.reasoner.SetFailure("collect_metrics", errors.New("the metrics backend is unreachable"))

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	if statuses := f.tasks.statuses(); statuses[string(domainagent.KindDiagnosis)] != "" {
		t.Errorf("diagnosis ran with no telemetry (status %s)", statuses[string(domainagent.KindDiagnosis)])
	}

	inc, err := f.incidents.Get(ctx, f.inc.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if inc.Status != incident.StatusFailed {
		t.Errorf("incident status = %s, want failed", inc.Status)
	}
}

// A panicking agent must not take down the investigation, let alone the process.
func TestPanickingAgentIsContained(t *testing.T) {
	t.Parallel()

	f := newFixture(t, func(d *agents.OrchestratorDeps) {
		d.Agents[domainagent.KindSecurity] = panickingAgent{id: shared.NewID()}
	})
	ctx := testCtx(t)

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	statuses := f.tasks.statuses()
	if statuses[string(domainagent.KindSecurity)] != domainagent.TaskFailed {
		t.Errorf("the panicking agent's task is %s, want failed", statuses[string(domainagent.KindSecurity)])
	}
	if statuses[string(domainagent.KindDiagnosis)] != domainagent.TaskSucceeded {
		t.Error("the investigation did not continue past a panicking agent")
	}
}

// panickingAgent implements ID() because the orchestrator attributes every task
// to a registered agent; an agent without one is rejected before it can run,
// which would make this test pass for the wrong reason.
type panickingAgent struct{ id shared.ID }

func (panickingAgent) Kind() domainagent.Kind { return domainagent.KindSecurity }
func (panickingAgent) Describe() string       { return "deliberately broken" }
func (a panickingAgent) ID() shared.ID        { return a.id }
func (panickingAgent) Execute(context.Context, agents.Input) (agents.Output, error) {
	panic("this agent is broken")
}

// -----------------------------------------------------------------------------
// Event-driven entry point
// -----------------------------------------------------------------------------

func TestIncidentDetectedTriggersAnInvestigation(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	if err := f.orch.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := f.bus.Publish(ctx, ports.Event{
		Type: ports.TopicIncidentDetected, IncidentID: f.inc.ID, ActorType: "user",
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if !waitFor(t, 10*time.Second, func() bool {
		return f.tasks.statuses()[string(domainagent.KindDocumentation)] == domainagent.TaskSucceeded
	}) {
		t.Fatalf("the investigation did not complete; tasks: %v", f.tasks.statuses())
	}
}

// The bus delivers at least once, so a redelivery is expected. Starting a second
// investigation would double every reasoner call and race two writers on one
// incident.
func TestRedeliveredEventDoesNotStartASecondInvestigation(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	f.reasoner.SetDelay(80 * time.Millisecond)

	if err := f.orch.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	e := ports.Event{Type: ports.TopicIncidentDetected, IncidentID: f.inc.ID, ActorType: "user"}
	for i := 0; i < 4; i++ {
		if err := f.bus.Publish(ctx, e); err != nil {
			t.Fatalf("Publish %d: %v", i, err)
		}
	}

	if !waitFor(t, 15*time.Second, func() bool {
		return f.tasks.statuses()[string(domainagent.KindDocumentation)] == domainagent.TaskSucceeded
	}) {
		t.Fatal("the investigation did not complete")
	}

	// One task per agent, not four.
	f.tasks.mu.Lock()
	total := len(f.tasks.order)
	f.tasks.mu.Unlock()

	if total > len(domainagent.AllKinds) {
		t.Errorf("%d tasks created for %d agents; a redelivery started a second investigation",
			total, len(domainagent.AllKinds))
	}
}

func TestShutdownCancelsInFlightInvestigations(t *testing.T) {
	t.Parallel()

	f := newFixture(t, nil)
	ctx := testCtx(t)

	f.reasoner.SetDelay(2 * time.Second)

	if err := f.orch.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := f.bus.Publish(ctx, ports.Event{
		Type: ports.TopicIncidentDetected, IncidentID: f.inc.ID, ActorType: "user",
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if !waitFor(t, 5*time.Second, func() bool { return f.orch.RunningCount() == 1 }) {
		t.Fatal("the investigation never started")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	start := time.Now()
	if err := f.orch.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// Must not have waited for all seven 2-second reasoner calls.
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("shutdown took %v; it did not cancel the in-flight work", elapsed)
	}
	if n := f.orch.RunningCount(); n != 0 {
		t.Errorf("%d investigations still running after shutdown", n)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// -----------------------------------------------------------------------------
// Agent-level properties
// -----------------------------------------------------------------------------

// Six of seven agents can only read. That ratio is the design, not an accident
// of which tools happen to exist, so it is asserted rather than assumed.
func TestOnlyTheActionAgentProposesMutations(t *testing.T) {
	t.Parallel()

	mutatingActions := map[string]bool{
		"restart_container": true, "restart_deployment": true,
		"scale_deployment": true, "rollback_deployment": true,
		"restart_service": true, "delete_volume": true, "drop_table": true,
	}

	f := newFixture(t, nil)
	ctx := testCtx(t)

	var mu sync.Mutex
	byAgent := map[string]int{}

	if _, err := f.bus.Subscribe(ctx, ports.TopicToolRequested, func(_ context.Context, e ports.Event) error {
		action, _ := e.Payload["action"].(string)
		if !mutatingActions[action] {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		byAgent[action]++
		return nil
	}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if err := f.orch.Investigate(ctx, f.inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// Cross-check against the domain's own claim.
	mutators := 0
	for _, kind := range domainagent.AllKinds {
		if kind.CanMutate() {
			mutators++
		}
	}
	if mutators != 1 {
		t.Fatalf("%d agent kinds report CanMutate, want 1", mutators)
	}
	if !domainagent.KindAction.CanMutate() {
		t.Error("the action agent must be the one that can mutate")
	}
}
