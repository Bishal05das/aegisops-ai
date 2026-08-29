//go:build integration

package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/agents"
	domainagent "github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/events/inproc"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/repository/postgres"
)

// The unit tests run the orchestrator against in-memory repositories, which
// proves the phasing and the security boundary. What they cannot prove is that
// the *persistence* holds up: seven agents writing a shared timeline from three
// concurrent goroutines is a database problem, and an in-memory map with one
// mutex will happily pass a test the real schema fails.
//
// This file is the counterpart. Everything here needs live Postgres.

// registerTestAgents reconciles a roster and returns registrations bound to the
// real rows, because every task and tool call is attributed to an agents row and
// a foreign key will reject an invented ID.
func registerTestAgents(t *testing.T, ctx context.Context, repo *postgres.AgentRepo) map[domainagent.Kind]agents.Registration {
	t.Helper()

	out := make(map[domainagent.Kind]agents.Registration, len(domainagent.AllKinds))
	for _, kind := range domainagent.AllKinds {
		a, err := domainagent.New(clock, string(kind), kind, "integration test agent")
		if err != nil {
			t.Fatalf("build agent %s: %v", kind, err)
		}
		// Upsert fills in the ID: on a re-run it returns the existing row's,
		// which is what the foreign keys on agent_tasks and tool_calls expect.
		if err := repo.Upsert(ctx, a); err != nil {
			t.Fatalf("register agent %s: %v", kind, err)
		}
		out[kind] = agents.Registration{ID: a.ID, Name: a.Name, Kind: kind}
	}
	return out
}

func newBus(t *testing.T) *inproc.Bus {
	t.Helper()
	bus := inproc.New(inproc.Config{Workers: 4, BlockOnFull: true})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = bus.Close(ctx)
	})
	return bus
}

// TestFullInvestigationPersists runs a complete investigation against the real
// schema and checks what a responder would actually read afterwards.
func TestFullInvestigationPersists(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)

	incidents := postgres.NewIncidentRepo(db)
	tasks := postgres.NewTaskRepo(db)
	agentRepo := postgres.NewAgentRepo(db)

	registry := registerTestAgents(t, ctx, agentRepo)
	inc := seedIncident(t, ctx, db, incidents, "integration: api-worker OOMKilled")

	orch := agents.NewOrchestrator(agents.OrchestratorDeps{
		Agents: agents.BuildAll(agents.Deps{
			Reasoner: agents.NewScriptedReasoner(), Clock: clock, Registry: registry,
		}),
		Incidents: incidents, Tasks: tasks, Bus: newBus(t),
	})

	if err := orch.Investigate(ctx, inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	// Every agent left a durable task row.
	res, err := tasks.List(ctx, ports.TaskFilter{IncidentID: &inc.ID}, ports.Page{Limit: 100})
	if err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	seen := map[string]domainagent.TaskStatus{}
	for _, task := range res.Items {
		seen[task.Type] = task.Status
	}
	for _, kind := range domainagent.AllKinds {
		if status, ok := seen[string(kind)]; !ok {
			t.Errorf("no task row for %s", kind)
		} else if status != domainagent.TaskSucceeded {
			t.Errorf("%s persisted as %s, want succeeded", kind, status)
		}
	}

	// The diagnosis was written back to the aggregate through optimistic
	// locking, so a concurrent close would have been rejected rather than lost.
	reloaded, err := incidents.Get(ctx, inc.ID)
	if err != nil {
		t.Fatalf("reload incident: %v", err)
	}
	if reloaded.RootCause == "" {
		t.Error("the incident has no root cause after a full investigation")
	}
	if reloaded.Version <= inc.Version {
		t.Errorf("version %d did not advance from %d", reloaded.Version, inc.Version)
	}
	t.Logf("root cause: %q (confidence %.2f, version %d)",
		reloaded.RootCause, reloaded.Confidence, reloaded.Version)
}

// TestTimelineIsGaplessUnderConcurrency is the regression test for the bug this
// phase found.
//
// The first wave writes agent.started and agent.completed from three goroutines
// at once. Sequence numbers were assigned with a read-then-insert, so two
// concurrent appends read the same max(seq) and one lost a unique-constraint
// race — the repository returned ErrConflict documenting "the caller retries",
// and the orchestrator, like every caller, only logged a warning. The visible
// symptom was an incident whose timeline was missing entries for whichever agent
// lost: a responder reading the timeline saw tool requests from an agent that
// apparently never started.
//
// The fix was a per-incident advisory lock inside AppendEvent, so serialisation
// is the adapter's job rather than an obligation on every caller. This asserts
// the property that matters: no gaps, no duplicates, nothing dropped.
func TestTimelineIsGaplessUnderConcurrency(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)

	incidents := postgres.NewIncidentRepo(db)
	inc := seedIncident(t, ctx, db, incidents, "integration: concurrent timeline appends")

	const (
		writers   = 8
		perWriter = 12
		wantTotal = writers * perWriter
	)

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	start := make(chan struct{})

	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start // release all writers at once, to maximise contention
			for i := range perWriter {
				ev, err := incident.NewEvent(clock, inc.ID, incident.EventAgentStarted,
					incident.ActorAgent, fmt.Sprintf("append %d from writer %d", i, w))
				if err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
					return
				}
				ev.ActorName = fmt.Sprintf("writer-%d", w)
				if err := incidents.AppendEvent(ctx, ev); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("writer %d append %d: %w", w, i, err))
					mu.Unlock()
					return
				}
			}
		}(w)
	}
	close(start)
	wg.Wait()

	// Not one append may fail. Before the fix this reported dozens of conflicts.
	if len(errs) > 0 {
		t.Fatalf("%d appends failed; first: %v", len(errs), errs[0])
	}

	page, err := incidents.Events(ctx, inc.ID, ports.Page{Limit: wantTotal + 10})
	if err != nil {
		t.Fatalf("read timeline: %v", err)
	}
	if len(page.Items) != wantTotal {
		t.Fatalf("timeline holds %d entries, want %d — appends were dropped",
			len(page.Items), wantTotal)
	}

	// Sequence numbers must be exactly 1..N: contiguous (no gap, so nothing was
	// silently skipped) and unique (no duplicate, so nothing was overwritten).
	seen := make(map[int64]bool, wantTotal)
	for _, e := range page.Items {
		if seen[e.Seq] {
			t.Errorf("sequence %d assigned twice", e.Seq)
		}
		seen[e.Seq] = true
	}
	for want := int64(1); want <= wantTotal; want++ {
		if !seen[want] {
			t.Errorf("sequence %d is missing from the timeline", want)
		}
	}
}

// TestInvestigationTimelineTellsTheWholeStory checks the ordering guarantee a
// responder actually relies on: every agent that requested a tool must have a
// preceding started entry. This is the exact symptom the dropped-append bug
// produced, asserted end to end rather than at the repository.
func TestInvestigationTimelineTellsTheWholeStory(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)

	incidents := postgres.NewIncidentRepo(db)
	tasks := postgres.NewTaskRepo(db)
	registry := registerTestAgents(t, ctx, postgres.NewAgentRepo(db))
	inc := seedIncident(t, ctx, db, incidents, "integration: timeline narrative")

	orch := agents.NewOrchestrator(agents.OrchestratorDeps{
		Agents: agents.BuildAll(agents.Deps{
			Reasoner: agents.NewScriptedReasoner(), Clock: clock, Registry: registry,
		}),
		Incidents: incidents, Tasks: tasks, Bus: newBus(t),
	})
	if err := orch.Investigate(ctx, inc.ID); err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	page, err := incidents.Events(ctx, inc.ID, ports.Page{Limit: 200})
	if err != nil {
		t.Fatalf("read timeline: %v", err)
	}

	started := map[string]int64{}
	completed := map[string]int64{}
	for _, e := range page.Items {
		switch e.Type {
		case incident.EventAgentStarted:
			started[e.ActorName] = e.Seq
		case incident.EventAgentCompleted:
			completed[e.ActorName] = e.Seq
		case incident.EventToolRequested:
			if _, ok := started[e.ActorName]; !ok {
				t.Errorf("%s requested a tool at seq %d but never appears as started "+
					"— a timeline append was dropped", e.ActorName, e.Seq)
			}
		}
	}

	for _, kind := range domainagent.AllKinds {
		name := string(kind)
		s, ok := started[name]
		if !ok {
			t.Errorf("%s never appears on the timeline", name)
			continue
		}
		c, ok := completed[name]
		if !ok {
			t.Errorf("%s started but never completed", name)
			continue
		}
		if c <= s {
			t.Errorf("%s completed (seq %d) before it started (seq %d)", name, c, s)
		}
	}

	// Sequence numbers are dense across the whole investigation.
	for i, e := range page.Items {
		if want := int64(i + 1); e.Seq != want {
			t.Fatalf("timeline has a gap: entry %d carries seq %d", i, e.Seq)
		}
	}
	t.Logf("%d timeline entries, contiguous, all seven agents accounted for", len(page.Items))
}

// TestConcurrentInvestigationsDoNotInterfere runs several incidents at once,
// which is the normal case during a real outage: one root cause trips many
// alerts. The advisory lock is taken per incident, so these must not serialise
// against each other, and no incident may pick up another's evidence.
func TestConcurrentInvestigationsDoNotInterfere(t *testing.T) {
	t.Parallel()

	ctx := testCtx(t)
	db := openDB(t)

	incidents := postgres.NewIncidentRepo(db)
	tasks := postgres.NewTaskRepo(db)
	registry := registerTestAgents(t, ctx, postgres.NewAgentRepo(db))

	orch := agents.NewOrchestrator(agents.OrchestratorDeps{
		Agents: agents.BuildAll(agents.Deps{
			Reasoner: agents.NewScriptedReasoner(), Clock: clock, Registry: registry,
		}),
		Incidents: incidents, Tasks: tasks, Bus: newBus(t),
	})

	const n = 4
	ids := make([]shared.ID, n)
	for i := range n {
		ids[i] = seedIncident(t, ctx, db, incidents,
			fmt.Sprintf("integration: concurrent investigation %d", i)).ID
	}

	var wg sync.WaitGroup
	failures := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			failures[i] = orch.Investigate(ctx, ids[i])
		}(i)
	}
	wg.Wait()

	for i, err := range failures {
		if err != nil {
			t.Errorf("investigation %d: %v", i, err)
		}
	}

	// Each incident's tasks belong to it alone.
	for i, id := range ids {
		res, err := tasks.List(ctx, ports.TaskFilter{IncidentID: &id}, ports.Page{Limit: 100})
		if err != nil {
			t.Fatalf("list tasks for incident %d: %v", i, err)
		}
		if len(res.Items) != len(domainagent.AllKinds) {
			t.Errorf("incident %d has %d tasks, want %d",
				i, len(res.Items), len(domainagent.AllKinds))
		}
		for _, task := range res.Items {
			if task.IncidentID != id {
				t.Errorf("incident %d picked up a task belonging to %s", i, task.IncidentID)
			}
		}
	}
}
