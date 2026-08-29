//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/database"
	"github.com/bishal05das/aegisops-ai/internal/database/migrate"
	"github.com/bishal05das/aegisops-ai/internal/database/migrations"
	"github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/harness"
	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/repository/postgres"
)

// openDB connects to the development database and ensures the schema is current.
//
// Tests run against the real thing rather than a mock on purpose: the properties
// under test here — optimistic locking, an append-only trigger, advisory-locked
// sequence assignment — are database behaviours. A mock would assert only that
// the mock behaves as the test author imagined.
func openDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		envOr("AEGIS_PG_USER", "aegis"),
		envOr("AEGIS_PG_PASSWORD", "aegis_dev_password"),
		envOr("AEGIS_PG_HOST", "localhost"),
		envOr("AEGIS_PG_PORT", "5434"),
		envOr("AEGIS_PG_DATABASE", "aegisops"),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := database.Open(ctx, database.Config{
		DSN: dsn, MaxOpenConns: 10, MaxIdleConns: 2,
		ConnMaxLifetime: time.Minute, ConnectTimeout: 10 * time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v\nIs the stack up? Run `make dev-up`.", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	loaded, err := migrate.Load(migrations.FS, migrations.Dir)
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	if err := migrate.New(db, loaded, nil).Up(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

var clock = shared.SystemClock{}

// seedIncident creates a throwaway incident and removes it afterwards.
//
// Deleting by ID rather than truncating tables: the tests run in parallel
// against one database, so each must clean up only its own rows.
func seedIncident(t *testing.T, ctx context.Context, db *sql.DB, repo *postgres.IncidentRepo, title string) *incident.Incident {
	t.Helper()

	inc, err := incident.New(clock, title, "seeded by an integration test",
		incident.SeverityHigh, incident.SourceAPI)
	if err != nil {
		t.Fatalf("build incident: %v", err)
	}
	inc.Service = "test-service"
	inc.Environment = "test"

	if err := repo.Create(ctx, inc); err != nil {
		t.Fatalf("create incident: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM incidents WHERE id = $1`, inc.ID)
	})
	return inc
}

func seedAgent(t *testing.T, ctx context.Context, db *sql.DB, repo *postgres.AgentRepo, name string) *agent.Agent {
	t.Helper()

	a, err := agent.New(clock, name, agent.KindAction, "seeded by an integration test")
	if err != nil {
		t.Fatalf("build agent: %v", err)
	}
	if err := repo.Upsert(ctx, a); err != nil {
		t.Fatalf("upsert agent: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM agents WHERE id = $1`, a.ID)
	})
	return a
}

// -----------------------------------------------------------------------------
// Migrations
// -----------------------------------------------------------------------------

func TestMigrationsAreIdempotent(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)

	loaded, err := migrate.Load(migrations.FS, migrations.Dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	runner := migrate.New(db, loaded, nil)

	// Running an already-current schema must be a no-op, not an error. Every
	// replica runs this on startup.
	for i := 0; i < 3; i++ {
		if err := runner.Up(ctx); err != nil {
			t.Fatalf("repeat migration %d: %v", i, err)
		}
	}

	statuses, err := runner.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(statuses) != 6 {
		t.Fatalf("got %d migrations, want 6", len(statuses))
	}
	for _, s := range statuses {
		if !s.Applied {
			t.Errorf("migration %04d_%s is not applied", s.Version, s.Name)
		}
		if s.ChecksumMismatch {
			t.Errorf("migration %04d_%s reports a checksum mismatch", s.Version, s.Name)
		}
	}
}

// Editing an applied migration diverges the database from the repository. The
// runner must refuse rather than silently continue.
func TestMigrationChecksumMismatchIsRefused(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)

	loaded, err := migrate.Load(migrations.FS, migrations.Dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Simulate an edit by corrupting the recorded checksum, then restore it.
	var original string
	if err := db.QueryRowContext(ctx,
		`SELECT checksum FROM schema_migrations WHERE version = 1`).Scan(&original); err != nil {
		t.Fatalf("read checksum: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1`); err != nil {
		t.Fatalf("corrupt checksum: %v", err)
	}
	t.Cleanup(func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = db.ExecContext(restoreCtx,
			`UPDATE schema_migrations SET checksum = $1 WHERE version = 1`, original)
	})

	err = migrate.New(db, loaded, nil).Up(ctx)
	if !errors.Is(err, migrate.ErrDirtyChecksum) {
		t.Fatalf("Up() error = %v, want ErrDirtyChecksum", err)
	}
	// The message must tell the operator what to do about it.
	if !strings.Contains(err.Error(), "add a new migration") {
		t.Errorf("error is not actionable: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Incidents
// -----------------------------------------------------------------------------

func TestIncidentCRUDRoundTrip(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	repo := postgres.NewIncidentRepo(db)

	inc := seedIncident(t, ctx, db, repo, "round trip "+shared.NewID().String())
	inc.SetLabel("cluster", "prod-eu")
	inc.SetLabel("alertname", "HighErrorRate")
	if err := repo.Update(ctx, inc); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := repo.Get(ctx, inc.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if got.Title != inc.Title || got.Severity != inc.Severity || got.Status != inc.Status {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if got.Labels["cluster"] != "prod-eu" || got.Labels["alertname"] != "HighErrorRate" {
		t.Errorf("labels did not round trip: %v", got.Labels)
	}
	// Timestamps must survive the round trip with sub-second fidelity.
	if !got.DetectedAt.Equal(inc.DetectedAt.Truncate(time.Microsecond)) &&
		got.DetectedAt.Sub(inc.DetectedAt).Abs() > time.Millisecond {
		t.Errorf("detected_at drifted: %v vs %v", got.DetectedAt, inc.DetectedAt)
	}
}

func TestIncidentGetNotFound(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)

	_, err := postgres.NewIncidentRepo(db).Get(ctx, shared.NewID())
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

// The concurrency guarantee that keeps seven agents from clobbering each other.
func TestIncidentOptimisticLocking(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	repo := postgres.NewIncidentRepo(db)

	inc := seedIncident(t, ctx, db, repo, "locking "+shared.NewID().String())

	// Two agents read the same version.
	first, err := repo.Get(ctx, inc.ID)
	if err != nil {
		t.Fatalf("get first: %v", err)
	}
	second, err := repo.Get(ctx, inc.ID)
	if err != nil {
		t.Fatalf("get second: %v", err)
	}
	if first.Version != second.Version {
		t.Fatalf("reads disagree on version: %d vs %d", first.Version, second.Version)
	}

	// The Diagnosis Agent writes.
	if err := first.SetDiagnosis(clock, "worker pool deadlock", 0.88); err != nil {
		t.Fatalf("set diagnosis: %v", err)
	}
	if err := repo.Update(ctx, first); err != nil {
		t.Fatalf("first update: %v", err)
	}
	if first.Version != second.Version+1 {
		t.Errorf("version = %d, want it advanced in place", first.Version)
	}

	// The Monitoring Agent writes from its stale read — this must be refused,
	// not silently applied over the diagnosis.
	second.Service = "clobbered"
	err = repo.Update(ctx, second)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale update error = %v, want ErrConflict", err)
	}

	// And the first writer's work must still be there.
	after, err := repo.Get(ctx, inc.ID)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if after.RootCause != "worker pool deadlock" {
		t.Errorf("root cause was lost: %q", after.RootCause)
	}
	if after.Service == "clobbered" {
		t.Error("the stale write was applied despite reporting a conflict")
	}
}

// Under real concurrency, exactly one writer wins and the rest are told.
func TestIncidentConcurrentUpdatesLoseNoWrites(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	repo := postgres.NewIncidentRepo(db)

	inc := seedIncident(t, ctx, db, repo, "concurrent "+shared.NewID().String())

	const writers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	var succeeded, conflicted int

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			read, err := repo.Get(ctx, inc.ID)
			if err != nil {
				t.Errorf("writer %d get: %v", n, err)
				return
			}
			read.Service = fmt.Sprintf("writer-%d", n)

			err = repo.Update(ctx, read)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, shared.ErrConflict):
				conflicted++
			default:
				t.Errorf("writer %d: unexpected error %v", n, err)
			}
		}(i)
	}
	wg.Wait()

	if succeeded == 0 {
		t.Fatal("no writer succeeded")
	}
	if succeeded+conflicted != writers {
		t.Errorf("accounted for %d of %d writers", succeeded+conflicted, writers)
	}
	// The point: losers are TOLD they lost rather than silently discarded.
	t.Logf("%d succeeded, %d correctly reported a conflict", succeeded, conflicted)
}

// Sequence assignment must be race-free: the timeline's ordering is what makes
// a multi-agent investigation readable after the fact.
func TestIncidentEventSequencingUnderConcurrency(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	repo := postgres.NewIncidentRepo(db)

	inc := seedIncident(t, ctx, db, repo, "events "+shared.NewID().String())

	const appenders = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	var appended int

	for i := 0; i < appenders; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ev, err := incident.NewEvent(clock, inc.ID, incident.EventAgentStarted,
				incident.ActorAgent, fmt.Sprintf("agent %d started", n))
			if err != nil {
				t.Errorf("build event: %v", err)
				return
			}
			// Concurrent appends can lose the max(seq) race; retry, exactly as
			// a caller is expected to.
			for attempt := 0; attempt < 10; attempt++ {
				err = repo.AppendEvent(ctx, ev)
				if err == nil {
					mu.Lock()
					appended++
					mu.Unlock()
					return
				}
				if !errors.Is(err, shared.ErrConflict) {
					t.Errorf("append: %v", err)
					return
				}
			}
			t.Errorf("append %d exhausted its retries: %v", n, err)
		}(i)
	}
	wg.Wait()

	page, err := repo.Events(ctx, inc.ID, ports.Page{Limit: 100})
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(page.Items) != appended {
		t.Fatalf("stored %d events, appended %d", len(page.Items), appended)
	}

	// Sequences must be a gapless 1..N in ascending order.
	for i, ev := range page.Items {
		if ev.Seq != int64(i+1) {
			t.Fatalf("event %d has seq %d; the timeline has a gap or a duplicate", i, ev.Seq)
		}
	}
}

func TestIncidentListFilteringAndPagination(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	repo := postgres.NewIncidentRepo(db)

	marker := "page-" + shared.NewID().String()
	const total = 7
	for i := 0; i < total; i++ {
		inc := seedIncident(t, ctx, db, repo, fmt.Sprintf("%s #%d", marker, i))
		_ = inc
		// Distinct detected_at values so the ordering is deterministic.
		time.Sleep(2 * time.Millisecond)
	}

	filter := ports.IncidentFilter{Search: marker}

	count, err := repo.Count(ctx, filter)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != total {
		t.Fatalf("count = %d, want %d", count, total)
	}

	// Walk every page and assert the set is complete and duplicate-free — the
	// property OFFSET pagination silently breaks when rows are inserted mid-walk.
	seen := map[shared.ID]bool{}
	page := ports.Page{Limit: 3}
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
		res, err := repo.List(ctx, filter, page)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, inc := range res.Items {
			if seen[inc.ID] {
				t.Errorf("incident %s appeared on two pages", inc.ID)
			}
			seen[inc.ID] = true
		}
		if !res.HasMore {
			break
		}
		page.Cursor = res.NextCursor
	}

	if len(seen) != total {
		t.Errorf("paged through %d incidents, want %d", len(seen), total)
	}
}

func TestIncidentFilterByStatusUsesArrayParam(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	repo := postgres.NewIncidentRepo(db)

	inc := seedIncident(t, ctx, db, repo, "filter "+shared.NewID().String())

	res, err := repo.List(ctx, ports.IncidentFilter{
		Statuses: []incident.Status{incident.StatusDetected, incident.StatusInvestigating},
		Search:   inc.Title,
	}, ports.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list by status: %v", err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("got %d incidents, want 1", len(res.Items))
	}

	// And the negative case: filtering to a status it is not in finds nothing.
	res, err = repo.List(ctx, ports.IncidentFilter{
		Statuses: []incident.Status{incident.StatusClosed},
		Search:   inc.Title,
	}, ports.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list by other status: %v", err)
	}
	if len(res.Items) != 0 {
		t.Errorf("got %d incidents, want 0", len(res.Items))
	}
}

// -----------------------------------------------------------------------------
// Transactions
// -----------------------------------------------------------------------------

// The guarantee that makes the harness trustworthy: an action and its audit
// record commit together or not at all.
func TestTransactionRollsBackEverything(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)

	incidents := postgres.NewIncidentRepo(db)
	audits := postgres.NewAuditRepo(db)
	txm := postgres.NewTxManager(db)

	inc, err := incident.New(clock, "tx rollback "+shared.NewID().String(), "",
		incident.SeverityLow, incident.SourceAPI)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	sentinel := errors.New("deliberate failure after both writes")
	err = txm.WithinTx(ctx, func(ctx context.Context) error {
		if err := incidents.Create(ctx, inc); err != nil {
			return err
		}
		entry := harness.NewAuditEntry(clock, "system", "test", "incident.create", harness.OutcomeExecuted)
		entry.IncidentID = &inc.ID
		if err := audits.Append(ctx, entry); err != nil {
			return err
		}
		return sentinel
	})

	if !errors.Is(err, sentinel) {
		t.Fatalf("WithinTx error = %v, want the callback's error unwrapped", err)
	}
	// Both writes must be gone.
	if _, err := incidents.Get(ctx, inc.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("the incident survived a rolled-back transaction: %v", err)
	}
	res, err := audits.List(ctx, ports.AuditFilter{IncidentID: &inc.ID}, ports.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(res.Items) != 0 {
		t.Errorf("%d audit entries survived a rolled-back transaction", len(res.Items))
	}
}

func TestTransactionCommitsBothWrites(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)

	incidents := postgres.NewIncidentRepo(db)
	audits := postgres.NewAuditRepo(db)
	txm := postgres.NewTxManager(db)

	inc, _ := incident.New(clock, "tx commit "+shared.NewID().String(), "",
		incident.SeverityLow, incident.SourceAPI)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = db.ExecContext(c, `DELETE FROM incidents WHERE id = $1`, inc.ID)
	})

	err := txm.WithinTx(ctx, func(ctx context.Context) error {
		if err := incidents.Create(ctx, inc); err != nil {
			return err
		}
		entry := harness.NewAuditEntry(clock, "system", "test", "incident.create", harness.OutcomeExecuted)
		entry.IncidentID = &inc.ID
		return audits.Append(ctx, entry)
	})
	if err != nil {
		t.Fatalf("WithinTx: %v", err)
	}

	if _, err := incidents.Get(ctx, inc.ID); err != nil {
		t.Errorf("the incident was not committed: %v", err)
	}
	res, err := audits.List(ctx, ports.AuditFilter{IncidentID: &inc.ID}, ports.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(res.Items) != 1 {
		t.Errorf("got %d audit entries, want 1", len(res.Items))
	}
}

// A nested WithinTx must join the outer transaction, not open a second one:
// Postgres has no true nested transactions.
func TestNestedTransactionJoins(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)

	incidents := postgres.NewIncidentRepo(db)
	txm := postgres.NewTxManager(db)

	inc, _ := incident.New(clock, "nested "+shared.NewID().String(), "",
		incident.SeverityLow, incident.SourceAPI)

	sentinel := errors.New("outer failure")
	err := txm.WithinTx(ctx, func(ctx context.Context) error {
		if err := txm.WithinTx(ctx, func(ctx context.Context) error {
			return incidents.Create(ctx, inc)
		}); err != nil {
			return err
		}
		// The inner "commit" must not have been real: failing here must undo it.
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the outer sentinel", err)
	}
	if _, err := incidents.Get(ctx, inc.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Error("the inner transaction committed independently of the outer one")
	}
}

func TestTransactionRollsBackOnPanic(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)

	incidents := postgres.NewIncidentRepo(db)
	txm := postgres.NewTxManager(db)
	inc, _ := incident.New(clock, "panic "+shared.NewID().String(), "",
		incident.SeverityLow, incident.SourceAPI)

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed; the caller would believe the work committed")
			}
		}()
		_ = txm.WithinTx(ctx, func(ctx context.Context) error {
			if err := incidents.Create(ctx, inc); err != nil {
				return err
			}
			panic("boom")
		})
	}()

	if _, err := incidents.Get(ctx, inc.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Error("a panicking transaction left its write committed")
	}
}

// -----------------------------------------------------------------------------
// Audit ledger
// -----------------------------------------------------------------------------

func TestAuditChainIsVerifiableEndToEnd(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	audits := postgres.NewAuditRepo(db)

	startSeq, err := audits.LatestSeq(ctx)
	if err != nil {
		t.Fatalf("latest seq: %v", err)
	}

	// Record a mix of outcomes, including the rejections that matter most.
	for i := 0; i < 5; i++ {
		e := harness.NewAuditEntry(clock, "agent", "action", "tool.request", harness.OutcomeDenied)
		e.Reason = "policy forbids database.drop_table"
		e.ResourceType = "tool_call"
		if err := audits.Append(ctx, e); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if e.Seq != startSeq+int64(i)+1 {
			t.Fatalf("entry %d got seq %d, want %d", i, e.Seq, startSeq+int64(i)+1)
		}
		if len(e.Hash) != 32 {
			t.Fatalf("entry %d hash is %d bytes, want 32", i, len(e.Hash))
		}
	}

	v, err := audits.VerifyChain(ctx, startSeq+1, startSeq+5)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.Valid {
		t.Fatalf("chain verification failed: %+v", v)
	}
	if v.Checked != 5 {
		t.Errorf("checked %d entries, want 5", v.Checked)
	}
}

// The database itself must refuse to rewrite history — not just the adapter.
func TestAuditLedgerIsAppendOnlyInTheDatabase(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	audits := postgres.NewAuditRepo(db)

	e := harness.NewAuditEntry(clock, "agent", "action", "tool.request", harness.OutcomeDenied)
	e.Reason = "the original reason"
	if err := audits.Append(ctx, e); err != nil {
		t.Fatalf("append: %v", err)
	}

	// A direct UPDATE, bypassing every Go-level guard.
	_, err := db.ExecContext(ctx,
		`UPDATE audit_logs SET reason = 'covered up' WHERE seq = $1`, e.Seq)
	if err == nil {
		t.Fatal("the database permitted an UPDATE on the audit ledger")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("error = %v, want the append-only trigger to fire", err)
	}

	_, err = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE seq = $1`, e.Seq)
	if err == nil {
		t.Fatal("the database permitted a DELETE on the audit ledger")
	}
}

func TestAuditListFiltersByOutcome(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	audits := postgres.NewAuditRepo(db)

	marker := "verify-" + shared.NewID().String()
	e := harness.NewAuditEntry(clock, "agent", "action", marker, harness.OutcomeDenied)
	if err := audits.Append(ctx, e); err != nil {
		t.Fatalf("append: %v", err)
	}

	res, err := audits.List(ctx, ports.AuditFilter{
		Action:   marker,
		Outcomes: []harness.Outcome{harness.OutcomeDenied},
	}, ports.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("got %d entries, want 1", len(res.Items))
	}
	if res.Items[0].Outcome != harness.OutcomeDenied {
		t.Errorf("outcome = %q", res.Items[0].Outcome)
	}
}

// -----------------------------------------------------------------------------
// Users and agents
// -----------------------------------------------------------------------------

func TestUserUniqueEmailAndCaseInsensitivity(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	repo := postgres.NewUserRepo(db)

	email := "Test-" + shared.NewID().String() + "@Example.COM"
	u, err := user.New(clock, email, "Test User", user.RoleOperator)
	if err != nil {
		t.Fatalf("build user: %v", err)
	}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = db.ExecContext(c, `DELETE FROM users WHERE id = $1`, u.ID)
	})

	// A case variant must be recognised as the same account, not a new one.
	dup, _ := user.New(clock, strings.ToUpper(email), "Impostor", user.RoleAdmin)
	if err := repo.Create(ctx, dup); !errors.Is(err, shared.ErrAlreadyExists) {
		t.Errorf("duplicate create error = %v, want ErrAlreadyExists", err)
	}

	found, err := repo.GetByEmail(ctx, strings.ToUpper(email))
	if err != nil {
		t.Fatalf("get by uppercase email: %v", err)
	}
	if found.ID != u.ID {
		t.Error("case-variant lookup found a different user")
	}

	// A missing user must not confirm which addresses exist.
	_, err = repo.GetByEmail(ctx, "nobody-"+shared.NewID().String()+"@example.com")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
	if strings.Contains(err.Error(), "@example.com") {
		t.Errorf("the error echoed the address back, enabling user enumeration: %v", err)
	}
}

func TestAgentUpsertPreservesIdentity(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)
	repo := postgres.NewAgentRepo(db)

	name := "test-agent-" + shared.NewID().String()
	first := seedAgent(t, ctx, db, repo, name)
	originalID, originalCreated := first.ID, first.CreatedAt

	// The orchestrator re-registers on every startup with a fresh object.
	second, err := agent.New(clock, name, agent.KindAction, "an updated description")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := repo.Upsert(ctx, second); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Rewriting the ID would orphan every task and tool call referencing it.
	if second.ID != originalID {
		t.Errorf("upsert changed the agent's ID from %s to %s", originalID, second.ID)
	}
	if !second.CreatedAt.Equal(originalCreated) {
		t.Errorf("upsert rewrote created_at")
	}

	got, err := repo.GetByName(ctx, name)
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if got.Description != "an updated description" {
		t.Errorf("description = %q, want the update applied", got.Description)
	}
}

// -----------------------------------------------------------------------------
// Seeded harness rules
// -----------------------------------------------------------------------------

// The seeded matrix is the thing standing between a hallucinated action and
// production, so its shape is asserted rather than assumed.
func TestSeededPolicyMatrixIsSane(t *testing.T) {
	db := openDB(t)
	ctx := testCtx(t)

	var forbidden int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM policies WHERE risk = 'forbidden'`).Scan(&forbidden); err != nil {
		t.Fatalf("count forbidden: %v", err)
	}
	if forbidden < 5 {
		t.Errorf("only %d forbidden policies; the destructive actions are not all covered", forbidden)
	}

	// No forbidden action may be auto-approvable.
	var badForbidden int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM policies WHERE risk = 'forbidden' AND NOT requires_approval`).Scan(&badForbidden); err != nil {
		t.Fatalf("query: %v", err)
	}
	if badForbidden != 0 {
		t.Errorf("%d forbidden policies do not require approval", badForbidden)
	}

	// Only the action agent may hold an allow on a mutating tool.
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT agent_kind FROM permissions
		WHERE effect = 'allow'
		  AND action IN ('restart_container', 'restart_deployment', 'scale_deployment',
		                 'rollback_deployment', 'restart_service')`)
	if err != nil {
		t.Fatalf("query mutating permissions: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var kinds []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatalf("scan: %v", err)
		}
		kinds = append(kinds, k)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	if len(kinds) != 1 || kinds[0] != string(agent.KindAction) {
		t.Errorf("agent kinds permitted to mutate = %v, want only [action]", kinds)
	}
}
