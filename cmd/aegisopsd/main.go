// Command aegisopsd is the AegisOps control plane.
//
// It hosts the HTTP API and, from Phase 5 onward, the agent orchestrator and the
// harness. Configuration comes entirely from the environment; see .env.example.
//
//	make run                      # run against the local dev stack
//	go run ./cmd/aegisopsd -check # validate configuration and exit
//
// This file is the composition root — the single place in the codebase that
// knows which concrete adapters are wired in. Everything beneath it depends only
// on interfaces, which is what makes Ollama, RabbitMQ and Postgres swappable
// without touching a use case. See docs/adr/0002-hexagonal-architecture.md.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/agents"
	"github.com/bishal05das/aegisops-ai/internal/api"
	"github.com/bishal05das/aegisops-ai/internal/api/handlers"
	"github.com/bishal05das/aegisops-ai/internal/config"
	"github.com/bishal05das/aegisops-ai/internal/database"
	"github.com/bishal05das/aegisops-ai/internal/database/migrate"
	"github.com/bishal05das/aegisops-ai/internal/database/migrations"
	domainagent "github.com/bishal05das/aegisops-ai/internal/domain/agent"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/events/inproc"
	"github.com/bishal05das/aegisops-ai/internal/harness"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/preflight"
	"github.com/bishal05das/aegisops-ai/internal/repository/postgres"
	"github.com/bishal05das/aegisops-ai/internal/security/password"
	"github.com/bishal05das/aegisops-ai/internal/security/ratelimit"
	"github.com/bishal05das/aegisops-ai/internal/security/token"
	"github.com/bishal05das/aegisops-ai/internal/services"
	"github.com/bishal05das/aegisops-ai/internal/tools"
	"github.com/bishal05das/aegisops-ai/internal/version"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// Exit codes are stable because supervisors and CI branch on them.
const (
	exitOK          = 0
	exitFailure     = 1
	exitConfigError = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags, err := parseFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfigError
	}

	if flags.showVersion {
		fmt.Println("aegisopsd", version.Get().Short())
		return exitOK
	}

	// ---- configuration ------------------------------------------------------
	// Loaded before the logger, because the logger is configured by it. A config
	// failure therefore reports to stderr in plain text — the one place in the
	// process where structured logging is not yet available.
	cfg, err := config.Load(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisopsd: %v\n\nSee .env.example for the full configuration surface.\n", err)
		return exitConfigError
	}

	// ---- logging ------------------------------------------------------------
	info := version.Get()
	log := logger.New(logger.Options{
		Level:     cfg.Log.Level,
		Format:    cfg.Log.Format,
		AddSource: cfg.Log.AddSource,
		Base: []slog.Attr{
			slog.String("service", cfg.Service),
			slog.String("version", info.Version),
			slog.String("env", string(cfg.Env)),
		},
	})
	// Anything reaching for the package-level default — a stray library, a
	// forgotten call site — lands in the same stream with the same format.
	slog.SetDefault(log)

	if flags.checkOnly {
		log.LogAttrs(context.Background(), slog.LevelInfo, "configuration valid", cfg.LogAttrs()...)
		return exitOK
	}

	log.LogAttrs(context.Background(), slog.LevelInfo, "starting aegisopsd",
		append(cfg.LogAttrs(),
			slog.String("build", info.Short()),
			slog.Int("gomaxprocs", runtime.GOMAXPROCS(0)),
			slog.Int("pid", os.Getpid()),
		)...)

	if cfg.Harness.DryRun {
		// Loud, because the difference between dry-run and live is the
		// difference between a log line and a restarted database.
		log.Warn("harness is in DRY-RUN mode; no infrastructure changes will be executed")
	}

	// ---- signal handling ----------------------------------------------------
	// SIGTERM is what Kubernetes and Compose send; SIGINT is Ctrl-C. Both must
	// trigger the same graceful drain, never an abrupt exit.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ---- composition root ---------------------------------------------------
	// The one place that knows which concrete adapters are wired in. Phase 5+
	// adds the event bus and LLM provider here; everything below is
	// interface-typed, so those additions do not ripple outward.
	db, err := database.Open(ctx, database.FromAppConfig(cfg), log)
	if err != nil {
		log.Error("failed to connect to postgres", "error", err, "target", cfg.Postgres.Safe())
		return exitFailure
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Warn("error closing the postgres pool", "error", err)
		}
	}()

	schemaVersion, migErr := applyMigrations(ctx, db, cfg, log)
	if migErr != nil {
		log.Error("schema is not usable", "error", migErr)
		return exitFailure
	}

	// ---- security -----------------------------------------------------------
	signer, verifier, tokenErr := buildTokens(cfg)
	if tokenErr != nil {
		log.Error("token configuration is invalid", "error", tokenErr)
		return exitConfigError
	}

	hasher := password.NewArgon2Hasher(password.Params{})

	// Two limiters with very different budgets. Credential guessing is a
	// different traffic shape from ordinary API use: a handful of attempts a
	// minute is generous for a human and useless for a brute-force run, whereas
	// the same budget applied to the whole API would break normal clients.
	apiLimiter := ratelimit.New(ratelimit.Config{
		Rate:  float64(cfg.Security.RateLimitRPS),
		Burst: cfg.Security.RateLimitBurst,
	})
	loginLimiter := ratelimit.New(ratelimit.Config{
		Rate:  loginAttemptsPerSecond,
		Burst: loginAttemptBurst,
		TTL:   loginLimiterTTL,
	})

	// ---- repositories and services ------------------------------------------
	users := postgres.NewUserRepo(db)
	sessions := postgres.NewSessionRepo(db)
	audit := postgres.NewAuditRepo(db)
	txm := postgres.NewTxManager(db)

	authSvc := services.NewAuthService(services.AuthDeps{
		Users: users, Sessions: sessions, Audit: audit, Tx: txm,
		Hasher: hasher, Signer: signer, Verifier: verifier,
		Config: services.AuthConfig{
			AccessTTL:  cfg.Security.JWTAccessTTL,
			RefreshTTL: cfg.Security.JWTRefreshTTL,
		},
		Logger: log,
	})

	// ---- event bus ----------------------------------------------------------
	bus := buildEventBus(cfg, log)
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := bus.Close(closeCtx); err != nil {
			log.Warn("the event bus did not drain cleanly", "error", err)
		}
	}()

	// ---- agents and orchestration -------------------------------------------
	agentRepo := postgres.NewAgentRepo(db)
	taskRepo := postgres.NewTaskRepo(db)
	incidentRepo := postgres.NewIncidentRepo(db)

	// The roster is reconciled from code on every start, so it cannot drift
	// from what this binary actually implements. Upsert deliberately leaves an
	// operator's `enabled` flag alone — see AgentRepository.Upsert.
	registry, regErr := registerAgents(ctx, agentRepo, log)
	if regErr != nil {
		log.Error("could not register the agent roster", "error", regErr)
		return exitFailure
	}

	reasoner := agents.NewScriptedReasoner()
	log.Info("reasoning provider selected", "provider", reasoner.Name(),
		"note", "Phase 8 replaces this with a local model behind the same port")

	roster := agents.BuildAll(agents.Deps{
		Reasoner: reasoner,
		Clock:    shared.SystemClock{},
		Registry: registry,
	})

	orchestrator := agents.NewOrchestrator(agents.OrchestratorDeps{
		Agents:    roster,
		Incidents: incidentRepo,
		Tasks:     taskRepo,
		Calls:     postgres.NewToolCallRepo(db),
		Bus:       bus,
		Logger:    log,
	})
	if err := orchestrator.Start(ctx); err != nil {
		log.Error("could not start the orchestrator", "error", err)
		return exitFailure
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := orchestrator.Shutdown(shutdownCtx); err != nil {
			log.Warn("investigations did not stop cleanly", "error", err)
		}
	}()

	// ---- the harness --------------------------------------------------------
	//
	// Built after the orchestrator because it subscribes to what the
	// orchestrator publishes, and before the API because the API serves its
	// approval queue. This is the only place in the process that holds a tool
	// executor.
	toolRegistry := harness.NewRegistry()
	for _, desc := range tools.Catalog() {
		// Phase 6 registers the declarations backed by an inert implementation.
		// Phase 7 swaps the backing without touching a descriptor.
		if err := toolRegistry.Register(harness.NewNoopTool(desc)); err != nil {
			log.Error("could not register a tool", "tool", desc.Name, "error", err)
			return exitFailure
		}
	}

	policyRepo := postgres.NewPolicyRepo(db)
	clock := shared.SystemClock{}
	permissionEngine := harness.NewPermissionEngine(policyRepo, clock, 0)
	policyEngine := harness.NewPolicyEngine(policyRepo, clock, 0, cfg.Harness.MaxAutoRisk)

	// Reconcile the registered tools against the policy table before serving.
	//
	// A mutating action tiered as low risk would execute automatically, and a
	// registered action with no policy cannot run at all. Neither is visible by
	// reading either source alone, so the mismatch is surfaced at startup rather
	// than the first time an agent proposes the action.
	problems, reconcileErr := policyEngine.ReconcileTools(ctx, toolRegistry)
	if reconcileErr != nil {
		log.Error("could not reconcile tools against policy", "error", reconcileErr)
		return exitFailure
	}
	for _, problem := range problems {
		log.Warn("tool/policy mismatch", "detail", problem)
	}

	executor := harness.NewExecutor(harness.ExecutorConfig{
		Registry: toolRegistry, Clock: clock, Live: !cfg.Harness.DryRun,
	})
	approvalGate := harness.NewApprovalGate(clock, cfg.Harness.ApprovalTimeout)
	toolCallRepo := postgres.NewToolCallRepo(db)

	theHarness := harness.New(harness.Deps{
		Registry: toolRegistry, Permission: permissionEngine, Policy: policyEngine,
		Approval: approvalGate, Executor: executor,
		Calls: toolCallRepo, Audit: audit, Incidents: incidentRepo, Agents: agentRepo,
		Bus: bus, Clock: clock, Logger: log,
	})
	if err := theHarness.Start(ctx); err != nil {
		log.Error("could not start the harness", "error", err)
		return exitFailure
	}

	if !cfg.Harness.DryRun {
		// Loud on purpose. This is the line that says the system can change
		// infrastructure, and it should be impossible to miss in a log.
		log.Warn("LIVE EXECUTION ENABLED — approved tool calls will change real infrastructure",
			"max_auto_risk", string(policyEngine.Ceiling()))
	}

	// Sweep lapsed approvals. Without this the queue accumulates stale
	// proposals and an operator loses the ability to tell "waiting for me" from
	// "waiting since Tuesday".
	stopSweeper := startApprovalSweeper(ctx, theHarness, log)
	defer stopSweeper()

	incidentSvc := services.NewIncidentService(services.IncidentDeps{
		Incidents: incidentRepo,
		Tasks:     taskRepo,
		Audit:     audit,
		Bus:       bus,
		Tx:        txm,
		Logger:    log,
	})

	health := handlers.NewHealth(
		handlers.WithChecks(dependencyChecks(cfg, db, schemaVersion)...),
	)

	server := api.NewServer(api.Deps{
		Config: cfg,
		Logger: log,
		Health: health,
		Auth: handlers.NewAuth(authSvc,
			handlers.WithLoginLimiter(loginLimiter),
			handlers.WithMaxBodyBytes(cfg.HTTP.MaxBodyBytes),
		),
		Incidents: handlers.NewIncidents(incidentSvc, agentRepo, cfg.HTTP.MaxBodyBytes),
		Harness: handlers.NewHarness(
			services.NewApprovalService(theHarness, toolCallRepo, users),
			services.NewRuleService(permissionEngine, policyEngine, toolRegistry),
			services.NewAuditService(audit),
			approvalGate.TTL(), cfg.Harness.DryRun, cfg.HTTP.MaxBodyBytes,
		),
		TokenVerifier: verifier,
		RateLimiter:   apiLimiter,
	})

	// ---- serve --------------------------------------------------------------
	if err := server.Run(ctx); err != nil {
		log.Error("server terminated with error", "error", err)
		return exitFailure
	}

	log.Info("aegisopsd stopped")
	return exitOK
}

// approvalSweepInterval is how often lapsed approvals are swept.
//
// A minute is frequent enough that an expired request does not sit in the queue
// looking actionable, and infrequent enough to be invisible in load.
const approvalSweepInterval = time.Minute

// startApprovalSweeper expires stale approval requests on a ticker.
func startApprovalSweeper(ctx context.Context, h *harness.Harness, log *slog.Logger) func() {
	sweepCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(approvalSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-sweepCtx.Done():
				return
			case <-ticker.C:
				if _, err := h.ExpirePending(sweepCtx); err != nil {
					log.Warn("the approval sweep failed", "error", err)
				}
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

// dependencyChecks builds the readiness probes for the backing services.
//
// Reuses the Phase 1 preflight package rather than duplicating health logic. The
// probes are protocol handshakes and real queries, not TCP connects, so
// readiness reflects "the dependency is genuinely usable" rather than "a port is
// open" — which is the distinction that keeps a broken pod out of rotation.
//
// PoolCheck supersedes the TCP-level Postgres probe here: what readiness needs
// to know is whether *our pool* can serve a query, not whether something is
// listening on 5434.
//
// RabbitMQ and the LLM are deliberately absent until Phase 5 and Phase 8 wire
// them in. A readiness probe must fail only on dependencies the process needs to
// serve traffic; failing on something unused stalls a deploy for no reason.
func dependencyChecks(cfg *config.Config, db *sql.DB, schemaVersion int) []preflight.Check {
	return []preflight.Check{
		database.NewPoolCheck(db),
		database.NewMigrationCheck(db, schemaVersion),
		preflight.NewRedisCheck(cfg.Redis.Addr(), cfg.Redis.Password.Reveal()),
	}
}

// applyMigrations brings the schema up to date and returns the version this
// build expects.
//
// Migrating on startup is safe here because the runner holds a Postgres advisory
// lock: several replicas starting at once serialise rather than race, and the
// losers find nothing to do. Combined with an embedded migration set, a container
// carries its own schema and needs no separate deployment step to stay in step
// with the image.
//
// AEGIS_DB_AUTO_MIGRATE=false disables it for deployments that prefer an
// explicit migration job — in which case the schema check below still refuses to
// serve traffic against an out-of-date database.
func applyMigrations(ctx context.Context, db *sql.DB, cfg *config.Config, log *slog.Logger) (int, error) {
	loaded, err := migrate.Load(migrations.FS, migrations.Dir)
	if err != nil {
		return 0, fmt.Errorf("load migrations: %w", err)
	}
	expected := 0
	if n := len(loaded); n > 0 {
		expected = loaded[n-1].Version
	}

	if !cfg.Postgres.AutoMigrate {
		log.Info("automatic migration is disabled; expecting an external migration job",
			"expected_schema_version", expected)
		return expected, nil
	}

	if err := migrate.New(db, loaded, log).Up(ctx); err != nil {
		return 0, fmt.Errorf("apply migrations: %w", err)
	}
	return expected, nil
}

// Login throttle. Deliberately tight and expressed as a slow refill with a
// small burst: a legitimate user retries a handful of times over a minute, a
// brute-force run wants thousands.
const (
	loginAttemptsPerSecond = 0.1 // one attempt per 10s sustained
	loginAttemptBurst      = 5   // five in quick succession, then throttled
	loginLimiterTTL        = 30 * time.Minute
)

// buildTokens constructs the signer and verifier from configuration.
//
// Both are built here rather than inside the service so a bad secret fails at
// startup with a clear message, rather than on the first login attempt.
func buildTokens(cfg *config.Config) (*token.Signer, *token.Verifier, error) {
	tc := token.Config{
		Secret:   cfg.Security.JWTSecret.Reveal(),
		Issuer:   cfg.Security.JWTIssuer,
		Audience: cfg.Security.JWTIssuer,
	}
	signer, err := token.NewSigner(tc)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := token.NewVerifier(tc)
	if err != nil {
		return nil, nil, err
	}
	return signer, verifier, nil
}

// buildEventBus selects the bus implementation.
//
// RabbitMQ is the production driver and the in-process bus serves single-node
// development and every test. Both satisfy ports.EventBus, so nothing above this
// line knows which is wired in — which is the whole point of the port. See
// docs/adr/0004.
func buildEventBus(cfg *config.Config, log *slog.Logger) ports.EventBus {
	switch cfg.AMQP.Driver {
	case "rabbitmq":
		// Phase 5 ships the port and the in-process implementation; the AMQP
		// adapter follows. Config validation already refuses `inproc` in
		// production, so this fallback cannot silently ship there.
		log.Warn("the rabbitmq event bus adapter is not implemented yet; using the in-process bus",
			"driver", cfg.AMQP.Driver)
	default:
	}
	return inproc.New(inproc.Config{
		Logger: log,
		OnDeadLetter: func(e ports.Event, cause error) {
			log.Error("an event was dead-lettered after exhausting its retries",
				"topic", e.Type, "incident_id", e.IncidentID.String(), "cause", cause)
		},
	})
}

// registerAgents reconciles the roster from code into the database.
//
// From code rather than from a seed migration: a migration would drift the
// moment an agent's description changed and would need a new one for every such
// edit. Upsert preserves each agent's id, created_at and — importantly — its
// `enabled` flag, so a restart cannot re-arm an agent an operator switched off.
func registerAgents(ctx context.Context, repo ports.AgentRepository, log *slog.Logger) (map[domainagent.Kind]agents.Registration, error) {
	clock := shared.SystemClock{}
	out := make(map[domainagent.Kind]agents.Registration, len(domainagent.AllKinds))

	descriptions := map[domainagent.Kind]string{
		domainagent.KindIncidentManager: "Plans and coordinates the investigation",
		domainagent.KindMonitoring:      "Collects metrics and service health",
		domainagent.KindLogAnalysis:     "Analyses logs for errors and patterns",
		domainagent.KindDiagnosis:       "Determines the root cause and its confidence",
		domainagent.KindSecurity:        "Checks for vulnerabilities and misconfiguration",
		domainagent.KindAction:          "Proposes remediations for human approval",
		domainagent.KindDocumentation:   "Writes the incident report and postmortem",
	}

	for _, kind := range domainagent.AllKinds {
		a, err := domainagent.New(clock, string(kind), kind, descriptions[kind])
		if err != nil {
			return nil, fmt.Errorf("build agent %s: %w", kind, err)
		}
		if err := repo.Upsert(ctx, a); err != nil {
			return nil, fmt.Errorf("register agent %s: %w", kind, err)
		}
		out[kind] = agents.Registration{ID: a.ID, Name: a.Name, Kind: kind}
	}

	log.Info("agent roster reconciled", "agents", len(out),
		"mutating", 1, "read_only", len(out)-1)
	return out, nil
}

// flags holds parsed command-line options.
type flags struct {
	showVersion bool
	checkOnly   bool
}

// parseFlags handles the small argument surface by hand.
//
// aegisopsd takes its configuration from the environment; the flags exist only
// for operations that must happen before configuration is usable. Pulling in
// the flag package for two booleans would add a global side effect for no gain.
func parseFlags(args []string) (flags, error) {
	var f flags
	for _, a := range args {
		switch a {
		case "-version", "--version", "-v":
			f.showVersion = true
		case "-check", "--check":
			f.checkOnly = true
		case "-h", "-help", "--help":
			return f, errors.New(usage)
		default:
			return f, fmt.Errorf("unknown argument %q\n\n%s", a, usage)
		}
	}
	return f, nil
}

const usage = `aegisopsd — the AegisOps AI control plane

Usage:
  aegisopsd [flags]

Flags:
  -check     validate configuration and exit
  -version   print build identity and exit
  -help      show this message

Configuration is read from the environment. See .env.example.

Exit codes:
  0  clean shutdown
  1  runtime failure
  2  invalid configuration or usage`
