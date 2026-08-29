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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/bishal05das/aegisops-ai/internal/api"
	"github.com/bishal05das/aegisops-ai/internal/api/handlers"
	"github.com/bishal05das/aegisops-ai/internal/config"
	"github.com/bishal05das/aegisops-ai/internal/preflight"
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
	// Phase 3+ constructs the Postgres pool, Redis client, event bus and LLM
	// provider here and passes them in through Deps. Everything below is
	// interface-typed, so those additions do not ripple outward.
	health := handlers.NewHealth(
		handlers.WithChecks(dependencyChecks(cfg)...),
	)

	server := api.NewServer(api.Deps{
		Config: cfg,
		Logger: log,
		Health: health,
	})

	// ---- serve --------------------------------------------------------------
	if err := server.Run(ctx); err != nil {
		log.Error("server terminated with error", "error", err)
		return exitFailure
	}

	log.Info("aegisopsd stopped")
	return exitOK
}

// dependencyChecks builds the readiness probes for the backing services.
//
// It reuses the Phase 1 preflight package rather than duplicating health logic.
// The probes are protocol handshakes, not TCP connects, so readiness reflects
// "the dependency is genuinely usable" rather than "a port is open" — which is
// the distinction that keeps a pod out of rotation when it should be.
//
// Only Postgres and Redis are checked. RabbitMQ is deliberately excluded until
// Phase 5 wires it in: a readiness probe must fail only on dependencies the
// process actually needs to serve traffic, or a deploy stalls on something
// irrelevant.
func dependencyChecks(cfg *config.Config) []preflight.Check {
	return []preflight.Check{
		preflight.NewPostgresCheck(cfg.Postgres.Addr()),
		preflight.NewRedisCheck(cfg.Redis.Addr(), cfg.Redis.Password.Reveal()),
	}
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
