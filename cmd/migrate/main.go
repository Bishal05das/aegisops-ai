// Command migrate applies, reverts and inspects the AegisOps database schema.
//
//	make db-migrate            # apply everything pending
//	make db-status             # show what is applied
//	make db-rollback STEPS=1   # revert the most recent migration
//
// It reads the same AEGIS_PG_* environment the daemon does, so a successful
// migration proves the settings the daemon will use.
//
// Exit codes are stable because CI and deployment scripts branch on them:
//
//	0  success
//	1  migration failure
//	2  invalid usage or configuration
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/config"
	"github.com/bishal05das/aegisops-ai/internal/database"
	"github.com/bishal05das/aegisops-ai/internal/database/migrate"
	"github.com/bishal05das/aegisops-ai/internal/database/migrations"
	"github.com/bishal05das/aegisops-ai/internal/version"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return exitUsage
	}

	command := args[0]
	switch command {
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
		return exitOK
	case "-version", "--version":
		fmt.Println("aegisops-migrate", version.Get().Short())
		return exitOK
	}

	cfg, err := config.Load(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		return exitUsage
	}

	log := logger.New(logger.Options{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
		Base:   []slog.Attr{slog.String("service", "aegisops-migrate")},
	})

	// Migrations must not be abandoned half-way by an impatient Ctrl-C, but they
	// must also not be unkillable. The context cancels in-flight statements;
	// each migration's own transaction then rolls back cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	loaded, err := migrate.Load(migrations.FS, migrations.Dir)
	if err != nil {
		log.Error("failed to load migrations", "error", err)
		return exitFailed
	}

	db, err := database.Open(ctx, database.FromAppConfig(cfg), nil)
	if err != nil {
		log.Error("failed to connect", "error", err, "target", cfg.Postgres.Safe())
		return exitFailed
	}
	defer func() { _ = db.Close() }()

	runner := migrate.New(db, loaded, log)

	switch command {
	case "up":
		return doUp(ctx, runner, log)
	case "status":
		return doStatus(ctx, runner, log)
	case "down":
		return doDown(ctx, runner, log, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "migrate: unknown command %q\n\n%s", command, usage)
		return exitUsage
	}
}

func doUp(ctx context.Context, runner *migrate.Runner, log *slog.Logger) int {
	start := time.Now()
	if err := runner.Up(ctx); err != nil {
		// A checksum mismatch is an operator error with a specific remedy, so it
		// gets a specific message rather than a stack of wrapped verbs.
		if errors.Is(err, migrate.ErrDirtyChecksum) {
			log.Error("refusing to migrate: an applied migration was edited", "error", err)
			_, _ = fmt.Fprintln(os.Stderr,
				"\nA migration that has already run was modified. The database and the\n"+
					"repository now describe different schemas. Add a NEW migration with the\n"+
					"change instead of editing the old one.")
			return exitFailed
		}
		log.Error("migration failed", "error", err)
		return exitFailed
	}
	log.Info("schema up to date", "elapsed", time.Since(start).String())
	return exitOK
}

func doDown(ctx context.Context, runner *migrate.Runner, log *slog.Logger, args []string) int {
	steps := 1
	if len(args) > 0 {
		// strconv.Atoi, not fmt.Sscanf("%d"): Sscanf stops at the first
		// non-digit and reports success, so "2oops" would parse as 2 and
		// silently roll back two migrations. On a destructive command, input
		// that is not exactly an integer must be refused, not interpreted.
		n, err := strconv.Atoi(args[0])
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr,
				"migrate: down expects a whole number of steps, got %q\n", args[0])
			return exitUsage
		}
		if n < 1 {
			_, _ = fmt.Fprintf(os.Stderr,
				"migrate: down expects a positive step count, got %d\n", n)
			return exitUsage
		}
		steps = n
	}
	if err := runner.Down(ctx, steps); err != nil {
		log.Error("rollback failed", "error", err)
		return exitFailed
	}
	return exitOK
}

func doStatus(ctx context.Context, runner *migrate.Runner, log *slog.Logger) int {
	statuses, err := runner.Status(ctx)
	if err != nil {
		log.Error("failed to read migration status", "error", err)
		return exitFailed
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	// Writes into a tabwriter cannot fail; only Flush touches the fd.
	_, _ = fmt.Fprintln(w, "VERSION\tNAME\tSTATE\tAPPLIED AT")

	var pending, dirty int
	for _, s := range statuses {
		state, appliedAt := "pending", "-"
		switch {
		case s.ChecksumMismatch:
			state = "MODIFIED"
			appliedAt = s.AppliedAt.Format(time.RFC3339)
			dirty++
		case s.Applied:
			state = "applied"
			appliedAt = s.AppliedAt.Format(time.RFC3339)
		default:
			pending++
		}
		_, _ = fmt.Fprintf(w, "%04d\t%s\t%s\t%s\n", s.Version, s.Name, state, appliedAt)
	}
	_ = w.Flush()

	fmt.Printf("\n%d migration(s): %d applied, %d pending",
		len(statuses), len(statuses)-pending, pending)
	if dirty > 0 {
		fmt.Printf(", %d MODIFIED AFTER APPLYING", dirty) //nolint:errcheck // stdout write; nothing useful to do on failure
	}
	fmt.Println()

	// A modified migration is a real problem, so it must fail the command —
	// otherwise a CI step running `migrate status` would report success while
	// the schema and the repository disagree.
	if dirty > 0 {
		return exitFailed
	}
	return exitOK
}

const usage = `aegisops-migrate — manage the AegisOps database schema

Usage:
  migrate up              apply every pending migration
  migrate down [steps]    revert the most recent migration(s), default 1
  migrate status          show which migrations are applied
  migrate -version        print build identity

Configuration is read from AEGIS_PG_* in the environment. See .env.example.

Exit codes:
  0  success
  1  migration failure (including a modified migration)
  2  invalid usage or configuration
`
