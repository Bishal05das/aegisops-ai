// Command preflight verifies that the AegisOps development environment is fully
// wired before any real work begins.
//
//	make preflight            # human-readable report
//	make preflight-json       # machine-readable, for CI
//	go run ./cmd/preflight -only postgres,redis
//
// Exit codes are meaningful and stable, because CI and the Makefile branch on
// them:
//
//	0  every required dependency answered (warnings allowed)
//	1  at least one required dependency failed
//	2  invalid usage
//
// Configuration is read from the environment with the same AEGIS_* names the
// rest of the platform uses, so a working preflight proves the same settings the
// daemon will consume. The full config package arrives in Phase 2; this binary
// intentionally keeps its own three-line reader rather than pre-empting it.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/preflight"
	"github.com/bishal05das/aegisops-ai/internal/version"
)

const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
	// Kept in lockstep with go.mod. Older toolchains still compile this code,
	// but carry unpatched stdlib CVEs in crypto/tls and net/http — unacceptable
	// for a process that terminates TLS and parses attacker-supplied headers.
	minimumGo   = "1.26"
	overallWait = 60 * time.Second
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		asJSON      = flag.Bool("json", false, "emit the report as JSON instead of text")
		timeout     = flag.Duration("timeout", preflight.DefaultCheckTimeout, "per-check timeout")
		only        = flag.String("only", "", "comma-separated check names to run (default: all)")
		wait        = flag.Duration("wait", 0, "keep retrying until healthy or this deadline elapses")
		showVersion = flag.Bool("version", false, "print build identity and exit")
		noColor     = flag.Bool("no-color", false, "disable ANSI colour in text output")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("aegisops-preflight", version.Get().Short())
		return exitOK
	}
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q\n\n", flag.Arg(0))
		usage()
		return exitUsage
	}

	// Ctrl-C must abort in-flight probes promptly; every check honours ctx.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	checks := buildChecks()
	runner := preflight.Runner{Timeout: *timeout, Only: parseOnly(*only)}

	if names := unknownNames(*only, checks); len(names) > 0 {
		fmt.Fprintf(os.Stderr, "unknown check name(s): %s\navailable: %s\n",
			strings.Join(names, ", "), strings.Join(checkNames(checks), ", "))
		return exitUsage
	}

	rep := runWithRetry(ctx, runner, checks, *wait)

	color := !*noColor && isTTY(os.Stdout)
	var err error
	if *asJSON {
		err = preflight.RenderJSON(os.Stdout, rep)
	} else {
		err = preflight.RenderText(os.Stdout, rep, color)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "render report:", err)
		return exitFailed
	}

	if !rep.Healthy {
		return exitFailed
	}
	return exitOK
}

// runWithRetry re-runs the full check set until healthy or the deadline passes.
//
// This exists for `make dev-up`: containers report healthy to Docker before
// RabbitMQ finishes booting its Erlang VM, and a one-shot preflight immediately
// after `up` produces a false negative that trains people to ignore it.
func runWithRetry(ctx context.Context, runner preflight.Runner, checks []preflight.Check, wait time.Duration) preflight.Report {
	rep := runner.Run(ctx, checks)
	if rep.Healthy || wait <= 0 {
		return rep
	}
	if wait > overallWait {
		wait = overallWait
	}

	deadline := time.Now().Add(wait)
	const interval = 2 * time.Second
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return rep
		case <-time.After(interval):
		}
		if rep = runner.Run(ctx, checks); rep.Healthy {
			return rep
		}
	}
	return rep
}

// buildChecks declares the dependency graph of the development environment.
// Order here is the order in the report: fastest and most local first, so a
// broken toolchain is reported before a network timeout scrolls it away.
func buildChecks() []preflight.Check {
	var (
		pgAddr    = hostPort("AEGIS_PG_HOST", "localhost", "AEGIS_PG_PORT", "5434")
		redisAddr = hostPort("AEGIS_REDIS_HOST", "localhost", "AEGIS_REDIS_PORT", "6380")
		amqpAddr  = hostPort("AEGIS_AMQP_HOST", "localhost", "AEGIS_AMQP_PORT", "5672")
		llmURL    = envOr("AEGIS_LLM_ENDPOINT", "http://localhost:11434")
		llmModel  = envOr("AEGIS_LLM_MODEL", "qwen2.5:7b")
	)

	rabbitUI := preflight.NewHTTPCheck(
		"rabbitmq-ui",
		"http://localhost:15672/api/overview",
		"if `rabbitmq` passed but this did not, the credentials are wrong — check AEGIS_AMQP_USER / AEGIS_AMQP_PASSWORD",
		preflight.Optional,
	)
	// The management API authenticates, so this check proves the credentials
	// the event bus will use are actually valid — something the AMQP handshake
	// probe deliberately does not attempt.
	rabbitUI.Accept = []int{200}
	rabbitUI.Username = envOr("AEGIS_AMQP_USER", "aegis")
	rabbitUI.Password = envOr("AEGIS_AMQP_PASSWORD", "aegis_dev_password")
	rabbitUI.Validate = func(body []byte) (string, error) {
		var overview struct {
			RabbitVersion string `json:"rabbitmq_version"`
			ProductName   string `json:"product_name"`
		}
		if err := json.Unmarshal(body, &overview); err != nil {
			return "", fmt.Errorf("decode /api/overview: %w", err)
		}
		if overview.RabbitVersion == "" {
			return "management API reachable", nil
		}
		return fmt.Sprintf("credentials valid, %s %s",
			cmp.Or(overview.ProductName, "RabbitMQ"), overview.RabbitVersion), nil
	}

	return []preflight.Check{
		preflight.NewGoRuntimeCheck(minimumGo, runtime.Version),
		preflight.NewPostgresCheck(pgAddr),
		preflight.NewRedisCheck(redisAddr, os.Getenv("AEGIS_REDIS_PASSWORD")),
		preflight.NewAMQPCheck(amqpAddr),
		rabbitUI,
		preflight.NewOllamaCheck(llmURL, llmModel),
		preflight.NewHTTPCheck("prometheus", "http://localhost:9090/-/healthy",
			"`make dev-up`, then check `make dev-logs SVC=prometheus`", preflight.Optional),
		preflight.NewHTTPCheck("grafana", "http://localhost:3000/api/health",
			"`make dev-up`, then check `make dev-logs SVC=grafana`", preflight.Optional),
		preflight.NewHTTPCheck("jaeger", "http://localhost:16686/",
			"`make dev-up`, then check `make dev-logs SVC=jaeger`", preflight.Optional),
	}
}

// ---------------------------------------------------------------------------
// small helpers — replaced by internal/config in Phase 2
// ---------------------------------------------------------------------------

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func hostPort(hostKey, hostDefault, portKey, portDefault string) string {
	return envOr(hostKey, hostDefault) + ":" + envOr(portKey, portDefault)
}

func parseOnly(s string) map[string]bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	set := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			set[p] = true
		}
	}
	return set
}

func checkNames(checks []preflight.Check) []string {
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		out = append(out, c.Name())
	}
	return out
}

// unknownNames catches typos in -only, which would otherwise silently run
// nothing and report a healthy environment.
func unknownNames(only string, checks []preflight.Check) []string {
	req := parseOnly(only)
	if req == nil {
		return nil
	}
	known := map[string]bool{}
	for _, c := range checks {
		known[c.Name()] = true
	}
	var bad []string
	for name := range req {
		if !known[name] {
			bad = append(bad, name)
		}
	}
	return bad
}

// isTTY reports whether w is a character device, so colour is emitted only when
// a human is actually looking at it.
func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func usage() {
	fmt.Fprintf(os.Stderr, `aegisops-preflight — verify the AegisOps development environment

Usage:
  preflight [flags]

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Checks:
  %s

Exit codes:
  0  environment ready (warnings allowed)
  1  a required dependency failed
  2  invalid usage
`, strings.Join(checkNames(buildChecks()), ", "))
}
