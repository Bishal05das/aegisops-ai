//go:build integration

// Package integration holds tests that require live backing services.
//
// They are behind the `integration` build tag so that `go test ./...` on a
// laptop with nothing running stays green and fast. Run them with:
//
//	make dev-up
//	go test -tags=integration ./tests/integration/...
//
// The Phase 1 suite asserts one thing, but it is the thing every later phase
// depends on: the development environment is genuinely wired, not just booted.
package integration

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/preflight"
)

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func addr(hostKey, hostDef, portKey, portDef string) string {
	return envOr(hostKey, hostDef) + ":" + envOr(portKey, portDef)
}

// TestBackingServicesSpeakTheirProtocols is the integration counterpart to the
// unit tests: those prove the probes decode correct and malformed responses,
// this proves the real servers produce responses the probes accept.
func TestBackingServicesSpeakTheirProtocols(t *testing.T) {
	checks := []preflight.Check{
		preflight.NewGoRuntimeCheck("1.24", runtime.Version),
		preflight.NewPostgresCheck(addr("AEGIS_PG_HOST", "localhost", "AEGIS_PG_PORT", "5434")),
		preflight.NewRedisCheck(addr("AEGIS_REDIS_HOST", "localhost", "AEGIS_REDIS_PORT", "6380"),
			os.Getenv("AEGIS_REDIS_PASSWORD")),
		preflight.NewAMQPCheck(addr("AEGIS_AMQP_HOST", "localhost", "AEGIS_AMQP_PORT", "5672")),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rep := preflight.Runner{Timeout: 5 * time.Second}.Run(ctx, checks)

	for _, r := range rep.Results {
		switch r.Status {
		case preflight.StatusOK:
			t.Logf("%-10s %s (%dms)", r.Name, r.Detail, r.Millis)
		case preflight.StatusWarn:
			t.Logf("%-10s WARN: %s", r.Name, r.Error)
		default:
			t.Errorf("%s is not healthy: %s\n  fix: %s", r.Name, r.Error, r.Hint)
		}
	}

	if !rep.Healthy {
		t.Fatal("development environment is not ready — run `make dev-up`")
	}
}

// TestRedisIsIsolatedFromTheHostInstance guards against a mistake that is very
// easy to make on this machine: a native Redis already listens on 6379, so a
// misconfigured port would silently share state with an unrelated server.
func TestRedisIsIsolatedFromTheHostInstance(t *testing.T) {
	port := envOr("AEGIS_REDIS_PORT", "6380")
	if port == "6379" {
		t.Fatalf("AEGIS_REDIS_PORT is 6379 — that is the host's own Redis, not the AegisOps container")
	}
}
