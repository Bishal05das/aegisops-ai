package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/api"
	"github.com/bishal05das/aegisops-ai/internal/api/handlers"
	"github.com/bishal05das/aegisops-ai/internal/config"
	"github.com/bishal05das/aegisops-ai/internal/preflight"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// testServer assembles the real server with the real middleware stack. These are
// integration tests over the assembled product, not unit tests of its parts:
// middleware ordering bugs only appear once everything is wired together.
func testServer(t *testing.T, opts ...handlers.HealthOption) http.Handler {
	t.Helper()

	cfg, err := config.Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	return api.NewServer(api.Deps{
		Config: cfg,
		Logger: logger.Discard(),
		Health: handlers.NewHealth(opts...),
	}).Handler()
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func call(t *testing.T, h http.Handler, method, path string) (*httptest.ResponseRecorder, errorEnvelope) {
	t.Helper()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))

	var env errorEnvelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	return rec, env
}

func TestLivenessIsAlwaysCheap(t *testing.T) {
	t.Parallel()

	// Deliberately wired with a dependency that cannot possibly answer. Liveness
	// must still return 200: a failing liveness probe gets the container KILLED,
	// so making it depend on Postgres means one database blip restarts every
	// replica at once and turns a hiccup into an outage.
	h := testServer(t, handlers.WithChecks(
		preflight.NewPostgresCheck("127.0.0.1:1"),
	))

	rec, _ := call(t, h, http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Errorf("liveness = %d with a dead dependency, want 200", rec.Code)
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Status != "ok" {
		t.Errorf("liveness body = %s (%v)", rec.Body, err)
	}
}

func TestReadinessReflectsDependencies(t *testing.T) {
	t.Parallel()

	t.Run("no dependencies wired", func(t *testing.T) {
		t.Parallel()
		rec, _ := call(t, testServer(t), http.MethodGet, "/readyz")
		if rec.Code != http.StatusOK {
			t.Errorf("readiness = %d, want 200", rec.Code)
		}
	})

	t.Run("dead dependency removes the pod from rotation", func(t *testing.T) {
		t.Parallel()

		h := testServer(t, handlers.WithChecks(
			preflight.NewPostgresCheck("127.0.0.1:1"),
		))
		rec, _ := call(t, h, http.MethodGet, "/readyz")

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("readiness = %d, want 503", rec.Code)
		}

		// The body must name the failing dependency. An operator debugging a pod
		// stuck out of rotation cannot act on a bare status code.
		var body struct {
			Status string `json:"status"`
			Checks map[string]struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			} `json:"checks"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("readiness body is not JSON: %v", err)
		}
		if body.Status != "not_ready" {
			t.Errorf("status = %q", body.Status)
		}
		pg, ok := body.Checks["postgres"]
		if !ok {
			t.Fatalf("readiness body does not name the failing check: %s", rec.Body)
		}
		if pg.Status != "fail" || pg.Error == "" {
			t.Errorf("postgres check = %+v, want a failure with a reason", pg)
		}
	})
}

// Readiness is polled every few seconds per replica. Without caching, a rolling
// deploy would open connections to every dependency several times a second —
// the health check becoming the load that fails it.
func TestReadinessCachesProbes(t *testing.T) {
	t.Parallel()

	counter := &countingCheck{}
	h := testServer(t,
		handlers.WithChecks(counter),
		handlers.WithCacheTTL(time.Hour),
	)

	for i := 0; i < 10; i++ {
		call(t, h, http.MethodGet, "/readyz")
	}

	if n := counter.count(); n != 1 {
		t.Errorf("dependency probed %d times across 10 readiness calls, want 1", n)
	}

	// The response must say it is cached, so an operator is not misled into
	// thinking a stale result is live.
	rec, _ := call(t, h, http.MethodGet, "/readyz")
	var body struct {
		Cached bool `json:"cached"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !body.Cached {
		t.Error("cached=false on a cached response")
	}
}

// countingCheck records how many times it was probed.
type countingCheck struct {
	mu sync.Mutex
	n  int
}

func (c *countingCheck) Name() string                 { return "counter" }
func (c *countingCheck) Target() string               { return "test" }
func (c *countingCheck) Hint() string                 { return "" }
func (c *countingCheck) Severity() preflight.Severity { return preflight.Required }

func (c *countingCheck) Probe(context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return "ok", nil
}

func (c *countingCheck) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func TestVersionEndpoint(t *testing.T) {
	t.Parallel()

	rec, _ := call(t, testServer(t), http.MethodGet, "/api/v1/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var body struct {
		Version   string `json:"version"`
		GoVersion string `json:"go_version"`
		Platform  string `json:"platform"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body.Version == "" || body.GoVersion == "" || body.Platform == "" {
		t.Errorf("incomplete build identity: %+v", body)
	}
}

// One error envelope for every failure mode means clients write one error
// handler instead of one per route.
func TestErrorEnvelopeIsUniform(t *testing.T) {
	t.Parallel()

	h := testServer(t)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantCode   string
	}{
		{"unknown route", http.MethodGet, "/api/v1/nope", http.StatusNotFound, "route_not_found"},
		{"unknown prefix", http.MethodGet, "/totally/unknown", http.StatusNotFound, "route_not_found"},
		{"wrong verb", http.MethodPost, "/healthz", http.StatusMethodNotAllowed, "method_not_allowed"},
		{"wrong verb on versioned route", http.MethodDelete, "/api/v1/version", http.StatusMethodNotAllowed, "method_not_allowed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec, env := call(t, h, tc.method, tc.path)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body)
			}
			if env.Error.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", env.Error.Code, tc.wantCode)
			}
			if env.Error.Message == "" {
				t.Error("message is empty")
			}
			// Without this, a user report cannot be matched to a log line.
			if env.Error.RequestID == "" {
				t.Error("request_id is empty")
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want JSON even for errors", ct)
			}
		})
	}
}

// A 405 that does not say which verbs work is correct but useless.
func TestMethodNotAllowedNamesTheAllowedVerbs(t *testing.T) {
	t.Parallel()

	rec, env := call(t, testServer(t), http.MethodPost, "/healthz")

	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") {
		t.Errorf("Allow header = %q, want it to list GET", allow)
	}
	if !strings.Contains(env.Error.Message, "GET") {
		t.Errorf("message %q should tell the caller which verb to use", env.Error.Message)
	}
}

// Security headers must be present on every response, including errors — an
// error page is just as capable of being sniffed or framed as a success.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	t.Parallel()

	h := testServer(t)
	for _, path := range []string{"/healthz", "/api/v1/version", "/nope"} {
		rec, _ := call(t, h, http.MethodGet, path)
		for _, header := range []string{
			"X-Content-Type-Options", "X-Frame-Options",
			"Content-Security-Policy", "Referrer-Policy",
		} {
			if rec.Header().Get(header) == "" {
				t.Errorf("%s: %s header missing", path, header)
			}
		}
		if rec.Header().Get("X-Request-Id") == "" {
			t.Errorf("%s: no request id header", path)
		}
	}
}

func TestEveryResponseCarriesAUniqueRequestID(t *testing.T) {
	t.Parallel()

	h := testServer(t)
	seen := map[string]bool{}
	for i := 0; i < 25; i++ {
		rec, _ := call(t, h, http.MethodGet, "/healthz")
		rid := rec.Header().Get("X-Request-Id")
		if seen[rid] {
			t.Fatalf("duplicate request id %q", rid)
		}
		seen[rid] = true
	}
}

// -----------------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------------

func newServerOn(t *testing.T, addr string, mutate func(*config.Config)) *api.Server {
	t.Helper()

	cfg, err := config.Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.HTTP.Addr = addr
	if mutate != nil {
		mutate(cfg)
	}

	return api.NewServer(api.Deps{
		Config: cfg,
		Logger: logger.Discard(),
		Health: handlers.NewHealth(),
	})
}

// freePort reserves and releases a port, so the server can bind it immediately.
func freePort(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestRunServesAndShutsDownOnContextCancel(t *testing.T) {
	t.Parallel()

	addr := freePort(t)
	srv := newServerOn(t, addr, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	waitForListener(t, addr)

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil on a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	// The listener must actually be released, or a restart cannot rebind.
	if _, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		t.Error("the port is still accepting connections after shutdown")
	}
}

// This is why a deploy does not sever an approval mid-execution: in-flight work
// is given the grace period to finish.
func TestShutdownDrainsInFlightRequests(t *testing.T) {
	t.Parallel()

	addr := freePort(t)

	cfg, err := config.Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.HTTP.Addr = addr

	// A handler that takes long enough for shutdown to begin underneath it.
	slow := handlers.NewHealth()
	srv := api.NewServer(api.Deps{Config: cfg, Logger: logger.Discard(), Health: slow})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	waitForListener(t, addr)

	// Start a request, then cancel the server context while it is still open.
	respCh := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/api/v1/version")
		if err != nil {
			respCh <- -1
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		respCh <- resp.StatusCode
	}()

	select {
	case status := <-respCh:
		if status != http.StatusOK {
			t.Errorf("in-flight request status = %d, want 200", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request never completed")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not complete")
	}
}

// A port conflict must be reported synchronously, before the process announces
// itself as started — otherwise a supervisor sees a healthy start and a dead
// service.
func TestRunReportsBindFailure(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := newServerOn(t, ln.Addr().String(), nil)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(context.Background()) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Run returned nil for an already-bound port")
		}
		if !strings.Contains(err.Error(), "bind") {
			t.Errorf("error = %v, want it to mention binding", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not report the bind failure")
	}
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server never started listening on %s", addr)
}

func TestServerAddr(t *testing.T) {
	t.Parallel()

	srv := newServerOn(t, "127.0.0.1:65000", nil)
	if srv.Addr() != "127.0.0.1:65000" {
		t.Errorf("Addr() = %q", srv.Addr())
	}
}

// A handler panic must not take the server down, and the response must still be
// a correlated JSON 500 rather than a dropped connection.
//
// This goes through the assembled server rather than a hand-built chain, so it
// keeps testing the ordering buildRouter actually uses.
func TestPanicInHandlerYieldsCorrelated500(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	srv := api.NewServer(api.Deps{
		Config: cfg,
		Logger: logger.Discard(),
		Health: handlers.NewHealth(),
	})
	srv.RegisterTestRoute(http.MethodGet, "/boom", func(http.ResponseWriter, *http.Request) {
		panic("deliberate handler failure")
	})

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/boom")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)

	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("500 body is not JSON: %v (%s)", err, body)
	}
	if env.Error.Code != "internal_error" {
		t.Errorf("code = %q", env.Error.Code)
	}
	if env.Error.RequestID == "" {
		t.Error("500 from a panic carries no request id")
	}
	// The panic value must never cross the boundary.
	if strings.Contains(string(body), "deliberate") {
		t.Errorf("the panic value leaked to the client: %s", body)
	}
	// The server must still be serving afterwards.
	if after, err := http.Get(ts.URL + "/healthz"); err != nil || after.StatusCode != http.StatusOK {
		t.Errorf("server unhealthy after a panic: %v", err)
	} else {
		_ = after.Body.Close()
	}
}
