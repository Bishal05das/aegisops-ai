package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/pkg/httpx"
	"github.com/bishal05das/aegisops-ai/pkg/id"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// okHandler is the terminal handler for middleware tests.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func get(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, path, nil)
}

// -----------------------------------------------------------------------------
// RequestID
// -----------------------------------------------------------------------------

func TestRequestIDGeneratesWhenAbsent(t *testing.T) {
	t.Parallel()

	var seen string
	h := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = logger.RequestID(r.Context())
	}))

	rec := serve(h, get("/"))
	header := rec.Header().Get(HeaderRequestID)

	if !id.Valid(header) {
		t.Errorf("generated request id %q is not valid", header)
	}
	if seen != header {
		t.Errorf("context id %q differs from header %q", seen, header)
	}
}

func TestRequestIDHonoursValidInboundValue(t *testing.T) {
	t.Parallel()

	upstream := id.New()
	req := get("/")
	req.Header.Set(HeaderRequestID, upstream)

	rec := serve(RequestID()(okHandler), req)
	if got := rec.Header().Get(HeaderRequestID); got != upstream {
		t.Errorf("request id = %q, want the inbound %q preserved across the hop", got, upstream)
	}
}

// The security property: an inbound header is attacker-controlled. A value with
// a newline and a fabricated JSON object can forge log entries in any aggregator
// parsing line-delimited JSON, so anything malformed is replaced.
func TestRequestIDRejectsForgedValues(t *testing.T) {
	t.Parallel()

	forged := []string{
		"short",
		strings.Repeat("A", 100),
		"01ARZ3NDEKTSV4RRFFQ69G5FA\n{\"forged\":\"entry\"}",
		`01ARZ3NDEKTSV4RRFFQ69G5F"}`,
		"../../../etc/passwd",
		"'; DROP TABLE audit_logs;--",
		"",
	}

	for _, bad := range forged {
		req := get("/")
		// http.Header.Set would panic on some of these through a real client;
		// setting the map directly reproduces what a raw socket can deliver.
		req.Header[HeaderRequestID] = []string{bad}

		got := serve(RequestID()(okHandler), req).Header().Get(HeaderRequestID)
		if got == bad && bad != "" {
			t.Errorf("forged request id %q was echoed back verbatim", bad)
		}
		if !id.Valid(got) {
			t.Errorf("replacement id %q is not valid (input %q)", got, bad)
		}
	}
}

// -----------------------------------------------------------------------------
// Recovery
// -----------------------------------------------------------------------------

func TestRecoveryConvertsPanicTo500(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := logger.New(logger.Options{Level: slog.LevelDebug, Format: logger.FormatJSON, Output: &buf})

	h := httpx.Chain(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("agent exploded")
		}),
		// Same order as the real server: logger and request ID must be
		// established before Recovery, or the 500 it renders has nothing to
		// correlate it with.
		InjectLogger(log), RequestID(), Recovery(),
	)

	rec := serve(h, get("/"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	// Explicit tags: encoding/json matches keys case-insensitively but does not
	// bridge snake_case to CamelCase, so RequestID would silently stay empty.
	var body struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("panic response is not JSON: %v (%s)", err, rec.Body)
	}
	if body.Error.Code != "internal_error" {
		t.Errorf("code = %q", body.Error.Code)
	}
	// The panic value must never reach the client...
	if strings.Contains(rec.Body.String(), "agent exploded") {
		t.Errorf("the panic value leaked to the client: %s", rec.Body)
	}
	if body.Error.RequestID == "" {
		t.Error("no request id in the panic response; the log would be unfindable")
	}
	// ...but must be fully present, with a stack, in the log.
	logged := buf.String()
	if !strings.Contains(logged, "agent exploded") || !strings.Contains(logged, "stack") {
		t.Errorf("panic detail missing from the log:\n%s", logged)
	}
}

// http.ErrAbortHandler is a deliberate signal from the standard library to
// abandon a response. Swallowing it turns an intentional abort into a spurious
// 500 and an alert nobody can explain.
func TestRecoveryRepanicsOnErrAbortHandler(t *testing.T) {
	t.Parallel()

	defer func() {
		p := recover()
		err, ok := p.(error)
		if !ok || !errors.Is(err, http.ErrAbortHandler) {
			t.Errorf("recovered %v, want ErrAbortHandler to propagate", p)
		}
	}()

	h := Recovery()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	serve(h, get("/"))
}

// Once bytes are on the wire, appending an error envelope corrupts a response
// the client is already parsing. Severing the connection is the honest signal.
func TestRecoveryAbortsWhenResponseAlreadyStarted(t *testing.T) {
	t.Parallel()

	defer func() {
		p := recover()
		err, ok := p.(error)
		if !ok || !errors.Is(err, http.ErrAbortHandler) {
			t.Errorf("recovered %v, want ErrAbortHandler after a partial write", p)
		}
	}()

	h := httpx.Chain(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"partial":`))
			panic("mid-response failure")
		}),
		InjectLogger(logger.Discard()), Recovery(),
	)
	serve(h, get("/"))
}

// -----------------------------------------------------------------------------
// AccessLog
// -----------------------------------------------------------------------------

func logCapture(t *testing.T) (*slog.Logger, func() []map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	log := logger.New(logger.Options{Level: slog.LevelDebug, Format: logger.FormatJSON, Output: &buf})
	return log, func() []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("log line is not JSON: %v\n%s", err, line)
			}
			out = append(out, rec)
		}
		return out
	}
}

// Uniform info-level logging makes failures invisible; uniform error-level
// logging makes the error stream meaningless. The level must follow the outcome.
func TestAccessLogLevelFollowsStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status    int
		wantLevel string
	}{
		{http.StatusOK, "INFO"},
		{http.StatusNotFound, "WARN"},
		{http.StatusBadRequest, "WARN"},
		{http.StatusInternalServerError, "ERROR"},
		{http.StatusServiceUnavailable, "ERROR"},
	}

	for _, tc := range tests {
		log, records := logCapture(t)
		h := httpx.Chain(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}),
			InjectLogger(log), AccessLog(LoggerOptions{}),
		)
		serve(h, get("/x"))

		recs := records()
		if len(recs) != 1 {
			t.Fatalf("status %d: got %d log records, want 1", tc.status, len(recs))
		}
		if recs[0]["level"] != tc.wantLevel {
			t.Errorf("status %d logged at %v, want %s", tc.status, recs[0]["level"], tc.wantLevel)
		}
		if recs[0]["status"] != float64(tc.status) {
			t.Errorf("logged status = %v, want %d", recs[0]["status"], tc.status)
		}
	}
}

// Probes fire every few seconds per replica; logging them buries real traffic.
// But a *failing* probe is exactly what you need to see.
func TestAccessLogSkipsHealthyProbesButLogsFailingOnes(t *testing.T) {
	t.Parallel()

	opts := LoggerOptions{SkipPaths: map[string]bool{"/healthz": true}}

	log, records := logCapture(t)
	h := httpx.Chain(okHandler, InjectLogger(log), AccessLog(opts))
	serve(h, get("/healthz"))
	if n := len(records()); n != 0 {
		t.Errorf("a healthy probe produced %d log lines, want 0", n)
	}

	log, records = logCapture(t)
	failing := httpx.Chain(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}),
		InjectLogger(log), AccessLog(opts),
	)
	serve(failing, get("/healthz"))
	if n := len(records()); n != 1 {
		t.Errorf("a failing probe produced %d log lines, want 1", n)
	}
}

func TestAccessLogRecordsRequestShape(t *testing.T) {
	t.Parallel()

	log, records := logCapture(t)
	h := httpx.Chain(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("hello"))
		}),
		InjectLogger(log), RequestID(), AccessLog(LoggerOptions{}),
	)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents?verbose=1", nil)
	req.Header.Set("User-Agent", "aegisctl/1.0")
	serve(h, req)

	rec := records()[0]
	for k, want := range map[string]any{
		"method": "POST",
		"path":   "/api/v1/incidents",
		"query":  "verbose=1",
		"bytes":  float64(5),
	} {
		if rec[k] != want {
			t.Errorf("%s = %v, want %v", k, rec[k], want)
		}
	}
	if rec["request_id"] == nil {
		t.Error("access log line has no request_id")
	}
	if _, ok := rec["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms = %v, want a number", rec["duration_ms"])
	}
}

// One request must not be able to emit a megabyte-long log line.
func TestAccessLogTruncatesClientStrings(t *testing.T) {
	t.Parallel()

	log, records := logCapture(t)
	h := httpx.Chain(okHandler, InjectLogger(log), AccessLog(LoggerOptions{}))

	req := get("/")
	req.Header.Set("User-Agent", strings.Repeat("A", 5000))
	serve(h, req)

	ua, _ := records()[0]["user_agent"].(string)
	if len([]rune(ua)) > 210 {
		t.Errorf("user_agent length = %d runes, want it truncated", len([]rune(ua)))
	}
}

// -----------------------------------------------------------------------------
// RealIP
// -----------------------------------------------------------------------------

// Every header RealIP reads is client-supplied. Honouring them without a trusted
// peer lets any caller spoof their address and defeat both rate limiting and the
// audit trail's record of who did what.
func TestRealIPIgnoresHeadersFromUntrustedPeers(t *testing.T) {
	t.Parallel()

	var got string
	h := RealIP(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
	}))

	req := get("/")
	req.RemoteAddr = "203.0.113.9:54321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8")
	serve(h, req)

	if got != "203.0.113.9" {
		t.Errorf("ClientIP = %q, want the transport peer — headers must be ignored without a trusted proxy", got)
	}
}

func TestRealIPHonoursHeadersFromTrustedProxies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"x-forwarded-for takes the leftmost", map[string]string{
			"X-Forwarded-For": "1.2.3.4, 10.0.0.2, 10.0.0.3"}, "1.2.3.4"},
		{"x-real-ip", map[string]string{"X-Real-IP": "5.6.7.8"}, "5.6.7.8"},
		{"true-client-ip", map[string]string{"True-Client-IP": "9.9.9.9"}, "9.9.9.9"},
		{"garbage falls back to the peer", map[string]string{
			"X-Forwarded-For": "not-an-ip"}, "10.0.0.1"},
		{"no headers", nil, "10.0.0.1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got string
			h := RealIP([]string{"10.0.0.0/8"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = ClientIP(r)
			}))

			req := get("/")
			req.RemoteAddr = "10.0.0.1:1234"
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			serve(h, req)

			if got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRealIPAcceptsBareIPAsTrustedProxy(t *testing.T) {
	t.Parallel()

	var got string
	h := RealIP([]string{"192.168.1.5"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
	}))

	req := get("/")
	req.RemoteAddr = "192.168.1.5:9999"
	req.Header.Set("X-Real-IP", "8.8.8.8")
	serve(h, req)

	if got != "8.8.8.8" {
		t.Errorf("ClientIP = %q, want 8.8.8.8", got)
	}
}

// -----------------------------------------------------------------------------
// Guards
// -----------------------------------------------------------------------------

func TestTimeoutSetsADeadline(t *testing.T) {
	t.Parallel()

	var deadlineSet bool
	var err error

	h := Timeout(30 * time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, deadlineSet = r.Context().Deadline()
		select {
		case <-r.Context().Done():
			err = r.Context().Err()
		case <-time.After(2 * time.Second):
		}
	}))
	serve(h, get("/"))

	if !deadlineSet {
		t.Error("no deadline was attached to the request context")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("context error = %v, want DeadlineExceeded", err)
	}
}

func TestTimeoutZeroIsPassThrough(t *testing.T) {
	t.Parallel()

	var hasDeadline bool
	h := Timeout(0)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasDeadline = r.Context().Deadline()
	}))
	serve(h, get("/"))

	if hasDeadline {
		t.Error("Timeout(0) attached a deadline")
	}
}

// The Content-Length pre-check rejects an oversized upload before a byte is read.
func TestMaxBodyRejectsOnContentLength(t *testing.T) {
	t.Parallel()

	var handlerRan bool
	h := MaxBody(100)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerRan = true
	}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 500)))
	rec := serve(h, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	if handlerRan {
		t.Error("the handler ran despite an oversized body")
	}
	if !strings.Contains(rec.Body.String(), "body_too_large") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

// A client streaming an endless body with no Content-Length must still be
// stopped — that is what MaxBytesReader adds over io.LimitReader.
func TestMaxBodyCapsUnknownLengthStreams(t *testing.T) {
	t.Parallel()

	var readErr error
	h := MaxBody(50)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		for {
			if _, err := r.Body.Read(buf); err != nil {
				readErr = err
				return
			}
		}
	}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 5000)))
	req.ContentLength = -1 // chunked / unknown
	serve(h, req)

	if readErr == nil || !strings.Contains(readErr.Error(), "too large") {
		t.Errorf("read error = %v, want the body limit to trip", readErr)
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()

	rec := serve(SecurityHeaders()(okHandler), get("/"))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q", csp)
	}
	// Asserting HSTS over plaintext can lock a developer out of their dev server.
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be set on a plaintext request")
	}
}

// An accidentally wide-open CORS policy is worse than no CORS support.
func TestCORSDisabledByDefault(t *testing.T) {
	t.Parallel()

	req := get("/")
	req.Header.Set("Origin", "https://evil.test")
	rec := serve(CORS(CORSOptions{})(okHandler), req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS headers were emitted with no configured origins")
	}
}

func TestCORSAllowlist(t *testing.T) {
	t.Parallel()

	mw := CORS(CORSOptions{AllowedOrigins: []string{"https://ops.test"}})

	req := get("/")
	req.Header.Set("Origin", "https://ops.test")
	rec := serve(mw(okHandler), req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://ops.test" {
		t.Errorf("allowed origin = %q", got)
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Origin") {
		t.Error("Vary: Origin missing; caches would serve the wrong response")
	}

	// A disallowed origin gets no headers — and no 403, which would leak the
	// allowlist's contents.
	req = get("/")
	req.Header.Set("Origin", "https://evil.test")
	rec = serve(mw(okHandler), req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("a disallowed origin received CORS headers")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want the request to proceed normally", rec.Code)
	}
}

func TestCORSPreflightShortCircuits(t *testing.T) {
	t.Parallel()

	var handlerRan bool
	mw := CORS(CORSOptions{AllowedOrigins: []string{"https://ops.test"}, MaxAge: time.Minute})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { handlerRan = true }))

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/incidents", nil)
	req.Header.Set("Origin", "https://ops.test")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := serve(h, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rec.Code)
	}
	if handlerRan {
		t.Error("a preflight reached the handler")
	}
	if !strings.Contains(rec.Header().Get("Access-Control-Allow-Methods"), "POST") {
		t.Errorf("Allow-Methods = %q", rec.Header().Get("Access-Control-Allow-Methods"))
	}
	if rec.Header().Get("Access-Control-Max-Age") != "60" {
		t.Errorf("Max-Age = %q, want 60", rec.Header().Get("Access-Control-Max-Age"))
	}
}
