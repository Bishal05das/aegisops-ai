package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// capture builds a logger writing JSON into a buffer, and a decoder for it.
func capture(t *testing.T, level slog.Level) (*slog.Logger, func() []map[string]any) {
	t.Helper()

	var mu sync.Mutex
	buf := &syncBuffer{mu: &mu}

	log := New(Options{Level: level, Format: FormatJSON, Output: buf})

	return log, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("log line is not valid JSON: %v\n%s", err, line)
			}
			out = append(out, rec)
		}
		return out
	}
}

type syncBuffer struct {
	mu  *sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string { return s.buf.String() }

// The central feature of this package: correlation IDs are lifted off the
// context automatically, so no call site has to remember to pass them.
func TestContextAttributesAreInjected(t *testing.T) {
	t.Parallel()

	log, records := capture(t, slog.LevelDebug)

	ctx := context.Background()
	ctx = WithRequestID(ctx, "req-1")
	ctx = WithTraceID(ctx, "trace-1")
	ctx = WithIncidentID(ctx, "inc-1")
	ctx = WithAgentID(ctx, "diagnosis-agent")
	ctx = WithUserID(ctx, "user-1")

	log.InfoContext(ctx, "investigating")

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	want := map[string]string{
		"request_id":  "req-1",
		"trace_id":    "trace-1",
		"incident_id": "inc-1",
		"agent_id":    "diagnosis-agent",
		"user_id":     "user-1",
		"msg":         "investigating",
	}
	for k, v := range want {
		if got := recs[0][k]; got != v {
			t.Errorf("%s = %v, want %q", k, got, v)
		}
	}
}

func TestContextAttributesAreOmittedWhenAbsent(t *testing.T) {
	t.Parallel()

	log, records := capture(t, slog.LevelDebug)
	log.InfoContext(context.Background(), "no correlation")

	rec := records()[0]
	for _, k := range []string{"request_id", "trace_id", "incident_id", "agent_id", "user_id"} {
		if _, present := rec[k]; present {
			t.Errorf("%s should be absent when unset, got %v", k, rec[k])
		}
	}
}

// WithAttrs and WithGroup must not discard the context wrapper — a common bug
// in hand-rolled slog handlers, and one that silently drops correlation IDs
// only on the derived logger.
func TestContextHandlerSurvivesWithAttrsAndWithGroup(t *testing.T) {
	t.Parallel()

	log, records := capture(t, slog.LevelDebug)
	ctx := WithRequestID(context.Background(), "req-42")

	log.With("component", "harness").InfoContext(ctx, "with attrs")
	log.WithGroup("tool").InfoContext(ctx, "with group")

	recs := records()
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	for i, rec := range recs {
		if rec["request_id"] != "req-42" {
			t.Errorf("record %d lost request_id: %v", i, rec)
		}
	}
	if recs[0]["component"] != "harness" {
		t.Errorf("With() attribute missing: %v", recs[0])
	}
}

func TestBaseAttributesAppearOnEveryRecord(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := New(Options{
		Level: slog.LevelDebug, Format: FormatJSON, Output: &buf,
		Base: []slog.Attr{slog.String("service", "aegisopsd"), slog.String("version", "1.0")},
	})
	log.Info("one")
	log.Error("two")

	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["service"] != "aegisopsd" || rec["version"] != "1.0" {
			t.Errorf("base attributes missing from %v", rec)
		}
	}
}

// Defence in depth behind config.Secret: this catches values that arrive in maps
// decoded from tool parameters, where no type could have protected them.
func TestSensitiveKeysAreRedacted(t *testing.T) {
	t.Parallel()

	log, records := capture(t, slog.LevelDebug)

	log.Info("attempt",
		"password", "hunter2",
		"api_key", "sk-live-abc123",
		"authorization", "Bearer eyJ...",
		"db_dsn", "postgres://u:p@h/db",
		"session_token", "sess-xyz",
		"incident_id", "inc-1",
		"count", 42,
	)

	rec := records()[0]
	for _, k := range []string{"password", "api_key", "authorization", "db_dsn", "session_token"} {
		if rec[k] != Redacted {
			t.Errorf("%s = %v, want %q", k, rec[k], Redacted)
		}
	}
	// Over-redaction is the chosen failure mode, but it must not swallow
	// everything: benign keys have to survive or logs become useless.
	if rec["incident_id"] != "inc-1" {
		t.Errorf("incident_id was redacted: %v", rec["incident_id"])
	}
	if rec["count"] != float64(42) {
		t.Errorf("count = %v, want 42", rec["count"])
	}
}

// Regression: redaction used to be skipped for grouped attributes, so
// log.WithGroup("db").Info(..., "password", pw) wrote the credential verbatim.
// Grouping is presentation; it must not change secret handling.
func TestSensitiveKeysAreRedactedInsideGroups(t *testing.T) {
	t.Parallel()

	log, records := capture(t, slog.LevelDebug)

	log.WithGroup("db").Info("connecting",
		"host", "postgres.internal",
		"password", "hunter2",
	)
	log.WithGroup("tool").WithGroup("params").Info("executing",
		"container", "api-7f9",
		"api_key", "sk-live-abc123",
	)

	recs := records()
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}

	db, ok := recs[0]["db"].(map[string]any)
	if !ok {
		t.Fatalf("expected a db group, got %T", recs[0]["db"])
	}
	if db["password"] != Redacted {
		t.Errorf("password inside a group = %v, want %q", db["password"], Redacted)
	}
	if db["host"] != "postgres.internal" {
		t.Errorf("benign grouped value altered: %v", db["host"])
	}

	// Nested groups must be covered too — tool parameters arrive from an LLM
	// and can carry anything the model read from the environment.
	tool, ok := recs[1]["tool"].(map[string]any)
	if !ok {
		t.Fatalf("expected a tool group, got %T", recs[1]["tool"])
	}
	params, ok := tool["params"].(map[string]any)
	if !ok {
		t.Fatalf("expected a nested params group, got %T", tool["params"])
	}
	if params["api_key"] != Redacted {
		t.Errorf("api_key in a nested group = %v, want %q", params["api_key"], Redacted)
	}
	if params["container"] != "api-7f9" {
		t.Errorf("benign nested value altered: %v", params["container"])
	}
}

func TestIsSensitiveKey(t *testing.T) {
	t.Parallel()

	sensitive := []string{
		"password", "Password", "PASSWORD", "user_password", "db_passwd",
		"secret", "client_secret", "token", "refresh_token", "apikey", "api_key",
		"authorization", "Authorization", "credential", "aws_access_key",
		"private_key", "cookie", "session", "dsn", "signature", "salt", "passphrase",
	}
	benign := []string{
		"incident_id", "agent", "status", "count", "duration_ms", "path",
		"method", "tool", "action", "reason", "confidence",
	}

	for _, k := range sensitive {
		if !isSensitiveKey(k) {
			t.Errorf("isSensitiveKey(%q) = false, want true", k)
		}
	}
	for _, k := range benign {
		if isSensitiveKey(k) {
			t.Errorf("isSensitiveKey(%q) = true, want false", k)
		}
	}
	if isSensitiveKey("") {
		t.Error(`isSensitiveKey("") = true`)
	}
}

func TestRedactMapIsRecursive(t *testing.T) {
	t.Parallel()

	in := map[string]any{
		"container": "api-7f9",
		"password":  "hunter2",
		"env": map[string]any{
			"LOG_LEVEL":      "debug",
			"DB_PASSWORD":    "s3cret",
			"AWS_SECRET_KEY": "abc",
		},
	}
	out := RedactMap(in)

	if out["container"] != "api-7f9" {
		t.Errorf("benign value altered: %v", out["container"])
	}
	if out["password"] != Redacted {
		t.Errorf("top-level secret not redacted: %v", out["password"])
	}

	nested, ok := out["env"].(map[string]any)
	if !ok {
		t.Fatalf("nested map lost its type: %T", out["env"])
	}
	if nested["DB_PASSWORD"] != Redacted || nested["AWS_SECRET_KEY"] != Redacted {
		t.Errorf("nested secrets not redacted: %v", nested)
	}
	if nested["LOG_LEVEL"] != "debug" {
		t.Errorf("nested benign value altered: %v", nested["LOG_LEVEL"])
	}

	// The input must not be mutated — the caller may still need the real values.
	if in["password"] != "hunter2" {
		t.Error("RedactMap mutated its input")
	}
	if RedactMap(nil) != nil {
		t.Error("RedactMap(nil) should be nil")
	}
}

func TestRedactString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in       string
		keepLast int
		want     string
	}{
		{"sk-live-abcdef123456", 4, Redacted + "3456"},
		{"short", 10, Redacted},
		{"anything", 0, Redacted},
		{"", 4, ""},
	}
	for _, tc := range tests {
		if got := RedactString(tc.in, tc.keepLast); got != tc.want {
			t.Errorf("RedactString(%q, %d) = %q, want %q", tc.in, tc.keepLast, got, tc.want)
		}
	}
}

func TestLevelFiltering(t *testing.T) {
	t.Parallel()

	log, records := capture(t, slog.LevelWarn)
	log.Debug("dropped")
	log.Info("dropped")
	log.Warn("kept")
	log.Error("kept")

	recs := records()
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (debug and info must be filtered)", len(recs))
	}
}

func TestFromContextNeverReturnsNil(t *testing.T) {
	t.Parallel()

	if FromContext(context.Background()) == nil {
		t.Error("FromContext(empty) = nil; a missing logger must fall back, not crash")
	}
	//nolint:staticcheck // deliberately exercising the nil-context path
	if FromContext(nil) == nil {
		t.Error("FromContext(nil) = nil")
	}

	custom, _ := capture(t, slog.LevelDebug)
	ctx := WithLogger(context.Background(), custom)
	if FromContext(ctx) != custom {
		t.Error("FromContext did not return the stored logger")
	}
}

func TestContextAccessors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	if RequestID(ctx) != "" || IncidentID(ctx) != "" || AgentID(ctx) != "" ||
		TraceID(ctx) != "" || UserID(ctx) != "" {
		t.Error("accessors on an empty context should return empty strings")
	}

	ctx = WithIncidentID(WithAgentID(ctx, "a-1"), "i-1")
	if AgentID(ctx) != "a-1" || IncidentID(ctx) != "i-1" {
		t.Errorf("accessors returned %q / %q", AgentID(ctx), IncidentID(ctx))
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in    string
		want  slog.Level
		valid bool
	}{
		{"debug", slog.LevelDebug, true},
		{"INFO", slog.LevelInfo, true},
		{" warn ", slog.LevelWarn, true},
		{"warning", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		{"", slog.LevelInfo, true},
		{"verbose", slog.LevelInfo, false},
	}
	for _, tc := range tests {
		got, ok := ParseLevel(tc.in)
		if got != tc.want || ok != tc.valid {
			t.Errorf("ParseLevel(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.valid)
		}
	}
}

func TestParseFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in    string
		want  Format
		valid bool
	}{
		{"json", FormatJSON, true},
		{"TEXT", FormatText, true},
		{"console", FormatText, true},
		{"", FormatJSON, true},
		{"xml", FormatJSON, false},
	}
	for _, tc := range tests {
		got, ok := ParseFormat(tc.in)
		if got != tc.want || ok != tc.valid {
			t.Errorf("ParseFormat(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.valid)
		}
	}
}

func TestErrorValuesRenderAsStrings(t *testing.T) {
	t.Parallel()

	log, records := capture(t, slog.LevelDebug)
	log.Error("failed", "error", context.Canceled)

	if got := records()[0]["error"]; got != "context canceled" {
		t.Errorf("error = %v, want the error's message as a string", got)
	}
}

func TestDiscardEmitsNothing(t *testing.T) {
	t.Parallel()

	log := Discard()
	log.Error("this must not panic or write anywhere")
}
