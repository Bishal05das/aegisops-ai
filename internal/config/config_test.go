package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// env builds a lookup function from a map, so tests never mutate the real
// process environment and can therefore run in parallel.
func env(kv map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := kv[k]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatalf("Load with empty environment failed: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"env", cfg.Env, EnvDevelopment},
		{"service", cfg.Service, "aegisopsd"},
		{"http addr", cfg.HTTP.Addr, ":8080"},
		// The non-default ports are load-bearing on this machine: 5432/5433 and
		// 6379 belong to native servers, not to the AegisOps stack.
		{"postgres port", cfg.Postgres.Port, 5434},
		{"redis port", cfg.Redis.Port, 6380},
		{"eventbus driver", cfg.AMQP.Driver, "inproc"},
		{"llm provider", cfg.LLM.Provider, "ollama"},
		{"llm model", cfg.LLM.Model, "qwen2.5:7b"},
		{"log level", cfg.Log.Level, slog.LevelDebug},
		{"log format", cfg.Log.Format, logger.FormatText},
		// Executing real infrastructure changes must be opt-in.
		{"harness dry run", cfg.Harness.DryRun, true},
		{"max auto risk", cfg.Harness.MaxAutoRisk, "low"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// The defining behaviour of this package: one run reports every problem, so an
// operator fixes a broken deployment in one pass instead of five.
func TestLoadAccumulatesEveryError(t *testing.T) {
	t.Parallel()

	_, err := Load(env(map[string]string{
		"AEGIS_ENV":               "banana",
		"AEGIS_LOG_LEVEL":         "verbose",
		"AEGIS_HTTP_READ_TIMEOUT": "not-a-duration",
		"AEGIS_PG_PORT":           "99999",
		"AEGIS_PG_MAX_CONNS":      "5",
		"AEGIS_PG_MIN_CONNS":      "50",
		"AEGIS_LLM_TEMPERATURE":   "9.5",
		"AEGIS_LLM_ENDPOINT":      "localhost:11434",
		"AEGIS_RATE_LIMIT_RPS":    "100",
		"AEGIS_RATE_LIMIT_BURST":  "10",
	}))
	if err == nil {
		t.Fatal("Load returned nil error for a thoroughly broken environment")
	}

	msg := err.Error()
	mustMention := []string{
		"AEGIS_ENV",
		"AEGIS_LOG_LEVEL",
		"AEGIS_HTTP_READ_TIMEOUT",
		"AEGIS_PG_PORT",
		"AEGIS_PG_MIN_CONNS",
		"AEGIS_LLM_TEMPERATURE",
		"AEGIS_LLM_ENDPOINT",
		"AEGIS_RATE_LIMIT_BURST",
	}
	for _, want := range mustMention {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not mention %s:\n%s", want, msg)
		}
	}
	if n := strings.Count(msg, "•"); n < len(mustMention) {
		t.Errorf("got %d bulleted errors, want at least %d:\n%s", n, len(mustMention), msg)
	}
}

// Listing the valid options turns a code dive into a two-minute fix.
func TestInvalidEnumErrorNamesTheOptions(t *testing.T) {
	t.Parallel()

	_, err := Load(env(map[string]string{"AEGIS_LLM_PROVIDER": "gpt4"}))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"ollama", "llamacpp", "mock"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should list valid option %q:\n%s", want, err)
		}
	}
}

func TestTypedReaders(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(map[string]string{
		"AEGIS_HTTP_ADDR":            "127.0.0.1:9999",
		"AEGIS_HTTP_READ_TIMEOUT":    "45s",
		"AEGIS_HTTP_REQUEST_TIMEOUT": "40s",
		"AEGIS_HTTP_WRITE_TIMEOUT":   "1m",
		"AEGIS_HTTP_MAX_BODY_BYTES":  "4096",
		"AEGIS_TRACING_ENABLED":      "yes",
		"AEGIS_HARNESS_DRY_RUN":      "off",
		"AEGIS_LLM_TEMPERATURE":      "0.75",
		"AEGIS_HTTP_CORS_ORIGINS":    "https://a.test, https://b.test , ",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.HTTP.Addr != "127.0.0.1:9999" {
		t.Errorf("addr = %q", cfg.HTTP.Addr)
	}
	if cfg.HTTP.ReadTimeout != 45*time.Second {
		t.Errorf("read timeout = %v", cfg.HTTP.ReadTimeout)
	}
	if cfg.HTTP.MaxBodyBytes != 4096 {
		t.Errorf("max body = %d", cfg.HTTP.MaxBodyBytes)
	}
	if !cfg.Observ.TracingEnabled {
		t.Error(`AEGIS_TRACING_ENABLED="yes" should parse as true`)
	}
	if cfg.Harness.DryRun {
		t.Error(`AEGIS_HARNESS_DRY_RUN="off" should parse as false`)
	}
	if cfg.LLM.Temperature != 0.75 {
		t.Errorf("temperature = %v", cfg.LLM.Temperature)
	}
	// Blank CSV entries must be dropped, not turned into empty origins.
	if len(cfg.HTTP.CORSOrigins) != 2 {
		t.Errorf("cors origins = %v, want 2 entries", cfg.HTTP.CORSOrigins)
	}
}

// An empty variable means "not set", never "set to the empty string" — the
// difference between a working default and a connection to host "".
func TestEmptyValueFallsBackToDefault(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(map[string]string{
		"AEGIS_PG_HOST":   "",
		"AEGIS_HTTP_ADDR": "   ",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Postgres.Host != "localhost" {
		t.Errorf("pg host = %q, want the default", cfg.Postgres.Host)
	}
	if cfg.HTTP.Addr != ":8080" {
		t.Errorf("http addr = %q, want the default", cfg.HTTP.Addr)
	}
}

func TestCrossFieldValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		env       map[string]string
		wantError string
	}{
		{
			name:      "min conns above max",
			env:       map[string]string{"AEGIS_PG_MIN_CONNS": "50", "AEGIS_PG_MAX_CONNS": "10"},
			wantError: "AEGIS_PG_MIN_CONNS",
		},
		{
			name:      "burst below sustained rate",
			env:       map[string]string{"AEGIS_RATE_LIMIT_RPS": "100", "AEGIS_RATE_LIMIT_BURST": "5"},
			wantError: "AEGIS_RATE_LIMIT_BURST",
		},
		{
			name: "refresh ttl not longer than access ttl",
			env: map[string]string{
				"AEGIS_JWT_ACCESS_TTL": "2h", "AEGIS_JWT_REFRESH_TTL": "1h",
			},
			wantError: "AEGIS_JWT_REFRESH_TTL",
		},
		{
			// If the write deadline fires first, the client gets a truncated
			// body instead of a readable 504.
			name: "request timeout not shorter than write timeout",
			env: map[string]string{
				"AEGIS_HTTP_REQUEST_TIMEOUT": "30s", "AEGIS_HTTP_WRITE_TIMEOUT": "30s",
			},
			wantError: "AEGIS_HTTP_REQUEST_TIMEOUT",
		},
		{
			name:      "llm endpoint without a scheme",
			env:       map[string]string{"AEGIS_LLM_ENDPOINT": "localhost:11434"},
			wantError: "AEGIS_LLM_ENDPOINT",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(env(tc.env))
			if err == nil {
				t.Fatalf("expected an error mentioning %s", tc.wantError)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("error should mention %s:\n%s", tc.wantError, err)
			}
		})
	}
}

// A development default that is merely inconvenient locally is a vulnerability
// in production, so production applies extra rules.
func TestProductionHardening(t *testing.T) {
	t.Parallel()

	base := map[string]string{
		"AEGIS_ENV":             "production",
		"AEGIS_JWT_SECRET":      strings.Repeat("k", 48),
		"AEGIS_PG_SSLMODE":      "require",
		"AEGIS_LOG_FORMAT":      "json",
		"AEGIS_EVENTBUS_DRIVER": "rabbitmq",
	}

	// The baseline must be valid, or the negative cases below prove nothing.
	if _, err := Load(env(base)); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}

	tests := []struct {
		name      string
		override  map[string]string
		wantError string
	}{
		{"plaintext database", map[string]string{"AEGIS_PG_SSLMODE": "disable"}, "SSLMODE"},
		{"test-double event bus", map[string]string{"AEGIS_EVENTBUS_DRIVER": "inproc"}, "inproc"},
		{"unparseable logs", map[string]string{"AEGIS_LOG_FORMAT": "text"}, "LOG_FORMAT"},
		{"wildcard cors", map[string]string{"AEGIS_HTTP_CORS_ORIGINS": "*"}, "CORS_ORIGINS"},
		{"missing jwt secret", map[string]string{"AEGIS_JWT_SECRET": ""}, "AEGIS_JWT_SECRET"},
		{"placeholder jwt secret", map[string]string{"AEGIS_JWT_SECRET": insecureDefaultSecret}, "placeholder"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := make(map[string]string, len(base))
			for k, v := range base {
				m[k] = v
			}
			for k, v := range tc.override {
				m[k] = v
			}

			_, err := Load(env(m))
			if err == nil {
				t.Fatalf("production accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("error should mention %q:\n%s", tc.wantError, err)
			}
		})
	}
}

// The same settings must be permitted in development — production strictness
// that also blocks local work would just be routed around.
func TestDevelopmentPermitsInsecureDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(map[string]string{
		"AEGIS_ENV":               "development",
		"AEGIS_PG_SSLMODE":        "disable",
		"AEGIS_EVENTBUS_DRIVER":   "inproc",
		"AEGIS_HTTP_CORS_ORIGINS": "*",
	}))
	if err != nil {
		t.Fatalf("development rejected its own defaults: %v", err)
	}
	if cfg.Security.JWTSecret.Reveal() != "" {
		t.Error("an unset JWT secret should stay empty in development")
	}
}

func TestShortJWTSecretRejectedEverywhere(t *testing.T) {
	t.Parallel()

	_, err := Load(env(map[string]string{"AEGIS_JWT_SECRET": "tooshort"}))
	if err == nil {
		t.Fatal("a short JWT secret was accepted in development")
	}
	if !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Errorf("error should state the minimum length:\n%s", err)
	}
	// The error must never quote the secret itself.
	if strings.Contains(err.Error(), "tooshort") {
		t.Errorf("the validation error leaked the secret value:\n%s", err)
	}
}

// -----------------------------------------------------------------------------
// Secret
// -----------------------------------------------------------------------------

// Secret closes every accidental path a credential could take out of the process.
func TestSecretRedactsThroughEveryPrintingPath(t *testing.T) {
	t.Parallel()

	const plaintext = "super-secret-signing-key"
	s := Secret(plaintext)

	renders := map[string]string{
		"String()": s.String(),
		"fmt %v":   fmt.Sprintf("%v", s),
		//nolint:staticcheck // the point of the test is that %s routes through Stringer
		"fmt %s":        fmt.Sprintf("%s", s),
		"fmt %q":        fmt.Sprintf("%q", s),
		"fmt %#v":       fmt.Sprintf("%#v", s),
		"slog.LogValue": s.LogValue().String(),
		"struct in %+v": fmt.Sprintf("%+v", struct{ Key Secret }{s}),
	}
	for name, out := range renders {
		if strings.Contains(out, plaintext) {
			t.Errorf("%s leaked the secret: %s", name, out)
		}
		if !strings.Contains(out, redactedPlaceholder) {
			t.Errorf("%s = %q, want the redaction placeholder", name, out)
		}
	}

	b, err := json.Marshal(struct {
		Key Secret `json:"key"`
	}{s})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(b), plaintext) {
		t.Errorf("json.Marshal leaked the secret: %s", b)
	}

	txt, err := s.MarshalText()
	if err != nil || strings.Contains(string(txt), plaintext) {
		t.Errorf("MarshalText leaked the secret: %s (%v)", txt, err)
	}

	// Reveal is the one deliberate, greppable way out.
	if s.Reveal() != plaintext {
		t.Errorf("Reveal() = %q, want the original value", s.Reveal())
	}
	if s.Len() != len(plaintext) {
		t.Errorf("Len() = %d, want %d", s.Len(), len(plaintext))
	}
	if s.IsZero() || !Secret("").IsZero() {
		t.Error("IsZero is wrong")
	}
}

// The startup log line is the most likely place for a credential to escape.
func TestLogAttrsContainNoSecrets(t *testing.T) {
	t.Parallel()

	cfg, err := Load(env(map[string]string{
		"AEGIS_PG_PASSWORD":    "pg-plaintext-password",
		"AEGIS_AMQP_PASSWORD":  "amqp-plaintext-password",
		"AEGIS_REDIS_PASSWORD": "redis-plaintext-password",
		"AEGIS_JWT_SECRET":     strings.Repeat("j", 48),
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	var rendered strings.Builder
	for _, a := range cfg.LogAttrs() {
		fmt.Fprintf(&rendered, "%s=%v ", a.Key, a.Value)
	}

	for _, leaked := range []string{
		"pg-plaintext-password", "amqp-plaintext-password",
		"redis-plaintext-password", strings.Repeat("j", 48),
	} {
		if strings.Contains(rendered.String(), leaked) {
			t.Errorf("LogAttrs leaked a credential:\n%s", rendered.String())
		}
	}

	// It must still be useful: the connection targets have to be visible.
	if !strings.Contains(rendered.String(), "localhost:5434") {
		t.Errorf("LogAttrs omitted the postgres target:\n%s", rendered.String())
	}
}

// DSN and URL are the deliberate exceptions. Safe() is what gets logged.
func TestDSNRevealsAndSafeDoesNot(t *testing.T) {
	t.Parallel()

	pg := PostgresConfig{
		Host: "db", Port: 5432, User: "aegis",
		Password: Secret("p@ssw0rd"), Database: "aegisops", SSLMode: "require",
	}
	if !strings.Contains(pg.DSN(), "p@ssw0rd") {
		t.Error("DSN must contain the password; it is the connection string")
	}
	if strings.Contains(pg.Safe(), "p@ssw0rd") {
		t.Errorf("Safe() leaked the password: %s", pg.Safe())
	}
	if pg.Addr() != "db:5432" {
		t.Errorf("Addr() = %q", pg.Addr())
	}

	amqp := AMQPConfig{Host: "mq", Port: 5672, User: "aegis", Password: Secret("mqpass"), VHost: "/"}
	if !strings.Contains(amqp.URL(), "mqpass") {
		t.Error("URL must contain the password")
	}
	if strings.Contains(amqp.Safe(), "mqpass") {
		t.Errorf("Safe() leaked the password: %s", amqp.Safe())
	}
}

func TestEnvironmentPredicates(t *testing.T) {
	t.Parallel()

	if !EnvProduction.IsProduction() || EnvProduction.IsDevelopment() {
		t.Error("EnvProduction predicates are wrong")
	}
	if !EnvDevelopment.IsDevelopment() || EnvDevelopment.IsProduction() {
		t.Error("EnvDevelopment predicates are wrong")
	}
	if EnvStaging.IsProduction() || EnvStaging.IsDevelopment() {
		t.Error("EnvStaging should be neither")
	}
}
