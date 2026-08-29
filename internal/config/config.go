// Package config loads and validates AegisOps configuration from the
// environment.
//
// Design rules:
//
//   - **Environment only.** Config files invite drift between what is deployed
//     and what is in the repository; the environment is what Compose, Kubernetes
//     and systemd all speak natively.
//   - **Every error at once.** [Load] accumulates problems rather than dying on
//     the first, so one run tells the operator everything that is wrong.
//   - **Fail fast, fail loud.** Validation happens at startup. A control plane
//     that boots with a 30-second-too-long shutdown grace and only discovers it
//     during a rolling deploy has failed at the worst possible moment.
//   - **Secrets are typed.** [Secret] cannot be printed by accident.
//   - **Production is stricter than development.** Several checks only apply
//     when AEGIS_ENV=production, because a development default that is merely
//     inconvenient locally is a vulnerability in production.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// Environment names the deployment tier.
type Environment string

// Deployment tiers.
const (
	EnvDevelopment Environment = "development"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

// IsProduction reports whether stricter production rules apply.
func (e Environment) IsProduction() bool { return e == EnvProduction }

// IsDevelopment reports whether development conveniences are permitted.
func (e Environment) IsDevelopment() bool { return e == EnvDevelopment }

// Config is the fully validated configuration of an AegisOps process.
type Config struct {
	Env     Environment
	Service string

	Log      LogConfig
	HTTP     HTTPConfig
	Postgres PostgresConfig
	Redis    RedisConfig
	AMQP     AMQPConfig
	LLM      LLMConfig
	Security SecurityConfig
	Harness  HarnessConfig
	Observ   ObservabilityConfig
}

// LogConfig controls log output.
type LogConfig struct {
	Level     slog.Level
	Format    logger.Format
	AddSource bool
}

// HTTPConfig controls the public API listener.
//
// Every timeout here exists to bound a specific attack or failure:
// ReadHeaderTimeout stops Slowloris; ReadTimeout stops a slow body; IdleTimeout
// reclaims kept-alive connections; ShutdownGrace bounds how long a deploy waits
// for in-flight work.
type HTTPConfig struct {
	Addr              string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownGrace     time.Duration
	MaxBodyBytes      int64
	RequestTimeout    time.Duration
	CORSOrigins       []string
}

// PostgresConfig describes the primary datastore. Phase 3 consumes it.
type PostgresConfig struct {
	Host            string
	Port            int
	User            string
	Password        Secret
	Database        string
	SSLMode         string
	MaxConns        int
	MinConns        int
	ConnMaxLifetime time.Duration
}

// DSN renders a libpq connection string.
//
// This method reveals the password by necessity, which is exactly why it is a
// named method rather than string concatenation scattered across the codebase:
// there is one place to audit, and it is never logged. Log [PostgresConfig.Safe]
// instead.
func (p PostgresConfig) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, p.Password.Reveal(), p.Host, p.Port, p.Database, p.SSLMode)
}

// Safe renders the connection target without credentials, for logs.
func (p PostgresConfig) Safe() string {
	return fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=%s", p.User, p.Host, p.Port, p.Database, p.SSLMode)
}

// Addr returns host:port.
func (p PostgresConfig) Addr() string { return fmt.Sprintf("%s:%d", p.Host, p.Port) }

// RedisConfig describes short-term memory. Phase 9 consumes it.
type RedisConfig struct {
	Host     string
	Port     int
	Password Secret
	DB       int
}

// Addr returns host:port.
func (r RedisConfig) Addr() string { return fmt.Sprintf("%s:%d", r.Host, r.Port) }

// AMQPConfig describes the event bus. Phase 5 consumes it.
type AMQPConfig struct {
	Driver   string // "inproc" | "rabbitmq"
	Host     string
	Port     int
	User     string
	Password Secret
	VHost    string
	Exchange string
}

// Addr returns host:port.
func (a AMQPConfig) Addr() string { return fmt.Sprintf("%s:%d", a.Host, a.Port) }

// URL renders an AMQP connection URL, revealing the password.
func (a AMQPConfig) URL() string {
	return fmt.Sprintf("amqp://%s:%s@%s:%d%s", a.User, a.Password.Reveal(), a.Host, a.Port, a.VHost)
}

// Safe renders the broker target without credentials, for logs.
func (a AMQPConfig) Safe() string {
	return fmt.Sprintf("amqp://%s@%s:%d%s", a.User, a.Host, a.Port, a.VHost)
}

// LLMConfig describes the local inference provider. Phase 8 consumes it.
type LLMConfig struct {
	Provider    string
	Endpoint    string
	Model       string
	EmbedModel  string
	Timeout     time.Duration
	MaxTokens   int
	Temperature float64
}

// SecurityConfig describes authentication and abuse limits. Phase 4 consumes it.
type SecurityConfig struct {
	JWTSecret      Secret
	JWTAccessTTL   time.Duration
	JWTRefreshTTL  time.Duration
	JWTIssuer      string
	RateLimitRPS   int
	RateLimitBurst int
}

// HarnessConfig describes the execution boundary. Phase 6 consumes it.
type HarnessConfig struct {
	DryRun          bool
	ApprovalTimeout time.Duration
	MaxAutoRisk     string
}

// ObservabilityConfig describes metrics and tracing. Phase 11 consumes it.
type ObservabilityConfig struct {
	MetricsAddr    string
	OTLPEndpoint   string
	TracingEnabled bool
}

// minJWTSecretLen is 32 bytes: HS256 keys shorter than the hash output add no
// security over a 256-bit key while creating a false impression of strength.
const minJWTSecretLen = 32

// insecureDefaultSecret is the placeholder shipped in .env.example. Booting
// production with it must be impossible, not merely discouraged.
const insecureDefaultSecret = "change-me-in-production-min-32-bytes-long"

// Load reads configuration from the environment.
//
// lookup is injectable for tests; pass nil to use os.LookupEnv. All problems are
// reported together in a single joined error.
func Load(lookup func(string) (string, bool)) (*Config, error) {
	l := newLoader(lookup)
	cfg := &Config{}

	// ---- runtime ------------------------------------------------------------
	cfg.Env = Environment(l.oneOf("AEGIS_ENV", string(EnvDevelopment),
		string(EnvDevelopment), string(EnvStaging), string(EnvProduction)))
	cfg.Service = l.str("AEGIS_SERVICE_NAME", "aegisopsd")

	// ---- logging ------------------------------------------------------------
	levelName := l.str("AEGIS_LOG_LEVEL", defaultLogLevel(cfg.Env))
	level, ok := logger.ParseLevel(levelName)
	if !ok {
		l.addf("AEGIS_LOG_LEVEL=%q must be one of: debug, info, warn, error", levelName)
	}
	formatName := l.str("AEGIS_LOG_FORMAT", defaultLogFormat(cfg.Env))
	format, ok := logger.ParseFormat(formatName)
	if !ok {
		l.addf("AEGIS_LOG_FORMAT=%q must be one of: json, text", formatName)
	}
	cfg.Log = LogConfig{
		Level:  level,
		Format: format,
		// Source locations cost a runtime.Callers per record. Worth it while
		// developing, not worth it under production load.
		AddSource: l.boolVal("AEGIS_LOG_SOURCE", cfg.Env.IsDevelopment()),
	}

	// ---- HTTP ---------------------------------------------------------------
	cfg.HTTP = HTTPConfig{
		Addr:              l.str("AEGIS_HTTP_ADDR", ":8080"),
		ReadTimeout:       l.duration("AEGIS_HTTP_READ_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
		ReadHeaderTimeout: l.duration("AEGIS_HTTP_READ_HEADER_TIMEOUT", 5*time.Second, time.Second, time.Minute),
		WriteTimeout:      l.duration("AEGIS_HTTP_WRITE_TIMEOUT", 30*time.Second, time.Second, 10*time.Minute),
		IdleTimeout:       l.duration("AEGIS_HTTP_IDLE_TIMEOUT", 120*time.Second, time.Second, 30*time.Minute),
		ShutdownGrace:     l.duration("AEGIS_HTTP_SHUTDOWN_GRACE", 20*time.Second, time.Second, 5*time.Minute),
		MaxBodyBytes:      int64(l.intVal("AEGIS_HTTP_MAX_BODY_BYTES", 1<<20, 1<<10, 64<<20)),
		RequestTimeout:    l.duration("AEGIS_HTTP_REQUEST_TIMEOUT", 25*time.Second, time.Second, 10*time.Minute),
		CORSOrigins:       l.csv("AEGIS_HTTP_CORS_ORIGINS", nil),
	}

	// ---- postgres -----------------------------------------------------------
	cfg.Postgres = PostgresConfig{
		Host:            l.str("AEGIS_PG_HOST", "localhost"),
		Port:            l.port("AEGIS_PG_PORT", 5434),
		User:            l.str("AEGIS_PG_USER", "aegis"),
		Password:        l.secret("AEGIS_PG_PASSWORD", "aegis_dev_password"),
		Database:        l.str("AEGIS_PG_DATABASE", "aegisops"),
		SSLMode:         l.oneOf("AEGIS_PG_SSLMODE", "disable", "disable", "require", "verify-ca", "verify-full", "prefer", "allow"),
		MaxConns:        l.intVal("AEGIS_PG_MAX_CONNS", 20, 1, 500),
		MinConns:        l.intVal("AEGIS_PG_MIN_CONNS", 2, 0, 500),
		ConnMaxLifetime: l.duration("AEGIS_PG_CONN_MAX_LIFETIME", 30*time.Minute, time.Minute, 24*time.Hour),
	}

	// ---- redis --------------------------------------------------------------
	cfg.Redis = RedisConfig{
		Host:     l.str("AEGIS_REDIS_HOST", "localhost"),
		Port:     l.port("AEGIS_REDIS_PORT", 6380),
		Password: l.secret("AEGIS_REDIS_PASSWORD", ""),
		DB:       l.intVal("AEGIS_REDIS_DB", 0, 0, 15),
	}

	// ---- event bus ----------------------------------------------------------
	cfg.AMQP = AMQPConfig{
		Driver:   l.oneOf("AEGIS_EVENTBUS_DRIVER", "inproc", "inproc", "rabbitmq"),
		Host:     l.str("AEGIS_AMQP_HOST", "localhost"),
		Port:     l.port("AEGIS_AMQP_PORT", 5672),
		User:     l.str("AEGIS_AMQP_USER", "aegis"),
		Password: l.secret("AEGIS_AMQP_PASSWORD", "aegis_dev_password"),
		VHost:    l.str("AEGIS_AMQP_VHOST", "/"),
		Exchange: l.str("AEGIS_AMQP_EXCHANGE", "aegisops.events"),
	}

	// ---- LLM ----------------------------------------------------------------
	cfg.LLM = LLMConfig{
		Provider:   l.oneOf("AEGIS_LLM_PROVIDER", "ollama", "ollama", "llamacpp", "mock"),
		Endpoint:   l.str("AEGIS_LLM_ENDPOINT", "http://localhost:11434"),
		Model:      l.str("AEGIS_LLM_MODEL", "qwen2.5:7b"),
		EmbedModel: l.str("AEGIS_LLM_EMBED_MODEL", "nomic-embed-text"),
		Timeout:    l.duration("AEGIS_LLM_TIMEOUT", 120*time.Second, 5*time.Second, 30*time.Minute),
		MaxTokens:  l.intVal("AEGIS_LLM_MAX_TOKENS", 2048, 64, 131072),
		// Diagnosis must be as reproducible as a sampled model allows; near-zero
		// temperature is a correctness requirement here, not a style choice.
		Temperature: l.float("AEGIS_LLM_TEMPERATURE", 0.1, 0, 2),
	}

	// ---- security -----------------------------------------------------------
	cfg.Security = SecurityConfig{
		JWTSecret:      l.secret("AEGIS_JWT_SECRET", ""),
		JWTAccessTTL:   l.duration("AEGIS_JWT_ACCESS_TTL", 15*time.Minute, time.Minute, 24*time.Hour),
		JWTRefreshTTL:  l.duration("AEGIS_JWT_REFRESH_TTL", 168*time.Hour, time.Hour, 90*24*time.Hour),
		JWTIssuer:      l.str("AEGIS_JWT_ISSUER", "aegisops-ai"),
		RateLimitRPS:   l.intVal("AEGIS_RATE_LIMIT_RPS", 20, 1, 100000),
		RateLimitBurst: l.intVal("AEGIS_RATE_LIMIT_BURST", 40, 1, 100000),
	}

	// ---- harness ------------------------------------------------------------
	cfg.Harness = HarnessConfig{
		// Dry-run defaults ON outside production. Executing real infrastructure
		// changes must be something you switch on deliberately.
		DryRun:          l.boolVal("AEGIS_HARNESS_DRY_RUN", !cfg.Env.IsProduction()),
		ApprovalTimeout: l.duration("AEGIS_HARNESS_APPROVAL_TIMEOUT", 30*time.Minute, time.Minute, 24*time.Hour),
		MaxAutoRisk:     l.oneOf("AEGIS_HARNESS_MAX_AUTO_RISK", "low", "none", "low", "medium", "high"),
	}

	// ---- observability ------------------------------------------------------
	cfg.Observ = ObservabilityConfig{
		MetricsAddr:    l.str("AEGIS_METRICS_ADDR", ":9091"),
		OTLPEndpoint:   l.str("AEGIS_OTLP_ENDPOINT", "localhost:4317"),
		TracingEnabled: l.boolVal("AEGIS_TRACING_ENABLED", false),
	}

	cfg.validate(l)

	if len(l.errs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n%w", indentErrors(l.errs))
	}
	return cfg, nil
}

// validate applies cross-field rules that no single typed reader can express.
func (c *Config) validate(l *loader) {
	// Connection pool coherence.
	if c.Postgres.MinConns > c.Postgres.MaxConns {
		l.addf("AEGIS_PG_MIN_CONNS=%d cannot exceed AEGIS_PG_MAX_CONNS=%d",
			c.Postgres.MinConns, c.Postgres.MaxConns)
	}

	// A burst below the sustained rate makes the limiter reject traffic it was
	// configured to allow.
	if c.Security.RateLimitBurst < c.Security.RateLimitRPS {
		l.addf("AEGIS_RATE_LIMIT_BURST=%d must be >= AEGIS_RATE_LIMIT_RPS=%d",
			c.Security.RateLimitBurst, c.Security.RateLimitRPS)
	}

	// A refresh token that outlives its access token is the entire point.
	if c.Security.JWTRefreshTTL <= c.Security.JWTAccessTTL {
		l.addf("AEGIS_JWT_REFRESH_TTL=%s must be longer than AEGIS_JWT_ACCESS_TTL=%s",
			c.Security.JWTRefreshTTL, c.Security.JWTAccessTTL)
	}

	// A per-request timeout at or above WriteTimeout means the connection is torn
	// down before the handler can render its own timeout response, turning a
	// clean 504 into a truncated body the client cannot interpret.
	if c.HTTP.RequestTimeout >= c.HTTP.WriteTimeout {
		l.addf("AEGIS_HTTP_REQUEST_TIMEOUT=%s must be shorter than AEGIS_HTTP_WRITE_TIMEOUT=%s "+
			"so the server can render a 504 before the write deadline fires",
			c.HTTP.RequestTimeout, c.HTTP.WriteTimeout)
	}

	if c.HTTP.ReadHeaderTimeout > c.HTTP.ReadTimeout {
		l.addf("AEGIS_HTTP_READ_HEADER_TIMEOUT=%s cannot exceed AEGIS_HTTP_READ_TIMEOUT=%s",
			c.HTTP.ReadHeaderTimeout, c.HTTP.ReadTimeout)
	}

	if !strings.HasPrefix(c.LLM.Endpoint, "http://") && !strings.HasPrefix(c.LLM.Endpoint, "https://") {
		l.addf("AEGIS_LLM_ENDPOINT=%q must start with http:// or https://", c.LLM.Endpoint)
	}

	// ---- JWT secret ---------------------------------------------------------
	switch {
	case c.Security.JWTSecret.IsZero():
		if c.Env.IsProduction() {
			l.addf("AEGIS_JWT_SECRET is required in production (generate one with `make gen-secret`)")
		}
	case c.Security.JWTSecret.Len() < minJWTSecretLen:
		l.addf("AEGIS_JWT_SECRET must be at least %d bytes, got %d (generate one with `make gen-secret`)",
			minJWTSecretLen, c.Security.JWTSecret.Len())
	case c.Security.JWTSecret.Reveal() == insecureDefaultSecret && c.Env.IsProduction():
		l.addf("AEGIS_JWT_SECRET is still the placeholder from .env.example — " +
			"generate a real one with `make gen-secret`")
	}

	// ---- production-only hardening ------------------------------------------
	if !c.Env.IsProduction() {
		return
	}
	if c.Postgres.SSLMode == "disable" {
		l.addf("AEGIS_PG_SSLMODE=disable is not permitted in production")
	}
	if c.AMQP.Driver == "inproc" {
		l.addf("AEGIS_EVENTBUS_DRIVER=inproc is a test double; production requires rabbitmq")
	}
	if c.Log.Format != logger.FormatJSON {
		l.addf("AEGIS_LOG_FORMAT must be json in production for log ingestion")
	}
	for _, o := range c.HTTP.CORSOrigins {
		if o == "*" {
			l.addf("AEGIS_HTTP_CORS_ORIGINS may not contain \"*\" in production")
		}
	}
}

func defaultLogLevel(env Environment) string {
	if env.IsDevelopment() {
		return "debug"
	}
	return "info"
}

func defaultLogFormat(env Environment) string {
	if env.IsDevelopment() {
		return "text"
	}
	return "json"
}

// indentErrors renders accumulated errors as a readable bulleted list.
func indentErrors(errs []error) error {
	var b strings.Builder
	for i, e := range errs {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("  • ")
		b.WriteString(e.Error())
	}
	return errors.New(b.String())
}

// LogAttrs renders the configuration for a startup log line.
//
// Secrets are unreachable here by construction: the Secret type redacts itself
// through slog, and no field below calls Reveal.
func (c *Config) LogAttrs() []slog.Attr {
	// service, version and env are attached to the logger as base attributes, so
	// they are deliberately absent here — repeating them would duplicate every
	// key in the startup line.
	return []slog.Attr{
		slog.String("log_level", c.Log.Level.String()),
		slog.String("log_format", string(c.Log.Format)),
		slog.String("http_addr", c.HTTP.Addr),
		slog.String("metrics_addr", c.Observ.MetricsAddr),
		slog.String("postgres", c.Postgres.Safe()),
		slog.String("redis", c.Redis.Addr()),
		slog.String("eventbus", c.AMQP.Driver),
		slog.String("amqp", c.AMQP.Safe()),
		slog.String("llm_provider", c.LLM.Provider),
		slog.String("llm_model", c.LLM.Model),
		slog.Bool("harness_dry_run", c.Harness.DryRun),
		slog.String("harness_max_auto_risk", c.Harness.MaxAutoRisk),
		slog.Bool("tracing", c.Observ.TracingEnabled),
	}
}
