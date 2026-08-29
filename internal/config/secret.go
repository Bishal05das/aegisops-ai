package config

import (
	"encoding/json"
	"log/slog"
)

// redactedPlaceholder is what a Secret renders as through every printing path.
const redactedPlaceholder = "[REDACTED]"

// Secret is a string that refuses to print itself.
//
// The threat it addresses is mundane and extremely common: someone adds
// `log.Info("config loaded", "config", cfg)` during debugging, and the JWT
// signing key ends up in a log aggregator with a 90-day retention and a much
// wider read audience than the process that held it.
//
// Secret closes every accidental path out:
//
//	fmt.Println(s)              → [REDACTED]   (Stringer)
//	fmt.Printf("%v/%s/%q", ...) → [REDACTED]   (Stringer / Formatter)
//	json.Marshal(s)             → "[REDACTED]" (Marshaler)
//	slog.Any("k", s)            → [REDACTED]   (LogValuer)
//
// Reading the real value requires calling [Secret.Reveal], which is greppable.
// That is the design: not "impossible to leak", but "impossible to leak by
// accident, and obvious in review when done deliberately".
type Secret string

// String implements fmt.Stringer, covering %v and %s.
func (s Secret) String() string { return redactedPlaceholder }

// GoString implements fmt.GoStringer, covering %#v.
func (s Secret) GoString() string { return redactedPlaceholder }

// MarshalJSON implements json.Marshaler.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redactedPlaceholder) }

// MarshalText implements encoding.TextMarshaler, covering YAML and map keys.
func (s Secret) MarshalText() ([]byte, error) { return []byte(redactedPlaceholder), nil }

// LogValue implements slog.LogValuer, covering every structured log path.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redactedPlaceholder) }

// Reveal returns the underlying value.
//
// Every call site is a deliberate decision to handle plaintext. Audit them with:
//
//	grep -rn '\.Reveal()' --include='*.go'
func (s Secret) Reveal() string { return string(s) }

// IsZero reports whether the secret is unset.
func (s Secret) IsZero() bool { return s == "" }

// Len returns the length of the underlying value without revealing it, so
// validation can check minimum entropy requirements safely.
func (s Secret) Len() int { return len(s) }
