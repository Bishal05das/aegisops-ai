package logger

import "strings"

// Redacted is the placeholder substituted for a sensitive value.
const Redacted = "[REDACTED]"

// sensitiveSubstrings are matched case-insensitively against attribute keys.
//
// This is a safety net, not the primary control. The primary control is
// config.Secret, which cannot be printed at all. This catches the cases that
// type cannot: a map decoded from a tool's JSON parameters, a header dump, a
// database DSN assembled at a call site.
//
// The list errs towards over-redaction. A redacted value that was harmless
// costs a debugging round-trip; a leaked credential costs a rotation and an
// incident.
var sensitiveSubstrings = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"apikey",
	"api_key",
	"credential",
	"authorization",
	"auth_header",
	"private_key",
	"privatekey",
	"session",
	"cookie",
	"dsn",
	"connection_string",
	"access_key",
	"secret_key",
	"signature",
	"salt",
	"passphrase",
}

// isSensitiveKey reports whether an attribute key looks like it names a secret.
func isSensitiveKey(key string) bool {
	if key == "" {
		return false
	}
	lower := strings.ToLower(key)
	for _, s := range sensitiveSubstrings {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// RedactMap returns a copy of m with sensitive values replaced.
//
// Tool call parameters are arbitrary maps supplied by an LLM and may contain
// anything the model read from the environment, so the harness passes them
// through here before they reach the audit log.
func RedactMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch {
		case isSensitiveKey(k):
			out[k] = Redacted
		default:
			if nested, ok := v.(map[string]any); ok {
				out[k] = RedactMap(nested)
				continue
			}
			out[k] = v
		}
	}
	return out
}

// RedactString masks all but the last n characters of s, for values that must
// remain partially identifiable — a key ID in an audit trail, for instance.
func RedactString(s string, keepLast int) string {
	if s == "" {
		return ""
	}
	if keepLast <= 0 || len(s) <= keepLast {
		return Redacted
	}
	return Redacted + s[len(s)-keepLast:]
}
