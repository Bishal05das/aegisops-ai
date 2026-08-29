package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// loader reads typed values from the environment, accumulating every problem
// instead of failing on the first.
//
// The alternative — return on first error — produces the worst possible
// operator experience during a deployment: fix a typo, redeploy, wait, discover
// the next typo, repeat. Accumulation turns five deploys into one.
type loader struct {
	// lookup is injectable so tests never mutate the real process environment,
	// which would make them order-dependent and hostile to t.Parallel.
	lookup func(string) (string, bool)
	errs   []error
	// seen records every key consulted, powering Keys() for documentation and
	// for detecting AEGIS_* variables that no longer have a consumer.
	seen map[string]bool
}

func newLoader(lookup func(string) (string, bool)) *loader {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	return &loader{lookup: lookup, seen: make(map[string]bool, 64)}
}

// get returns the trimmed raw value and whether it was present and non-empty.
// An empty variable is treated as absent: `AEGIS_PG_HOST=` in a .env file means
// "I did not set this", never "the host is the empty string".
func (l *loader) get(key string) (string, bool) {
	l.seen[key] = true
	v, ok := l.lookup(key)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	return v, v != ""
}

func (l *loader) fail(key, raw, want string) {
	l.errs = append(l.errs, fmt.Errorf("%s=%q is not a valid %s", key, raw, want))
}

// str reads a string with a default.
func (l *loader) str(key, def string) string {
	if v, ok := l.get(key); ok {
		return v
	}
	return def
}

// required reads a string that must be present.
func (l *loader) required(key string) string {
	v, ok := l.get(key)
	if !ok {
		l.errs = append(l.errs, fmt.Errorf("%s is required but not set", key))
	}
	return v
}

// secret reads a value into a Secret, which redacts itself everywhere.
func (l *loader) secret(key, def string) Secret {
	if v, ok := l.get(key); ok {
		return Secret(v)
	}
	return Secret(def)
}

// oneOf reads a string constrained to an allowed set. Listing the valid options
// in the error is the difference between a two-minute fix and a code dive.
func (l *loader) oneOf(key, def string, allowed ...string) string {
	v := l.str(key, def)
	for _, a := range allowed {
		if strings.EqualFold(v, a) {
			return strings.ToLower(v)
		}
	}
	l.errs = append(l.errs, fmt.Errorf("%s=%q must be one of: %s", key, v, strings.Join(allowed, ", ")))
	return def
}

// intVal reads an integer with bounds. min/max are inclusive.
func (l *loader) intVal(key string, def, minV, maxV int) int {
	raw, ok := l.get(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		l.fail(key, raw, "integer")
		return def
	}
	if n < minV || n > maxV {
		l.errs = append(l.errs, fmt.Errorf("%s=%d is out of range [%d, %d]", key, n, minV, maxV))
		return def
	}
	return n
}

// port reads a TCP port number.
func (l *loader) port(key string, def int) int {
	return l.intVal(key, def, 1, 65535)
}

// boolVal reads a boolean, accepting the spellings people actually write.
func (l *loader) boolVal(key string, def bool) bool {
	raw, ok := l.get(key)
	if !ok {
		return def
	}
	switch strings.ToLower(raw) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	case "0", "f", "false", "n", "no", "off":
		return false
	default:
		l.fail(key, raw, "boolean (true/false, yes/no, 1/0, on/off)")
		return def
	}
}

// duration reads a Go duration string such as "15s" or "2h30m".
func (l *loader) duration(key string, def, minV, maxV time.Duration) time.Duration {
	raw, ok := l.get(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		l.fail(key, raw, `duration (e.g. "15s", "2m", "1h30m")`)
		return def
	}
	if d < minV || d > maxV {
		l.errs = append(l.errs, fmt.Errorf("%s=%s is out of range [%s, %s]", key, d, minV, maxV))
		return def
	}
	return d
}

// float reads a float with inclusive bounds.
func (l *loader) float(key string, def, minV, maxV float64) float64 {
	raw, ok := l.get(key)
	if !ok {
		return def
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		l.fail(key, raw, "number")
		return def
	}
	if f < minV || f > maxV {
		l.errs = append(l.errs, fmt.Errorf("%s=%v is out of range [%v, %v]", key, f, minV, maxV))
		return def
	}
	return f
}

// csv reads a comma-separated list, dropping empty entries.
func (l *loader) csv(key string, def []string) []string {
	raw, ok := l.get(key)
	if !ok {
		return def
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

// addf records a validation error discovered outside a typed reader.
func (l *loader) addf(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

// Keys returns every environment variable the loader consulted, sorted.
func (l *loader) Keys() []string {
	out := make([]string, 0, len(l.seen))
	for k := range l.seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
