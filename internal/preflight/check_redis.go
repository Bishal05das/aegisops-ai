package preflight

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RedisCheck speaks RESP directly to prove a real Redis server is listening and,
// where possible, reports its version.
//
// Redis is AegisOps' short-term memory: live incident state, agent scratchpads
// and idempotency keys. A stale or wrong server behind port 6380 would silently
// corrupt in-flight incident context, so "port is open" is not good enough.
//
// RESP is small enough to implement honestly in ~60 lines, which keeps Phase 1
// dependency-free.
type RedisCheck struct {
	base
	Address  string
	Password string
}

// NewRedisCheck builds a RESP probe.
func NewRedisCheck(address, password string) *RedisCheck {
	return &RedisCheck{
		base: base{
			name:     "redis",
			target:   address,
			severity: Required,
			hint:     "start the stack with `make dev-up`; note the host port is 6380, not 6379",
		},
		Address:  address,
		Password: password,
	}
}

// Probe implements Check.
func (c *RedisCheck) Probe(ctx context.Context) (string, error) {
	conn, err := dial(ctx, c.Address)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	if c.Password != "" {
		if _, err := respCommand(rw, "AUTH", c.Password); err != nil {
			return "", fmt.Errorf("AUTH: %w", err)
		}
	}

	pong, err := respCommand(rw, "PING")
	if err != nil {
		return "", fmt.Errorf("PING: %w", err)
	}
	if !strings.EqualFold(pong, "PONG") {
		return "", fmt.Errorf("PING returned %q, expected PONG: not a redis server", pong)
	}

	// Version is informational; a server that pongs but refuses INFO (ACL-
	// restricted, for instance) is still usable.
	detail := "RESP PING/PONG ok"
	if info, err := respCommand(rw, "INFO", "server"); err == nil {
		if v := field(info, "redis_version"); v != "" {
			detail = "redis " + v + " responding"
		}
	}
	return detail, nil
}

// respCommand writes one command as a RESP array of bulk strings and returns the
// decoded reply as a string.
func respCommand(rw *bufio.ReadWriter, args ...string) (string, error) {
	if _, err := fmt.Fprintf(rw, "*%d\r\n", len(args)); err != nil {
		return "", err
	}
	for _, a := range args {
		if _, err := fmt.Fprintf(rw, "$%d\r\n%s\r\n", len(a), a); err != nil {
			return "", err
		}
	}
	if err := rw.Flush(); err != nil {
		return "", err
	}
	return respRead(rw.Reader)
}

// respRead decodes the reply types a preflight can encounter: simple string,
// error, integer and bulk string. Arrays are out of scope — no command we issue
// returns one — and are reported rather than silently mishandled.
func respRead(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", fmt.Errorf("empty RESP reply")
	}

	switch line[0] {
	case '+': // simple string
		return line[1:], nil
	case '-': // error
		return "", fmt.Errorf("redis error: %s", line[1:])
	case ':': // integer
		return line[1:], nil
	case '$': // bulk string
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", fmt.Errorf("bad bulk length %q: %w", line[1:], err)
		}
		if n < 0 {
			return "", nil // RESP nil
		}
		buf := make([]byte, n+2) // payload + trailing CRLF
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("read bulk payload: %w", err)
		}
		return string(buf[:n]), nil
	default:
		return "", fmt.Errorf("unsupported RESP type %q: not a redis server", line[0])
	}
}

// field extracts a `key:value` line from a Redis INFO payload.
func field(info, key string) string {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if name, val, ok := strings.Cut(line, ":"); ok && name == key {
			return val
		}
	}
	return ""
}

// compile-time assertions that the checks satisfy the interface.
var (
	_ Check = (*RedisCheck)(nil)
	_ Check = (*PostgresCheck)(nil)
	_ Check = (*TCPCheck)(nil)
	_ Check = (*HTTPCheck)(nil)
)
