package preflight

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// PostgresCheck proves that a live PostgreSQL backend — not merely an open port
// — is listening, by performing the frontend/backend protocol's SSLRequest
// negotiation.
//
// The exchange is the smallest conversation PostgreSQL will hold with a client:
//
//	client -> int32(8) int32(80877103)      // length, SSLRequest magic
//	server -> 'S' | 'N'                     // SSL available / not available
//
// Anything else on that port either refuses the connection, ignores it until we
// time out, or answers with a byte we do not recognise. That is exactly the
// discrimination a preflight needs, and it costs no driver dependency — which
// matters in Phase 1, before pgx is introduced in Phase 3.
type PostgresCheck struct {
	base
	Address string
}

// sslRequestCode is the magic protocol number for an SSLRequest packet:
// 1234 in the high 16 bits, 5679 in the low 16 bits.
const sslRequestCode = 80877103

// NewPostgresCheck builds a PostgreSQL wire-protocol probe.
func NewPostgresCheck(address string) *PostgresCheck {
	return &PostgresCheck{
		base: base{
			name:     "postgres",
			target:   address,
			severity: Required,
			hint:     "start the stack with `make dev-up`, then `make dev-logs SVC=postgres`",
		},
		Address: address,
	}
}

// Probe implements Check.
func (c *PostgresCheck) Probe(ctx context.Context) (string, error) {
	conn, err := dial(ctx, c.Address)
	if err != nil {
		return "", err
	}
	// The probe is read-only; a close failure tells us nothing actionable.
	defer func() { _ = conn.Close() }()

	// An SSLRequest is a self-describing 8-byte packet: its own length,
	// then the magic code. There is no message-type byte during startup.
	packet := make([]byte, 8)
	binary.BigEndian.PutUint32(packet[0:4], 8)
	binary.BigEndian.PutUint32(packet[4:8], sslRequestCode)

	if _, err := conn.Write(packet); err != nil {
		return "", fmt.Errorf("write SSLRequest: %w", err)
	}

	reply := make([]byte, 1)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return "", fmt.Errorf("read SSLRequest reply (is this really postgres?): %w", err)
	}

	switch reply[0] {
	case 'S':
		return "postgres backend responding (TLS available)", nil
	case 'N':
		return "postgres backend responding (TLS not configured)", nil
	case 'E':
		// A pre-8.0 server, or one that rejected the packet outright. It is
		// alive and speaking the protocol, so this is a warning, not a failure.
		return "postgres backend responding (SSLRequest rejected)",
			fmt.Errorf("%w: server returned an ErrorResponse to SSLRequest", ErrDegraded)
	default:
		return "", fmt.Errorf("unexpected byte %q from %s: not a postgres backend", reply[0], c.Address)
	}
}
