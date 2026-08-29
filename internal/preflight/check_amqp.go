package preflight

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// AMQPCheck performs the AMQP 0-9-1 protocol handshake to prove a real broker is
// listening on the event-bus port.
//
// The handshake is the first thing any AMQP client does:
//
//	client -> "AMQP" 0x00 0x00 0x09 0x01     // literal protocol header
//	server -> frame{type=1, channel=0, ...}  // Connection.Start (class 10, method 10)
//
// If the broker speaks a different version it replies with its own 8-byte header
// instead of a frame and closes — which we detect and report precisely, rather
// than as a generic "connection failed".
//
// We stop at Connection.Start: authenticating would require implementing SASL
// PLAIN and field tables for no additional signal at preflight time. Credential
// validity is proven by the RabbitMQ management HTTP check, which does
// authenticate.
type AMQPCheck struct {
	base
	Address string
}

// amqp091Header is the protocol header for AMQP 0-9-1.
var amqp091Header = []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}

const (
	frameMethod       = 1 // frame type octet for a method frame
	frameEnd          = 0xCE
	classConnection   = 10 // AMQP class id for `connection`
	methodConnStart   = 10 // AMQP method id for `connection.start`
	maxHandshakeFrame = 1 << 20
)

// NewAMQPCheck builds an AMQP 0-9-1 handshake probe.
func NewAMQPCheck(address string) *AMQPCheck {
	return &AMQPCheck{
		base: base{
			name:     "rabbitmq",
			target:   address,
			severity: Required,
			hint:     "start the stack with `make dev-up`; RabbitMQ needs ~25s to become healthy on first boot",
		},
		Address: address,
	}
}

// Probe implements Check.
func (c *AMQPCheck) Probe(ctx context.Context) (string, error) {
	conn, err := dial(ctx, c.Address)
	if err != nil {
		return "", err
	}
	// The probe is read-only; a close failure tells us nothing actionable.
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(amqp091Header); err != nil {
		return "", fmt.Errorf("write protocol header: %w", err)
	}

	// A method frame header is: type(1) channel(2) size(4).
	head := make([]byte, 7)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", fmt.Errorf("read frame header (is this really an AMQP broker?): %w", err)
	}

	// A version-mismatch reply is not a frame: it is another 8-byte protocol
	// header, "AMQP" followed by the version the broker does support. We have
	// only read 7 of those 8 bytes, so pull the last one before reporting.
	if string(head[:4]) == "AMQP" {
		rev := make([]byte, 1)
		_, _ = io.ReadFull(conn, rev)
		return "", fmt.Errorf("broker rejected AMQP 0-9-1; it advertises %d-%d-%d",
			head[5], head[6], rev[0])
	}

	if head[0] != frameMethod {
		return "", fmt.Errorf("expected method frame (type 1), got type %d", head[0])
	}

	size := binary.BigEndian.Uint32(head[3:7])
	if size > maxHandshakeFrame {
		return "", fmt.Errorf("implausible frame size %d, refusing to read", size)
	}

	// Payload plus the mandatory 0xCE frame-end octet.
	payload := make([]byte, size+1)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return "", fmt.Errorf("read frame payload: %w", err)
	}
	if payload[size] != frameEnd {
		return "", fmt.Errorf("malformed frame: end octet was 0x%02X, expected 0xCE", payload[size])
	}

	// Connection.Start payload: class(2) method(2) version-major(1) version-minor(1) ...
	if size < 6 {
		return "", fmt.Errorf("Connection.Start truncated: %d bytes", size)
	}
	class := binary.BigEndian.Uint16(payload[0:2])
	method := binary.BigEndian.Uint16(payload[2:4])
	if class != classConnection || method != methodConnStart {
		return "", fmt.Errorf("expected Connection.Start (10/10), got %d/%d", class, method)
	}

	return fmt.Sprintf("AMQP %d-%d broker responding (Connection.Start received)",
		payload[4], payload[5]), nil
}

var _ Check = (*AMQPCheck)(nil)
