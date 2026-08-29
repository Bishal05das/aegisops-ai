package preflight

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// base carries the metadata every check shares. Embedding it keeps each concrete
// check focused on the one thing that differs: its handshake.
type base struct {
	name     string
	target   string
	hint     string
	severity Severity
}

// Name implements Check.
func (b base) Name() string { return b.name }

// Target implements Check.
func (b base) Target() string { return b.target }

// Hint implements Check.
func (b base) Hint() string { return b.hint }

// Severity implements Check.
func (b base) Severity() Severity { return b.severity }

// dial opens a TCP connection bounded by ctx and applies the context deadline to
// the socket itself, so a peer that accepts but never speaks still times out.
func dial(ctx context.Context, address string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(DefaultCheckTimeout))
	}
	return conn, nil
}

// -----------------------------------------------------------------------------
// TCP
// -----------------------------------------------------------------------------

// TCPCheck proves only that something is accepting connections on a port.
//
// It is the weakest useful check and is used for services whose protocol we do
// not need to speak. Anything AegisOps depends on for correctness gets a real
// protocol handshake instead.
type TCPCheck struct {
	base
	Address string
}

// NewTCPCheck builds a plain reachability probe.
func NewTCPCheck(name, address, hint string, sev Severity) *TCPCheck {
	return &TCPCheck{
		base:    base{name: name, target: address, hint: hint, severity: sev},
		Address: address,
	}
}

// Probe implements Check.
func (c *TCPCheck) Probe(ctx context.Context) (string, error) {
	conn, err := dial(ctx, c.Address)
	if err != nil {
		return "", err
	}
	// The probe is read-only; a close failure tells us nothing actionable.
	defer func() { _ = conn.Close() }()
	return "tcp connect ok", nil
}

// -----------------------------------------------------------------------------
// HTTP
// -----------------------------------------------------------------------------

// HTTPCheck issues a GET and validates the response.
//
// Redirects are not followed: a health endpoint that redirects is misconfigured,
// and silently following it would hide that.
type HTTPCheck struct {
	base
	URL string
	// Accept lists status codes treated as healthy. Empty means 200-299.
	Accept []int
	// Validate optionally inspects the body; return ErrDegraded to warn.
	Validate func(body []byte) (string, error)
	// MaxBody caps how much of the response is read. Zero means 64 KiB.
	MaxBody int64
	// Username and Password enable HTTP Basic auth. Supplying them turns a
	// liveness probe into a credential check: a 401 then proves the configured
	// credentials are wrong, not merely that the service is protected.
	Username string
	Password string
}

// NewHTTPCheck builds an HTTP probe against a health or status endpoint.
func NewHTTPCheck(name, url, hint string, sev Severity) *HTTPCheck {
	return &HTTPCheck{
		base: base{name: name, target: url, hint: hint, severity: sev},
		URL:  url,
	}
}

const defaultMaxBody = 64 << 10

// Probe implements Check.
func (c *HTTPCheck) Probe(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegisops-preflight")
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}

	client := &http.Client{
		// Surface redirects rather than chasing them.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 3 * time.Second,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	limit := c.MaxBody
	if limit <= 0 {
		limit = defaultMaxBody
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	if !c.accepts(resp.StatusCode) {
		return "", fmt.Errorf("unexpected status %s: %s", resp.Status, snippet(body))
	}

	if c.Validate != nil {
		return c.Validate(body)
	}
	return fmt.Sprintf("HTTP %d", resp.StatusCode), nil
}

func (c *HTTPCheck) accepts(code int) bool {
	if len(c.Accept) == 0 {
		return code >= 200 && code < 300
	}
	for _, want := range c.Accept {
		if want == code {
			return true
		}
	}
	return false
}

// snippet trims a response body down to something safe to put in a one-line
// error, collapsing whitespace so multi-line error pages stay readable.
func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	const limit = 120
	if len(s) > limit {
		return s[:limit] + "…"
	}
	if s == "" {
		return "<empty body>"
	}
	return s
}
