package preflight

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// serveOnce starts a TCP listener that hands the first connection to handler and
// returns its address. Using a real socket rather than a mock means these tests
// exercise the actual byte-level encoding the production probes emit.
func serveOnce(t *testing.T, handler func(net.Conn)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		handler(conn)
	}()
	return ln.Addr().String()
}

func probe(t *testing.T, c Check) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.Probe(ctx)
}

// -----------------------------------------------------------------------------
// PostgreSQL — SSLRequest negotiation
// -----------------------------------------------------------------------------

// fakePostgres reads the 8-byte SSLRequest and replies with the given byte.
func fakePostgres(t *testing.T, reply byte) string {
	return serveOnce(t, func(conn net.Conn) {
		buf := make([]byte, 8)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		// Assert the client actually sent a well-formed SSLRequest.
		if binary.BigEndian.Uint32(buf[0:4]) != 8 ||
			binary.BigEndian.Uint32(buf[4:8]) != sslRequestCode {
			t.Errorf("client sent %v, want a valid SSLRequest packet", buf)
			return
		}
		_, _ = conn.Write([]byte{reply})
	})
}

func TestPostgresCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		reply      byte
		wantErr    bool
		wantDegrad bool
		wantDetail string
	}{
		{name: "tls available", reply: 'S', wantDetail: "TLS available"},
		{name: "tls not configured", reply: 'N', wantDetail: "TLS not configured"},
		{name: "error response is degraded", reply: 'E', wantErr: true, wantDegrad: true},
		{name: "not postgres", reply: 'X', wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := fakePostgres(t, tc.reply)
			detail, err := probe(t, NewPostgresCheck(addr))

			if tc.wantErr && err == nil {
				t.Fatalf("err = nil, want an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if tc.wantDegrad && !errors.Is(err, ErrDegraded) {
				t.Errorf("err = %v, want it to wrap ErrDegraded", err)
			}
			if tc.wantDetail != "" && !strings.Contains(detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to contain %q", detail, tc.wantDetail)
			}
		})
	}
}

func TestPostgresCheckRefusedConnection(t *testing.T) {
	t.Parallel()

	// Bind then immediately close, so the port is almost certainly unused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	if _, err := probe(t, NewPostgresCheck(addr)); err == nil {
		t.Fatal("err = nil, want a dial failure against a closed port")
	}
}

// -----------------------------------------------------------------------------
// Redis — RESP
// -----------------------------------------------------------------------------

// fakeRedis implements just enough RESP to answer PING and INFO.
func fakeRedis(t *testing.T, version string, requireAuth bool) string {
	return serveOnce(t, func(conn net.Conn) {
		r := bufio.NewReader(conn)
		authed := !requireAuth
		for {
			args, err := readRESPCommand(r)
			if err != nil || len(args) == 0 {
				return
			}
			switch strings.ToUpper(args[0]) {
			case "AUTH":
				if len(args) == 2 && args[1] == "s3cret" {
					authed = true
					_, _ = conn.Write([]byte("+OK\r\n"))
				} else {
					_, _ = conn.Write([]byte("-ERR invalid password\r\n"))
				}
			case "PING":
				if !authed {
					_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
					continue
				}
				_, _ = conn.Write([]byte("+PONG\r\n"))
			case "INFO":
				body := "# Server\r\nredis_version:" + version + "\r\nos:Linux\r\n"
				_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(body), body)
			default:
				_, _ = conn.Write([]byte("-ERR unknown command\r\n"))
			}
		}
	})
}

// readRESPCommand parses a client-side RESP array of bulk strings.
func readRESPCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 || line[0] != '*' {
		return nil, fmt.Errorf("expected array, got %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(strings.TrimRight(hdr, "\r\n")[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

func TestRedisCheckReportsVersion(t *testing.T) {
	t.Parallel()

	addr := fakeRedis(t, "7.4.1", false)
	detail, err := probe(t, NewRedisCheck(addr, ""))
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !strings.Contains(detail, "7.4.1") {
		t.Errorf("detail = %q, want it to report the server version", detail)
	}
}

func TestRedisCheckAuthenticates(t *testing.T) {
	t.Parallel()

	addr := fakeRedis(t, "7.4.1", true)
	if _, err := probe(t, NewRedisCheck(addr, "s3cret")); err != nil {
		t.Fatalf("err = %v, want nil with the correct password", err)
	}
}

func TestRedisCheckWrongPassword(t *testing.T) {
	t.Parallel()

	addr := fakeRedis(t, "7.4.1", true)
	_, err := probe(t, NewRedisCheck(addr, "wrong"))
	if err == nil {
		t.Fatal("err = nil, want an AUTH failure")
	}
	if !strings.Contains(err.Error(), "AUTH") {
		t.Errorf("err = %v, want it to name the failing command", err)
	}
}

// A port that answers but is not Redis must be reported as such, not as a
// generic connection error — that distinction is the whole point of the probe.
func TestRedisCheckNotRedis(t *testing.T) {
	t.Parallel()

	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	})
	_, err := probe(t, NewRedisCheck(addr, ""))
	if err == nil {
		t.Fatal("err = nil, want a protocol mismatch error")
	}
	if !strings.Contains(err.Error(), "not a redis server") {
		t.Errorf("err = %v, want it to say this is not a redis server", err)
	}
}

func TestRESPFieldExtraction(t *testing.T) {
	t.Parallel()

	info := "# Server\r\nredis_version:7.4.1\r\nredis_mode:standalone\r\n"
	if got := field(info, "redis_version"); got != "7.4.1" {
		t.Errorf("field(redis_version) = %q, want %q", got, "7.4.1")
	}
	if got := field(info, "absent"); got != "" {
		t.Errorf("field(absent) = %q, want empty", got)
	}
}

// -----------------------------------------------------------------------------
// RabbitMQ — AMQP 0-9-1 handshake
// -----------------------------------------------------------------------------

// connectionStartFrame builds a minimal but structurally valid Connection.Start.
func connectionStartFrame(major, minor byte) []byte {
	payload := []byte{
		0x00, 0x0A, // class 10 = connection
		0x00, 0x0A, // method 10 = start
		major, minor,
		0x00, 0x00, 0x00, 0x00, // empty server-properties field table
	}
	frame := []byte{frameMethod, 0x00, 0x00}
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)
	return append(frame, frameEnd)
}

func TestAMQPCheckHandshake(t *testing.T) {
	t.Parallel()

	addr := serveOnce(t, func(conn net.Conn) {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		if string(hdr) != string(amqp091Header) {
			t.Errorf("client header = %v, want the AMQP 0-9-1 header", hdr)
			return
		}
		_, _ = conn.Write(connectionStartFrame(0, 9))
	})

	detail, err := probe(t, NewAMQPCheck(addr))
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !strings.Contains(detail, "AMQP 0-9") {
		t.Errorf("detail = %q, want it to report the negotiated version", detail)
	}
}

func TestAMQPCheckVersionMismatch(t *testing.T) {
	t.Parallel()

	// A broker that does not support 0-9-1 replies with its own header.
	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = io.ReadFull(conn, make([]byte, 8))
		_, _ = conn.Write([]byte{'A', 'M', 'Q', 'P', 0x00, 0x01, 0x00, 0x00})
	})

	_, err := probe(t, NewAMQPCheck(addr))
	if err == nil {
		t.Fatal("err = nil, want a version-mismatch error")
	}
	if !strings.Contains(err.Error(), "1-0-0") {
		t.Errorf("err = %v, want it to report the version the broker advertises", err)
	}
}

func TestAMQPCheckMalformedFrame(t *testing.T) {
	t.Parallel()

	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = io.ReadFull(conn, make([]byte, 8))
		// Correct header shape, but the frame-end octet is wrong.
		frame := []byte{frameMethod, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
			0x00, 0x0A, 0x00, 0x0A, 0x00, 0x09, 0xFF}
		_, _ = conn.Write(frame)
	})

	_, err := probe(t, NewAMQPCheck(addr))
	if err == nil || !strings.Contains(err.Error(), "end octet") {
		t.Errorf("err = %v, want a malformed-frame error", err)
	}
}

// A hostile or buggy peer must not be able to make the probe allocate an
// arbitrary amount of memory.
func TestAMQPCheckRejectsImplausibleFrameSize(t *testing.T) {
	t.Parallel()

	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = io.ReadFull(conn, make([]byte, 8))
		frame := []byte{frameMethod, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}
		_, _ = conn.Write(frame)
	})

	_, err := probe(t, NewAMQPCheck(addr))
	if err == nil || !strings.Contains(err.Error(), "implausible frame size") {
		t.Errorf("err = %v, want the size guard to trip", err)
	}
}

// -----------------------------------------------------------------------------
// Ollama
// -----------------------------------------------------------------------------

func ollamaServer(t *testing.T, body string, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestOllamaCheckModelPresent(t *testing.T) {
	t.Parallel()

	body := `{"models":[{"name":"qwen2.5:7b","model":"qwen2.5:7b","size":4700000000}]}`
	detail, err := probe(t, NewOllamaCheck(ollamaServer(t, body, 200), "qwen2.5:7b"))
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !strings.Contains(detail, "qwen2.5:7b") || !strings.Contains(detail, "GiB") {
		t.Errorf("detail = %q, want the model name and its size", detail)
	}
}

// A reachable daemon missing the model is recoverable with one command, so it
// must warn rather than fail — failing here would block the whole stack.
func TestOllamaCheckModelMissingIsDegraded(t *testing.T) {
	t.Parallel()

	body := `{"models":[{"name":"llama3:8b","model":"llama3:8b","size":100}]}`
	detail, err := probe(t, NewOllamaCheck(ollamaServer(t, body, 200), "qwen2.5:7b"))
	if !errors.Is(err, ErrDegraded) {
		t.Fatalf("err = %v, want ErrDegraded", err)
	}
	if !strings.Contains(err.Error(), "ollama pull qwen2.5:7b") {
		t.Errorf("err = %v, want an actionable pull command", err)
	}
	if !strings.Contains(detail, "llama3:8b") {
		t.Errorf("detail = %q, want it to list what IS available", detail)
	}
}

func TestOllamaCheckNoModels(t *testing.T) {
	t.Parallel()

	_, err := probe(t, NewOllamaCheck(ollamaServer(t, `{"models":[]}`, 200), "qwen2.5:7b"))
	if !errors.Is(err, ErrDegraded) {
		t.Fatalf("err = %v, want ErrDegraded", err)
	}
}

func TestOllamaCheckNotOllama(t *testing.T) {
	t.Parallel()

	_, err := probe(t, NewOllamaCheck(ollamaServer(t, `<html>hello</html>`, 200), "qwen2.5:7b"))
	if err == nil || errors.Is(err, ErrDegraded) {
		t.Fatalf("err = %v, want a hard decode failure", err)
	}
}

func TestOllamaCheckTrailingSlashInEndpoint(t *testing.T) {
	t.Parallel()

	body := `{"models":[{"name":"qwen2.5:7b","model":"qwen2.5:7b","size":1}]}`
	url := ollamaServer(t, body, 200)
	if _, err := probe(t, NewOllamaCheck(url+"/", "qwen2.5:7b")); err != nil {
		t.Fatalf("err = %v; a trailing slash must not produce a double slash", err)
	}
}

func TestModelMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		have, want string
		match      bool
	}{
		{"qwen2.5:7b", "qwen2.5:7b", true},
		{"mistral:latest", "mistral", true}, // implicit :latest
		{"mistral", "mistral:latest", true},
		{"Qwen2.5:7B", "qwen2.5:7b", true}, // case-insensitive
		{"qwen2.5:7b", "qwen2.5:14b", false},
		{"", "qwen2.5:7b", false},
	}
	for _, tc := range tests {
		if got := modelMatches(tc.have, tc.want); got != tc.match {
			t.Errorf("modelMatches(%q, %q) = %v, want %v", tc.have, tc.want, got, tc.match)
		}
	}
}

// -----------------------------------------------------------------------------
// HTTP + Go runtime
// -----------------------------------------------------------------------------

func TestHTTPCheckRejectsUnexpectedStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "service unavailable")
	}))
	t.Cleanup(srv.Close)

	_, err := probe(t, NewHTTPCheck("x", srv.URL, "hint", Required))
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("err = %v, want the status code in the message", err)
	}
}

// Following redirects would mask a misconfigured health endpoint.
func TestHTTPCheckDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	if _, err := probe(t, NewHTTPCheck("x", srv.URL+"/", "hint", Required)); err == nil {
		t.Error("err = nil, want the 302 to be reported rather than followed")
	}
}

func TestGoRuntimeCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		actual, minimum string
		wantErr         bool
	}{
		{"go1.24.3", "1.24", false},
		{"go1.25.0", "1.24", false},
		{"go1.23.9", "1.24", true},
		{"go1.24", "1.24", false},
		{"go1.24rc1", "1.24", false},
	}
	for _, tc := range tests {
		c := NewGoRuntimeCheck(tc.minimum, func() string { return tc.actual })
		_, err := c.Probe(context.Background())
		if (err != nil) != tc.wantErr {
			t.Errorf("Probe(actual=%s, min=%s) err = %v, wantErr = %v",
				tc.actual, tc.minimum, err, tc.wantErr)
		}
	}
}

func TestCompareSemverish(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b string
		want int
	}{
		{"1.24.3", "1.24", 1}, // a patch release is newer than the bare minor
		{"1.24", "1.24.0", 0}, // missing components read as zero
		{"1.24.0", "1.24", 0},
		{"1.25", "1.24.9", 1},
		{"1.23.9", "1.24", -1},
		{"2.0", "1.99.99", 1},
	}
	for _, tc := range tests {
		if got := compareSemverish(tc.a, tc.b); got != tc.want {
			t.Errorf("compareSemverish(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	t.Parallel()

	tests := map[int64]string{
		0:          "unknown size",
		512:        "512 B",
		1536:       "1.5 KiB",
		4700000000: "4.4 GiB",
	}
	for in, want := range tests {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestSnippetCollapsesWhitespace(t *testing.T) {
	t.Parallel()

	if got := snippet([]byte("line one\n\n  line two\t")); got != "line one line two" {
		t.Errorf("snippet = %q", got)
	}
	if got := snippet(nil); got != "<empty body>" {
		t.Errorf("snippet(nil) = %q", got)
	}
	long := snippet([]byte(strings.Repeat("x", 500)))
	if len([]rune(long)) != 121 { // 120 chars + ellipsis
		t.Errorf("snippet length = %d runes, want 121", len([]rune(long)))
	}
}
