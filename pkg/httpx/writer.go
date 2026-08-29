package httpx

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

// ResponseRecorder wraps an http.ResponseWriter to capture the status code and
// byte count, which logging and metrics middleware need after the handler has
// returned.
//
// The subtlety worth understanding: wrapping an http.ResponseWriter silently
// hides the optional interfaces the real one implements — http.Flusher (needed
// for streaming), http.Hijacker (needed for WebSocket upgrades), io.ReaderFrom
// (needed for efficient sendfile). Naively wrapping breaks all three.
//
// The modern fix is [ResponseRecorder.Unwrap]: since Go 1.20, http.ResponseController
// walks Unwrap() chains to find the underlying capabilities. Implementing that
// one method restores every optional behaviour without the combinatorial
// interface-assertion soup older codebases resort to. Flush and Hijack are still
// implemented explicitly, because plenty of third-party code type-asserts
// directly rather than going through ResponseController.
type ResponseRecorder struct {
	http.ResponseWriter

	status      int
	bytes       int64
	wroteHeader bool
}

// NewResponseRecorder wraps w.
func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{ResponseWriter: w, status: http.StatusOK}
}

// WriteHeader records the status and forwards it exactly once.
//
// A duplicate WriteHeader is a handler bug that the standard library reports by
// logging "superfluous response.WriteHeader call". Swallowing the second call
// here keeps the *recorded* status equal to the one actually sent, so metrics do
// not disagree with reality.
func (r *ResponseRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.status = status
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(status)
}

// Write records the byte count, implying a 200 if no status was set.
func (r *ResponseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Status returns the status code sent to the client.
func (r *ResponseRecorder) Status() int { return r.status }

// BytesWritten returns the size of the response body.
func (r *ResponseRecorder) BytesWritten() int64 { return r.bytes }

// Wrote reports whether the handler produced any response at all. A handler that
// returns without writing indicates a bug — and, importantly, a panic recovered
// *after* a partial write cannot be converted into a clean error response.
func (r *ResponseRecorder) Wrote() bool { return r.wroteHeader }

// Unwrap exposes the underlying writer to http.ResponseController, restoring
// Flush, Hijack, SetReadDeadline and SetWriteDeadline.
func (r *ResponseRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Flush implements http.Flusher for code that type-asserts directly.
func (r *ResponseRecorder) Flush() {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ErrNotHijackable reports that the underlying writer does not support hijacking.
var ErrNotHijackable = errors.New("httpx: underlying ResponseWriter is not an http.Hijacker")

// Hijack implements http.Hijacker for connection upgrades.
func (r *ResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, ErrNotHijackable
	}
	return h.Hijack()
}
