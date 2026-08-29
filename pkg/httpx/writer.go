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
// for streaming), http.Hijacker (needed for connection upgrades), io.ReaderFrom
// (the zero-copy fast path io.Copy takes to reach sendfile).
//
// [ResponseRecorder.Unwrap] recovers most of that: since Go 1.20,
// http.ResponseController walks Unwrap() chains to find Flush, Hijack,
// SetReadDeadline and SetWriteDeadline on the underlying writer, which avoids
// the combinatorial interface-assertion soup older codebases resort to. Flush
// and Hijack are additionally implemented outright, because plenty of
// third-party code type-asserts directly instead of going through
// ResponseController.
//
// What Unwrap does NOT recover is io.ReaderFrom. ResponseController has no
// method for it, and io.Copy checks for the interface on the concrete value it
// is handed — which is this wrapper, not the writer underneath. So a handler
// that io.Copy's a *os.File into the response loses the sendfile fast path and
// falls back to a buffered copy while this middleware is in the chain. That is
// an acceptable trade for accurate status and byte accounting on a JSON API
// that serves no large files; it would not be for a static file server, and a
// future streaming endpoint should measure before assuming otherwise.
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
