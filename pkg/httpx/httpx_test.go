package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bishal05das/aegisops-ai/pkg/errs"
)

// -----------------------------------------------------------------------------
// Router
// -----------------------------------------------------------------------------

func newTestRouter() *Router {
	r := NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("live"))
	})
	r.Post("/api/v1/incidents", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	r.Get("/api/v1/incidents/{id}", func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte("incident:" + req.PathValue("id")))
	})
	return r
}

func do(r http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestRouterMatching(t *testing.T) {
	t.Parallel()

	r := newTestRouter()

	if rec := do(r, http.MethodGet, "/healthz"); rec.Code != 200 || rec.Body.String() != "live" {
		t.Errorf("GET /healthz = %d %q", rec.Code, rec.Body.String())
	}
	if rec := do(r, http.MethodPost, "/api/v1/incidents"); rec.Code != 201 {
		t.Errorf("POST /api/v1/incidents = %d, want 201", rec.Code)
	}
	// Path wildcards are the Go 1.22 feature that makes a hand-rolled router
	// unnecessary; PathValue must work through our wrapper.
	if rec := do(r, http.MethodGet, "/api/v1/incidents/abc123"); rec.Body.String() != "incident:abc123" {
		t.Errorf("wildcard extraction failed: %q", rec.Body.String())
	}
}

// The bug this guards against: registering the not-found handler at "/" makes it
// match every path, so a verb mismatch renders 404 and the client is told the
// endpoint does not exist when they merely used the wrong method.
func TestRouterDistinguishes404From405(t *testing.T) {
	t.Parallel()

	r := newTestRouter()
	var got405, got404 bool

	r.NotFound(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		got404 = true
		w.WriteHeader(http.StatusNotFound)
	}))
	r.MethodNotAllowed(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		got405 = true
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))

	rec := do(r, http.MethodPost, "/healthz")
	if !got405 || rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST to a GET-only route = %d (405 handler hit: %v), want 405", rec.Code, got405)
	}
	// The Allow header is what makes a 405 actionable rather than merely correct.
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "GET") {
		t.Errorf("Allow = %q, want it to list GET", allow)
	}

	got404, got405 = false, false
	rec = do(r, http.MethodGet, "/does/not/exist")
	if !got404 || rec.Code != http.StatusNotFound {
		t.Errorf("unknown path = %d (404 handler hit: %v), want 404", rec.Code, got404)
	}
	if got405 {
		t.Error("the 405 handler ran for a genuinely unknown path")
	}
}

func TestRouterDefaultsWhenNoHandlersRegistered(t *testing.T) {
	t.Parallel()

	r := newTestRouter() // no NotFound / MethodNotAllowed set

	if rec := do(r, http.MethodGet, "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("default 404 = %d", rec.Code)
	}
	if rec := do(r, http.MethodPost, "/healthz"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("default 405 = %d", rec.Code)
	}
}

// Middleware order is the load-bearing property of the stack: Use(A, B) must
// mean A wraps B, so recovery and request-ID observe everything inside them.
func TestMiddlewareRunsOutermostFirst(t *testing.T) {
	t.Parallel()

	var order []string
	mark := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name+":in")
				next.ServeHTTP(w, r)
				order = append(order, name+":out")
			})
		}
	}

	r := NewRouter()
	r.Use(mark("outer"), mark("inner"))
	r.Get("/x", func(w http.ResponseWriter, _ *http.Request) {
		order = append(order, "handler")
	}, mark("route"))

	do(r, http.MethodGet, "/x")

	want := []string{
		"outer:in", "inner:in", "route:in",
		"handler",
		"route:out", "inner:out", "outer:out",
	}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v\nwant   %v", order, want)
	}
}

// A 404 must still pass through the global stack, or traffic hitting wrong URLs
// becomes invisible in the logs — exactly when you most want to see it.
func TestUnmatchedRequestsTraverseGlobalMiddleware(t *testing.T) {
	t.Parallel()

	var ran bool
	r := NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ran = true
			w.Header().Set("X-Traced", "1")
			next.ServeHTTP(w, req)
		})
	})
	r.Get("/known", func(w http.ResponseWriter, _ *http.Request) {})
	r.NotFound(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	rec := do(r, http.MethodGet, "/unknown")
	if !ran || rec.Header().Get("X-Traced") != "1" {
		t.Error("global middleware did not run for an unmatched request")
	}
}

func TestGroupPrefixAndScopedMiddleware(t *testing.T) {
	t.Parallel()

	var globalHits, groupHits int
	r := NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			globalHits++
			next.ServeHTTP(w, req)
		})
	})

	v1 := r.Group("/api/v1", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			groupHits++
			next.ServeHTTP(w, req)
		})
	})
	v1.Get("/agents", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("agents"))
	})
	r.Get("/outside", func(w http.ResponseWriter, _ *http.Request) {})

	if rec := do(r, http.MethodGet, "/api/v1/agents"); rec.Body.String() != "agents" {
		t.Errorf("group route not registered under its prefix: %d", rec.Code)
	}
	if groupHits != 1 || globalHits != 1 {
		t.Errorf("hits: global=%d group=%d, want 1 and 1", globalHits, groupHits)
	}

	// Group middleware must not leak onto routes outside the group.
	do(r, http.MethodGet, "/outside")
	if groupHits != 1 {
		t.Errorf("group middleware ran for a route outside the group (hits=%d)", groupHits)
	}
	if globalHits != 2 {
		t.Errorf("global middleware hits = %d, want 2", globalHits)
	}
}

func TestJoinPath(t *testing.T) {
	t.Parallel()

	tests := []struct{ prefix, pattern, want string }{
		{"", "/x", "/x"},
		{"/api", "/x", "/api/x"},
		{"/api/", "/x", "/api/x"},
		{"/api", "x", "/api/x"},
		{"/api", "/", "/api"},
		{"/api", "", "/api"},
	}
	for _, tc := range tests {
		if got := joinPath(tc.prefix, tc.pattern); got != tc.want {
			t.Errorf("joinPath(%q, %q) = %q, want %q", tc.prefix, tc.pattern, got, tc.want)
		}
	}
}

func TestChainHandlesNilMiddleware(t *testing.T) {
	t.Parallel()

	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), nil, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("nil middleware broke the chain: %d", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// ResponseRecorder
// -----------------------------------------------------------------------------

func TestResponseRecorderCapturesStatusAndBytes(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rr := NewResponseRecorder(rec)

	if rr.Wrote() {
		t.Error("Wrote() is true before anything was written")
	}
	rr.WriteHeader(http.StatusCreated)
	n, _ := rr.Write([]byte("hello"))

	if rr.Status() != http.StatusCreated {
		t.Errorf("Status() = %d, want 201", rr.Status())
	}
	if rr.BytesWritten() != int64(n) || n != 5 {
		t.Errorf("BytesWritten() = %d, wrote %d", rr.BytesWritten(), n)
	}
	if !rr.Wrote() {
		t.Error("Wrote() is false after writing")
	}
}

func TestResponseRecorderImpliesOKOnBareWrite(t *testing.T) {
	t.Parallel()

	rr := NewResponseRecorder(httptest.NewRecorder())
	_, _ = rr.Write([]byte("x"))
	if rr.Status() != http.StatusOK {
		t.Errorf("Status() = %d, want 200 implied", rr.Status())
	}
}

// A duplicate WriteHeader is a handler bug. The recorded status must stay equal
// to the one actually sent, or metrics disagree with reality.
func TestResponseRecorderIgnoresSecondWriteHeader(t *testing.T) {
	t.Parallel()

	inner := httptest.NewRecorder()
	rr := NewResponseRecorder(inner)
	rr.WriteHeader(http.StatusCreated)
	rr.WriteHeader(http.StatusInternalServerError)

	if rr.Status() != http.StatusCreated {
		t.Errorf("recorded status = %d, want the first one (201)", rr.Status())
	}
	if inner.Code != http.StatusCreated {
		t.Errorf("forwarded status = %d, want 201", inner.Code)
	}
}

// Wrapping a ResponseWriter normally hides Flusher/Hijacker. Unwrap is what
// restores them via http.ResponseController.
func TestResponseRecorderUnwrapExposesUnderlyingWriter(t *testing.T) {
	t.Parallel()

	inner := httptest.NewRecorder()
	rr := NewResponseRecorder(inner)

	if rr.Unwrap() != http.ResponseWriter(inner) {
		t.Error("Unwrap did not return the underlying writer")
	}

	// httptest.ResponseRecorder implements Flusher; the controller must find it.
	rc := http.NewResponseController(rr)
	if err := rc.Flush(); err != nil {
		t.Errorf("Flush through ResponseController failed: %v", err)
	}
	if !inner.Flushed {
		t.Error("the underlying writer was never flushed")
	}
}

func TestResponseRecorderHijackReportsUnsupported(t *testing.T) {
	t.Parallel()

	rr := NewResponseRecorder(httptest.NewRecorder())
	if _, _, err := rr.Hijack(); !errors.Is(err, ErrNotHijackable) {
		t.Errorf("Hijack error = %v, want ErrNotHijackable", err)
	}
}

// -----------------------------------------------------------------------------
// JSON
// -----------------------------------------------------------------------------

type incidentPayload struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Replicas int    `json:"replicas"`
}

func decodeInto(t *testing.T, body string, contentType string, maxBytes int64) (incidentPayload, error) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	var dst incidentPayload
	err := Decode(httptest.NewRecorder(), req, &dst, maxBytes)
	return dst, err
}

func TestDecodeSuccess(t *testing.T) {
	t.Parallel()

	got, err := decodeInto(t, `{"title":"api down","severity":"high","replicas":3}`, ContentTypeJSON, 1<<20)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Title != "api down" || got.Severity != "high" || got.Replicas != 3 {
		t.Errorf("decoded %+v", got)
	}
}

// Every decode failure must name the offending field or offset. "invalid JSON"
// without a location is a useless error, and for a system that executes
// infrastructure actions, silently ignoring an input field is unacceptable.
func TestDecodeErrorsAreActionable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		contentType string
		wantCode    string
		wantInMsg   string
	}{
		{
			name: "unknown field is named", body: `{"sevrity":"high"}`,
			contentType: ContentTypeJSON, wantCode: "unknown_field", wantInMsg: "sevrity",
		},
		{
			name: "type mismatch names the field", body: `{"replicas":"three"}`,
			contentType: ContentTypeJSON, wantCode: "invalid_field_type", wantInMsg: "replicas",
		},
		{
			name: "syntax error gives an offset", body: `{"title":`,
			contentType: ContentTypeJSON, wantCode: "malformed_json", wantInMsg: "end of body",
		},
		{
			name: "empty body", body: ``,
			contentType: ContentTypeJSON, wantCode: "empty_body", wantInMsg: "must not be empty",
		},
		{
			name: "trailing content", body: `{"title":"a"}{"title":"b"}`,
			contentType: ContentTypeJSON, wantCode: "malformed_json", wantInMsg: "exactly one JSON object",
		},
		{
			name: "wrong content type", body: `title=a`,
			contentType: "application/x-www-form-urlencoded",
			wantCode:    "unsupported_media_type", wantInMsg: "Content-Type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := decodeInto(t, tc.body, tc.contentType, 1<<20)
			if err == nil {
				t.Fatal("Decode returned nil error")
			}

			var e *errs.Error
			if !errors.As(err, &e) {
				t.Fatalf("error is not an *errs.Error: %T", err)
			}
			if e.Kind != errs.Invalid {
				t.Errorf("kind = %v, want Invalid (a client mistake, not a 500)", e.Kind)
			}
			if e.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", e.Code, tc.wantCode)
			}
			if !strings.Contains(e.Message, tc.wantInMsg) {
				t.Errorf("message %q should contain %q", e.Message, tc.wantInMsg)
			}
		})
	}
}

// An uncapped decode is a memory-exhaustion vector.
func TestDecodeEnforcesSizeLimit(t *testing.T) {
	t.Parallel()

	huge := `{"title":"` + strings.Repeat("x", 5000) + `"}`
	_, err := decodeInto(t, huge, ContentTypeJSON, 100)
	if err == nil {
		t.Fatal("oversized body was accepted")
	}

	var e *errs.Error
	if !errors.As(err, &e) || e.Code != "body_too_large" {
		t.Errorf("error = %v, want a body_too_large errs.Error", err)
	}
}

// A missing Content-Type is tolerated (many CLI clients omit it); a *wrong* one
// is not, because a form post would otherwise decode to a zero-valued struct.
func TestDecodeAllowsMissingContentType(t *testing.T) {
	t.Parallel()

	if _, err := decodeInto(t, `{"title":"a"}`, "", 1<<20); err != nil {
		t.Errorf("missing Content-Type was rejected: %v", err)
	}
	// Parameters must not defeat the check.
	if _, err := decodeInto(t, `{"title":"a"}`, "application/json; charset=utf-8", 1<<20); err != nil {
		t.Errorf("Content-Type with a charset was rejected: %v", err)
	}
}

// A non-pointer destination is a programming error and must be a 500, not a 400.
func TestDecodeInvalidTargetIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", ContentTypeJSON)

	var notAPointer incidentPayload
	err := Decode(httptest.NewRecorder(), req, notAPointer, 1<<20)

	var e *errs.Error
	if !errors.As(err, &e) || e.Kind != errs.Internal {
		t.Errorf("error = %v, want an Internal errs.Error", err)
	}
}

func TestRespond(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if err := Respond(rec, http.StatusCreated, map[string]string{"id": "inc-1"}); err != nil {
		t.Fatalf("Respond: %v", err)
	}

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, ContentTypeJSON) {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff header missing")
	}

	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if got["id"] != "inc-1" {
		t.Errorf("body = %v", got)
	}
	if !bytes.HasSuffix(rec.Body.Bytes(), []byte("\n")) {
		t.Error("body should end with a newline for line-delimited consumers")
	}
}

// Encoding into a buffer first means a marshalling failure can still become a
// clean 500, rather than a truncated body under an already-sent 200.
func TestRespondReportsEncodingFailureBeforeWritingStatus(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	err := Respond(rec, http.StatusOK, map[string]any{"bad": make(chan int)})
	if err == nil {
		t.Fatal("Respond accepted an unencodable value")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("a partial body was written: %q", rec.Body.String())
	}

	var e *errs.Error
	if !errors.As(err, &e) || e.Kind != errs.Internal {
		t.Errorf("error = %v, want an Internal errs.Error", err)
	}
}

func TestRespondNoContent(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if err := Respond(rec, http.StatusNoContent, map[string]string{"ignored": "x"}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("204 wrote a body: %d %q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	NoContent(rec)
	if rec.Code != http.StatusNoContent {
		t.Errorf("NoContent = %d", rec.Code)
	}
}
