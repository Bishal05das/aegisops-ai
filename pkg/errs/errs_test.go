package errs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// The single most important property in this package: an internal error's cause
// must never reach a client, while remaining fully available to the log.
func TestInternalErrorsNeverLeakDetail(t *testing.T) {
	t.Parallel()

	driverErr := errors.New(`pq: relation "incidents" does not exist`)
	err := E("postgres.IncidentRepo.Get", Internal, "select incident", driverErr)

	code, msg := err.Public()

	if strings.Contains(msg, "pq:") || strings.Contains(msg, "incidents") {
		t.Fatalf("public message leaked internal detail: %q", msg)
	}
	if msg != genericInternalMessage {
		t.Errorf("public message = %q, want the generic internal message", msg)
	}
	if code != "internal_error" {
		t.Errorf("public code = %q, want %q", code, "internal_error")
	}

	// The operator's view keeps everything.
	full := err.Error()
	for _, want := range []string{"postgres.IncidentRepo.Get", "select incident", "pq: relation"} {
		if !strings.Contains(full, want) {
			t.Errorf("internal Error() missing %q: %s", want, full)
		}
	}
}

func TestPublicPreservesClientFacingMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *Error
		wantCode string
		wantMsg  string
	}{
		{
			name:     "explicit code and message",
			err:      E("op", NotFound, "incident not found").WithCode("incident_not_found"),
			wantCode: "incident_not_found",
			wantMsg:  "incident not found",
		},
		{
			name:     "code falls back to kind",
			err:      E("op", Forbidden, "agent may not restart databases"),
			wantCode: "forbidden",
			wantMsg:  "agent may not restart databases",
		},
		{
			name:     "message falls back to kind default",
			err:      E("op", RateLimited),
			wantCode: "rate_limited",
			wantMsg:  "too many requests",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			code, msg := tc.err.Public()
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if msg != tc.wantMsg {
				t.Errorf("message = %q, want %q", msg, tc.wantMsg)
			}
		})
	}
}

// An error that never passed through this package must be treated as Internal,
// so an unclassified failure cannot accidentally render its raw text as a 400.
func TestUnclassifiedErrorsDefaultToInternal(t *testing.T) {
	t.Parallel()

	plain := errors.New("some driver blew up")
	if got := KindOf(plain); got != Internal {
		t.Errorf("KindOf(plain error) = %v, want Internal", got)
	}
	if got := StatusOf(plain); got != http.StatusInternalServerError {
		t.Errorf("StatusOf(plain error) = %d, want 500", got)
	}
	if got := KindOf(nil); got != Internal {
		t.Errorf("KindOf(nil) = %v, want Internal", got)
	}
}

func TestKindHTTPStatusIsTotal(t *testing.T) {
	t.Parallel()

	want := map[Kind]int{
		Internal:         500,
		Invalid:          400,
		Unauthorized:     401,
		Forbidden:        403,
		NotFound:         404,
		MethodNotAllowed: 405,
		Conflict:         409,
		Exists:           409,
		RateLimited:      429,
		Timeout:          504,
		Canceled:         499,
		Unavailable:      503,
		NotImplemented:   501,
	}
	for kind, status := range want {
		if got := kind.HTTPStatus(); got != status {
			t.Errorf("%v.HTTPStatus() = %d, want %d", kind, got, status)
		}
		if kind.String() == "" {
			t.Errorf("%v has an empty String()", kind)
		}
	}

	// Any future Kind added without a mapping must still be safe.
	unknown := Kind(200)
	if got := unknown.HTTPStatus(); got != 500 {
		t.Errorf("unmapped kind = %d, want 500", got)
	}
}

// Context errors arrive from deep inside the standard library and never pass
// through E, so they need explicit translation. Misclassifying a cancelled
// request as a 500 pollutes the error rate that pages an on-call.
func TestContextErrorsAreClassified(t *testing.T) {
	t.Parallel()

	if got := StatusOf(context.DeadlineExceeded); got != http.StatusGatewayTimeout {
		t.Errorf("StatusOf(DeadlineExceeded) = %d, want 504", got)
	}
	if got := StatusOf(context.Canceled); got != 499 {
		t.Errorf("StatusOf(Canceled) = %d, want 499", got)
	}
	if got := StatusOf(nil); got != http.StatusOK {
		t.Errorf("StatusOf(nil) = %d, want 200", got)
	}

	// Wrapped just as deeply as they arrive in practice.
	wrapped := fmt.Errorf("query: %w", fmt.Errorf("pool: %w", context.DeadlineExceeded))
	if got := StatusOf(wrapped); got != http.StatusGatewayTimeout {
		t.Errorf("StatusOf(wrapped DeadlineExceeded) = %d, want 504", got)
	}

	if e := FromContextError("op", context.Canceled); e == nil || e.Kind != Canceled {
		t.Errorf("FromContextError(Canceled) = %v, want a Canceled Error", e)
	}
	if e := FromContextError("op", errors.New("other")); e != nil {
		t.Errorf("FromContextError(other) = %v, want nil", e)
	}
}

func TestErrorsIsAndAsTraverseTheChain(t *testing.T) {
	t.Parallel()

	err := E("api.Get", Internal, "handler",
		E("service.Load", Internal, "service",
			E("repo.Query", NotFound, "no rows", sql.ErrNoRows)))

	// The sentinel at the bottom is still reachable.
	if !errors.Is(err, sql.ErrNoRows) {
		t.Error("errors.Is could not reach sql.ErrNoRows through the chain")
	}

	// KindOf takes the OUTERMOST kind: the outer layer has the most context
	// about how the failure should be presented.
	if got := KindOf(err); got != Internal {
		t.Errorf("KindOf = %v, want Internal (outermost wins)", got)
	}

	var target *Error
	if !errors.As(err, &target) || target.Op != "api.Get" {
		t.Errorf("errors.As found %+v, want the outermost Error", target)
	}
}

// Ops reconstructs the call path at a fraction of the cost of a stack trace.
func TestOpsReconstructsCallPath(t *testing.T) {
	t.Parallel()

	err := E("api.CreateIncident", Internal, "",
		E("service.Incidents.Create", Internal, "",
			E("postgres.Insert", Internal, "", errors.New("boom"))))

	got := Ops(err)
	want := []string{"api.CreateIncident", "service.Incidents.Create", "postgres.Insert"}

	if len(got) != len(want) {
		t.Fatalf("Ops = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Ops[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if ops := Ops(errors.New("plain")); ops != nil {
		t.Errorf("Ops(plain error) = %v, want nil", ops)
	}
}

func TestFieldsMergeWithOuterWinning(t *testing.T) {
	t.Parallel()

	inner := E("repo", NotFound, "").
		WithField("incident_id", "inner").
		WithField("table", "incidents")
	outer := E("api", NotFound, "", inner).
		WithField("incident_id", "outer").
		WithField("user_id", "u-1")

	fields := Fields(outer)

	if fields["incident_id"] != "outer" {
		t.Errorf("incident_id = %v, want the outer value to win", fields["incident_id"])
	}
	if fields["table"] != "incidents" {
		t.Errorf("table = %v, want the inner value preserved", fields["table"])
	}
	if fields["user_id"] != "u-1" {
		t.Errorf("user_id = %v", fields["user_id"])
	}
	if Fields(errors.New("plain")) != nil {
		t.Error("Fields(plain error) should be nil")
	}
}

// The harness consults Retryable to decide between backoff and dead-lettering a
// failed tool execution, so the classification is load-bearing.
func TestRetryable(t *testing.T) {
	t.Parallel()

	retryable := []Kind{Timeout, Unavailable, RateLimited}
	permanent := []Kind{Internal, Invalid, NotFound, Forbidden, Unauthorized,
		Conflict, Exists, Canceled, NotImplemented, MethodNotAllowed}

	for _, k := range retryable {
		if !Retryable(E("op", k)) {
			t.Errorf("Retryable(%v) = false, want true", k)
		}
	}
	for _, k := range permanent {
		if Retryable(E("op", k)) {
			t.Errorf("Retryable(%v) = true, want false", k)
		}
	}
}

// Logging a 404 at error level is how an error dashboard becomes noise.
func TestShouldLogAsErrorSeparatesFaultFromClientMistake(t *testing.T) {
	t.Parallel()

	serverFault := []Kind{Internal, Unavailable, NotImplemented}
	clientMistake := []Kind{Invalid, NotFound, Unauthorized, Forbidden,
		Conflict, Exists, RateLimited, Canceled, MethodNotAllowed}

	for _, k := range serverFault {
		if !ShouldLogAsError(E("op", k)) {
			t.Errorf("ShouldLogAsError(%v) = false, want true", k)
		}
	}
	for _, k := range clientMistake {
		if ShouldLogAsError(E("op", k)) {
			t.Errorf("ShouldLogAsError(%v) = true, want false", k)
		}
	}
	if !ShouldLogAsError(context.DeadlineExceeded) {
		t.Error("a deadline overrun is a server-side problem and should log as an error")
	}
}

func TestEArgumentForms(t *testing.T) {
	t.Parallel()

	cause := errors.New("cause")

	if e := E("op", Invalid, "msg"); e.Message != "msg" || e.Err != nil {
		t.Errorf("message-only form: %+v", e)
	}
	if e := E("op", Invalid, cause); e.Err != cause || e.Message != "" {
		t.Errorf("error-only form: %+v", e)
	}
	if e := E("op", Invalid, "msg", cause); e.Message != "msg" || e.Err != cause {
		t.Errorf("message+error form: %+v", e)
	}
	// Order-independence keeps call sites from having to remember a convention.
	if e := E("op", Invalid, cause, "msg"); e.Message != "msg" || e.Err != cause {
		t.Errorf("error+message form: %+v", e)
	}
	// A misused argument must be visible, not silently dropped.
	if e := E("op", Invalid, 42); !strings.Contains(e.Message, "unsupported arg") {
		t.Errorf("unsupported argument was swallowed: %+v", e)
	}
}

func TestErrorStringWithoutMessageUsesKind(t *testing.T) {
	t.Parallel()

	if got := E("repo.Get", NotFound).Error(); got != "repo.Get: not_found" {
		t.Errorf("Error() = %q", got)
	}
}

func TestIs(t *testing.T) {
	t.Parallel()

	err := E("op", Forbidden, "denied")
	if !Is(err, Forbidden) {
		t.Error("Is(err, Forbidden) = false")
	}
	if Is(err, NotFound) {
		t.Error("Is(err, NotFound) = true")
	}
}
