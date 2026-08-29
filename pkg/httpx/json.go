package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bishal05das/aegisops-ai/pkg/errs"
)

// ContentTypeJSON is the media type used for every API request and response.
const ContentTypeJSON = "application/json"

// Decode reads and validates a JSON request body into dst.
//
// It is deliberately strict, and each rule earns its place:
//
//   - **Content-Type must be JSON.** Otherwise a form post silently decodes to a
//     zero-valued struct and the handler acts on empty input.
//   - **Body size is capped.** An uncapped decode is a trivial memory-exhaustion
//     vector. The cap is applied by the caller's MaxBytes middleware and enforced
//     again here.
//   - **Unknown fields are rejected.** A client sending `{"sevrity":"high"}`
//     gets told about the typo instead of silently receiving the default
//     severity. For a system that executes infrastructure actions, silently
//     ignoring an input field is unacceptable.
//   - **Exactly one JSON value.** Trailing content usually means a
//     double-encoded body or a concatenation bug.
//
// Every failure returns a classified errs.Invalid naming the offending field or
// byte offset, because "invalid JSON" without a location is a useless error.
func Decode(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	const op = "httpx.Decode"

	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType := strings.TrimSpace(strings.Split(ct, ";")[0])
		if !strings.EqualFold(mediaType, ContentTypeJSON) {
			return errs.E(op, errs.Invalid,
				fmt.Sprintf("Content-Type must be %s, got %s", ContentTypeJSON, mediaType)).
				WithCode("unsupported_media_type")
		}
	}

	if maxBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return decodeError(op, err, maxBytes)
	}

	// A second successful decode means there was more than one value in the body.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errs.E(op, errs.Invalid, "body must contain exactly one JSON object").
			WithCode("malformed_json")
	}
	return nil
}

// decodeError converts an encoding/json failure into an actionable message.
//
// json's errors are precise but their default rendering is not: a caller reading
// "json: cannot unmarshal string into Go value of type int" has to guess which
// field. These branches extract the field name or byte offset that json already
// knows about.
func decodeError(op string, err error, maxBytes int64) error {
	var (
		syntaxErr     *json.SyntaxError
		typeErr       *json.UnmarshalTypeError
		maxBytesErr   *http.MaxBytesError
		invalidTarget *json.InvalidUnmarshalError
	)

	switch {
	case errors.As(err, &syntaxErr):
		return errs.E(op, errs.Invalid,
			fmt.Sprintf("malformed JSON at byte offset %d", syntaxErr.Offset)).
			WithCode("malformed_json")

	case errors.Is(err, io.ErrUnexpectedEOF):
		return errs.E(op, errs.Invalid, "malformed JSON: unexpected end of body").
			WithCode("malformed_json")

	case errors.As(err, &typeErr):
		field := typeErr.Field
		if field == "" {
			field = "body"
		}
		return errs.E(op, errs.Invalid,
			fmt.Sprintf("field %q must be of type %s, got %s", field, typeErr.Type, typeErr.Value)).
			WithCode("invalid_field_type").
			WithField("field", field)

	case strings.HasPrefix(err.Error(), "json: unknown field "):
		name := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		return errs.E(op, errs.Invalid, fmt.Sprintf("unknown field %q", name)).
			WithCode("unknown_field").
			WithField("field", name)

	case errors.Is(err, io.EOF):
		return errs.E(op, errs.Invalid, "request body must not be empty").
			WithCode("empty_body")

	case errors.As(err, &maxBytesErr):
		return errs.E(op, errs.Invalid,
			fmt.Sprintf("request body must not exceed %d bytes", maxBytes)).
			WithCode("body_too_large")

	case errors.As(err, &invalidTarget):
		// A nil or non-pointer destination is a programming error, not a client
		// error, and must not be reported as a 400.
		return errs.E(op, errs.Internal, "invalid decode target", err)

	default:
		return errs.E(op, errs.Invalid, "the request body could not be parsed", err).
			WithCode("malformed_json")
	}
}

// Respond writes v as JSON with the given status.
//
// Encoding into a buffer before touching the ResponseWriter is deliberate: if
// encoding fails partway (an unsupported type, a marshaller returning an error)
// the status line has not been sent yet, so the failure can still be converted
// into a clean 500 instead of a truncated body under a 200.
func Respond(w http.ResponseWriter, status int, v any) error {
	if v == nil || status == http.StatusNoContent {
		w.WriteHeader(status)
		return nil
	}

	buf, err := json.Marshal(v)
	if err != nil {
		return errs.E("httpx.Respond", errs.Internal, "encode response", err)
	}
	buf = append(buf, '\n')

	w.Header().Set("Content-Type", ContentTypeJSON+"; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	// A write failure here means the client hung up; there is no way to report
	// it to them and nothing useful to do about it.
	_, _ = w.Write(buf)
	return nil
}

// NoContent writes a 204.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }
