package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/bishal05das/aegisops-ai/pkg/httpx"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// LoggerOptions configures access logging.
type LoggerOptions struct {
	// SkipPaths are not logged on success. Kubernetes probes hit /healthz every
	// few seconds; logging them buries real traffic under readiness noise. They
	// are still logged when they fail, which is the only time they matter.
	SkipPaths map[string]bool
}

// AccessLog emits one structured line per request.
//
// The level is chosen from the outcome, not fixed:
//
//	5xx → error   (our fault; should alert)
//	4xx → warn    (caller's fault; worth noticing in aggregate)
//	else → info
//
// Uniformly logging at info makes failures invisible; uniformly logging at error
// makes the error stream meaningless. Both are common and both are wrong.
func AccessLog(opts LoggerOptions) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := httpx.NewResponseRecorder(w)

			next.ServeHTTP(rec, r)

			elapsed := time.Since(start)
			status := rec.Status()

			if opts.SkipPaths[r.URL.Path] && status < 400 {
				return
			}

			ctx := r.Context()
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				// Milliseconds as a float keeps sub-millisecond handlers
				// distinguishable from zero in a latency histogram.
				slog.Float64("duration_ms", float64(elapsed.Microseconds())/1000.0),
				slog.Int64("bytes", rec.BytesWritten()),
				slog.String("remote_ip", ClientIP(r)),
			}
			if ua := r.UserAgent(); ua != "" {
				attrs = append(attrs, slog.String("user_agent", truncate(ua, 200)))
			}
			if q := r.URL.RawQuery; q != "" {
				// Query strings can carry tokens in badly-behaved clients, so the
				// value is truncated and never parsed into individual keys here.
				attrs = append(attrs, slog.String("query", truncate(q, 500)))
			}

			log := logger.FromContext(ctx)
			switch {
			case status >= 500:
				log.LogAttrs(ctx, slog.LevelError, "http request", attrs...)
			case status >= 400:
				log.LogAttrs(ctx, slog.LevelWarn, "http request", attrs...)
			default:
				log.LogAttrs(ctx, slog.LevelInfo, "http request", attrs...)
			}
		})
	}
}

// truncate bounds a client-supplied string so one request cannot emit a
// megabyte-long log line.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
