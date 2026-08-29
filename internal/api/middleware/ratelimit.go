package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/api/render"
	"github.com/bishal05das/aegisops-ai/internal/security/ratelimit"
	"github.com/bishal05das/aegisops-ai/pkg/errs"
	"github.com/bishal05das/aegisops-ai/pkg/logger"
)

// RateLimitOptions configures the middleware.
type RateLimitOptions struct {
	Limiter *ratelimit.Limiter
	// Cost is the tokens one request consumes. Lets an expensive endpoint be
	// limited more tightly than a cheap one without a second limiter.
	Cost int
	// SkipPaths are not limited. Health probes fire every few seconds and must
	// never be throttled — a rate-limited readiness check reads to Kubernetes
	// as an unhealthy pod, so the limiter would cause the outage it prevents.
	SkipPaths map[string]bool
}

// RateLimit throttles requests per principal.
//
// The key is the authenticated user when there is one, and the client address
// otherwise. That distinction matters in both directions:
//
//   - Keying purely by IP puts every user behind one corporate NAT or VPN into
//     a single bucket, so one busy client throttles their colleagues.
//   - Keying purely by user leaves unauthenticated endpoints — login above all
//     — with no limit at all, which is precisely where brute force happens.
//
// Must sit inside RequireAuth on authenticated routes so the principal is
// available; on public routes it falls back to the address on its own.
func RateLimit(opts RateLimitOptions) Middleware {
	cost := opts.Cost
	if cost <= 0 {
		cost = 1
	}

	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if opts.Limiter == nil || opts.SkipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		key, scope := rateLimitKey(r)
		decision := opts.Limiter.AllowN(key, cost)

		// Emitted on every response, not just rejections: a well-behaved client
		// can then slow down before being refused, which is the whole point of
		// publishing a budget.
		h := w.Header()
		h.Set("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
		h.Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
		h.Set("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))

		if decision.Allowed {
			next.ServeHTTP(w, r)
			return
		}

		// Rounded up: a Retry-After of 0 invites an immediate retry, which is
		// the opposite of what the limit is asking for.
		retryAfter := int(decision.RetryAfter.Round(time.Second) / time.Second)
		if retryAfter < 1 {
			retryAfter = 1
		}
		h.Set("Retry-After", strconv.Itoa(retryAfter))

		logger.FromContext(r.Context()).Warn("rate limit exceeded",
			"scope", scope, "path", r.URL.Path,
			"remote_ip", ClientIP(r), "retry_after_s", retryAfter)

		render.WriteError(w, r, errs.E("middleware.RateLimit", errs.RateLimited,
			"too many requests; retry in "+strconv.Itoa(retryAfter)+"s").
			WithCode("rate_limited").
			WithField("scope", scope).
			WithField("retry_after_seconds", retryAfter))
	})
}

// rateLimitKey chooses the bucket for a request, returning the key and a label
// for logs and metrics.
//
// The scope is part of the key so an authenticated user and an anonymous caller
// from the same address cannot collide — otherwise logging in would inherit the
// anonymous bucket's depletion, and a user could be throttled at the moment
// they authenticate by traffic that was never theirs.
func rateLimitKey(r *http.Request) (key, scope string) {
	if p, ok := PrincipalFrom(r.Context()); ok {
		return "user:" + p.UserID.String(), "user"
	}
	return "ip:" + ClientIP(r), "ip"
}
