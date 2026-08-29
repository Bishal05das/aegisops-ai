package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Timeout bounds how long a handler may run by attaching a context deadline.
//
// Deliberately *not* http.TimeoutHandler. That wrapper buffers the entire
// response in memory to be able to discard it on timeout, which breaks streaming
// and adds an allocation proportional to every response body. It also produces
// its own plain-text error page, bypassing the JSON error envelope this API
// guarantees.
//
// Signalling via context is the honest mechanism: it cancels the database query,
// the LLM call and the tool execution beneath the handler, and lets the handler
// render a proper 504. It relies on downstream code respecting ctx — which is
// exactly the discipline the contextcheck and noctx linters enforce in CI.
//
// Server.WriteTimeout remains the backstop for a handler that ignores its
// context entirely; config validation requires it to exceed this value so the
// handler gets a chance to respond first.
func Timeout(d time.Duration) Middleware {
	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if d <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MaxBody caps the request body size.
//
// http.MaxBytesReader is used rather than a plain io.LimitReader because it
// additionally aborts the connection once the limit is exceeded, so a client
// streaming an endless body cannot hold a goroutine open indefinitely.
//
// The Content-Length pre-check rejects an oversized upload before a single byte
// of it is read.
func MaxBody(limit int64) Middleware {
	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if limit <= 0 || r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > limit {
			w.Header().Set("Connection", "close")
			http.Error(w,
				`{"error":{"code":"body_too_large","message":"request body exceeds `+
					strconv.FormatInt(limit, 10)+` bytes"}}`,
				http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders sets defensive response headers.
//
// AegisOps serves JSON to programmatic clients, so the policy can be far
// stricter than a typical web application's: nothing is framed, nothing is
// sniffed, no scripts run, no referrers leak, and every browser API is denied.
func SecurityHeaders() Middleware {
	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		h := w.Header()
		// Stop a browser from second-guessing our Content-Type — the classic
		// route from "JSON endpoint" to "stored XSS".
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// A JSON API needs no scripts, styles, frames or connections of its own.
		h.Set("Content-Security-Policy",
			"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=()")
		// Approval tokens must never sit in a shared cache.
		h.Set("Cache-Control", "no-store")

		// HSTS is only meaningful over TLS, and asserting it over plaintext can
		// lock a developer out of their own http:// dev server.
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// CORSOptions configures cross-origin access.
type CORSOptions struct {
	// AllowedOrigins is an exact-match allowlist. Empty disables CORS entirely,
	// which is correct for an API with no browser clients.
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         time.Duration
	// AllowCredentials permits cookies. Config validation forbids combining it
	// with a "*" origin in production — the browser would reject that pairing
	// anyway, but failing loudly at startup beats failing silently at runtime.
	AllowCredentials bool
}

// CORS handles preflight requests and sets cross-origin response headers.
//
// It must sit above Timeout: an OPTIONS preflight does no work and should never
// be able to consume the request budget.
func CORS(opts CORSOptions) Middleware {
	if len(opts.AllowedOrigins) == 0 {
		// No browser clients configured. Return a pass-through rather than a
		// permissive default — a wide-open CORS policy by accident is worse than
		// no CORS support at all.
		return func(next http.Handler) http.Handler { return next }
	}

	allowAll := false
	allowed := make(map[string]bool, len(opts.AllowedOrigins))
	for _, o := range opts.AllowedOrigins {
		if o == "*" {
			allowAll = true
		}
		allowed[o] = true
	}

	methods := strings.Join(defaultIfEmpty(opts.AllowedMethods,
		[]string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}), ", ")
	headers := strings.Join(defaultIfEmpty(opts.AllowedHeaders,
		[]string{"Authorization", "Content-Type", HeaderRequestID}), ", ")
	maxAge := strconv.Itoa(int(defaultDuration(opts.MaxAge, 10*time.Minute).Seconds()))

	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		if !allowAll && !allowed[origin] {
			// Disallowed origin: omit the CORS headers and let the browser block
			// it. Returning 403 would leak which origins are allowed.
			next.ServeHTTP(w, r)
			return
		}

		h := w.Header()
		if allowAll && !opts.AllowCredentials {
			h.Set("Access-Control-Allow-Origin", "*")
		} else {
			h.Set("Access-Control-Allow-Origin", origin)
			// The response varies by Origin, so caches must key on it.
			h.Add("Vary", "Origin")
		}
		if opts.AllowCredentials {
			h.Set("Access-Control-Allow-Credentials", "true")
		}
		h.Set("Access-Control-Expose-Headers", HeaderRequestID)

		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", methods)
			h.Set("Access-Control-Allow-Headers", headers)
			h.Set("Access-Control-Max-Age", maxAge)
			h.Add("Vary", "Access-Control-Request-Method")
			h.Add("Vary", "Access-Control-Request-Headers")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func defaultIfEmpty(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

func defaultDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
