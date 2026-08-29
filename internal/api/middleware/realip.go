package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// Proxy headers, in the order they are consulted.
const (
	headerXForwardedFor = "X-Forwarded-For"
	headerXRealIP       = "X-Real-IP"
	headerTrueClientIP  = "True-Client-IP"
)

// ctxKeyRealIP is unexported so nothing outside this package can forge it.
type ctxKeyRealIP struct{}

// RealIP resolves the client address from proxy headers.
//
// **This middleware must only be enabled behind a trusted proxy.** Every header
// it reads is client-supplied and trivially forged; enabling it on a
// directly-exposed listener lets any caller spoof their address and thereby
// defeat both rate limiting and the audit trail's record of who did what.
//
// trustedProxies is therefore mandatory rather than optional: headers are
// honoured only when the immediate peer (RemoteAddr) is inside one of the given
// CIDR ranges. An empty list disables header parsing entirely, which is the
// correct default for a service with no proxy in front of it.
func RealIP(trustedProxies []string) Middleware {
	nets := parseCIDRs(trustedProxies)

	return wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		ip := remoteAddrIP(r.RemoteAddr)

		if len(nets) > 0 && ipInAny(ip, nets) {
			if forwarded := clientFromHeaders(r); forwarded != "" {
				ip = forwarded
			}
		}

		ctx := r.Context()
		if ip != "" {
			ctx = withRealIP(ctx, ip)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// clientFromHeaders extracts the originating address from proxy headers.
func clientFromHeaders(r *http.Request) string {
	// X-Forwarded-For is a chain: "client, proxy1, proxy2". The leftmost entry
	// is the original client — and also the only one the client itself could
	// have set, which is why this is gated on a trusted peer.
	if xff := r.Header.Get(headerXForwardedFor); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		if ip := strings.TrimSpace(first); isValidIP(ip) {
			return ip
		}
	}
	for _, h := range []string{headerXRealIP, headerTrueClientIP} {
		if v := strings.TrimSpace(r.Header.Get(h)); isValidIP(v) {
			return v
		}
	}
	return ""
}

// ClientIP returns the resolved client address for a request, falling back to
// the transport peer when RealIP is not enabled.
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(ctxKeyRealIP{}).(string); ok && ip != "" {
		return ip
	}
	return remoteAddrIP(r.RemoteAddr)
}

func withRealIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ctxKeyRealIP{}, ip)
}

// remoteAddrIP strips the port from a "host:port" transport address.
func remoteAddrIP(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func isValidIP(s string) bool {
	return s != "" && net.ParseIP(s) != nil
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Accept a bare IP as a single-host range for operator convenience.
		if !strings.Contains(c, "/") {
			if ip := net.ParseIP(c); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			}
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func ipInAny(ip string, nets []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
