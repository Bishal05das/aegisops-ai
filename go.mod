module github.com/bishal05das/aegisops-ai

go 1.26

// Pinned deliberately, not merely to "1.26". CI's govulncheck flagged seven
// unpatched standard-library CVEs on Go 1.24 — crypto/tls, crypto/x509,
// net/http, net/url, net/textproto, encoding/asn1 — because Go backports
// security fixes only to the two most recent major releases, and 1.24 had aged
// out of that window.
//
// A bare `go 1.26` directive would let GOTOOLCHAIN=auto satisfy itself with
// go1.26.0; naming the patch level makes the security floor explicit and
// identical on every machine and CI runner. Raise it when a new CVE lands.
toolchain go1.26.7

// Phase 1 deliberately has zero third-party dependencies.
// Every check in cmd/preflight speaks its protocol over the standard library
// (net, net/http, encoding/json, encoding/binary) to keep the "raw Go" mandate
// honest from the very first commit. Driver dependencies (pgx, otel, prometheus)
// arrive in the phases that actually need them.
