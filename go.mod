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

// Phases 1 and 2 had NO third-party dependencies: cmd/preflight speaks
// PostgreSQL, Redis and AMQP over the standard library, and the HTTP layer is
// net/http with a hand-written router and middleware.
//
// pgx arrives in Phase 3 because the alternative is reimplementing the
// PostgreSQL wire protocol — ~15k lines including binary type codecs, where a
// subtly wrong codec silently corrupts data. It is imported in exactly ONE file
// (internal/database/postgres.go), registered as a database/sql driver, so
// nothing else in the codebase depends on it. See docs/adr/0008.
//
// x/text and x/sync are pinned above their pgx-implied minimums: CI's
// govulncheck flagged GO-2026-5970 in x/text v0.29.0. Transitive dependencies
// get patched here, not waived.

require github.com/jackc/pgx/v5 v5.10.0

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)
