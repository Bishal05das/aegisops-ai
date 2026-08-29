module github.com/bishal05das/aegisops-ai

go 1.24

// Phase 1 deliberately has zero third-party dependencies.
// Every check in cmd/preflight speaks its protocol over the standard library
// (net, net/http, encoding/json, encoding/binary) to keep the "raw Go" mandate
// honest from the very first commit. Driver dependencies (pgx, otel, prometheus)
// arrive in the phases that actually need them.
