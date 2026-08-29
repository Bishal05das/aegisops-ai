# ADR 0009 — Hand-written JWT, argon2id, and rotating refresh tokens

- **Status:** accepted
- **Date:** 2026-08-29
- **Phase:** 4

## Context

The API needs authentication and authorisation. Humans authorise infrastructure
changes through it — approving a database restart or a deployment rollback — so
a credential compromise here is not a data-privacy incident, it is production
access.

Three decisions had to be made: how tokens are signed, how passwords are stored,
and how sessions are maintained. They are recorded together because they interact.

## Decision 1 — JWT is hand-written on `crypto/hmac`

No JWT library. HS256 only, in ~300 lines.

This is where the "raw Go" mandate earns its keep rather than costing something.
JWT's well-known vulnerabilities live almost entirely in the *verify* path, and
each is a default that a library author chose:

| Vulnerability | How it is closed here |
|---|---|
| **`alg: none`** — the spec's "unsecured JWT". Libraries that honoured it let anyone forge any token by editing one header field. | The verifier accepts exactly one algorithm, pinned at construction. `"none"` is simply a value that is not `HS256`, so it is rejected with everything else — there is no special case to forget. |
| **Algorithm confusion** — a service that verifies with whatever the token names can be fed an RS256 token re-signed as HS256 using the public key as the HMAC secret. | The algorithm is never read from the token to decide anything. It is compared against the pinned one and the token is rejected on mismatch. |
| **Timing leak** in signature comparison | `hmac.Equal`, which is constant-time. |
| **Trusting unverified claims** | The payload is not decoded until after the signature verifies. A verifier that parses claims first — however briefly — hands the caller attacker-controlled data and relies on discipline to prevent its use. |

Additional properties that fall out of writing it:

- **Purpose separation.** Access and refresh tokens carry an `aegis_purpose`
  claim and are verified against an expected value. Without it a long-lived
  refresh token works as a bearer credential everywhere, collapsing the reason
  for having two lifetimes.
- **A missing `exp` is refused**, not treated as "never expires". A missing
  claim must never read as permission.
- **Input is size-bounded before parsing.** An unbounded token is a cheap
  denial of service: base64-decoding and JSON-parsing a megabyte costs far more
  than rejecting it.
- **Unpadded base64url is enforced.** A permissive decoder would accept two
  distinct encodings of one token, giving it two identities in any cache or
  replay check.

The cost: no library maintenance, and key rotation is not built yet (the `kid`
header field is emitted but unused). Both are accepted; rotation lands in
Phase 15.

## Decision 2 — argon2id, not the standard library's PBKDF2

This adds `golang.org/x/crypto`, and the justification is quantitative rather
than aesthetic.

`crypto/pbkdf2` entered the standard library in Go 1.24, so PBKDF2 was available
at zero dependency cost. It was rejected because it is **not memory-hard**: it
parallelises almost perfectly onto GPUs. At equal wall-clock cost to the server,
a leaked PBKDF2-SHA256 hash falls to offline attack roughly two to three orders
of magnitude faster than argon2id, which forces every guess to allocate 19 MiB.

For a system whose users can authorise the destruction of production
infrastructure, that difference is worth one module from `golang.org/x`,
maintained by the Go team. `Hasher` is an interface, so PBKDF2 remains a drop-in
if the dependency ever needs to go.

Parameters follow the OWASP baseline (m=19 MiB, t=2, p=1) and are stored **in the
digest** as a PHC string. That is what makes raising the cost factor safe: an old
hash carries the parameters it was made with, so it still verifies, and
`NeedsRehash` flags it for transparent upgrade at the user's next login. Storing
parameters in configuration instead would invalidate every existing password the
moment they changed.

### The timing side channel, and a bug worth recording

A login for an address that does not exist returns immediately, while one for a
real address spends ~40 ms hashing. That difference is a **user-enumeration
oracle**: an attacker learns which addresses are registered without ever guessing
a password — the reconnaissance step before targeted credential stuffing.

`BurnTime` closes it by verifying against a decoy digest. The first
implementation hardcoded that decoy as a constant with `m=19456,t=2,p=1` — and
was wrong: the hasher's parameters are configurable, so an operator *hardening*
the real path to 64 MiB would have made genuine verifications 6× more expensive
than the decoy, silently reopening the oracle that the decoy exists to close.
The decoy is now derived from the hasher's own parameters, so the two costs are
equal by construction. Measured: 178 ms vs 164 ms at 64 MiB.

## Decision 3 — opaque refresh tokens with rotation and reuse detection

Refresh tokens are 256-bit random values, not JWTs, and only their SHA-256 is
stored.

**Why not JWTs:** a JWT refresh token cannot be revoked before it expires without
a server-side deny list — at which point it is server-side state anyway, and an
opaque token is the simpler thing that does the same job.

**Why SHA-256 and not argon2:** the input is a 256-bit random value. There is no
dictionary to defend against, so a memory-hard function adds no security and
would make every refresh cost 40 ms of CPU — a self-inflicted denial of service.
Argon2 defends against *guessable* inputs; this is not one.

**Rotation with reuse detection.** Every refresh invalidates the token presented
and issues a replacement. If an already-rotated token is presented again, either
it was stolen after the legitimate client rotated it, or the client is racing
itself. Those are indistinguishable from the server, and only one is benign — so
the entire token **family** is revoked and the user re-authenticates.

That deliberately logs out the honest user. It is the correct trade: a live
credential is known to be in someone else's hands, and choosing the benign
interpretation leaves a thief holding a valid session.

The rotation UPDATE carries `AND rotated_at IS NULL`, so two concurrent refreshes
cannot both succeed. Verified: six concurrent refreshes of one token yield
exactly one winner.

## Decision 4 — RBAC as a compiled table, not database rows

Roles map to permissions in a package-level table. This is deliberately *unlike*
the harness permission matrix (Phase 6), which lives in Postgres.

The distinction: harness permissions govern what an **AI agent** may attempt and
must be editable at runtime as tools are added. These govern what a **human role**
may do through the API — a contract that changes only when the API changes, and
should therefore change under code review with a deploy behind it.

Two properties are load-bearing:

- **Deny by default, with no wildcard.** Admin is a role with a long list, not a
  bypass.
- **Approving a `forbidden` action is unrepresentable.** `ApprovalPermissionFor`
  returns `ok=false` for that tier rather than a permission nobody holds.
  Returning an unheld permission would work today and start granting the moment
  someone added it to the admin list while tidying the matrix. Unrepresentable is
  stronger than unassigned.

An unknown role grants nothing, which matters during a rolling deploy: a token
minted by a newer build can carry a role an older binary does not recognise.

## Consequences

**Positive**

- Every JWT vulnerability class above is closed structurally and covered by a
  test that performs the actual attack.
- A leaked password digest is expensive to attack; a leaked refresh-token
  digest is useless without a preimage.
- Session theft is *detectable* rather than merely survivable.
- The authorisation matrix is one readable table.

**Negative, stated plainly**

- **Access tokens cannot be revoked.** They are stateless and valid until they
  expire, which is the price of not hitting the database on every request.
  Mitigated by a 15-minute TTL and by refusing refresh immediately, so a
  deactivated user's session cannot be extended — but there is a window, and
  anything needing instant revocation must check the database itself.
- **Role changes are not immediate.** The role is carried in the token, so a
  downgrade takes effect at next refresh. Same window, same reason.
- **The limiter is per-process.** Several replicas each enforce their own
  budget, so the effective rate is multiplied by the replica count. Acceptable
  for a control plane that runs few replicas; Phase 9 moves it to Redis.
- **`aegisctl user passwd` does not revoke sessions**, because it does not open
  the session repository. Named in its own output rather than hidden.

## Alternatives rejected

| Option | Why not |
|---|---|
| `golang-jwt/jwt` | Mature and widely used. Rejected because the verify path is exactly what this project exists to demonstrate understanding of, and because its API has historically made `alg` confusion easy to write by accident. |
| RS256 / asymmetric signing | Solves verifying tokens you did not issue, which does not arise: one service issues and verifies. It would add key management for no benefit, and a second algorithm to confuse. |
| bcrypt | Fine, and better than PBKDF2. Rejected because it caps input at 72 bytes (silently, in most libraries) and is less memory-hard than argon2id. |
| Sessions in Redis instead of Postgres | Refresh tokens are security state that must survive a cache eviction. Redis is for expendable working memory ([ADR 0005](0005-postgres-with-pgvector.md)); a token vanishing on eviction logs everyone out. |
| Non-rotating refresh tokens | Simpler, and gives up reuse detection entirely — a stolen token stays valid until expiry with nothing to notice it. |
| Storing the JWT in an httpOnly cookie | Better for a browser-only client. Rejected because the primary clients are the CLI and CI, which have no cookie jar, and because it would require CSRF defences the token-in-header approach does not need. |
