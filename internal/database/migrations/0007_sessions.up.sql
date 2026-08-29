-- 0007_sessions: refresh tokens with rotation and reuse detection.
--
-- Refresh tokens are opaque random values, not JWTs. A JWT refresh token cannot
-- be revoked before it expires without a server-side deny list — at which point
-- it is server-side state anyway, and an opaque token is the simpler thing.
--
-- Only a SHA-256 of the token is stored. A database leak then yields nothing an
-- attacker can present: they would need a preimage. Argon2 is unnecessary here
-- and would be a mistake — these are 256-bit random values, not user-chosen
-- passwords, so there is no dictionary to defend against, and a memory-hard hash
-- on every refresh would be a self-inflicted denial of service.

CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- SHA-256 of the opaque token. Unique so a collision is impossible to
    -- insert silently.
    token_hash BYTEA NOT NULL,

    -- All tokens descended from one login share a family. When a rotated token
    -- is replayed, the whole family is revoked: the replay means either the
    -- token was stolen after rotation, or the legitimate client is racing
    -- itself. Both warrant re-authentication, and only one is benign.
    family_id  UUID NOT NULL,

    -- Set when this token is exchanged, pointing at its replacement. Its
    -- presence is what makes a replay detectable: a token that has already been
    -- rotated is being presented a second time.
    rotated_to UUID REFERENCES refresh_tokens (id) ON DELETE SET NULL,
    rotated_at TIMESTAMPTZ,

    revoked_at     TIMESTAMPTZ,
    revoked_reason TEXT NOT NULL DEFAULT '',

    -- Recorded for the audit trail: a session that appears from a new address
    -- or client is what a compromise looks like.
    issued_ip  TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',

    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT refresh_tokens_hash_len CHECK (length(token_hash) = 32),
    CONSTRAINT refresh_tokens_expiry_future CHECK (expires_at > created_at),
    -- rotated_to and rotated_at must be set together, or "has this been
    -- rotated?" has two different answers depending which column is consulted.
    CONSTRAINT refresh_tokens_rotation_consistent
        CHECK ((rotated_to IS NULL) = (rotated_at IS NULL))
);

CREATE UNIQUE INDEX refresh_tokens_hash_key ON refresh_tokens (token_hash);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id, created_at DESC);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

-- The active-session query, and the set a cleanup job sweeps.
CREATE INDEX refresh_tokens_live_idx ON refresh_tokens (expires_at)
    WHERE revoked_at IS NULL AND rotated_at IS NULL;

COMMENT ON TABLE refresh_tokens IS
    'Opaque refresh tokens, stored hashed. Rotated on every use; replaying a '
    'rotated token revokes its entire family.';
COMMENT ON COLUMN refresh_tokens.family_id IS
    'All descendants of one login. Revoked together on replay detection.';
