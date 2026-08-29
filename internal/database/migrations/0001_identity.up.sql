-- 0001_identity: users and the agent roster.
--
-- Extensions are created by the Compose init script, which runs only on an
-- empty volume. They are asserted here too so a fresh database created by any
-- other means (a managed instance, a restored backup, CI) still works.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------------------
-- users — the humans who approve what the AI proposes
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT        NOT NULL,
    name          TEXT        NOT NULL DEFAULT '',
    role          TEXT        NOT NULL,
    password_hash BYTEA,
    active        BOOLEAN     NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT users_role_valid CHECK (role IN ('viewer', 'operator', 'admin')),
    CONSTRAINT users_email_shape CHECK (email LIKE '%@%.%' AND length(email) <= 320),
    -- Stored lowercase by the domain; the constraint stops a direct SQL insert
    -- from creating a case-variant duplicate that the unique index below would
    -- consider distinct.
    CONSTRAINT users_email_lower CHECK (email = lower(email))
);

CREATE UNIQUE INDEX users_email_key ON users (email);
CREATE INDEX users_active_idx ON users (active) WHERE active;

COMMENT ON TABLE users IS
    'Human principals. Approval authority is derived from role; see Role.CanApprove.';

-- ---------------------------------------------------------------------------
-- agents — the seven specialists
-- ---------------------------------------------------------------------------
CREATE TABLE agents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    kind        TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    config      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The roster is closed. A row with an unrecognised kind would be an agent
    -- the permission engine has no rules for, which must be impossible.
    CONSTRAINT agents_kind_valid CHECK (kind IN (
        'incident_manager', 'monitoring', 'log_analysis',
        'diagnosis', 'security', 'action', 'documentation'
    ))
);

CREATE UNIQUE INDEX agents_name_key ON agents (name);
CREATE INDEX agents_kind_idx ON agents (kind);

COMMENT ON TABLE agents IS
    'Registered specialists. An agent row confers no capability by itself: what '
    'an agent may do is decided entirely by the permissions table.';
