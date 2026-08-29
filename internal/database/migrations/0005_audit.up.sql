-- 0005_audit: the append-only, hash-chained ledger.
--
-- The property that matters most: rejections are recorded as fully as
-- executions. "The Action Agent requested delete_database at 03:14, reasoning
-- X, and was blocked by policy" is the single most valuable line this system
-- produces, and you only get it if the write is unconditional.

CREATE TABLE audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Monotonic within the ledger. Assigned under an advisory lock inside the
    -- insert transaction, because the hash chain must be computed against the
    -- row that is actually the predecessor.
    seq         BIGINT      NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,

    actor_type  TEXT        NOT NULL,
    actor_id    UUID,
    actor_name  TEXT        NOT NULL DEFAULT '',

    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id   TEXT NOT NULL DEFAULT '',

    -- Deliberately NOT a foreign key.
    --
    -- The ledger outlives everything it references. If this cascaded, deleting
    -- an incident would erase the record that an agent tried to drop a table —
    -- destroying exactly the evidence an investigation needs. The cost is that
    -- these columns can reference rows that no longer exist, which is the
    -- correct trade for an audit trail.
    incident_id  UUID,
    tool_call_id UUID,

    outcome TEXT NOT NULL,
    reason  TEXT NOT NULL DEFAULT '',

    -- Redacted before insert by logger.RedactMap: tool arguments are arbitrary
    -- maps assembled by an LLM and may carry anything the model read from the
    -- environment.
    params  JSONB NOT NULL DEFAULT '{}'::jsonb,
    result  JSONB NOT NULL DEFAULT '{}'::jsonb,
    error   TEXT  NOT NULL DEFAULT '',

    request_id    TEXT NOT NULL DEFAULT '',
    build_version TEXT NOT NULL DEFAULT '',

    -- Tamper-evidence. Each row commits to its predecessor, so removing or
    -- editing a row breaks every hash after it.
    --
    -- This does not stop an attacker with full write access from rewriting the
    -- entire chain, and does not pretend to. It makes SELECTIVE tampering —
    -- quietly deleting the one row showing what an agent tried to do —
    -- detectable by VerifyChain.
    prev_hash BYTEA,
    hash      BYTEA NOT NULL,

    CONSTRAINT audit_logs_actor_valid CHECK (actor_type IN ('agent', 'user', 'system')),
    CONSTRAINT audit_logs_outcome_valid CHECK (outcome IN (
        'allowed', 'denied', 'executed', 'failed', 'dry_run'
    )),
    CONSTRAINT audit_logs_seq_positive CHECK (seq >= 1),
    CONSTRAINT audit_logs_hash_len CHECK (length(hash) = 32),
    CONSTRAINT audit_logs_action_present CHECK (length(action) BETWEEN 1 AND 200)
);

-- The chain's spine. UNIQUE, so a duplicate sequence is impossible even if two
-- writers race past the advisory lock.
CREATE UNIQUE INDEX audit_logs_seq_key ON audit_logs (seq);

CREATE INDEX audit_logs_occurred_idx ON audit_logs (occurred_at DESC);
CREATE INDEX audit_logs_incident_idx ON audit_logs (incident_id, seq) WHERE incident_id IS NOT NULL;
CREATE INDEX audit_logs_actor_idx ON audit_logs (actor_id, occurred_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_logs_action_idx ON audit_logs (action, occurred_at DESC);
CREATE INDEX audit_logs_outcome_idx ON audit_logs (outcome, occurred_at DESC);

-- The drift-detection query: everything the harness refused, newest first.
CREATE INDEX audit_logs_denied_idx ON audit_logs (occurred_at DESC)
    WHERE outcome = 'denied';

-- Enforce append-only at the database, not merely in the adapter. A bug, a
-- migration, or a hand-typed UPDATE in psql must all be refused: the ledger's
-- value comes from being immutable, and a convention is not immutability.
CREATE OR REPLACE FUNCTION audit_logs_reject_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'audit_logs is append-only: % is not permitted (seq=%)',
        TG_OP, COALESCE(OLD.seq, -1)
        USING HINT = 'Corrections are appended as new entries, never edits.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_mutation();

CREATE TRIGGER audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_mutation();

COMMENT ON TABLE audit_logs IS
    'Append-only and hash-chained. UPDATE and DELETE are rejected by trigger. '
    'incident_id is intentionally not a foreign key so the ledger survives the '
    'deletion of anything it describes.';
