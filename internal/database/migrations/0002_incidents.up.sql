-- 0002_incidents: the aggregate root and its append-only timeline.

CREATE TABLE incidents (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title        TEXT        NOT NULL,
    description  TEXT        NOT NULL DEFAULT '',
    severity     TEXT        NOT NULL,
    status       TEXT        NOT NULL,
    source       TEXT        NOT NULL,

    service      TEXT        NOT NULL DEFAULT '',
    environment  TEXT        NOT NULL DEFAULT '',
    labels       JSONB       NOT NULL DEFAULT '{}'::jsonb,

    root_cause   TEXT        NOT NULL DEFAULT '',
    confidence   NUMERIC(4,3) NOT NULL DEFAULT 0,

    detected_at     TIMESTAMPTZ NOT NULL,
    acknowledged_at TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,

    -- A deleted user must not cascade away their incidents; the incident
    -- outlives the account that filed it.
    created_by   UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Optimistic locking. Seven agents mutate one incident concurrently; every
    -- UPDATE carries "WHERE version = $n" and bumps it, so a lost update
    -- surfaces as a conflict instead of silently discarding an agent's work.
    version      INTEGER     NOT NULL DEFAULT 1,

    CONSTRAINT incidents_title_len CHECK (length(title) BETWEEN 1 AND 500),
    CONSTRAINT incidents_severity_valid CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    CONSTRAINT incidents_status_valid CHECK (status IN (
        'detected', 'investigating', 'diagnosing', 'awaiting_approval',
        'remediating', 'verifying', 'resolved', 'closed', 'failed'
    )),
    CONSTRAINT incidents_source_valid CHECK (source IN ('alert', 'api', 'manual', 'agent')),
    CONSTRAINT incidents_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT incidents_version_positive CHECK (version >= 1),
    -- Resolution cannot predate detection. Cheap to assert, and it catches a
    -- clock-skew bug that would otherwise show up as a negative MTTR.
    CONSTRAINT incidents_resolved_after_detected
        CHECK (resolved_at IS NULL OR resolved_at >= detected_at)
);

-- The operator's default view: newest first, optionally filtered by status.
CREATE INDEX incidents_status_detected_idx ON incidents (status, detected_at DESC);
CREATE INDEX incidents_detected_at_idx ON incidents (detected_at DESC);
CREATE INDEX incidents_severity_idx ON incidents (severity, detected_at DESC);
CREATE INDEX incidents_service_idx ON incidents (service) WHERE service <> '';

-- Partial index over the states agents still work. This is the hottest query in
-- the system — the orchestrator polls it — and the partial predicate keeps the
-- index proportional to open incidents rather than to all history.
CREATE INDEX incidents_active_idx ON incidents (detected_at DESC)
    WHERE status NOT IN ('resolved', 'closed', 'failed');

-- Trigram index for fuzzy title search: "OOMKilled" should find an incident
-- titled "container was OOM killed".
CREATE INDEX incidents_title_trgm_idx ON incidents USING gin (title gin_trgm_ops);
CREATE INDEX incidents_labels_idx ON incidents USING gin (labels jsonb_path_ops);

COMMENT ON COLUMN incidents.version IS
    'Optimistic lock. UPDATE ... WHERE id = $1 AND version = $2 returning 0 rows '
    'means a concurrent writer won; the caller must re-read and retry.';
COMMENT ON COLUMN incidents.confidence IS
    'Diagnosis Agent self-reported certainty, 0..1. Load-bearing: the policy '
    'engine routes a low-confidence diagnosis to a human rather than an action.';

-- ---------------------------------------------------------------------------
-- incident_events — append-only timeline
-- ---------------------------------------------------------------------------
CREATE TABLE incident_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID        NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,

    -- Ordering within an incident. Timestamps are insufficient: agents run
    -- concurrently and can produce identical microsecond stamps, and clocks are
    -- not monotonic across processes. Assigned under the insert's lock.
    seq         BIGINT      NOT NULL,

    type        TEXT        NOT NULL,
    actor_type  TEXT        NOT NULL,
    actor_id    UUID,
    actor_name  TEXT        NOT NULL DEFAULT '',
    message     TEXT        NOT NULL DEFAULT '',
    payload     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT incident_events_actor_valid CHECK (actor_type IN ('agent', 'user', 'system')),
    CONSTRAINT incident_events_seq_positive CHECK (seq >= 1),
    CONSTRAINT incident_events_message_len CHECK (length(message) <= 2000)
);

-- Makes the ordering total and gives the timeline read its index in one object.
CREATE UNIQUE INDEX incident_events_incident_seq_key
    ON incident_events (incident_id, seq);
CREATE INDEX incident_events_type_idx ON incident_events (type, occurred_at DESC);
CREATE INDEX incident_events_actor_idx ON incident_events (actor_id) WHERE actor_id IS NOT NULL;

COMMENT ON TABLE incident_events IS
    'Append-only. Reconstructing what the system believed and when depends on '
    'nothing ever rewriting history, so there is no UPDATE path in the adapter.';
