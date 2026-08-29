-- 0006_memory: long-term semantic memory.
--
-- Lives in the same database as the records it describes, so that writing an
-- incident and writing the embedding of its postmortem happen in ONE
-- transaction.
--
-- With a separate vector store they would be two operations sharing no
-- transaction, and a crash between them leaves the system either remembering an
-- incident it cannot recall, or recalling one that does not exist.
-- See docs/adr/0005-postgres-with-pgvector.md.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE memory_records (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- CASCADE here is correct and is the point: foreign keys mean deleting an
    -- incident cannot orphan its memory. Contrast audit_logs, which must
    -- survive precisely because it is evidence rather than derived knowledge.
    incident_id UUID REFERENCES incidents (id) ON DELETE CASCADE,

    kind     TEXT NOT NULL,
    title    TEXT NOT NULL DEFAULT '',
    content  TEXT NOT NULL,

    -- 768 dimensions matches nomic-embed-text, the default local embedding
    -- model. Changing models changes this width and requires a migration plus a
    -- re-embed; the dimension is part of the schema contract, not a setting.
    embedding vector(768),

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT memory_records_kind_valid CHECK (kind IN (
        'postmortem', 'runbook', 'resolution', 'note'
    )),
    CONSTRAINT memory_records_content_present CHECK (length(content) >= 1)
);

CREATE INDEX memory_records_incident_idx ON memory_records (incident_id)
    WHERE incident_id IS NOT NULL;
CREATE INDEX memory_records_kind_idx ON memory_records (kind, created_at DESC);
CREATE INDEX memory_records_metadata_idx ON memory_records USING gin (metadata jsonb_path_ops);

-- HNSW over cosine distance. Chosen over IVFFlat because HNSW needs no training
-- step and stays accurate as rows are added one at a time — which is how this
-- table grows: one postmortem per resolved incident, never a bulk load.
--
-- Partial, because a record without an embedding yet (written before the
-- embedding job ran) must not occupy index space.
CREATE INDEX memory_records_embedding_idx ON memory_records
    USING hnsw (embedding vector_cosine_ops)
    WHERE embedding IS NOT NULL;

COMMENT ON TABLE memory_records IS
    'Long-term agent memory. Retrieved as precedent by the Diagnosis Agent, '
    'which is what "learns from previous incidents" means here: retrieval over '
    'your own history, not fine-tuning.';
