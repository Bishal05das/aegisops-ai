-- Runs once, on first initialisation of an empty data volume.
--
-- Only extensions live here. Schema is owned by the versioned migrations in
-- internal/database/migrations (Phase 3) — never by this file, because this
-- script does not run again on an existing volume and would silently drift.

-- Vector similarity search: long-term agent memory embeds past incidents,
-- runbooks and resolutions so the Diagnosis Agent can retrieve precedent.
CREATE EXTENSION IF NOT EXISTS vector;

-- gen_random_uuid() for primary keys, plus digest()/hmac() for audit chaining.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Trigram indexes for fuzzy matching over log lines and incident titles.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Query-level performance visibility during load testing (Phase 15).
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Sanity beacon: `make dev-verify` greps for this line in the container logs.
DO $$
BEGIN
    RAISE NOTICE 'AegisOps: extensions ready (vector, pgcrypto, pg_trgm, pg_stat_statements)';
END
$$;
