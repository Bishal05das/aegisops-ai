-- 0003_tasks_tools: agent work, agent intent, and what the harness actually did.

-- ---------------------------------------------------------------------------
-- agent_tasks — one unit of work dispatched to an agent
-- ---------------------------------------------------------------------------
CREATE TABLE agent_tasks (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id    UUID        NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    agent_id       UUID        NOT NULL REFERENCES agents (id) ON DELETE RESTRICT,

    -- Chains a task to the one that spawned it, so the Incident Manager's plan
    -- and the sub-tasks it fanned out form a readable tree.
    parent_task_id UUID REFERENCES agent_tasks (id) ON DELETE SET NULL,

    type        TEXT        NOT NULL,
    status      TEXT        NOT NULL,
    input       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    output      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    error       TEXT        NOT NULL DEFAULT '',
    attempts    INTEGER     NOT NULL DEFAULT 0,

    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT agent_tasks_status_valid CHECK (status IN (
        'pending', 'running', 'succeeded', 'failed', 'cancelled', 'timed_out'
    )),
    CONSTRAINT agent_tasks_attempts_nonneg CHECK (attempts >= 0),
    CONSTRAINT agent_tasks_finished_after_started
        CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at),
    -- A task cannot be its own parent. Deeper cycles are prevented by the
    -- orchestrator, which only ever sets a parent that already exists.
    CONSTRAINT agent_tasks_no_self_parent CHECK (parent_task_id IS NULL OR parent_task_id <> id)
);

CREATE INDEX agent_tasks_incident_idx ON agent_tasks (incident_id, created_at);
CREATE INDEX agent_tasks_agent_idx ON agent_tasks (agent_id, created_at DESC);
CREATE INDEX agent_tasks_parent_idx ON agent_tasks (parent_task_id) WHERE parent_task_id IS NOT NULL;
-- The scheduler's queue: unfinished work, oldest first.
CREATE INDEX agent_tasks_open_idx ON agent_tasks (created_at)
    WHERE status IN ('pending', 'running');

-- ON DELETE RESTRICT on agent_id, not CASCADE: deleting an agent registration
-- must not silently erase the history of what it did.
COMMENT ON COLUMN agent_tasks.agent_id IS
    'RESTRICT on delete: an agent registration cannot be removed while its work '
    'history exists. Disable the agent instead.';

-- ---------------------------------------------------------------------------
-- tool_calls — an agent's INTENT to act
-- ---------------------------------------------------------------------------
CREATE TABLE tool_calls (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID        NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    task_id     UUID REFERENCES agent_tasks (id) ON DELETE SET NULL,
    agent_id    UUID        NOT NULL REFERENCES agents (id) ON DELETE RESTRICT,
    agent_name  TEXT        NOT NULL DEFAULT '',

    tool        TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    params      JSONB       NOT NULL DEFAULT '{}'::jsonb,

    -- The model's own justification, stored verbatim and never summarised.
    -- During a postmortem, "what did the AI think it was doing" is answerable
    -- only if this was captured exactly as generated.
    reason      TEXT        NOT NULL,
    confidence  NUMERIC(4,3) NOT NULL DEFAULT 0,

    risk        TEXT,
    decision    TEXT        NOT NULL DEFAULT 'pending',

    decided_by    UUID REFERENCES users (id) ON DELETE SET NULL,
    decided_at    TIMESTAMPTZ,
    decision_note TEXT      NOT NULL DEFAULT '',

    -- The bus delivers at-least-once. Without this, a redelivered
    -- ToolRequested event would restart the container a second time.
    idempotency_key TEXT,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT tool_calls_reason_present CHECK (length(reason) BETWEEN 1 AND 10000),
    CONSTRAINT tool_calls_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT tool_calls_risk_valid CHECK (risk IS NULL OR risk IN ('low', 'medium', 'high', 'forbidden')),
    CONSTRAINT tool_calls_decision_valid CHECK (decision IN (
        'pending', 'allowed', 'denied_unknown_tool', 'denied_invalid_params',
        'denied_permission', 'denied_policy', 'awaiting_approval',
        'approved', 'rejected', 'expired'
    )),
    -- An approval must record who granted it. An approved action with no
    -- approver is exactly the record a postmortem cannot accept.
    CONSTRAINT tool_calls_approval_attributed
        CHECK (decision <> 'approved' OR decided_by IS NOT NULL)
);

CREATE UNIQUE INDEX tool_calls_idempotency_key
    ON tool_calls (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX tool_calls_incident_idx ON tool_calls (incident_id, created_at);
CREATE INDEX tool_calls_agent_idx ON tool_calls (agent_id, created_at DESC);
CREATE INDEX tool_calls_decision_idx ON tool_calls (decision, created_at DESC);
-- The operator's approval queue.
CREATE INDEX tool_calls_awaiting_idx ON tool_calls (created_at)
    WHERE decision = 'awaiting_approval';
-- Every rejection, newest first: the drift-detection query.
CREATE INDEX tool_calls_denied_idx ON tool_calls (created_at DESC)
    WHERE decision LIKE 'denied%';

COMMENT ON TABLE tool_calls IS
    'An agent INTENT, not an action. Rows with decision LIKE ''denied%'' are the '
    'most valuable in the database: they record what the model tried to do and '
    'was prevented from doing.';

-- ---------------------------------------------------------------------------
-- executions — what the harness actually did
-- ---------------------------------------------------------------------------
CREATE TABLE executions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- One execution per tool call. This unique constraint is what makes
    -- idempotency observable: a redelivered event finds the row already there.
    tool_call_id UUID        NOT NULL UNIQUE REFERENCES tool_calls (id) ON DELETE CASCADE,

    status     TEXT    NOT NULL,
    dry_run    BOOLEAN NOT NULL DEFAULT FALSE,
    exit_code  INTEGER,
    stdout     TEXT    NOT NULL DEFAULT '',
    stderr     TEXT    NOT NULL DEFAULT '',
    truncated  BOOLEAN NOT NULL DEFAULT FALSE,
    error      TEXT    NOT NULL DEFAULT '',

    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    duration_ms BIGINT      NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT executions_status_valid CHECK (status IN ('succeeded', 'failed', 'timed_out', 'dry_run')),
    CONSTRAINT executions_duration_nonneg CHECK (duration_ms >= 0),
    CONSTRAINT executions_finished_after_started CHECK (finished_at >= started_at),
    CONSTRAINT executions_output_bounded CHECK (length(stdout) <= 65536 AND length(stderr) <= 65536)
);

CREATE INDEX executions_status_idx ON executions (status, created_at DESC);
CREATE INDEX executions_failed_idx ON executions (created_at DESC)
    WHERE status IN ('failed', 'timed_out');
