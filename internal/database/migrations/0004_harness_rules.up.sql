-- 0004_harness_rules: the permission and policy tables.
--
-- These two tables are the thing standing between a hallucinated action and
-- production. They are DATA rather than code deliberately: the matrix is
-- reviewable, diffable and testable without reading Go, and changing it does
-- not require a deploy. See docs/adr/0006-harness-as-security-boundary.md.

-- ---------------------------------------------------------------------------
-- permissions — per-agent allowlist, deny by default
-- ---------------------------------------------------------------------------
CREATE TABLE permissions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_kind TEXT        NOT NULL,
    tool       TEXT        NOT NULL,
    action     TEXT        NOT NULL,
    effect     TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT permissions_effect_valid CHECK (effect IN ('allow', 'deny')),
    CONSTRAINT permissions_agent_kind_valid CHECK (agent_kind IN (
        'incident_manager', 'monitoring', 'log_analysis',
        'diagnosis', 'security', 'action', 'documentation'
    ))
);

CREATE UNIQUE INDEX permissions_subject_key ON permissions (agent_kind, tool, action);
CREATE INDEX permissions_agent_kind_idx ON permissions (agent_kind);

COMMENT ON TABLE permissions IS
    'Deny by default: an action with no matching allow rule is refused. An '
    'explicit deny beats an allow, and the most specific rule wins.';

-- ---------------------------------------------------------------------------
-- policies — risk tiering and approval requirements
-- ---------------------------------------------------------------------------
CREATE TABLE policies (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT        NOT NULL,
    description       TEXT        NOT NULL DEFAULT '',
    tool              TEXT        NOT NULL,
    action            TEXT        NOT NULL,
    risk              TEXT        NOT NULL,
    requires_approval BOOLEAN     NOT NULL DEFAULT TRUE,
    min_confidence    NUMERIC(4,3) NOT NULL DEFAULT 0,
    priority          INTEGER     NOT NULL DEFAULT 0,
    enabled           BOOLEAN     NOT NULL DEFAULT TRUE,
    conditions        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT policies_risk_valid CHECK (risk IN ('low', 'medium', 'high', 'forbidden')),
    CONSTRAINT policies_confidence_range CHECK (min_confidence >= 0 AND min_confidence <= 1),
    -- A forbidden action is not reachable with any approval, so a row claiming
    -- otherwise is a misconfiguration the database refuses to store.
    CONSTRAINT policies_forbidden_requires_approval
        CHECK (risk <> 'forbidden' OR requires_approval)
);

CREATE UNIQUE INDEX policies_name_key ON policies (name);
CREATE UNIQUE INDEX policies_subject_key ON policies (tool, action);
CREATE INDEX policies_enabled_idx ON policies (enabled) WHERE enabled;

COMMENT ON COLUMN policies.min_confidence IS
    'Routes a low-confidence agent to a human even for an otherwise-automatic '
    'action. A weak local model reasoning poorly is exactly what this catches.';

-- ---------------------------------------------------------------------------
-- Seed: the default matrix.
--
-- Six of the seven agents are read-only. Exactly one can propose a mutation,
-- and its proposals still pass the policy engine. That ratio is the design.
-- ---------------------------------------------------------------------------

INSERT INTO permissions (agent_kind, tool, action, effect) VALUES
    -- Read-only agents. A blanket deny on mutating tools makes the intent
    -- explicit rather than relying on the absence of an allow.
    ('monitoring',       'monitoring', '*',                   'allow'),
    ('monitoring',       'docker',     'list_containers',     'allow'),
    ('monitoring',       'docker',     'inspect_container',   'allow'),
    ('monitoring',       'kubernetes', 'get_pods',            'allow'),
    ('monitoring',       'kubernetes', 'describe_pod',        'allow'),
    ('monitoring',       'linux',      'read_metrics',        'allow'),

    ('log_analysis',     'docker',     'logs',                'allow'),
    ('log_analysis',     'kubernetes', 'logs',                'allow'),
    ('log_analysis',     'linux',      'read_file',           'allow'),

    ('security',         'security',   '*',                   'allow'),
    ('security',         'docker',     'inspect_container',   'allow'),
    ('security',         'kubernetes', 'get_pods',            'allow'),
    ('security',         'git',        'diff',                'allow'),

    ('diagnosis',        'monitoring', 'query',               'allow'),
    ('documentation',    'git',        'read',                'allow'),

    -- The one agent that may propose a mutation.
    ('action',           'docker',     'restart_container',   'allow'),
    ('action',           'docker',     'start_container',     'allow'),
    ('action',           'kubernetes', 'restart_deployment',  'allow'),
    ('action',           'kubernetes', 'scale_deployment',    'allow'),
    ('action',           'kubernetes', 'rollback_deployment', 'allow'),
    ('action',           'linux',      'restart_service',     'allow'),
    -- Explicit denies. Redundant against deny-by-default, and kept anyway: an
    -- operator reading this table should see the destructive actions named and
    -- refused, not have to infer it from an absence.
    ('action',           'database',   'drop_table',          'deny'),
    ('action',           'database',   'delete_database',     'deny'),
    ('action',           'database',   'truncate',            'deny'),
    ('action',           'kubernetes', 'delete_namespace',    'deny'),
    ('action',           'docker',     'delete_volume',       'deny');

INSERT INTO policies (name, description, tool, action, risk, requires_approval, min_confidence, priority) VALUES
    ('read-only-default',   'Anything read-only executes automatically.',
        'monitoring', '*',                   'low',       FALSE, 0.00,  0),
    ('logs-read',           'Reading logs is non-destructive.',
        'docker',     'logs',                'low',       FALSE, 0.00,  0),
    ('k8s-logs-read',       'Reading pod logs is non-destructive.',
        'kubernetes', 'logs',                'low',       FALSE, 0.00,  0),
    ('list-containers',     'Listing containers is non-destructive.',
        'docker',     'list_containers',     'low',       FALSE, 0.00,  0),

    ('restart-container',   'Reversible, but visible to users. Needs a human.',
        'docker',     'restart_container',   'medium',    TRUE,  0.70, 10),
    ('scale-deployment',    'Reversible capacity change.',
        'kubernetes', 'scale_deployment',    'medium',    TRUE,  0.70, 10),
    ('restart-deployment',  'Rolling restart; brief disruption.',
        'kubernetes', 'restart_deployment',  'medium',    TRUE,  0.70, 10),

    ('rollback-deployment', 'Reverts a release. Requires justification.',
        'kubernetes', 'rollback_deployment', 'high',      TRUE,  0.85, 20),
    ('restart-service',     'Host-level service restart.',
        'linux',      'restart_service',     'high',      TRUE,  0.85, 20),
    ('restart-database',    'Disruptive and slow to recover.',
        'database',   'restart',             'high',      TRUE,  0.90, 20),

    -- Not "needs a very senior approver" — there is deliberately no path.
    ('forbid-drop-table',   'Never reachable through this system.',
        'database',   'drop_table',          'forbidden', TRUE,  1.00, 100),
    ('forbid-delete-db',    'Never reachable through this system.',
        'database',   'delete_database',     'forbidden', TRUE,  1.00, 100),
    ('forbid-truncate',     'Never reachable through this system.',
        'database',   'truncate',            'forbidden', TRUE,  1.00, 100),
    ('forbid-delete-ns',    'Never reachable through this system.',
        'kubernetes', 'delete_namespace',    'forbidden', TRUE,  1.00, 100),
    ('forbid-delete-volume','Never reachable through this system.',
        'docker',     'delete_volume',       'forbidden', TRUE,  1.00, 100);
