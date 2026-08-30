-- 0008_policy_coverage: tier every action the tool catalog declares.
--
-- Why this migration exists, in one sentence: the policy engine denies an action
-- no policy governs, and migration 0004 tiered only the actions that existed as
-- ideas at the time, so ten actions the Phase 6 catalog declares had no policy
-- and were therefore unusable.
--
-- That gap was found by PolicyEngine.ReconcileTools, which cross-checks the
-- registered tool descriptors against this table at startup. It is worth
-- recording how it read, because it is the reconciler doing exactly its job:
--
--     kubernetes.get_pods has no policy and cannot run until one is added
--     docker.start_container is a mutating action with no policy
--
-- The first nine are read-only and tier low with no approval. The last is
-- mutating and tiers medium: starting a container is a change to production,
-- reversible but visible, and it belongs in the same tier as restarting one.
--
-- Note the direction of the failure this fixes. The missing policies made the
-- system *too restrictive* — the read-only agents could gather no evidence.
-- That is the correct direction for a bug in a safety control to fail, and it is
-- deny-by-default working as designed rather than in spite of it.

INSERT INTO policies (name, description, tool, action, risk, requires_approval, min_confidence, priority) VALUES
    -- Inspection. Nothing here changes anything.
    ('inspect-container',  'Reading a container''s configuration is non-destructive.',
        'docker',     'inspect_container',  'low',    FALSE, 0.00, 0),
    ('k8s-get-pods',       'Listing pods is non-destructive.',
        'kubernetes', 'get_pods',           'low',    FALSE, 0.00, 0),
    ('k8s-describe-pod',   'Reading a pod''s events is non-destructive.',
        'kubernetes', 'describe_pod',       'low',    FALSE, 0.00, 0),
    ('host-read-metrics',  'Reading host utilisation is non-destructive.',
        'linux',      'read_metrics',       'low',    FALSE, 0.00, 0),
    ('host-read-file',     'Reading an allowlisted path is non-destructive. Path traversal is refused by the parameter schema, not by this policy.',
        'linux',      'read_file',          'low',    FALSE, 0.00, 0),
    ('security-scan',      'Scanning an image for known vulnerabilities is non-destructive.',
        'security',   'scan_image',         'low',    FALSE, 0.00, 0),
    ('security-config',    'Checking a workload''s security configuration is non-destructive.',
        'security',   'check_config',       'low',    FALSE, 0.00, 0),
    ('git-diff',           'Reading repository history correlates incidents with changes.',
        'git',        'diff',               'low',    FALSE, 0.00, 0),
    ('git-read',           'Reading a file at a revision is non-destructive.',
        'git',        'read',               'low',    FALSE, 0.00, 0),

    -- Mutating. Same tier as restarting a container: reversible, but visible to
    -- users, so a human decides.
    ('start-container',    'Starting a container is a visible change to production.',
        'docker',     'start_container',    'medium', TRUE,  0.70, 10)

-- Idempotent so a re-run against a database that already has these is a no-op
-- rather than a failed migration.
ON CONFLICT (tool, action) DO NOTHING;
