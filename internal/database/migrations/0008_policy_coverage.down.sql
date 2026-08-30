-- Reverses 0008_policy_coverage.
--
-- Removing these makes the actions untiered, and an untiered action is denied.
-- So rolling back tightens rather than loosens, which is the safe direction.
DELETE FROM policies WHERE name IN (
    'inspect-container', 'k8s-get-pods', 'k8s-describe-pod',
    'host-read-metrics', 'host-read-file',
    'security-scan', 'security-config',
    'git-diff', 'git-read',
    'start-container'
);
