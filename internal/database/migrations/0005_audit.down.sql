-- Reverses 0005_audit.
--
-- The triggers must go before the table, or the DROP itself would be refused by
-- the very guard this migration installed.
DROP TRIGGER IF EXISTS audit_logs_no_delete ON audit_logs;
DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
DROP TABLE IF EXISTS audit_logs;
DROP FUNCTION IF EXISTS audit_logs_reject_mutation();
