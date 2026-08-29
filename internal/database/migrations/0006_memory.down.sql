-- Reverses 0006_memory. The vector extension is left installed: other schemas
-- may depend on it, and a migration must not reach outside its own footprint.
DROP TABLE IF EXISTS memory_records;
