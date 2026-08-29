-- Reverses 0001_identity.
--
-- Extensions are deliberately NOT dropped: other schemas in the same database
-- may depend on pgcrypto or pg_trgm, and a migration must not reach outside its
-- own footprint.

DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS users;
