-- LOOP-664 phase 3 — read-only role for the `loop` domain (ryl_beta).
--
-- Run as the ryl-beta-db master user, connected to the `ryl_beta` database.
-- This is the DB-layer half of the read-only guarantee; the app layer adds
-- --access-mode=restricted plus readonly_guard.py. Both are required: the guard
-- can be bypassed by a router bug, the role cannot.
--
--   psql "$RYL_BETA_ADMIN_URI" -v ON_ERROR_STOP=1 -f loop_readonly_role.sql
--
-- Set the password out of band; do not commit it:
--   psql ... -v mcp_pw="$(openssl rand -base64 32)"

\if :{?mcp_pw}
\else
  \echo 'ERROR: pass -v mcp_pw=<password>'
  \quit 1
\endif

BEGIN;

-- NOLOGIN group holding the grants, so the login role can be rotated without
-- re-granting across every table.
CREATE ROLE mcp_readonly_grp NOLOGIN;

CREATE ROLE mcp_readonly LOGIN PASSWORD :'mcp_pw' CONNECTION LIMIT 4 IN ROLE mcp_readonly_grp;

-- Guard rails. These are role-level so they survive reconnects and cannot be
-- raised by the MCP: an ad-hoc query can never pin a connection or run long
-- enough to contend with Loop's write path on this single t4g.medium primary.
ALTER ROLE mcp_readonly SET statement_timeout = '30s';
ALTER ROLE mcp_readonly SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE mcp_readonly SET default_transaction_read_only = on;
ALTER ROLE mcp_readonly SET lock_timeout = '2s';
-- Keep ad-hoc scans off the shared buffer pool's hot set.
ALTER ROLE mcp_readonly SET work_mem = '32MB';

REVOKE ALL ON DATABASE ryl_beta FROM PUBLIC;
GRANT CONNECT ON DATABASE ryl_beta TO mcp_readonly_grp;

GRANT USAGE ON SCHEMA public TO mcp_readonly_grp;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly_grp;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_readonly_grp;

-- Future tables created by the migration role must be readable too, otherwise
-- the domain silently goes blind after the next Alembic revision.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO mcp_readonly_grp;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO mcp_readonly_grp;

-- Explicitly deny the write path even if a future GRANT is over-broad.
REVOKE CREATE ON SCHEMA public FROM mcp_readonly_grp;

COMMIT;

-- Verify: every one of these must be false / empty.
--   SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
--     FROM pg_roles WHERE rolname = 'mcp_readonly';
--   SELECT count(*) FROM information_schema.table_privileges
--    WHERE grantee IN ('mcp_readonly','mcp_readonly_grp')
--      AND privilege_type <> 'SELECT';
