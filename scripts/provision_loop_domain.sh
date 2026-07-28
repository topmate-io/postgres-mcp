#!/usr/bin/env bash
# LOOP-664 phase 3 — provision the `loop` domain sidecar on ryl-beta-host.
#
# Runs ON ryl-beta-host (i-0a4de19cc55a0d0ca or i-00f45c1a60148f37f), which is
# inside ryl-beta-vpc and therefore the only place that can reach ryl-beta-db.
#
#   aws ssm start-session --target i-0a4de19cc55a0d0ca --profile topmate-prod
#   sudo -i; curl -fsSL <this file> -o /tmp/prov.sh; bash /tmp/prov.sh
#
# Idempotent per host: re-running rotates only THIS host's login-role password
# and recreates its container in place. Set LOOP_MCP_ROLE to a distinct name on
# each host (see the role section) so one host's rotation cannot invalidate
# another's baked-in DSN.
#
# Requires LOOP_MCP_DIGEST — the sha256 of the router bearer. The bearer itself
# is minted operator-side and never reaches this host; nothing secret is printed.
set -euo pipefail

IMAGE="072528252688.dkr.ecr.ap-south-1.amazonaws.com/topmate-postgres-mcp:latest"
DB_HOST="ryl-beta-db.cloiauy88d9t.ap-south-1.rds.amazonaws.com"
DB_NAME="ryl_beta"
PORT=8000
PSQL="docker run --rm -i -e PGCONNECT_TIMEOUT=10 postgres:16-alpine psql"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------- admin DSN
# Reuse the app's own connection string; it is the RDS master user on this
# lift-and-shift. Never echoed.
ADMIN_DSN="$(docker exec ryl-beta-backend-api printenv DATABASE_URL)"
[ -n "$ADMIN_DSN" ] || { echo "FATAL: could not read DATABASE_URL from ryl-beta-backend-api"; exit 1; }

say "Preflight"
$PSQL "$ADMIN_DSN" -At -c "SELECT current_user || ' can_create_role=' || rolcreaterole FROM pg_roles WHERE rolname=current_user"
$PSQL "$ADMIN_DSN" -At -c "SELECT 'public tables: ' || count(*) FROM information_schema.tables WHERE table_schema='public'"

# ------------------------------------------------------------------- role
# ONE LOGIN ROLE PER HOST. All grants live on the NOLOGIN group mcp_readonly_grp,
# so each sidecar host gets its own login role and therefore its own password,
# generated locally and never transmitted. A single shared role would make this
# script unsafe to run on a second host: it rotates the password, which would
# invalidate the DSN already baked into the first host's container.
#   host 1: LOOP_MCP_ROLE=mcp_readonly (default)
#   host 2: LOOP_MCP_ROLE=mcp_readonly_h2
ROLE="${LOOP_MCP_ROLE:-mcp_readonly}"
GRP=mcp_readonly_grp

# Alphanumeric only: the password goes into a DSN, and percent-encoding it would
# need jq/python that may not be on the host. 48 chars of [A-Za-z0-9] is ~285
# bits, so dropping the symbol class costs nothing.
MCP_PW="$(openssl rand -base64 96 | tr -dc 'A-Za-z0-9' | cut -c1-48)"

if [ "$($PSQL "$ADMIN_DSN" -At -c "SELECT count(*) FROM pg_roles WHERE rolname='$GRP'")" = "0" ]; then
  say "Creating grant-holder group $GRP"
  $PSQL "$ADMIN_DSN" -v ON_ERROR_STOP=1 <<SQL
BEGIN;
CREATE ROLE $GRP NOLOGIN;
GRANT CONNECT ON DATABASE $DB_NAME TO $GRP;
GRANT USAGE ON SCHEMA public TO $GRP;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO $GRP;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO $GRP;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO $GRP;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO $GRP;
REVOKE CREATE ON SCHEMA public FROM $GRP;
COMMIT;
SQL
else
  say "Grant-holder group $GRP already exists — leaving grants untouched"
fi

if [ "$($PSQL "$ADMIN_DSN" -At -c "SELECT count(*) FROM pg_roles WHERE rolname='$ROLE'")" = "1" ]; then
  say "Login role $ROLE exists — rotating its password only (other hosts unaffected)"
  $PSQL "$ADMIN_DSN" -v ON_ERROR_STOP=1 -c "ALTER ROLE $ROLE PASSWORD '$MCP_PW'"
else
  say "Creating login role $ROLE (SELECT-only via $GRP, CONNECTION LIMIT 4)"
  $PSQL "$ADMIN_DSN" -v ON_ERROR_STOP=1 -c "CREATE ROLE $ROLE LOGIN PASSWORD '$MCP_PW' CONNECTION LIMIT 4 IN ROLE $GRP"
fi

$PSQL "$ADMIN_DSN" -v ON_ERROR_STOP=1 <<SQL
ALTER ROLE $ROLE SET statement_timeout = '30s';
ALTER ROLE $ROLE SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE $ROLE SET default_transaction_read_only = on;
ALTER ROLE $ROLE SET lock_timeout = '2s';
ALTER ROLE $ROLE SET work_mem = '32MB';
SQL

# 25 of 131 tables carry tenant-isolation RLS keyed on current_setting('app.creator_id').
# Without BYPASSRLS this role matches zero rows on all of them and returns an EMPTY
# SUCCESS rather than an error -- which is how a 4847-row table once reported
# "paying_creators: 0". Set unconditionally so a re-provision cannot silently
# reintroduce that blindness. It confers read visibility only, never write.
say "Granting BYPASSRLS (tenant-isolation RLS would otherwise return silent zeros)"
$PSQL "$ADMIN_DSN" -v ON_ERROR_STOP=1 -c "ALTER ROLE $ROLE BYPASSRLS"

say "Verifying the role really is read-only"
$PSQL "$ADMIN_DSN" -At -c "
  SELECT 'super='||rolsuper||' createdb='||rolcreatedb||' createrole='||rolcreaterole||' bypassrls='||rolbypassrls
    FROM pg_roles WHERE rolname='$ROLE'"
NONSELECT=$($PSQL "$ADMIN_DSN" -At -c "
  SELECT count(*) FROM information_schema.table_privileges
   WHERE grantee IN ('$ROLE','$GRP') AND privilege_type <> 'SELECT'")
[ "$NONSELECT" = "0" ] || { echo "FATAL: $ROLE holds $NONSELECT non-SELECT privileges"; exit 1; }
echo "non-SELECT privileges: 0 — OK"
# BYPASSRLS must be on (read visibility) while every escalation flag stays off.
ATTRS=$($PSQL "$ADMIN_DSN" -At -c "
  SELECT rolsuper::int::text || rolcreatedb::int::text || rolcreaterole::int::text || rolbypassrls::int::text
    FROM pg_roles WHERE rolname='$ROLE'")
[ "$ATTRS" = "0001" ] || { echo "FATAL: expected super/createdb/createrole/bypassrls = 0,0,0,1 — got $ATTRS"; exit 1; }
echo "attributes super=0 createdb=0 createrole=0 bypassrls=1 — OK"

RO_DSN="postgresql://${ROLE}:${MCP_PW}@${DB_HOST}:5432/${DB_NAME}"

say "Proving the write path is closed at the DB layer"
# Do NOT pipe psql straight into grep: `set -o pipefail` would surface psql's
# (expected, desired) non-zero exit as the pipeline status and invert the test
# into a false FATAL. Capture first, match second.
WRITE_OUT="$($PSQL "$RO_DSN" -At -c 'CREATE TABLE _mcp_should_fail(x int)' 2>&1 || true)"
if printf '%s\n' "$WRITE_OUT" | grep -qiE 'permission denied|read-only transaction'; then
  echo "write rejected: $(printf '%s\n' "$WRITE_OUT" | head -1)"
else
  echo "FATAL: expected a write rejection, got: $WRITE_OUT"; exit 1
fi
# Belt and braces: whatever the message said, the table must not exist. This
# catches a rejection that was really a connection failure in disguise.
LEAKED="$($PSQL "$ADMIN_DSN" -At -c "SELECT count(*) FROM pg_tables WHERE tablename='_mcp_should_fail'")"
[ "$LEAKED" = "0" ] || { echo "FATAL: _mcp_should_fail exists — the write went through"; exit 1; }
echo "table absent — OK"

# ---------------------------------------------------------------- sidecar
say "Installing router PERSON_TOKENS"
# The bearer itself is minted on the operator's side and NEVER travels here or
# appears in any log: this host only ever sees its sha256. That is the whole
# point of the digest-based registry -- a compromised sidecar cannot replay the
# router's credential, because it does not hold it.
: "${LOOP_MCP_DIGEST:?set LOOP_MCP_DIGEST to the sha256 of the router bearer}"
[ "${#LOOP_MCP_DIGEST}" -eq 64 ] || { echo "FATAL: LOOP_MCP_DIGEST must be a 64-char sha256 hex digest"; exit 1; }
PERSON_TOKENS="{\"svc-router\":\"$LOOP_MCP_DIGEST\"}"

say "Starting loop-mcp on :$PORT"
aws ecr get-login-password --region ap-south-1 \
  | docker login --username AWS --password-stdin 072528252688.dkr.ecr.ap-south-1.amazonaws.com
docker pull "$IMAGE"
docker rm -f loop-mcp 2>/dev/null || true
docker run -d --name loop-mcp --restart unless-stopped \
  -p "${PORT}:8000" \
  -e DATABASE_URI="$RO_DSN" \
  -e ACCESS_MODE=restricted \
  -e TRANSPORT=streamable-http \
  -e PORT=8000 \
  -e DB_POOL_MIN_SIZE=1 \
  -e DB_POOL_MAX_SIZE=4 \
  -e PERSON_AUTH_ENABLED=true \
  -e PERSON_TOKENS="$PERSON_TOKENS" \
  "$IMAGE" \
  --transport=streamable-http --sse-host=0.0.0.0 --sse-port=8000 --access-mode=restricted

sleep 12
say "Health + auth checks"
curl -fsS "http://localhost:${PORT}/health" >/dev/null && echo "health: OK"

# PersonAuth must REJECT an unauthenticated call. ALLOWED_IPS is empty here, and
# empty means allow-all in IPAllowlistMiddleware, so PersonAuth is the ONLY
# thing standing between this port and the internet once the ALB fronts it.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://localhost:${PORT}/mcp" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}')
[ "$CODE" = "401" ] || { echo "FATAL: unauthenticated call returned $CODE, expected 401"; exit 1; }
echo "unauthenticated -> 401 — OK"

# A bogus bearer must also be refused -- proves PersonAuth is comparing against
# the registry rather than merely requiring the header to be present.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://localhost:${PORT}/mcp" \
  -H "Authorization: Bearer definitely-not-the-router-token" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}')
[ "$CODE" = "401" ] || { echo "FATAL: bogus bearer returned $CODE, expected 401"; exit 1; }
echo "bogus bearer   -> 401 — OK"

# The positive (200) case is deliberately NOT checked here: this host has no
# copy of the bearer. The router proves it end-to-end after the ALB rule lands.

say "Persisting sidecar secrets (best-effort)"
# BEST-EFFORT ON PURPOSE. ryl-beta-ec2-role has no secretsmanager:PutSecretValue,
# and this is not worth an IAM change: `docker run -e` bakes the DSN into the
# container config and --restart unless-stopped carries it across reboots, so
# the running service never reads these back. They exist only so a human can
# recover the DSN without a rotation. If it fails, re-running this script
# rotates the password and recreates the container, which is the real recovery
# path anyway. Do not let it kill an otherwise-good provision.
persist() { # name value
  aws secretsmanager create-secret --region ap-south-1 --name "$1" --secret-string "$2" >/dev/null 2>&1 \
    || aws secretsmanager put-secret-value --region ap-south-1 --secret-id "$1" --secret-string "$2" >/dev/null 2>&1 \
    || { echo "  skipped $1 (no secretsmanager write permission on this instance role)"; return 0; }
  echo "  stored $1"
}
persist /ryl-beta/loop_mcp_database_uri "$RO_DSN"
persist /ryl-beta/loop_mcp_person_tokens "$PERSON_TOKENS"

cat <<'EOF'

================================================================
 Sidecar is up and verified read-only + auth-gated.
 No secret was printed by this script.

 Remaining, both off-host:
   1) ALB target group + listener rule + Cloudflare CNAME
      for loop-mcp.ryloop.co
   2) Put the router bearer (held by the operator who minted
      the digest) into postgres-mcp-secrets, then roll the
      router. MERGE into that secret -- it also holds
      person-tokens and database-uri.
================================================================
EOF
