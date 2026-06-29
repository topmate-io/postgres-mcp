#!/usr/bin/env bash
# Smoke matrix for the 2026-06-10 MCP remediation (LOOP-305 / spec_09).
# Exercises the auth/identity boundary end-to-end against the local rig
# (docker-compose.test.yml). The CallerIdentity/IPAllowlist middleware runs
# BEFORE the MCP app, so the HTTP status reliably reflects G1/G2/G3 behavior.
#
# LLM-dependent rows (G2 via NL, free-form BI) are SKIPPED unless OPENROUTER_API_KEY
# is set — the G2 fail-closed guard is already proven by tests/test_sql_scope_guard.py.
set -u

DB=http://localhost:9000
PG=http://localhost:8000
ACCEPT='Accept: application/json, text/event-stream'
CT='Content-Type: application/json'
CALL='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ask_topmate_bi","arguments":{"question":"hi"}}}'
LIST='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

fails=0
status() { curl -s -o /dev/null -w '%{http_code}' -m 15 "$@"; }
row() { # row <name> <expected-expr> <actual>
  local name="$1" cond="$2" actual="$3"
  if eval "$cond"; then printf 'PASS  %-58s (got %s)\n' "$name" "$actual"
  else printf 'FAIL  %-58s (got %s)\n' "$name" "$actual"; fails=$((fails+1)); fi
}

echo "== Row H: health bypass (no auth) =="
row "H1 db-mcp /healthz == 200" '[ "$3" = 200 ]' "$(status $DB/healthz)"
row "H2 pg /healthz == 200"     '[ "$3" = 200 ]' "$(status $PG/healthz)"

echo "== Row A: unauthenticated scoped caller -> 401 =="
row "A1 db-mcp expert, no token == 401" '[ "$3" = 401 ]' \
  "$(status -X POST -H "$CT" -H "$ACCEPT" -H 'X-User-Scope: expert' -H 'X-User-Username: expert_bob' -d "$CALL" $DB/mcp)"
row "A2 pg expert, no token == 401" '[ "$3" = 401 ]' \
  "$(status -X POST -H "$CT" -H "$ACCEPT" -H 'X-User-Scope: expert' -d "$CALL" $PG/mcp)"

echo "== Row B: Tier-1 trusted superadmin (Bearer) passes the auth boundary =="
row "B1 db-mcp Bearer+superadmin != 401" '[ "$3" != 401 ] && [ "$3" != 403 ]' \
  "$(status -X POST -H "$CT" -H "$ACCEPT" -H 'Authorization: Bearer test-shared-token' -H 'X-User-Scope: superadmin' -d "$CALL" $DB/mcp)"
row "B2 pg Bearer+superadmin != 401/403" '[ "$3" != 401 ] && [ "$3" != 403 ]' \
  "$(status -X POST -H "$CT" -H "$ACCEPT" -H 'Authorization: Bearer test-shared-token' -H 'X-User-Scope: superadmin' -d "$CALL" $PG/mcp)"

echo "== Row C: pg is admin-only -> expert (even trusted) is 403 =="
row "C1 pg Bearer+expert == 403" '[ "$3" = 403 ]' \
  "$(status -X POST -H "$CT" -H "$ACCEPT" -H 'Authorization: Bearer test-shared-token' -H 'X-User-Scope: expert' -H 'X-User-Username: expert_bob' -d "$CALL" $PG/mcp)"
row "C2 db-mcp Bearer+expert != 401/403" '[ "$3" != 401 ] && [ "$3" != 403 ]' \
  "$(status -X POST -H "$CT" -H "$ACCEPT" -H 'Authorization: Bearer test-shared-token' -H 'X-User-Scope: expert' -H 'X-User-Username: expert_bob' -d "$CALL" $DB/mcp)"

echo "== Row S1: postgres-mcp stateless /mcp accepts tools/list without a prior session =="
row "S1 pg /mcp tools/list (stateless) != 000/404" '[ "$3" != 000 ] && [ "$3" != 404 ]' \
  "$(status -X POST -H "$CT" -H "$ACCEPT" -H 'Authorization: Bearer test-shared-token' -H 'X-User-Scope: superadmin' -d "$LIST" $PG/mcp)"

echo "== Row G: G2 cross-join PII leak =="
if [ -n "${OPENROUTER_API_KEY:-}" ]; then
  echo "  (LLM available — drive ask_topmate_bi with the cross-join intent; manual inspect for amy/victim PII)"
else
  echo "SKIP  Row G live (no OPENROUTER_API_KEY — NL->SQL needs the LLM)."
  echo "      The G2 fail-closed guard is proven by topmate-db-mcp-server tests/"
  echo "      test_sql_scope_guard.py: a scoped 'SELECT u.* FROM user_user u CROSS"
  echo "      JOIN booking_booking b' raises ScopeViolation (no PII leak)."
fi

echo
if [ "$fails" -eq 0 ]; then echo "SMOKE: all rows PASS"; else echo "SMOKE: $fails row(s) FAILED"; fi
exit $fails
