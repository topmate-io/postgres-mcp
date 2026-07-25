#!/usr/bin/env bash
# ============================================================================
# Multi-domain live smoke test for the unified postgres-mcp router
# (LOOP-664 M3). Mirrors tests/smoke/run_smoke.sh's curl/JSON-RPC style
# against the deployed streamable-HTTP /mcp endpoint. The server runs
# FastMCP(..., stateless_http=True, json_response=True), so a single POST
# with a tools/call request returns the JSON result directly -- no separate
# initialize handshake is required.
#
# ----------------------------------------------------------------------------
# VERIFY-FIRST RUNBOOK -- read and do this BEFORE running the script live.
# Nothing below this comment block executes kubectl; these are documented
# manual steps against the prod cluster (requires SSO + kube context).
# ----------------------------------------------------------------------------
#
#   Step 1: Confirm each fin downstream actually has a DATABASE_URI wired up.
#   deploy.sh provisions the v2-*-database-uri secrets with `|| true`, which
#   silently swallows a failed provision -- verify, don't assume:
#
#     kubectl -n postgres-mcp exec deploy/postgres-mcp-v2-ledger -- \
#       sh -lc 'python -c "import os;print(bool(os.environ.get(\"DATABASE_URI\")))"'
#     kubectl -n postgres-mcp exec deploy/postgres-mcp-v2-payment -- \
#       sh -lc 'python -c "import os;print(bool(os.environ.get(\"DATABASE_URI\")))"'
#     kubectl -n postgres-mcp exec deploy/postgres-mcp-v2-payout -- \
#       sh -lc 'python -c "import os;print(bool(os.environ.get(\"DATABASE_URI\")))"'
#
#   Expected: `True` for all three. If any prints `False` (or the exec fails),
#   that domain's secret was never provisioned -- fix it before enabling that
#   domain, or its row below will FAIL.
#
#   Step 2: Flip the router flag on (only after Step 1 is all True):
#
#     kubectl -n postgres-mcp set env deployment/postgres-mcp MULTI_DOMAIN_ENABLED=true
#
#   Step 3: Run this script against the live endpoint:
#
#     MCP_BASE=https://mcp.gabbanext.run/postgres-mcp \
#     POSTGRES_MCP_TOKEN=*** \
#     bash tests/smoke/run_multidomain_smoke.sh
#
#   Expected: "SMOKE: all rows PASS" -- all five domains return a row from
#   execute_sql, and get_schema_guide lists every enabled domain.
#
#   Step 4: Rollback if anything fails:
#
#     kubectl -n postgres-mcp set env deployment/postgres-mcp MULTI_DOMAIN_ENABLED=false
#
# ============================================================================
set -u

MCP_BASE="${MCP_BASE:-https://mcp.gabbanext.run/postgres-mcp}"

if [ -z "${POSTGRES_MCP_TOKEN:-}" ]; then
  echo "FATAL: POSTGRES_MCP_TOKEN is not set." >&2
  echo "       Export the Bearer token for ${MCP_BASE} and retry, e.g.:" >&2
  echo "         POSTGRES_MCP_TOKEN=*** bash tests/smoke/run_multidomain_smoke.sh" >&2
  exit 1
fi

ENDPOINT="${MCP_BASE}/mcp"
ACCEPT='Accept: application/json, text/event-stream'
CT='Content-Type: application/json'
AUTH="Authorization: Bearer ${POSTGRES_MCP_TOKEN}"

fails=0

row() { # row <name> <expected-expr> <actual>
  local name="$1" cond="$2" actual="$3"
  if eval "$cond"; then printf 'PASS  %-58s (got %s)\n' "$name" "$actual"
  else printf 'FAIL  %-58s (got %s)\n' "$name" "$actual"; fails=$((fails+1)); fi
}

# request <json-rpc-payload> -> sets RESP_STATUS and RESP_BODY
request() {
  local payload="$1" raw
  raw="$(curl -s -m 20 -w $'\n%{http_code}' -X POST -H "$CT" -H "$ACCEPT" -H "$AUTH" -d "$payload" "$ENDPOINT")"
  RESP_STATUS="${raw##*$'\n'}"
  RESP_BODY="${raw%$'\n'*}"
}

echo "== Row D: execute_sql 'select 1 as ok' across all domains =="
for dom in tm igdm fin_ledger fin_payment fin_payout; do
  payload=$(printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_sql","arguments":{"sql":"select 1 as ok","domain":"%s"}}}' "$dom")
  request "$payload"
  cond='[ "$RESP_STATUS" = 200 ] && printf "%s" "$RESP_BODY" | grep -qi "ok" && printf "%s" "$RESP_BODY" | grep -q "1" && ! printf "%s" "$RESP_BODY" | grep -qiE "\"?error\"?:"'
  row "D-${dom} execute_sql domain=${dom} returns ok row" "$cond" "http=${RESP_STATUS} body=${RESP_BODY:0:100}"
done

echo "== Row G: get_schema_guide lists all enabled domains =="
guide_payload='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_schema_guide","arguments":{}}}'
request "$guide_payload"
cond='[ "$RESP_STATUS" = 200 ] && printf "%s" "$RESP_BODY" | grep -q "igdm" && printf "%s" "$RESP_BODY" | grep -q "fin_ledger" && ! printf "%s" "$RESP_BODY" | grep -qiE "\"?error\"?:"'
row "G1 get_schema_guide lists igdm + fin_ledger" "$cond" "http=${RESP_STATUS} body=${RESP_BODY:0:100}"

echo
if [ "$fails" -eq 0 ]; then echo "SMOKE: all rows PASS"; else echo "SMOKE: $fails row(s) FAILED"; fi
exit $fails
