<!-- docs/PERSON_AUTH.md -->
# PersonAuth rollout (LOOP-664 M1)

Per-person bearer tokens replacing the shared AUTH_TOKEN for team callers.

## Config contract
| Env | Meaning |
|---|---|
| `PERSON_AUTH_ENABLED` | `"true"` = every non-health request needs a personal token. Anything else = middleware is a no-op (rollback path). |
| `PERSON_TOKENS` | JSON object `{"<name>": "<sha256 hex of raw token>"}`. Raw tokens are never stored server-side. |

## Rollout
1. Mint a token per teammate + one per service caller (staging EC2, CI):
   `python scripts/mint_person_token.py dharsan`
2. Merge all fragments into one JSON object and store it:
   `aws secretsmanager create-secret --name topmate/postgres-mcp/person-tokens --secret-string '{...}'`
   (or `put-secret-value` to rotate/add).
3. `./eks/deploy.sh` — refreshes the `postgres-mcp-secrets` k8s secret.
4. Flip `PERSON_AUTH_ENABLED` to `"true"` in `eks/manifests/base/deployment-postgres-mcp.yaml`, apply, verify:
   - no token → 401; personal token → 200; old shared AUTH_TOKEN alone → still passes the IP-allowlist bypass but NOT PersonAuth (401) — expected: humans move to personal tokens now, AUTH_TOKEN fully retires in M4.
5. Each caller adds `Authorization: Bearer <personal token>` in their MCP client config,
   AND switches to the streamable-HTTP endpoint — `https://mcp.gabbanext.run/postgres-mcp/mcp`
   (`"type": "http"` in `.mcp.json`) instead of `/sse`. `/mcp` is the promoted path from M1 on;
   `/sse` keeps working for stragglers until it is removed in M4.

## Rollback
Set `PERSON_AUTH_ENABLED` to `"false"` and re-apply the deployment. Exact pre-M1 behavior returns.

## Revoking one person
Remove their entry from the AWS secret, re-run deploy.sh, restart the deployment.

## Audit trail
Every request logs one JSON line on logger `postgres_mcp.audit` (person, tool,
arg keys, status, duration, request_id). Argument values are never logged.
