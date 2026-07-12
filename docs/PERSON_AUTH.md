<!-- docs/PERSON_AUTH.md -->
# PersonAuth rollout (LOOP-664 M1)

Per-person bearer tokens replacing the shared AUTH_TOKEN for team callers.

## Config contract — three independent knobs
| Env | Meaning |
|---|---|
| `AUTH_TOKEN` | Shared static token. When set, a `Bearer <AUTH_TOKEN>` bypasses the IP allowlist (legacy; retired in M4). |
| `PERSON_TOKENS` | JSON object `{"<name>": "<sha256 hex of raw token>"}`. Raw tokens are never stored server-side. When non-empty, a valid **person token also bypasses the IP allowlist** — a person token is a stronger, revocable per-person credential, so it grants the same network access `AUTH_TOKEN` does. This is active whenever the secret is populated, **independent of `PERSON_AUTH_ENABLED`**. |
| `PERSON_AUTH_ENABLED` | `"true"` = `PersonAuthMiddleware` *requires* a valid person token on every non-health request (rejects AUTH_TOKEN-only and no-token callers with 401). Anything else = that enforcement is a no-op. |

**How the two token knobs combine:** the IP allowlist (outer) admits a caller
if their IP is whitelisted **or** they present a valid `AUTH_TOKEN`/person token.
PersonAuth (inner) then, *only when `PERSON_AUTH_ENABLED=true`*, additionally
rejects anyone without a valid person token. So:

- **Populate `PERSON_TOKENS`, flag off:** teammates can migrate off the shared
  `AUTH_TOKEN` to personal tokens and reach the service from any IP **now**,
  while db-mcp (IP-whitelisted, in-cluster) keeps working untouched. This is the
  safe migration window — do this first.
- **Flip `PERSON_AUTH_ENABLED=true` (later):** identity is enforced for
  everyone; `AUTH_TOKEN`-only callers start getting 401s; `AUTH_TOKEN` can then
  be retired. Requires the db-mcp precondition below.

## Rollout
1. Mint a token per teammate + one per service caller (staging EC2, CI):
   `python scripts/mint_person_token.py dharsan`
2. Merge all fragments into one JSON object and store it:
   `aws secretsmanager create-secret --name topmate/postgres-mcp/person-tokens --secret-string '{...}'`
   (or `put-secret-value` to rotate/add).
3. `./eks/deploy.sh` — refreshes the `postgres-mcp-secrets` k8s secret.
4. **STOP — before flipping the flag in prod:** flipping `PERSON_AUTH_ENABLED=true` immediately
   401s ANY caller that doesn't send a personal/service bearer token. TODAY that includes
   **db-mcp-server's inter-MCP client**, which sends NO `Authorization` header (it is an
   in-cluster caller trusted by IP/network today). Do NOT flip this flag in prod until:
   1. a service token has been minted for db-mcp (`python scripts/mint_person_token.py db-mcp-server`),
   2. that token's digest is added to the `PERSON_TOKENS` secret, and
   3. db-mcp-server's client is configured to send `Authorization: Bearer <service token>`.

   Also note: `PERSON_AUTH_ENABLED=true` with an **empty** `PERSON_TOKENS` makes the
   pod fail-fast (crashloop) by design — populate the secret first.

   Flip `PERSON_AUTH_ENABLED` to `"true"` in `eks/manifests/base/deployment-postgres-mcp.yaml`, apply, verify:
   - no token → 401; personal token → 200; old shared AUTH_TOKEN alone → still passes the IP-allowlist bypass but NOT PersonAuth (401) — expected: humans move to personal tokens now, AUTH_TOKEN fully retires in M4.
5. Each caller adds `Authorization: Bearer <personal token>` in their MCP client config,
   AND switches to the streamable-HTTP endpoint — `https://mcp.gabbanext.run/postgres-mcp/mcp`
   (`"type": "http"` in `.mcp.json`) instead of `/sse`. `/mcp` is the promoted path from M1 on;
   `/sse` keeps working for stragglers until it is removed in M4.

## Scope of the flag
`PERSON_AUTH_ENABLED` gates ONLY the auth check (the 401-or-pass decision in
`PersonAuthMiddleware`). The audit logging (`AuditLogMiddleware`) and the
rewritten person-keyed, LRU-bounded rate limiter (`RateLimiterMiddleware`) are
**active regardless of the flag** — they shipped as part of M1 and are not
behind a rollback toggle. Reverting either of those requires a code revert,
not an env var flip.

## Rollback
Set `PERSON_AUTH_ENABLED` to `"false"` and re-apply the deployment. Exact pre-M1 behavior returns
for the auth check specifically (see "Scope of the flag" above — audit logging and the rate
limiter are unaffected by this toggle either way).

## Revoking one person
Remove their entry from the AWS secret, re-run deploy.sh, restart the deployment.

## Audit trail
Every request logs one JSON line on logger `postgres_mcp.audit` (person, tool,
arg keys, status, duration, request_id). Argument values are never logged.
401 denials from `PersonAuthMiddleware` are also logged as JSON lines on the
same `postgres_mcp.audit` logger, marked with `"denied": "person_auth"`
(person is always `""` since the caller never authenticated).
