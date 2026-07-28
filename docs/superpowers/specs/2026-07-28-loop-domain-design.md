# LOOP-664 phase 3 — `loop` domain (RYL agents platform, ryl_beta)

Status: **role + sidecar LIVE and verified on ryl-beta-host; exposure blocked on DNS/TLS.**
Date: 2026-07-28.

## Live state (verified 2026-07-28)

- `mcp_readonly` exists on `ryl_beta` (131 public tables). `rolsuper/createdb/
  createrole/bypassrls` all false; 0 non-SELECT privileges; schema ACL grants
  USAGE only. A `CREATE TABLE` as that role is rejected and leaves no table.
- Container `loop-mcp` on `i-0a4de19cc55a0d0ca`: `Up (healthy)`,
  `restart=unless-stopped`, listening `0.0.0.0:8000`, `DATABASE_URI` user is
  `mcp_readonly` (not `ryl_admin`). Unauthenticated → 401, bogus bearer → 401.
- The router bearer was minted operator-side; the host holds only its sha256
  (`svc-router` in PERSON_TOKENS). It was never transmitted or logged.
- `/ryl-beta/loop_mcp_*` secrets were NOT written: `ryl-beta-ec2-role` lacks
  `secretsmanager:PutSecretValue`. This is non-fatal — the DSN is baked into the
  container config and survives reboot; recovery is a re-run, which rotates.

### Blocker: no hostname for the sidecar

Path-prefix exposure (`ryl-beta.ryloop.co/loop-mcp/...`) does **not** work:
`asgi_utils.ALB_PREFIXES` is hardcoded to `/postgres-mcp`, `/db-mcp`,
`/instagram-mcp`, and `route_by_transport` matches `path == "/mcp"` exactly.
Verified live — `/loop-mcp/health` returns 401 instead of being health-exempt.

A dedicated hostname needs a new ACM cert (no `*.ryloop.co` wildcard exists;
every subdomain has its own) and therefore Cloudflare DNS validation.

## What this adds

A sixth `execute_sql` domain, `loop`, backed by `ryl_beta` — the RYL/Loop agents
platform database. Read-only, caller-scoped through the existing person-token
boundary, same routing contract as `igdm` and the three `fin_*` domains.

## Why it is not just another registry entry

Every existing proxied domain resolves to an in-cluster Service, because every
database they front sits in the same VPC as the EKS cluster:

| Database | VPC | Public |
|---|---|---|
| topmate-db-prod-replica | `vpc-0662b8d5b8adf8b5b` topmate-prod | true |
| instagram-autodm-v2-db | `vpc-0662b8d5b8adf8b5b` topmate-prod | false |
| financial-prod | `vpc-0662b8d5b8adf8b5b` topmate-prod | false |
| **ryl-beta-db** | **`vpc-013addcaa78946089` ryl-beta (10.20.0.0/16)** | **false** |

`ryl-beta-db` is the outlier. It is private, in a different VPC, and the only
active peering on the account is topmate-prod ↔ `vpc-0b95d4f237cad1b8c` — not
ryl-beta-vpc. A router pod cannot open a socket to it.

The asymmetry is easy to misread: Loop's own hosts already call postgres-mcp
(they egress to the public ingress and authenticate as `person:"dharsan"` —
see `memory/loop-is-postgres-mcp-client-as-dharsan.md`). Traffic flows Loop → MCP
only. Nothing flows back.

## Decision

**Sidecar MCP inside ryl-beta-vpc, reached over HTTPS with a bearer.** Rejected
the alternative — VPC peering plus an in-cluster deployment — because it opens a
permanent route from the Topmate production cluster into Loop's network for what
is a read-only reporting need. This is the same shape the analytics ClickHouse
design chose (`2026-07-25-analytics-domain-design.md`).

```
 topmate-prod-vpc                    ryl-beta-vpc
 ┌────────────────┐                  ┌──────────────────────┐
 │ postgres-mcp   │ ── HTTPS ──────▶ │ loop-mcp (sidecar)   │
 │ (router)       │    + bearer      │ on ryl-beta-host     │
 └────────────────┘                  │        │ private     │
                                     │        ▼             │
                                     │  ryl-beta-db         │
                                     │  (mcp_readonly)      │
                                     └──────────────────────┘
```

**Reads land on the primary, with role-level guard rails.** `ryl-beta-db` is a
single `db.t4g.medium` carrying Loop's live write traffic and has no replica.
Ad-hoc MCP queries are low-volume, so a replica is not yet worth ~$50/mo; the
guard rails below bound the blast radius instead. Revisit if query volume grows.

## Security: the non-obvious part

`IPAllowlistMiddleware` returns `None` (= allow all) when `ALLOWED_IPS` is empty
(`server.py:975`), and `AUTH_TOKEN` only *bypasses* the IP check — it never
*requires* a bearer. **`PersonAuthMiddleware` is the only layer that requires
one.**

The in-cluster domains get away with no auth because they are unroutable from
outside and covered by the NetworkPolicy. The `loop` sidecar is publicly
reachable, so it **must** run:

```
PERSON_AUTH_ENABLED=true
PERSON_TOKENS={"svc-router":"<sha256 of LOOP_MCP_TOKEN>"}
```

Shipping the sidecar with `AUTH_TOKEN` alone, or with an empty `ALLOWED_IPS` and
no PersonAuth, publishes read access to `ryl_beta` on the open internet.

Defence in depth, all four required:

1. `mcp_readonly` Postgres role — SELECT only, no write grants at all.
2. `--access-mode=restricted` + `readonly_guard.py` on the sidecar.
3. `PERSON_AUTH_ENABLED=true` on the sidecar — bearer required.
4. Router-side person-auth — unchanged; callers already need their own token.

## Runbook

### 1. Read-only role

```bash
psql "$RYL_BETA_ADMIN_URI" -v ON_ERROR_STOP=1 \
     -v mcp_pw="$(openssl rand -base64 32)" \
     -f scripts/loop_readonly_role.sql
```

Verify (both must come back empty/false):

```sql
SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
  FROM pg_roles WHERE rolname='mcp_readonly';
SELECT count(*) FROM information_schema.table_privileges
 WHERE grantee IN ('mcp_readonly','mcp_readonly_grp') AND privilege_type <> 'SELECT';
```

### 2. Secrets

```bash
# router -> sidecar bearer
LOOP_MCP_TOKEN=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-43)
DIGEST=$(printf '%s' "$LOOP_MCP_TOKEN" | shasum -a 256 | awk '{print $1}')

# sidecar side (ryl-beta account secrets)
aws secretsmanager create-secret --name /ryl-beta/loop_mcp_person_tokens \
  --secret-string "{\"svc-router\":\"$DIGEST\"}"
aws secretsmanager create-secret --name /ryl-beta/loop_mcp_database_uri \
  --secret-string "postgresql://mcp_readonly:<pw>@ryl-beta-db.cloiauy88d9t.ap-south-1.rds.amazonaws.com:5432/ryl_beta"

# router side — add key `loop-mcp-token` to the EXISTING postgres-mcp-secrets.
# Merge, never replace: that secret also holds person-tokens and database-uri.
```

### 3. Sidecar on ryl-beta-host

Add to the ryl-agents-backend compose stack:

```yaml
  loop-mcp:
    image: 072528252688.dkr.ecr.ap-south-1.amazonaws.com/topmate-postgres-mcp:latest
    command: ["--transport=streamable-http", "--sse-host=0.0.0.0", "--sse-port=8000", "--access-mode=restricted"]
    environment:
      DATABASE_URI: ${LOOP_MCP_DATABASE_URI}
      ACCESS_MODE: restricted
      TRANSPORT: streamable-http
      PORT: "8000"
      DB_POOL_MIN_SIZE: "1"
      DB_POOL_MAX_SIZE: "4"      # matches the role's CONNECTION LIMIT 4
      PERSON_AUTH_ENABLED: "true"
      PERSON_TOKENS: ${LOOP_MCP_PERSON_TOKENS}
    ports: ["8000:8000"]
    restart: unless-stopped
```

`DB_POOL_MAX_SIZE` must not exceed the role's `CONNECTION LIMIT`, or the pod
will fail health checks under concurrency instead of degrading.

### 4. Expose it

Target group → `ryl-beta-alb` (internet-facing, HTTPS:443 already terminated,
Cloudflare-fronted on `ryloop.co`):

```bash
aws elbv2 create-target-group --name ryl-beta-loop-mcp-tg \
  --protocol HTTP --port 8000 --vpc-id vpc-013addcaa78946089 \
  --health-check-path /health --target-type instance
# register both ryl-beta-host instances: i-0a4de19cc55a0d0ca, i-00f45c1a60148f37f
# then add a host-header rule on the :443 listener for loop-mcp.ryloop.co
```

Cloudflare: `loop-mcp.ryloop.co` → `ryl-beta-alb-876116568.ap-south-1.elb.amazonaws.com`, proxied.

### 5. Router

`DOMAIN_REGISTRY_JSON` and the `LOOP_MCP_TOKEN` secret ref are already in
`eks/manifests/base/deployment-postgres-mcp.yaml`. Apply and roll:

```bash
kubectl -n postgres-mcp apply -f eks/manifests/base/deployment-postgres-mcp.yaml
kubectl -n postgres-mcp rollout status deployment/postgres-mcp
```

## Verification

```
get_schema_guide                      -> routing includes `loop`
execute_sql(domain='loop', sql='SELECT current_database()')        -> ryl_beta
execute_sql(domain='loop', sql='DELETE FROM creators')             -> rejected by guard
execute_sql(domain='loop',
  sql="SELECT count(*) FROM creator_credit_balances
        WHERE plan_tier NOT IN ('free','trial')")                  -> paying creators
```

Then confirm the DB-layer guarantee independently of the app guard, by
connecting as `mcp_readonly` directly and attempting a write — it must fail with
a privilege error, not a guard message.

## Rollback

Remove the `loop` key from `DOMAIN_REGISTRY_JSON` and roll. The domain
disappears from the guide and `domain='loop'` returns "unknown domain" again.
Nothing else in the router changes; the sidecar and role can be torn down
afterwards at leisure.

## Follow-ups

- `creator_credit_balances` is the only paying-user source of truth; if Loop
  migrates billing to Kelviq-as-primary, the guide's first gotcha goes stale.
- Loop's own MCP calls still authenticate as `person:"dharsan"`. Mint `svc-loop`
  before rotating that token — see `memory/loop-is-postgres-mcp-client-as-dharsan.md`.
