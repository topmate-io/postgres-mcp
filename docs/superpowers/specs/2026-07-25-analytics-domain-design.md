# LOOP-664 phase 2 — `analytics` domain (OpenPanel ClickHouse) design

- **Date:** 2026-07-25
- **Status:** Approved (design), not yet planned
- **Parent:** LOOP-664 (unified internal MCP). Phase 1 (M1 perimeter auth + M3 five-domain router) is live in prod — image `cf655c6-20260725130700`.
- **Scope:** adds a sixth router domain, `analytics`. The `loop` domain is **explicitly out of scope** — see §11.

> **PRIVACY: this file must never reach public git history.** `topmate-io/postgres-mcp` is a public fork. `docs/superpowers/**` is excluded from the public release branch by convention (see the M3 code-only PR #5 precedent). Do not push the working branch to `origin`.

---

## 1. Problem

The router today serves five Postgres domains: `tm` (local pool) plus `igdm`, `fin_ledger`, `fin_payment`, `fin_payout` (proxied to sibling per-DB MCPs inside the EKS cluster). Product analytics is not reachable at all.

Topmate's product analytics lives in **ClickHouse**, database `openpanel`, table `openpanel.events` — 58,546,286 events across 651 event types over an 84-day window. It is self-hosted **OpenPanel on Hetzner** at `5.223.90.31`, reachable by operators only through `ssh openpanel-analytics` followed by `curl localhost:8123`. Answering even a routine question ("how did this creator's funnel move last week?") currently means leaving the assistant, opening an SSH session, and hand-writing ClickHouse SQL from a runbook.

Three properties of the target make this materially different from every existing domain, and they drive the whole design:

1. **Different engine.** ClickHouse, not Postgres. Dialect, system catalog, and hazard surface all differ.
2. **Different cloud.** Hetzner, outside AWS entirely. There is no VPC path; traffic must cross the public internet.
3. **Resource-constrained and customer-facing.** The box is CPU-bound — load ~8 on 4 cores — and the *same* ClickHouse instance backs the live creator analytics dashboard on topmate.io. An ad-hoc query surface that starves that dashboard degrades a paying-customer feature.

A fourth property is a security constraint: ClickHouse's HTTP interface on `:8123` has **no authentication** and is bound to localhost. Verified 2026-07-25: TCP connect to `5.223.90.31:8123` from outside is filtered. That must remain true.

## 2. Goals / non-goals

**Goals**

- `execute_sql(sql, domain="analytics")` runs arbitrary **read-only** ClickHouse SQL, using the same tool contract as the other five domains.
- Discovery works: `list_objects` / `get_object_details` resolve against ClickHouse's catalog.
- `get_schema_guide()` teaches the caller the event catalog and the non-obvious query rules, so queries are correct and cheap by construction.
- The creator dashboard cannot be starved by analytics-domain traffic.
- ClickHouse `:8123` stays localhost-only and unauthenticated-but-unreachable.

**Non-goals**

- No writes, ever, in this phase. Consistent with LOOP-664 v1's strictly-read-only stance.
- No new deployed service, no new host, no new TLS certificate, no VPC change.
- No ClickHouse driver or connection pool in the router. The M3 invariant — the aggregator proxies and never opens its own database connections — is preserved.
- Not porting all 651 event types into the schema guide. Curated subset only (§6).
- No Redis caching of ad-hoc SQL results (rationale in §8).
- No hard-enforced date filter (rationale in §8).

## 3. Architecture

```
Claude ──HTTPS + person token──▶ postgres-mcp router (EKS, vpc-0662b8d5b8adf8b5b)
                                    │  domain="analytics"
                                    │  readonly_guard  (defence-in-depth)
                                    ▼
                            HTTPS + ANALYTICS_MCP_TOKEN
                                    │   (public internet — Hetzner is not in AWS)
                                    ▼
              Caddy ──▶ topmate-analytics-api : POST /mcp    (Hetzner 5.223.90.31)
                                    │  requireMcpToken
                                    │  chQueue: 20 in-flight, 429 past 200 queued
                                    │  in-flight coalescing, timeout retry
                                    ▼
                            ClickHouse localhost:8123
                            user: mcp_readonly  ◀── authoritative security boundary
```

Two existing services gain a capability; nothing new is deployed. `topmate-analytics-api` (Node 
+ TypeScript, Express 5, PM2 cluster ×2, behind Caddy at `https://data.analytics.topmate.io`) already holds every piece of infrastructure this needs: a ClickHouse client, a Redis cache, TLS, a deploy pipeline, and — critically — a tuned concurrency limiter.

### 3.1 Why inside the existing API rather than a separate process

A separate MCP process on the same 4-core box provides **no CPU isolation**; it removes the protection the shared queue provides. Routing ad-hoc SQL through the existing `chQueue` (concurrency 20, hard 429 past 200 queued) means a query storm degrades gracefully instead of starving the customer-facing dashboard. Reusing `runQuery` also inherits in-flight coalescing and timeout-retry-at-90s for free.

The accepted cost is blast radius: a defect in the MCP path can crash the Express app and take the dashboard with it. Mitigations: PM2 cluster mode runs 2 instances; the tool bodies delegate to the already-hardened `runQuery` rather than talking to ClickHouse directly; and the MCP route is additive, touching no existing handler.

Rejected alternatives: an off-the-shelf `mcp-clickhouse` server (third-party code with production DB access, no shared limiter, no Topmate schema guide, unaudited guard posture, on a box already at load 8); exposing `:8123` through Caddy (puts a raw, natively-unauthenticated DB port on the internet behind a single proxy rule); an SSH-tunnel sidecar from EKS (private key in a Kubernetes secret, `autossh` fragility, rotation burden).

## 4. The security boundary — and the trap that defines it

The authoritative boundary is a dedicated ClickHouse user, **not** the router's regex guard.

The non-obvious part, and the single most important detail in this document: **`readonly=1` is not sufficient.** It blocks writes and setting changes, but `SELECT * FROM url('http://169.254.169.254/latest/meta-data/')` is a *read* query. ClickHouse table functions are how a nominally read-only user achieves SSRF and arbitrary local file reads. A settings profile alone does not close this.

What closes it is the **absence of RBAC `SOURCES` privileges**:

```sql
CREATE SETTINGS PROFILE mcp_readonly_profile SETTINGS
    readonly          = 1,
    max_execution_time = 60,
    max_threads        = 2,
    max_result_rows    = 10000,
    max_result_bytes   = 33554432,   -- 32 MiB
    result_overflow_mode = 'break';

CREATE USER mcp_readonly IDENTIFIED WITH sha256_password BY '<generated>'
    SETTINGS PROFILE mcp_readonly_profile;

GRANT SELECT ON openpanel.*      TO mcp_readonly;
GRANT SELECT ON system.tables    TO mcp_readonly;   -- list_objects
GRANT SELECT ON system.columns   TO mcp_readonly;   -- get_object_details

-- Deliberately NOT granted: SOURCES and its children
-- (URL, FILE, S3, REMOTE, MYSQL, POSTGRES, HDFS, JDBC, ODBC).
-- Their absence is what blocks the table-function exfiltration path.
```

`result_overflow_mode = 'break'` is chosen over the default `throw` so an oversized result returns a truncated page rather than failing the whole investigation.

This mirrors the M3 philosophy exactly: the downstream enforces the real boundary (there, `--access-mode=restricted`; here, ClickHouse RBAC), and the router adds a cheap belt-and-braces check.

### 4.1 Prerequisite that must be verified, not assumed

OpenPanel ships ClickHouse in a container whose access control may be XML-driven. If **SQL-driven access control is not enabled** (`access_management = 1` on the bootstrap user), none of the DDL above will work, and this becomes a `users.d/` file change plus a container restart — a heavier, coordinated operation on a live CPU-bound box serving customer traffic.

The implementation plan must verify this **first** and treat the XML path as a distinct, explicitly-sequenced task. Deploy.sh-style `|| true` optimism is exactly how the `financial-prod` secrets silently went unprovisioned; do not repeat it here.

## 5. Router changes (`postgres-mcp`)

### 5.1 Registry — no code change needed

`domain_registry.py` already supports `token_env`, resolving it to `DomainEntry.token`, which `downstream_client` sends as `Authorization: Bearer …` on every transport connection. `transport="streamable_http"` already resolves the endpoint to `{base_url}/mcp`. So the domain is pure configuration:

```json
"analytics": {
  "base_url": "https://data.analytics.topmate.io",
  "transport": "streamable_http",
  "database": "openpanel",
  "token_env": "ANALYTICS_MCP_TOKEN"
}
```

`analytics` is the **first domain that genuinely requires a token.** The four existing proxy domains send none — they are reachable because the cluster pod CIDR sits inside each downstream's IP allowlist. That reasoning does not extend across the public internet to Hetzner. The token must be newly generated and distinct from the shared `985f21…` value, whose allowlist-bypass behaviour is a separately tracked issue.

### 5.2 `readonly_guard.py` — ClickHouse-aware denials

The proxy-path guard is a regex/keyword check, not `pglast` (which guards only the local `tm` pool). Most ClickHouse SQL therefore already passes. Two changes:

- Add `describe` to `_ALLOWED_FIRST` — ClickHouse's `DESCRIBE TABLE` is a legitimate read.
- Deny table-function and exfiltration forms that begin with `select` and so slip past the first-word check:
  - `\b(url|file|remote|remoteSecure|s3|hdfs|mysql|postgresql|jdbc|odbc)\s*\(`
  - `\binto\s+outfile\b`

Two coupled string changes that are easy to miss:

- The rejection message in `execute_sql` reads `only read-only (SELECT/WITH/EXPLAIN/SHOW) statements are allowed.` Admitting `DESCRIBE` makes that enumeration wrong. **Existing routing/discovery tests assert on exact message substrings** (a constraint already hit during M3's proxy-helper dedup), so grep the test suite before editing the string and update assertions in the same commit.
- The `domain` parameter's `Field(description=…)` on `execute_sql`, `list_objects` and `get_object_details` hardcodes the five current domain names. It is the text the model actually reads when choosing a domain, so `analytics` must be added there or the new domain stays effectively undiscoverable through the tool schema.

Applied to **all** domains. Harmless for Postgres (these are ClickHouse function names) and simpler than per-engine guard dispatch, which would add a branch with no current second consumer.

False-positive care, to be pinned by tests: `properties['url']` must pass (no open paren), and a column named `url` referenced without a call must pass. The `\s*\(` anchor is what distinguishes a call from a reference.

### 5.3 `domain_guide.py` — the runbook becomes the schema guide

Curated content, not a dump. What earns its place is what a caller gets *wrong* without it:

- The 4 ⭐ dashboard events vs 117 🌐 creator-attributed vs 530 🛠 app-telemetry (the last carry no `expert_id`, which silently breaks creator filters).
- `expert_id` / `service_id` are `MATERIALIZED` from `properties[…]` and bloom-indexed — filter on the column, not the map.
- **Always** bucket dates in a timezone: `toDate(created_at,'Asia/Calcutta')`. Comparing raw UTC produces off-by-one days.
- `countDistinct(device_id)` = unique visitors; `count(*)` = raw hits. Conflating them is the most common analytics error.
- Custom fields live in the `properties` Map, read as `properties['key']`.
- Prefer the pre-aggregated `expert_daily_views` MV for booking/payment counts.
- Cost discipline: add a `created_at` bound on large scans; append `SETTINGS max_threads=2` to heavy aggregations; run heavy queries one at a time.
- Top ~40 event types by volume, with counts, so the caller can pick real event names instead of guessing.

Source material: `topmate-analytics-runbook.md` and `topmate-analytics-events.csv` (652 rows). `CROSS_DOMAIN_NOTE` gating already keys off enabled-domain count and needs no change.

### 5.4 Bundled targeted fix: log the routed domain

The 2026-07-25 production audit found the structured audit line records `arg_keys` (parameter *names*) but never the **value** of `domain`. The router can therefore prove "person X ran `execute_sql` at time T" but not against which database — undercutting the M3 spec's §4.3 claim that the router's log is the authoritative per-caller record, since proxied calls share one downstream identity.

Adding a sixth domain — the first one outside Topmate's own infrastructure, crossing the public internet — makes that gap materially worse. `audit.py` gains an explicit `domain` field for `execute_sql` / `list_objects` / `get_object_details`. This is routing metadata, not sensitive payload like SQL text, so it does not widen what the log exposes.

## 6. Analytics-api changes (`topmate-analytics-api`)

Add `@modelcontextprotocol/sdk` and mount `StreamableHTTPServerTransport` at `POST /mcp` in **stateless JSON mode**, matching how the router already talks to the other four downstreams (`stateless_http=True, json_response=True`). Stateless is required: the router opens a session per cached client and must not depend on server-side session affinity behind Caddy.

Three tools, named to match what the router forwards **verbatim** — the router passes `tool_name` and `arguments` straight through, so names and argument keys are a hard contract:

| Tool | Arguments | Implementation |
|---|---|---|
| `execute_sql` | `{sql}` | `runQuery(sql)` as `mcp_readonly`; rows serialised to MCP text content |
| `list_objects` | `{schema_name, object_type}` | `SELECT name, engine FROM system.tables WHERE database = {schema_name}` |
| `get_object_details` | `{schema_name, object_name}` | `SELECT name, type FROM system.columns WHERE database = … AND table = …` |

Note `execute_sql` receives no `domain` key — the router strips it before forwarding.

A new `requireMcpToken` middleware sits alongside the existing `requireAuth` (expert-scoped, `x-access-token`) and `requireInternalKey` (`x-internal-key`). It reads a `Bearer` token and compares against `ANALYTICS_MCP_TOKEN` using a **constant-time** comparison. This is a third, higher trust tier: unlike `requireAuth`, it is not scoped to a single `expertId`, so it must not be reachable with an expert access token.

All three tools call `runQuery`, inheriting `chQueue`, coalescing and timeout retry. The ClickHouse user, not parameter binding, is the security boundary here.

One precise interaction to note: `runQuery` asserts that every `{name:Type}` placeholder in the query has a matching entry in `query_params`. Parameterless ad-hoc SQL trivially satisfies this (no placeholders, nothing missing). But a caller whose ClickHouse SQL legitimately contains `{…:…}` — ClickHouse's own query-parameter syntax — would be rejected with a `missing query_params` error rather than executed. That is an acceptable and documented limitation, not a bug: the fix is for the caller to inline the literal. It should be stated in the tool description so the error is self-explanatory.

## 7. Data flow and error handling

A successful call: router validates the domain → `readonly_guard` passes → `_call_downstream` reuses the per-domain cached MCP session → analytics-api authenticates the bearer, enqueues on `chQueue` → ClickHouse executes as `mcp_readonly` under the settings profile → rows return as MCP text content → router wraps and audits with `person` and `domain`.

| Failure | Surfaces as | Owner |
|---|---|---|
| Guard rejection | Existing bounded router message | Router |
| Unknown domain | Existing `unknown domain '<d>'. Valid domains: …` | Router |
| Missing/bad bearer | HTTP 401 from analytics-api → router collapses to `downstream 'analytics' unavailable (<ExceptionClass>)` | Both |
| ClickHouse timeout | Tool-level error inside a 200 response, not a connection failure | Downstream |
| Queue overflow | HTTP 429 `Analytics service busy` | Downstream |
| Result too large | Truncated page (`result_overflow_mode='break'`) + explicit truncation marker | Downstream |
| Hetzner unreachable / TLS failure | `downstream 'analytics' unavailable (<ExceptionClass>)` | Router |

The router's `_call_downstream` already bounds error text to the domain plus exception class name, never echoing raw exception text — which matters more here than for in-cluster domains, because the exception could otherwise carry the Hetzner hostname.

**Result-size bounding is required, not optional.** With 58.5M events, one careless `GROUP BY` on a high-cardinality column can return millions of rows and exhaust the caller's context window. Two independent bounds apply: `max_result_rows` / `max_result_bytes` server-side, and explicit truncation marking in the tool response so the caller knows the answer is partial rather than silently believing an incomplete result.

## 8. Two decisions worth recording

**No Redis caching of ad-hoc SQL.** Tempting on a CPU-bound box, but a stale answer during an investigation is worse than the CPU it saves — an operator iterating on a query would silently receive a previous result. In-flight coalescing already prevents duplicate *concurrent* work, which is where the real waste is. The curated dashboard endpoints keep their 1-hour cache; only `/mcp` opts out.

**No hard-enforced date filter.** The runbook mandates one by convention, but enforcement would reject legitimate queries against `system.tables`, small dimension tables, and the pre-aggregated `expert_daily_views` MV. The settings profile (`max_execution_time`, `max_threads=2`, `max_result_rows`) bounds the damage from an unbounded scan, and the schema guide instructs. Enforcement by guidance plus resource limits, not by rejection.

## 9. Testing

Mirroring M3's approach, with one correction.

- **Unit (`postgres-mcp`):** guard denials for each table-function form and `INTO OUTFILE`; guard *acceptance* of `properties['url']`, a bare `url` column reference, and `DESCRIBE TABLE`; registry resolution of `token_env` → `Authorization` header; audit line contains the `domain` value.
- **Unit (`topmate-analytics-api`):** `requireMcpToken` rejects missing/wrong/expert tokens; tool schemas match the router's forwarded argument keys; `execute_sql` delegates to `runQuery` (so the queue is not bypassed).
- **Live security verification — the one that actually matters:** confirm `SELECT * FROM url(…)` and `SELECT * FROM file(…)` are refused **by the ClickHouse user**, with the router-side regex temporarily out of the path. A regex-only pass proves nothing about the real boundary.
- **Smoke:** a new `tests/smoke/run_analytics_smoke.sh` with **correct** assertions — the existing `run_multidomain_smoke.sh` reports FAIL on healthy responses because its guard `! grep -qiE '"?error"?:'` matches `Error":` inside `"isError":false`. Assert HTTP 200 **and** `result.isError is false` **and** the parsed value, via `python3 -c` JSON parsing rather than `grep`. Neither existing smoke script is CI-gated, which is how that defect shipped; wire this one into `.github/workflows/build.yml`.

## 10. Rollout and rollback

Sequence, each step verified before the next: create the ClickHouse user and profile (after resolving §4.1) → generate the token and place it in `postgres-mcp-secrets` and the analytics-api environment → deploy the analytics-api `/mcp` route and verify it directly with `curl` → add the `analytics` registry entry to the router → run the analytics smoke → verify via real ingress with a person token.

Rollback is graduated: remove the `analytics` key from `DOMAIN_REGISTRY_JSON` (instant, router-side, leaves the other five domains untouched); or revert the analytics-api deploy; or `DROP USER mcp_readonly` as the hard stop.

Deploy the router change with `kubectl set env`, **not** `eks/deploy.sh`. The audit established that `deploy.sh`'s `__IMAGE_TAG__` placeholder substitution is dead code — the manifest hardcodes `:latest` — so a full run would regress the pinned SHA image tag. That defect is tracked separately and is a prerequisite for trusting `deploy.sh` again, not for this work.

## 11. Out of scope: the `loop` domain

Deferred to its own spec, because it shares nothing with this one but the registry entry shape.

Findings from the 2026-07-25 investigation, recorded so the next spec starts from fact:

- A loop MCP **already exists and is deployed**: `ryl-loop-mcp`, built from `ryl-agents-backend/mcp-servers/expert-concierge-mcp`, running on `mcp-beta-asg` under `/opt/mcp-beta` via docker compose, behind `internal-mcp-beta-alb:8081` (target group `mcp-beta-loop-tg`), in AWS account 072528252688 — the **same account** as the EKS cluster.
- It is nonetheless **unreachable from the router**: it and `ryl-beta-db` sit in `vpc-013addcaa78946089`; EKS is in `vpc-0662b8d5b8adf8b5b`; the only peering connection is `pcx-0a103f02c57a34458` (`vpc-0b95d4f237cad1b8c` ↔ EKS). The RYL VPC is not peered with EKS.
- It is also the **wrong shape**: it exposes product tools (`loops_client`, `profile`, `call_prep`, loop reads/creates), not SQL. `ryl-beta-db` is Postgres 16.13 on `db.t4g.medium`.

So `loop` needs a networking decision (peer the VPCs, or expose a loop data MCP over authenticated public HTTPS as `analytics` does) **and** a decision about whether to add a SQL surface to a product MCP or stand up a separate per-DB MCP inside the RYL VPC. Those are independent of everything above.
