# Topmate MCP Stack — Production-Readiness & Code-Quality Audit

**Date:** 2026-06-10
**Scope:** `postgres-mcp` (DB-admin MCP) + `topmate-db-mcp-server` (BI intelligence MCP), one EKS namespace `postgres-mcp`.
**Method:** Read-only static audit. Every claim verified against current code (`file:line`). 6 parallel dimension agents → adversarial verification of each Critical/High finding (35 findings, 8 confirmed Critical/High, 0 fully refuted, several severity-adjusted down by the verifier). Cross-checked by direct reads of the choke points (`server.py` × both, the middleware chains, `orchestrator.py`, `postgres_mcp_client.py`, `sql_scope_guard.py`, `cache_manager.py`, `ai/providers/base.py`, EKS manifests + HPA). **No live load probe was run** against prod (would add load to a single-replica server reading a prod RDS replica); scale is reasoned from code + manifests.

> Severities are shown as **auditor → verified** where the adversarial pass adjusted them. The headline number is the verified one. "Confidence" is the verifier's.

---

## 1. Executive summary

The stack is **functionally well-built** — a clean provider-agnostic AI layer, a real two-tier trust model, DB-layer read-only enforcement (`BEGIN TRANSACTION READ ONLY` + pglast AST allowlist on a physical replica), circuit breakers, Redis L2 cache, metrics, and a correctly-stateless BI tier. Async hygiene is mostly good: Athena/S3/Bedrock are correctly offloaded with `asyncio.to_thread`, psycopg is fully async, and most HTTP clients are `AsyncClient`.

But it is **architecturally bottlenecked and has two release-blocking security gaps**. All DB reads from every BI replica funnel through **one** `postgres-mcp` pod pinned to **1 replica / 0.5 vCPU / 15 DB connections**, which is simultaneously the throughput ceiling and a single point of failure. The rate limiter collapses every end user into a single Cloudflare-IP bucket at an effective **60 req/min**, and the operator's `RATE_LIMIT_MAX_REQUESTS=1000` knob is silently ignored (wrong env-var name for that service). There is no concurrency limiting in front of the LLM and no task queue for long operations. On security, the entire anti-impersonation guarantee rests on **one shared static `AUTH_TOKEN`**, and the per-creator SQL scope guard leaves `user_user` unscoped — a scoped expert can read every creator's PII (verified by executing the guard).

### Scale-readiness verdict

> ## ❌ **NOT READY** for "1000s of requests, 100s of concurrent users, sustained."
> Conditional-ready for the current low-volume / superadmin-led usage. The blockers are concentrated and fixable without a rewrite.

**Top 3 scale blockers**

1. **`postgres-mcp` single-replica funnel** (P0). `replicas: 1`, HPA `min=max=1`, CPU limit `500m`, psycopg pool `max_size=15`. Every BI DB read serializes here; the 16th concurrent read waits on a 10 s `PoolTimeout`. Scaling the BI tier does nothing. *Also a SPOF* (`karpenter.sh/do-not-disrupt` + PDB `minAvailable: 1` + live-DB readiness probe → load-induced self-eviction).
2. **Rate limiter is both too tight and misconfigured** (P0). Keyed on `CF-Connecting-IP` → all of Loop/Claude.ai = one bucket; default `60/min` (~3 req/s) because the deployment sets `RATE_LIMIT_MAX_REQUESTS` (a *postgres-mcp* env name) which `db-mcp` never reads. Legit traffic is 429'd far below any real ceiling; per-pod buckets are also inconsistent under HPA.
3. **No LLM backpressure + no task queue + per-pod state** (P1). The orchestrator fans out up to ~5 sequential LLM calls per request with zero semaphore; long ops (reports, multi-step LLM) run inline under a 25 s budget; rate buckets, token cache, creator-resolver cache, schema-RAG embeddings, and circuit breakers are all per-pod in-memory despite Redis being deployed.

**Top 2 security blockers (release-gating, independent of scale)**

- **`shared-auth-token-impersonation` — Critical.** One static `AUTH_TOKEN` (shared across postgres-mcp + db-mcp + CI + staging) is the *only* thing separating "Loop forwarding a real user" from "attacker fabricating `X-User-Scope: superadmin`." Any token holder reads every creator's data.
- **`scope-guard-user_user-leak` — Critical.** `scope_sql` filters only 3 data tables and leaves `user_user` unscoped; an expert-facing NL query that joins/cross-joins/sub-selects `user_user` returns all creators' PII. Verified by executing `scope_sql()` against current code.

---

## 2. Findings by dimension

### 2.1 Architecture, pipelines & data flow

**Request path — `postgres-mcp` (single replica, in-memory SSE sessions):**
```
db-mcp pod / ops → Cloudflare → ALB (/postgres-mcp/{sse,mcp})
  → RequestID → CORS → IPAllowlist(+AUTH_TOKEN Bearer bypass) → CallerIdentity
    → RateLimiter → HealthCheck(strip /postgres-mcp, set root_path) → SSEKeepAlive
      → route_by_transport ( /mcp* → streamable_http_app ; else → sse_app )
        → @mcp.tool (execute_sql, list_schemas, explain_query, analyze_db_health, …)
          → get_sql_driver() → SafeSqlDriver(restricted, timeout=30) → DbConnPool(max=15)
            → RDS read replica (BEGIN TRANSACTION READ ONLY + SET LOCAL statement_timeout)
```
**Request path — `topmate-db-mcp-server` (HPA 1-3, `stateless_http=True`, `json_response=True`):**
```
Claude.ai / Loop → Cloudflare → ALB (/db-mcp/mcp, /bi-mcp/mcp, /sse)
  → Metrics(/metrics no-auth) → IPAllowlist(IP | AUTH_TOKEN | OAuth-JWT | galactus-Token)
    → RateLimiter → HealthCheck(strip /db-mcp|/bi-mcp, webhooks) → OAuth → AcceptHeader
      → SSEKeepAlive → CallerIdentity(innermost; sets caller_ctx) → route_by_transport
        → 1 of 51 tools → is_unrestricted()/effective_creator_id() scope gate
          → orchestrator (NL→SQL) ── inter-MCP ──▶ postgres-mcp.execute_sql
          → Athena / S3 / GitHub / LLM provider
```
**NL→SQL pipeline** (`orchestrator.py`): live tools use the **fast** path (7 call-sites of `process_question_fast`, **0** of `process_question`): `gather(classify, generate_sql)` → `_fetch_data` (inter-MCP) → `_analyze`. `_generate_sql` does cache-lookup → SchemaRAG → LLM → strip fences → if `creator_id`: `scope_sql()` → cache-write. **Inter-MCP hop**: one `PostgresMCPClient` singleton per pod owns a single `ClientSession` whose lifecycle runs in an independent `asyncio.Task` (avoids anyio cancel-scope nesting); the MCP SDK multiplexes concurrent calls over the one stream by request-id (no client-side serialization).

| # | Finding | Severity | Conf. | Evidence | Fix shape |
|---|---|---|---|---|---|
| A1 | Orphaned duplicate db-mcp entrypoint in postgres-mcp repo: `db_mcp_main.py` (2-tool stub) + `Dockerfile.db-mcp-server` + the **`BearerTokenMiddleware`** class kept alive only by that import (never in the live chain, server.py:1340-1354 uses IPAllowlist's bypass). | **Medium** | High | `Dockerfile.db-mcp-server:43,67`; `server.py:734-784`; deploy.sh builds the *sibling* `Dockerfile` (deploy.sh:115-119) | Delete `Dockerfile.db-mcp-server`, `db_mcp_main.py`, and `BearerTokenMiddleware`. |
| A2 | Root-level stale stubs in db-mcp repo: `main.py`, `topmate_buisness_logic.py` (misspelled), `proxy.py` (dead Cloud Run URL), `cloud_run_mcp_client.py` (GCP, migrated to EKS). Not shipped (`Dockerfile` copies only `src/`). | **Medium** | High | `main.py:18`; `proxy.py:4`; pyproject console-script → `topmate_mcp.server:cli_main` | Delete the four root modules. |
| A3 | **Full orchestrator pipeline (clarifier + critic) is dead from the tool surface** — every NL query uses the fast path; `process_question`/Clarifier/CriticEngine have 0 tool call-sites. "Agentic clarification" (advertised, server.py:10) is effectively disabled. | **Low** | Medium | `orchestrator.py:98` vs `:221`; grep `.process_question(` = 0, `.process_question_fast(` = 7 | Wire ≥1 tool to `process_question`, or delete the dead branch. |
| A4 | Inter-MCP transport drift: code default `streamable_http` vs manifest `POSTGRES_MCP_TRANSPORT=sse` vs `--transport` CLI flags that don't actually gate which apps mount. The `--transport` flag is cosmetic (both transports always served). | **Low** | High | `config.py:51`; `deployment-db-mcp-server.yaml:55-56`; `postgres_mcp_client.py:38` | Pick one transport intentionally; make `--transport` gate app construction or document it. |
| A5 | Dead duplicate `if "duplicate" in e_lower:` branch in postgres-mcp `_sanitize_error` (second copy unreachable). | **Low** | High | `server.py:108` & `:115` | Remove the second block. |

*Refuted (avoided false positives):* `artifacts.py` and `topmate_business_logic.py` are **live** (imported + used by tools); the 51-tool count is correct (the `server.py:4` "38 tools / 8 categories" docstring is stale).

### 2.2 Python best practices — async correctness (priority)

**The only confirmed event-loop-blocking site is the sync galactus call, present in *both* repos.** Everything else suspected (pyathena, boto3/S3, Bedrock, psycopg, redis, vertex/github/logic-hub clients) is correctly async or `to_thread`-offloaded — explicitly verified and **not** filed, to avoid false positives.

| # | Finding | Severity | Conf. | Evidence | Fix shape |
|---|---|---|---|---|---|
| P1 | **SYNC `httpx.get(..., timeout=8.0)` on the event loop** inside db-mcp's `CallerIdentityMiddleware`. `validate_token` (sync) is called inline from `async __call__` with no offload → up to **8 s full-loop stall per uncached Tier-2 token**, freezing all concurrent requests on the pod. | **Critical → High** | High | `middleware/caller_identity.py:68` (call) ← `:144` ← `__call__ :270/:282` | `async def validate_token` + `httpx.AsyncClient`, or `await asyncio.to_thread(httpx.get, …)`; drop timeout to 2-3 s. |
| P2 | **Same sync `httpx.get` in postgres-mcp** `caller_identity.py:82`, wired from `CallerIdentityMiddleware.__call__` (server.py:1020-1037). Single replica → stalls the *only* instance incl. all SSE streams + inbound inter-MCP calls. | **High** | High | `caller_identity.py:82`; `server.py:1032-1037` | Same fix; share one async impl between the repos (see DRY #2). |
| P3 | Fire-and-forget `asyncio.create_task(...)` **without storing references** (GC can cancel mid-flight → silently dropped webhook/index events). | **Medium** | High | `webhooks/github_webhook.py:117,152,161` (contrast `codebase_index.py:155` which stores+cancels) | `self._bg = set(); t=create_task(...); self._bg.add(t); t.add_done_callback(self._bg.discard)`. |
| P4 | Broad `except Exception` density (222 sites); a few fully silent: `postgres_mcp_client.py:116 except Exception: pass` (hides transport-close errors), `github_webhook.py:171 logger.debug` (drops index triggers invisibly in prod). | **Low** | Medium | as cited | Log teardown errors at debug w/ exc; raise webhook-index failures to `warning`; narrow business-logic excepts. |

**Reachability note (both sync-httpx):** the dominant production path is Loop's *trusted-gateway* (`Bearer AUTH_TOKEN`), which short-circuits **before** `validate_token`. The stall fires only on the Tier-2 untrusted `Authorization: Token <x>` path on a 300 s-TTL cache miss — latent for steady-state Loop traffic, but a live per-pod DoS for any direct end-user-token caller or whenever galactus latency spikes.

### 2.3 Guard rails (security & safety)

**Trust model (as built):** Tier-1 "trusted transport" = `Bearer <AUTH_TOKEN>` or a `SUPERADMIN_TOKENS` credential → forwarded `X-User-*` headers trusted **verbatim** incl. `superadmin`/any username. Tier-2 "untrusted" = `Authorization: Token <knox>` galactus-validated, non-superadmin forced to its own username (real anti-impersonation). No header = legacy passthrough. Scope enforcement lives **entirely** in db-mcp; the inter-MCP client forwards **no** auth/identity downstream, so postgres-mcp executes whatever SQL db-mcp builds.

| # | Finding | Severity | Conf. | Evidence | Fix shape |
|---|---|---|---|---|---|
| G1 | **Shared static `AUTH_TOKEN` is the entire anti-impersonation boundary.** Any holder (CI, staging EC2 per manifest comment, ops, or a leak) sends `X-User-Scope: superadmin` (or `expert` + `X-User-Username: <victim>`) → full cross-creator exfiltration + privilege escalation. Same token also bypasses the IP allowlist. No per-request identity signature. | **Critical** | High | `middleware/caller_identity.py:103-104,130-137`; `deployment-postgres-mcp.yaml:69-75`; `deployment-db-mcp-server.yaml:197-202`; `server.py:942-951,961` | Require a **Loop-signed JWT** (RS256) over `(scope,username,email,exp,aud)`; `is_transport_trusted` returns true only on valid sig whose claims **must equal** the X-User-* headers (or derive identity from claims). Rotate + least-privilege the shared token. |
| G2 | **`sql_scope_guard` leaves `user_user` unscoped.** `scope_sql` only AND-injects `creator_col = expert_id` into scopes referencing the 3 data tables and passes as long as `touched ≥ 1` — so a join / cross-join / CTE / scalar-subquery against `user_user` returns **all** creators' PII. **Verified by executing `scope_sql(sql, 42)`** on current code: `SELECT u.* FROM user_user u CROSS JOIN booking_booking b` → only `b` constrained; scalar `(SELECT email FROM user_user WHERE id=99)` untouched. Reachable via expert-marked `ask_topmate_bi` free text. | **Critical** | High | `sql_scope_guard.py:11-13,29-33,63-75`; `tools/intelligence/__init__.py:109,136-137`; `orchestrator.py:490-494,521` | Fail-closed: reject any query referencing a non-scopable row-bearing table that isn't itself constrained to the caller; only allow `user_user` joined on `user_user.id = <scoped>.<creator_col>`; forbid literal-id subqueries over `user_user`. Prefer a vetted query-shape allowlist over free LLM SQL + AST patching. |
| G3 | Forwarded `X-User-*` identity is **unsigned**; one transport decision fully determines authz (no defense-in-depth). Superadmin grantable by header alone on the trusted path. | **High → Medium** | High | `caller_identity.py:152-163` | Folds into G1's signed-JWT fix. |
| G4 | **OAuth "Claude.ai workaround" token reuse** *(auditor's own finding, verified)*: a credential-less request from a non-allowlisted IP is authorized with the **most-recently-issued OAuth token across all clients** (`get_latest_token()`), then — with no `X-User-Scope` — is treated as legacy/unrestricted admin. 5-min window after any OAuth flow. | **Medium** | High | `ip_allowlist.py:251-262`; `token_cache.py:35-42` | Bind cached token to the issuing `client_id` (require a client hint), shorten TTL, or remove once Claude.ai issue #2157 is resolved. |
| G5 | db-mcp error sanitizer passes short raw DB errors verbatim (`<200 chars, no newline`) → table/column enumeration via error oracle. | **Low** | High | `types.py _sanitize_error_for_user`; callers `analytics:299`, `intelligence:162` | Map SQLSTATE → generic message; log detail server-side; whitelist tool-produced strings only. |
| G6 | `_FORBIDDEN_SQL` keyword regex is bypassable (MERGE/DO/CALL/stacked `;`/CTE-writes) **but** only guards the superadmin-only `sql_override`, and SafeSqlDriver's pglast AST allowlist + read-only txn is the real boundary downstream. | **Low** | High | `data_query/__init__.py:23-26,46,54`; `safe_sql.py` allowlist | Remove the redundant regex or replace with the same pglast parse; don't rely on keyword matching. |
| G7 | `CreatorResolver` inlines the username into SQL (`f"… username = '{username}'"`); safe **today** only because `_USERNAME_RE` excludes quote/backslash — brittle, one regex away from injection on an unscoped query. | **Low** | Medium | `creator_resolver.py:20,57,64-66` | Pass a bound parameter instead of interpolating. |

*Confirmed-safe (refuted):* read-only enforcement is real (`--access-mode=restricted` + `BEGIN TRANSACTION READ ONLY` + pglast allowlist on a read replica); `scope_sql` **correctly** handles UNION-of-scopable-arms, CTE inner refs, aliased subqueries, and `WHERE 1=1 OR …` (top-level AND); Tier-2 anti-impersonation works; the "12 marked scoped tools" coverage is consistent.

### 2.4 Concurrency, throughput & scale

| # | Finding | Severity | Conf. | Evidence | Fix shape |
|---|---|---|---|---|---|
| S1 | **`postgres-mcp` single-replica funnel = system throughput ceiling + SPOF.** All BI reads serialize onto one 0.5-vCPU loop / 15-conn pool; 16th read waits 10 s then errors. | **Critical → High** | High | `deployment-postgres-mcp.yaml:13,100-102`; `hpa-postgres-mcp.yaml:15-16`; `sql_driver.py:91-93`; `server.py:52` singleton | Add `stateless_http=True` to `FastMCP("postgres-mcp")` (server.py:46 — **currently stateful**), repoint db-mcp to `/mcp` streamable, raise `maxReplicas` 3-5 + CPU; raise pool `max_size` after checking RDS `max_connections`. |
| S2 | **No semaphore/backpressure before the LLM.** Up to ~5 sequential LLM calls/request, ×3 retries, 25 s budget, zero concurrency cap → provider 429 amplification + breaker flap (per-pod) under load. | **Critical → High** | High | `orchestrator.py:96,173,189-192,206,212`; `ai/providers/base.py:49-54`; grep: 0 `Semaphore` in `ai/` | Module-level `asyncio.Semaphore(8-16)` around `generate`/`embed`; fast-fail 429 on queue overflow; optional Redis token-bucket for cross-pod provider awareness. |
| S3 | **Rate limiter: shared CF-IP bucket + ignored env var.** Keyed on `CF-Connecting-IP` → all users = one bucket; effective **60/min** because the deployment's `RATE_LIMIT_MAX_REQUESTS=1000` is a *postgres-mcp* env name db-mcp never reads. Per-pod buckets also inconsistent under HPA. | **High** | High | `rate_limiter.py:56,63-68,99-101`; `config.py:162`; `deployment-db-mcp-server.yaml:43-46` vs `postgres-mcp/server.py:1348-1349` | Rename env → `RATE_LIMIT_PER_MINUTE`; key on forwarded end-user identity; Redis `INCR`+`EXPIRE` for a global limit. |
| S4 | **Per-pod in-memory state bypasses Redis:** schema-RAG embeddings (`_refreshing` is a per-process bool, no single-flight), creator-resolver cache, OAuth token cache. Under HPA: per-pod re-embed, duplicate resolves, cross-pod token invisibility → intermittent 401s. | **High → Medium** | High | `schema_rag.py:34-35,38,42-44,72-78`; `creator_resolver.py:22-23`; `token_cache.py:23` | Route through `CacheManager` L2; add a Redis single-flight lock for schema refresh. |
| S5 | **No task queue / background worker.** Long ops (multi-LLM analysis, reportlab PDF `doc.build` reports/__init__.py:251, multi-step pipelines) run inline under 25 s. Cosine/embedding math is sync on the loop (`schema_rag.py:248-259`). | **High → Medium** | High | grep: no celery/taskiq/rq/sqs; `orchestrator.py:96,129,251` | Async-job pattern (enqueue on existing Redis via taskiq/RQ or SQS → job-id → poll/result tool) for ops > 5 s; `to_thread` the CPU math + PDF build. |
| S6 | **Health probe self-DoS.** Readiness does a live pooled `SELECT 1` every 10 s; under pool saturation it queues past the 5 s probe timeout → 503 → the *single* pod flips NotReady (PDB `minAvailable:1`) → Service loses all endpoints exactly when busiest. | **Medium** | High | `deployment-postgres-mcp.yaml:111-118`; `server.py:1180-1181`; `pdb-postgres-mcp.yaml:9` | Cheap readiness (pool-state, not a live conn each probe) or a reserved health connection; structurally fixed by S1. |
| S7 | **Inter-MCP session reset thundering herd.** A transient error on any one `call_tool` calls `disconnect()`, nulling the **shared** session other in-flight calls use → they fail + race to reconnect against the degraded single replica. | **Medium** | Medium | `postgres_mcp_client.py:39,136-139,184-193` | Don't tear down the shared session per-call; retry the individual call, or use a small session pool. |

*Refuted:* the inter-MCP client does **not** head-of-line-block (SDK multiplexes by request-id, `call_tool` holds no lock); db-mcp is **not** stuck stateful (`stateless_http=True` is correct for its HPA). *Uncertainty:* the "~100-150 reads/s, ~15 concurrent" figures are reasoned estimates (only the 15-conn cap is code-proven); RDS `max_connections` not read from code — validate before raising `max_size`.

### 2.5 MCP best practices

| Aspect | postgres-mcp (11 tools) | db-mcp (51 tools) | Contract |
|---|---|---|---|
| name/description | ✅ all | ✅ all | met |
| per-param `Field(description=...)` | 13 present | **0** | partially met |
| inputSchema constraints (`Literal`/enum) | 2 only | **0** | permissive but un-hinted |
| `annotations.readOnlyHint` | **0** | 12/51 | reads MUST set it |
| `_meta` input field + `additionalProperties:true` | ❌ (Pydantic default) | ❌ | unmet, mitigated |
| error semantics | in-band `"Error: …"` text | in-band text (168 sites) | no `isError` anywhere |
| protocolVersion pin | ❌ SDK-negotiated | ❌ | readiness item |

| # | Finding | Severity | Conf. | Evidence |
|---|---|---|---|---|
| M1 | All tool errors are in-band `"Error: …"` text, never JSON-RPC `isError`/`McpError` — callers can't programmatically distinguish success from failure; retries keyed on protocol errors never fire. | **Medium** | High | `server.py:122-124`; `types.py:106-108`; 168 call sites; 0 `isError`/`McpError` in src |
| M2 | 39/51 db-mcp read-only tools omit `readOnlyHint` → Loop's adapter maps missing hint to `RiskTier.REVERSIBLE` and needlessly soft-confirm-gates every read (raw SQL, git browse, reports, schema guides). `readOnlyHint` (risk) is orthogonal to `loop/minScope` (scope). | **Medium** | High | grep: 12/51 set; `ryl-base-platform/.../mcp_adapter.py:48-53` |
| M3 | postgres-mcp sets `readOnlyHint` on **zero** tools despite being read-only/restricted → all 11 tools gated when registered directly with Loop. | **Medium** | High | `server.py` 11 `@mcp.tool` + dynamic `execute_sql:1264`; no `ToolAnnotations` |
| M4 | db-mcp inputSchemas fully unconstrained (bare `str`/`int`, no `Literal`/`Field`); model must infer valid enum values from prose → invalid args fail only at runtime. | **Medium** | High | `analytics:237-241`, `intelligence:168-171`; grep 0 `Literal`/`Field` |
| M5 | No tool declares `additionalProperties:true` + a top-level `_meta` field (contract-required for injected locale/UA). Mitigated: FastMCP's arg model is `extra='ignore'`, so injected `_meta` is dropped, not rejected. | **Low** | High | contract §4/§10; `func_metadata.py:64-66` |
| M6 | Neither server pins `protocolVersion '2024-11-05'`; relies on SDK-default negotiation (newer SDK defaults differ). | **Low** | Medium | grep: no version string in either src |

*Refuted:* JSON-RPC **batch** handling is the SDK transport's job (and removed in the 2025-06-18 spec) — no app-level defect; both transport choices (stateful-single-replica SSE vs stateless HPA) are sound; missing `readOnlyHint` on the 39 is partly *intentional* scoping but still wrong on the orthogonal risk axis.

### 2.6 DRY / shared adapters

The audit confirmed **5 real duplication clusters**, including one security primitive that has **already drifted**. (Several suspected dups were refuted: `_safe_int`/`_safe_str` are single-definition; `format_error_response`/`_tool_cache_key` are already centralized; postgres-mcp has *no* per-tool inline admin guard — it uses a global AccessMode + factory.)

| # | Duplication | Count | Severity | Single shared thing to introduce |
|---|---|---|---|---|
| D1 | `_FORBIDDEN_SQL` write-statement regex — **already drifted** (`athena_client` missing `EXEC\|EXECUTE\|COPY`). | 5 copies | **High → Medium** | `topmate_mcp/security/sql_guard.py` → one `FORBIDDEN_SQL` + `is_write(sql)`; all 5 import it. |
| D2 | `caller_identity` trust-model core (`resolve_identity`, `is_transport_trusted`, `validate_token`, `parse_auth`, constants) **byte-identical across both repos** (only galactus-URL source differs). | 2 repos | **High → Medium** | Extract to an installable `topmate-mcp-identity` package; inject `galactus_url`; each repo keeps only its thin middleware + helpers. *(Also fixes P1/P2 once.)* |
| D3 | ASGI path-prefix stripping (`_get_path`/`_strip_prefix`) with **divergent prefix lists** (`/postgres-mcp,/db-mcp,/instagram-mcp` vs `/bi-mcp,/db-mcp`; one db-mcp copy strips only `/bi-mcp`). | 12+ copies | **High → Medium** | `asgi_utils.strip_known_prefix(path, PREFIXES)` + one `PREFIXES` constant per service (or a `BaseASGIMiddleware`). |
| D4 | Client-IP extraction (`CF-Connecting-IP > XFF[0] > scope`) — the load-bearing "XFF[0] not [-1]" rule. | 4 copies | **High → Medium** | `asgi_utils.client_ip(scope)`; one fallback sentinel. |
| D5 | Inline `if not is_unrestricted(): return format_error_response("…superadmin only.")` + `except PermissionError → format_error_response`. An **unused** `require_admin()` already exists but raises instead of returning the MCP envelope. | 21 + 9 | **Medium** | `@admin_only` decorator wrapping the tool coroutine; decorate the 21, delete the inline checks + the 9 except-blocks. |

---

## 3. Scale model

**Topology.** db-mcp: HPA 1-3 @ 70 % CPU, limit 1000m/1Gi, stateless `/mcp` — *can* scale. postgres-mcp: `replicas:1`, HPA `min=max=1`, limit **500m**/512Mi, stateful in-memory SSE. **Every** db-mcp DB read (from all replicas) → one `PostgresMCPClient` singleton/pod → the single postgres-mcp replica → `DbConnPool(min=2, max=15)` → RDS read replica.

**Where it binds, in order:**
1. **postgres-mcp core** — one event loop on 0.5 vCPU, 15 concurrent statements max; the 16th waits 10 s (`PoolTimeout`) then errors. Code-proven cap: **15 concurrent DB reads platform-wide**. (Throughput estimate ~100-150 reads/s is *reasoned, not measured*.) 100s of users × 1-3 reads = 200-600 concurrent → 10-40× over the cap. **Scaling db-mcp does not help.**
2. **Rate limiter** — effective **60 req/min per pod** on a single shared CF-IP bucket (the `1000` knob is ignored) → ~3 req/s aggregate. This is the *first* wall a real multi-user load hits, **before** the DB or LLM ceiling.
3. **LLM fan-out** — no semaphore; under load → provider 429s + per-pod breaker flap, every request burning up to 25 s.
4. **Per-pod state** — limiter/token/creator/schema caches + breakers don't survive HPA → inconsistent limits, cold-start re-embed, cross-pod 401s.

**Minimal changes to reach the target** (1000s req / 100s users):
- **A.** postgres-mcp: `stateless_http=True` (server.py:46) → scale `maxReplicas` 3-5, raise CPU to ~1-2 vCPU; behind a stateless ALB target group. *(Stateful `/mcp` today; must flip the flag or add a shared session store first.)*
- **B.** psycopg pool `min=5, max=30-40` per replica — **validate against RDS `max_connections`** (N replicas × max must fit).
- **C.** Rate limiter → Redis `INCR`+`EXPIRE`, keyed on end-user identity; fix the env-var name.
- **D.** `asyncio.Semaphore` + fast-fail 429 in front of the LLM.
- **E.** Move per-pod caches into the Redis `CacheManager`; add a single-flight refresh lock.
- **F.** Task queue (taskiq/RQ on existing Redis, or SQS) for ops > 5 s with job-id + poll/result tool.

---

## 4. Prioritized remediation roadmap

### P0 — release-gating (do before any volume / external exposure)
| Item | Findings | Effort |
|---|---|---|
| Replace shared-token trust with a **Loop-signed JWT** over X-User claims; rotate + least-privilege the static token | G1, G3 | M (2-3 d, needs Loop-side signing) |
| **Fail-closed `sql_scope_guard`** (reject unscopable row-bearing tables / `user_user` leaks) + add regression tests for the verified exploit shapes | G2 | S-M (1-2 d) |
| Make `validate_token` **async / offloaded** (kills the 8 s loop stall) — do it once in the shared identity package | P1, P2, D2 | S (0.5 d) |
| **Scale postgres-mcp**: `stateless_http=True`, raise replicas + CPU, raise pool `max_size` (vs RDS), cheap readiness probe | S1, S6 | M (1-2 d + load test) |
| **Fix the rate limiter**: correct env var, end-user-keyed, Redis-backed | S3 | S-M (1 d) |

### P1 — scale & resilience (before sustained 100s-users load)
| Item | Findings | Effort |
|---|---|---|
| `Semaphore` + 429 backpressure in front of the LLM | S2 | S (0.5 d) |
| Move per-pod caches to Redis + single-flight schema refresh | S4 | M (1-2 d) |
| Task queue for long ops + `to_thread` the CPU/PDF work | S5 | M-L (3-5 d) |
| Scope the OAuth `get_latest_token` workaround (bind to client_id / TTL) | G4 | S (0.5 d) |
| Inter-MCP: stop tearing down the shared session per transient error | S7 | S (0.5 d) |

### P2 — hardening & hygiene
| Item | Findings | Effort |
|---|---|---|
| DRY consolidations D1, D3, D4, D5 (shared `sql_guard`, `asgi_utils`, `@admin_only`) | D1,D3,D4,D5 | M (2-3 d) |
| MCP contract: add `readOnlyHint` to all reads, `isError` for failures, `Literal`/`Field` on enumerable params, `_meta`/protocol pin | M1-M6 | M (1-2 d) |
| Delete dead code (A1, A2, A3, A5); store webhook task refs (P3); sanitize raw DB errors (G5); parameterize CreatorResolver (G7); narrow silent excepts (P4) | A1-A5,P3,P4,G5,G7 | S-M (1-2 d) |

---

## 5. DRY consolidation list (each duplication → the one shared thing)

1. **`topmate_mcp/security/sql_guard.py`** — one `FORBIDDEN_SQL` regex + `is_write()`/`assert_select_only()`. Replaces 5 copies; closes the athena drift. *(D1)*
2. **`topmate-mcp-identity` package** — the pure trust-model core (`resolve_identity`, `is_transport_trusted`, `parse_auth`, `validate_token`, constants), `galactus_url` injected; consumed by both images. Replaces ~120 LOC duplicated across repos and makes the async-validate fix land once. *(D2, P1, P2)*
3. **`asgi_utils.strip_known_prefix(path, PREFIXES)`** + one `PREFIXES` constant per service (or a `BaseASGIMiddleware._path`). Replaces 12+ hand-rolled prefix loops with divergent lists. *(D3)*
4. **`asgi_utils.client_ip(scope)`** — canonical `CF > XFF[0] > scope` precedence, one fallback sentinel. Replaces 4 copies. *(D4)*
5. **`@admin_only` decorator** (in the identity helpers) returning the MCP error envelope — replaces 21 inline guards + folds the 9 `except PermissionError` blocks; retires the unused `require_admin()`. *(D5)*

---

## 6. Method, confidence & honesty notes

- **No live load probe** was run (read-only audit; avoid loading a single-replica prod funnel). Throughput numbers in §3 are reasoned from `max_size=15`, 0.5 vCPU, and typical indexed-read latency — only the 15-concurrent cap is code-proven. Validate RDS `max_connections` headroom before raising the pool.
- **Adversarial verification** downgraded several auditor severities (Critical→High on S1/S2/P1; High→Medium on D1-D4/G3/S4/S5) — those reflect real mitigations (read-only txn, breaker, 25 s bound, HPA, TTLs). **No finding was fully refuted**; the two security Criticals (G1, G2) survived verification at Critical, and G2 was confirmed by *executing* the guard.
- **Confirmed-safe** (refuting common suspicions): Athena/S3/Bedrock/psycopg/redis are correctly async/offloaded; read-only is DB-enforced; `scope_sql` handles the WHERE/UNION/CTE-of-scopable-arms classes correctly; Tier-2 anti-impersonation works.
- **Live-infra verification** (running pods, actual CPU/mem allocation, HPA status, RDS instance class/`max_connections`) is a follow-up — tracked separately in the handoff doc; this report reflects the manifests in `eks/manifests/base/` as of 2026-06-10, not necessarily the live cluster state.
