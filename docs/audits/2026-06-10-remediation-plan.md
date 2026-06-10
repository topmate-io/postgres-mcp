# MCP Stack Remediation — Execution Plan (2026-06-10)

Source audit: `docs/audits/2026-06-10-mcp-stack-audit.md` + handoff `~/Downloads/topmate-mcp-infra-handoff-2026-06-10.md`.
Grounded per-finding specs (workflow wf_badb1c3b-4d1): `/tmp/mcp-specs/spec_00..09.json`.

**Scope:** ALL findings (P0+P1+P2), both repos. **Verify:** pytest per chunk + local Docker smoke per batch. **No prod deploy.**
**Repos:** `postgres-mcp` (PG, `/Users/dharsankumar/Documents/GitHub/postgres-mcp`) · `topmate-db-mcp-server` (DB, `/Users/dharsankumar/Documents/GitHub/topmate-db-mcp-server`). Branch `feat/caller-scoped-access` in both.
**Baseline (pre-change):** DB 127 passed · PG unit 187 passed + 4 pre-existing testcontainer failures in `tests/unit/explain/test_explain_plan*` (unrelated, ignore).

## PROGRESS (loop state)
**Done + green (DB suite now 176 passed), UNCOMMITTED pending LOOP key:**
- ✅ G2 fail-closed scope guard (`ai/sql_scope_guard.py` + 15 new tests; exploit confirmed closed)
- ✅ A2 deleted 4 dead root modules + fixed claude_desktop_config/README refs
- ✅ D1 new `security/sql_guard.py` (parse-based `is_write`) replacing 5 `_FORBIDDEN_SQL` copies (athena drift fixed) + `tests/test_sql_guard.py` (22)
- ✅ G6 `data_query` sql_override uses `is_write` (parse-based, catches MERGE/DO/CALL/CTE/stacked)
- ✅ G7 CreatorResolver single-quote escape + defensive test
- ✅ G5 error-oracle fix (`types.py`: Exception always sanitized incl. schema-leak/SQLSTATE patterns; tool-authored str verbatim) + 26 broad-`except` callers switched `str(e)`→`e` (9 `except PermissionError` kept verbatim) + `tests/test_error_semantics.py` (11)
- ✅ M1 isError (`format_error_response`→`CallToolResult(isError=True)`). **SPEC CORRECTION:** mcp≥1.26 validates a returned CallToolResult's `structuredContent` against the tool's output_model (all `-> ResponseType` tools have one = `{"result": list}`), so `structuredContent` MUST be populated, not None — set to mirror the error content. Verified via integration test `test_at3_raw_tool_denied_for_expert`.
- ✅ M2 readOnlyHint on 48/51 tools (3 S3-writers=False, 0 unannotated) — verified via register_all_tools+list_tools; +2 `test_tools_meta.py` assertions
- ✅ M4 Literal/Field on analytics (get_business_metrics/analyze_trends/compare_periods/analyze_funnel/cohort_analysis) + intelligence (summarize_data/detect_anomalies/forecast_metric). **SPEC CORRECTION:** used `Annotated[Literal[...], Field(...)] = default` (NOT `= Field(default=...)`, which would set the runtime default to a FieldInfo and break direct fn calls). Shared `_MetricLit` constant. +7 `tests/test_param_schemas.py`.
**DB suite now 185 passed.**
**Next:** M5 (no-op doc) + M6 (pin mcp `<2.0.0`) → D5 (@admin_only) → D3/D4 (asgi_utils) → A3 (dead pipeline) → P3/P4. Then Batch 3 (scale), Batch 4 (identity core), Batch 5 (PG), Batch 6 (docker rig).
**Commit plan when keyed:** per-finding commits via selective `git add` (file sets are disjoint). Files staged-ready listed by `git status` in db-mcp.

## Canonical cross-spec decisions (unify the two repos' G1 specs)
- **Signed-identity header:** `X-Identity-JWT` (dedicated header; Authorization keeps shared AUTH_TOKEN/galactus token).
- **Env (both repos):** `REQUIRE_SIGNED_IDENTITY` (default `false`), `IDENTITY_JWT_PUBLIC_KEY` (PEM), `IDENTITY_JWT_PUBLIC_KEY_PATH`, `IDENTITY_JWT_AUDIENCE` (default `topmate-mcp`), leeway 60s.
- **Claims:** `scope, username, email, aud, exp, iat`; alg RS256 (pinned).
- **G3 policy on header/claim mismatch:** Option A — derive identity from claims AND reject (INVALID) if a *present* header disagrees.
- **Secret key (AWS):** `topmate-bi-secrets` key `identity-jwt-public-key` (optional).
- **D2 shared core:** vendored byte-identical `_identity_core.py` in both repos (NOT a pip package); the P1/P2 async fix + JWT verify land there once. Sync byte-identity guarded by a sha256 check.
- **Docker rig:** `postgres-mcp/docker-compose.test.yml` (redis + throwaway postgres:16 seeded + both MCPs + optional galactus-mock). Never point at prod replica.
- **Jira key:** _PENDING — see top-of-loop question._

## Dependency-ordered batches (each = independently committable + testable)

### Batch 1 — DB G2 fail-closed scope guard  ✅/⬜  [spec_00]
- [ ] G2 rewrite `scope_sql` (sqlglot traverse_scope, `_PII_JOIN_KEY`, `_pii_join_keyed`) + tests (7 reject / 6 pass + funnel regression). **#1 Critical, no deps.**

### Batch 2 — DB low-risk hygiene + MCP best-practices  [spec_05, spec_06]
- [ ] A2 delete dead root modules (main.py, topmate_buisness_logic.py, proxy.py, cloud_run_mcp_client.py) + doc refs
- [ ] D1 new `security/sql_guard.py` (FORBIDDEN_SQL + is_write) → replace 5 copies (athena drift fix) ; G6 use is_write for sql_override
- [ ] G7 quote-escape username in CreatorResolver
- [ ] G5 error-oracle fix (types.py: Exception→sanitize, str→safe) + M1 isError (format_error_response→CallToolResult)
- [ ] M2 readOnlyHint on ~30 read tools (3 S3-writers = false)
- [ ] M4 Literal/Field on analytics+intelligence enum params
- [ ] M5 no-op (doc _meta via Context) ; M6 pin mcp `<2.0.0` + handshake test
- [ ] D5 `@admin_only` decorator (20 gates) + `resolve_scope_or_error` (9 except-blocks); retire require_admin
- [ ] D3 `asgi_utils.strip_known_prefix` (7 copies, fixes auth.py /bi-mcp-only) ; D4 `asgi_utils.client_ip` (3 copies)
- [ ] A3 delete dead full pipeline (process_question + Clarifier/CriticEngine + enable_clarification)
- [ ] P3 webhook bg-task refs ; P4 observable logging (postgres_mcp_client teardown, webhook index-trigger warning)

### Batch 3 — DB scale/resilience  [spec_02 S7, spec_03, spec_04]
- [ ] S3 rate limiter: AliasChoices env, identity-keyed, Redis INCR (redis_backend.incr_with_expire) ; G4 token_cache client-bind + TTL90 + kill-switch
- [ ] S2 LLM semaphore at retry_llm_call chokepoint + 429 fast-fail + backpressure→friendly response
- [ ] S5 to_thread cosine scoring + reportlab/openpyxl ; design doc async-job-queue.md
- [ ] S4 Redis L2 for schema-RAG (asyncio.Lock + Redis single-flight), creator-resolver, token_cache ; acquire_lock/release_lock  (depends G1 for token_cache decision)
- [ ] S7 inter-MCP `_ensure_session` single-flight, stop per-call disconnect

### Batch 4 — Identity core (D2 + P1 + P2 + G1 + G3) BOTH repos  [spec_01, spec_02 P1, spec_07, spec_09 D2]
- [ ] Build canonical `_identity_core.py` (pure fns + async validate_token + verify_signed_identity + resolve_identity require_signed branch)
- [ ] Vendor byte-identical into PG (`src/postgres_mcp/_identity_core.py`) + DB (`src/topmate_mcp/middleware/_identity_core.py`) + sha256 guard test
- [ ] Wire DB middleware (await async validate, signed_claims, REQUIRE_SIGNED_IDENTITY) ; keep db-mcp-only helpers
- [ ] Wire PG middleware (server.py CallerIdentityMiddleware) + await resolve_identity
- [ ] P1 DB ip_allowlist async `_has_valid_token` ; P2 PG async ; timeouts 8→2.5/3s
- [ ] Manifests: REQUIRE_SIGNED_IDENTITY=false + IDENTITY_JWT_* env (both deployments)
- [ ] Contract doc `docs/LOOP_SIGNED_IDENTITY_CONTRACT.md`

### Batch 5 — PG dead code + scale + manifests  [spec_07, spec_08]
- [ ] A1 delete db_mcp_main.py + Dockerfile.db-mcp-server + BearerTokenMiddleware ; A5 dup duplicate-branch
- [ ] M1 isError (raise McpError on genuine failure, keep validation in-band) ; M3 readOnlyHint 11 tools + execute_sql
- [ ] S1 `stateless_http=True, json_response=True` on FastMCP + mcp pin ≥1.8 ; flip DB POSTGRES_MCP_TRANSPORT=streamable_http ; replicas 3 / HPA max5 / CPU 1.5
- [ ] POOL env-configurable min5/max30 (⚠ verify RDS headroom first) ; S6 cheap readiness (is_valid) + /health/db diag
- [ ] INFRA-REDIS off-spot+do-not-disrupt ; INFRA-PDB maxUnavailable:1 ; INFRA-V2 pool env ; DEPLOY-SH note (commit before deploy)

### Batch 6 — Docker verification rig  [spec_09 DOCKER-VERIFY]  (build after Batch 1, re-run per batch)
- [ ] `docker-compose.test.yml` + `tests/fixtures/seed.sql` + `tests/smoke/run_smoke.sh` (Rows A–I) + optional galactus-mock

## Verify commands
- DB: `cd topmate-db-mcp-server && .venv/bin/python -m pytest -q`
- PG: `cd postgres-mcp && .venv/bin/python -m pytest tests/unit -q`
- Docker: `docker compose -f postgres-mcp/docker-compose.test.yml build && up -d && bash postgres-mcp/tests/smoke/run_smoke.sh`

## Open items needing human (non-blocking; defaulted)
- RDS `SHOW max_connections` before raising pool max (POOL ⚠). Start max=20 if unverified.
- Redis durability (AOF+PVC) decision if it becomes session store.
- Loop team must RS256-sign `X-Identity-JWT` before flipping REQUIRE_SIGNED_IDENTITY=true.
- M1 isError wire-contract: confirm Loop adapter handles isError before relying on it.
