# MCP Stack Remediation — Execution Plan (2026-06-10)

Source audit: `docs/audits/2026-06-10-mcp-stack-audit.md` + handoff `~/Downloads/topmate-mcp-infra-handoff-2026-06-10.md`.
Grounded per-finding specs (workflow wf_badb1c3b-4d1): `/tmp/mcp-specs/spec_00..09.json`.

**Scope:** ALL findings (P0+P1+P2), both repos. **Verify:** pytest per chunk + local Docker smoke per batch. **No prod deploy.**
**Repos:** `postgres-mcp` (PG, `/Users/dharsankumar/Documents/GitHub/postgres-mcp`) · `topmate-db-mcp-server` (DB, `/Users/dharsankumar/Documents/GitHub/topmate-db-mcp-server`). Branch `feat/caller-scoped-access` in both.
**Baseline (pre-change):** DB 127 passed · PG unit 187 passed + 4 pre-existing testcontainer failures in `tests/unit/explain/test_explain_plan*` (unrelated, ignore).

## PROGRESS (loop state)
**Done + green (DB suite now 185 passed), ✅ COMMITTED to feat/caller-scoped-access (db-mcp 6 commits 26713dc..9295c9d; audit docs in postgres-mcp 5987d54):**
- ✅ G2 fail-closed scope guard (`ai/sql_scope_guard.py` + 15 new tests; exploit confirmed closed)
- ✅ A2 deleted 4 dead root modules + fixed claude_desktop_config/README refs
- ✅ D1 new `security/sql_guard.py` (parse-based `is_write`) replacing 5 `_FORBIDDEN_SQL` copies (athena drift fixed) + `tests/test_sql_guard.py` (22)
- ✅ G6 `data_query` sql_override uses `is_write` (parse-based, catches MERGE/DO/CALL/CTE/stacked)
- ✅ G7 CreatorResolver single-quote escape + defensive test
- ✅ G5 error-oracle fix (`types.py`: Exception always sanitized incl. schema-leak/SQLSTATE patterns; tool-authored str verbatim) + 26 broad-`except` callers switched `str(e)`→`e` (9 `except PermissionError` kept verbatim) + `tests/test_error_semantics.py` (11)
- ✅ M1 isError (`format_error_response`→`CallToolResult(isError=True)`). **SPEC CORRECTION:** mcp≥1.26 validates a returned CallToolResult's `structuredContent` against the tool's output_model (all `-> ResponseType` tools have one = `{"result": list}`), so `structuredContent` MUST be populated, not None — set to mirror the error content. Verified via integration test `test_at3_raw_tool_denied_for_expert`.
- ✅ M2 readOnlyHint on 48/51 tools (3 S3-writers=False, 0 unannotated) — verified via register_all_tools+list_tools; +2 `test_tools_meta.py` assertions
- ✅ M4 Literal/Field on analytics (get_business_metrics/analyze_trends/compare_periods/analyze_funnel/cohort_analysis) + intelligence (summarize_data/detect_anomalies/forecast_metric). **SPEC CORRECTION:** used `Annotated[Literal[...], Field(...)] = default` (NOT `= Field(default=...)`, which would set the runtime default to a FieldInfo and break direct fn calls). Shared `_MetricLit` constant. +7 `tests/test_param_schemas.py`.
- ✅ M5+M6 (LOOP-302, committed db-mcp 550f0b5 / pg-mcp ed3d0b8): pinned `mcp[cli]<2.0.0` both repos; documented `_meta` handled via Context (FastMCP extra=ignore); +`tests/test_sdk_pin.py` (2).
- ✅ D5 (LOOP-303, committed b416e0d): `@admin_only` decorator + `resolve_scope_or_error` in `caller_identity.py`; 20 inline superadmin gates across data_query/events/intelligence/reports/team_tools replaced; `require_admin` retired; functools.wraps preserves FastMCP schema (validated, all 20 deny expert with isError). is_unrestricted kept where used by non-gate branches. +`tests/test_admin_only.py` (5).
- ✅ D3/D4 (LOOP-303, committed 34e4192): new `asgi_utils.py` — `strip_known_prefix` (equals-or-slash, fixes auth.py `/bi-mcp`-only divergence + `/bi-mcp-foo` over-strip) replaced 7 copies; `client_ip` replaced 4 copies (dead oauth one deleted). +`tests/test_asgi_utils.py` (9).
- ✅ A3 (LOOP-304, committed a230db9): deleted dead `process_question`/`_process_question_pipeline`/`enable_clarification` + unused `ai/clarifier.py`+`ai/critic.py` (530 LOC); `process_question_fast` unchanged.
- ✅ P3/P4 (LOOP-300, committed b8d54f1): webhook bg-tasks tracked via `_bg_tasks` set + `_spawn` (strong ref + done-callback); silent inter-MCP teardown + webhook index-trigger failures now logged (debug exc_info / warning exc_info). +`tests/test_github_webhook.py` (3).
**✅ BATCH 1 + BATCH 2 COMPLETE (17).**
**Batch 3 (scale) in progress:**
- ✅ S3+G4 (LOOP-301/299, cbd5413): rate_limiter AliasChoices env (RATE_LIMIT_MAX_REQUESTS now honored) + identity-keyed + Redis `incr_with_expire` + in-memory fallback; token_cache client-scoped + TTL90 + `OAUTH_BEARER_WORKAROUND_ENABLED` kill-switch. +9 tests
- ✅ S2 (LOOP-301, 384a9a9): `asyncio.Semaphore(12)` at retry_llm_call + `LLMBackpressureError` fast-fail + orchestrator friendly-degrade. +3 tests
- ✅ S5 (LOOP-301, fa43ae2): `to_thread` cosine `_score_all` + reportlab/openpyxl; `docs/design/async-job-queue.md`. +2 tests
- ✅ S4 (LOOP-301, 37677a3): Redis single-flight `acquire_lock`/`release_lock`; schema-RAG `asyncio.Lock` (replaced racy `_refreshing`) + cross-pod Redis lock; creator-resolver L2 (Redis) with negative caching; memory-only fallback preserved. +10 tests
- ✅ S7 (LOOP-301, 08dcece): removed per-call `disconnect()` on transient error (tenacity retries on shared session); `_ensure_session` single-flight reconnect (rebuild only if session/lifecycle dead); `_connect_locked` refactor. +4 tests
**DB suite 230 passed. 23/35 findings done+committed. Batch 3 db-mcp items COMPLETE (S2/S3/S4/S5/S7/G4); S1/S6 fold into the PG batch.**
**Batch 4 (identity core) in progress:**
- ✅ P1 (LOOP-300, db-mcp 3a634ef): `validate_token_async` (to_thread, timeout 8→2.5); middleware pre-resolves off-loop + memoized validator (resolve_identity stays pure/sync); `ip_allowlist._has_valid_token` async. +3 tests
- ✅ P2 (LOOP-300, pg 8ff7993): identical to_thread fix for the single replica. +2 tests. **LOOP-300 (P1–P4) COMPLETE.**
- ✅ G1/G3 (LOOP-299, db-mcp b918a68 / pg 62ec99e): `verify_signed_identity` (RS256, `X-Identity-JWT`, PyJWT, alg-pinned) + `resolve_identity` require_signed branch (derive from claims, reject header/claim mismatch → INVALID) in BOTH repos; config/env `REQUIRE_SIGNED_IDENTITY`(default false)+`IDENTITY_JWT_*`; manifest env on both deployments; `docs/LOOP_SIGNED_IDENTITY_CONTRACT.md`. Flag OFF preserves all behavior. +15 tests across repos. **🔍 adversarial review (2 agents) → NO exploitable bypass (severity none on all 8 checks); one low note (signed JWT w/o X-User-Scope fell to legacy) closed by a 1-line hardening (db-mcp 2ca27b5 / pg db41d48, +4 tests).** db 244 / pg fast-unit 122.
**DB suite 242 passed; PG fast-unit 120 passed. 27/35 findings done+committed. ✅ Security (LOOP-299 G1–G7) + Async (LOOP-300 P1–P4) workstreams COMPLETE.**
**✅ Batch 5 (postgres-mcp) essentially COMPLETE:**
- ✅ A1 (LOOP-304, 14811d2): deleted db_mcp_main.py + Dockerfile.db-mcp-server + BearerTokenMiddleware. A5 (same commit): removed the dup `duplicate` branch.
- ✅ M3 (LOOP-302, e9d2d0f): readOnlyHint on 11 read tools + execute_sql (restricted=True). +3 tests.
- ✅ S1 (LOOP-301, c36a0a3): `stateless_http=True`+`json_response` + db-mcp transport→streamable_http + replicas 3 / HPA max5 / CPU 1.5 / mcp pin ≥1.8. +test.
- ✅ POOL+S6 (LOOP-301, 278e8b6): env-config pool (min5/max20, ⚠RDS-verify before 30; V2 max10) + cheap `is_valid` readiness + `/health/db` diag. +3 tests.
- ✅ INFRA (LOOP-305, b1a8d2e): Redis off-spot+do-not-disrupt; PDB minAvailable→maxUnavailable; deploy.sh note. A4 resolved by S1's transport flip.
**DEFERRED (documented): pg-M1** (raise McpError) — risky wire-semantics change, lower value (pg sits behind the inter-MCP client; db-mcp M1 already gives Loop isError). **D2** (vendored module).
**~33/35 findings done+committed (D2 + pg-M1 deferred).** db-mcp 244 · pg fast-unit ~135.
**Next — Batch 6 (FINAL):** local-Docker smoke rig (LOOP-305) — `docker-compose.test.yml` (redis + throwaway seeded postgres + both MCPs) + `tests/fixtures/seed.sql` + `tests/smoke/run_smoke.sh` (rows A–I incl G2 cross-join reject + Bearer-only 401), then build+up+run the smoke matrix. Then mark LOOP-298 + sub-issues Done + final summary.
**D2 (vendored `_identity_core.py`) DEFERRED** — the two repos' caller_identity files diverged structurally (db-mcp has admin_only/asgi_utils/enforcement helpers; pg has different middleware location), so byte-identical vendoring is high-risk for both suites. P1/P2/G1/G3 done per-repo; D2 left as a lower-risk follow-up (noted in LOOP-303).
Then Batch 5 (PG: A1,A5,M1,M3,S1,POOL,S6,manifests→LOOP-304/302/301/305), Batch 6 (docker rig + run smoke→LOOP-305).
**Commit plan when keyed:** per-finding commits via selective `git add` (file sets are disjoint). Files staged-ready listed by `git status` in db-mcp.

## Canonical cross-spec decisions (unify the two repos' G1 specs)
- **Signed-identity header:** `X-Identity-JWT` (dedicated header; Authorization keeps shared AUTH_TOKEN/galactus token).
- **Env (both repos):** `REQUIRE_SIGNED_IDENTITY` (default `false`), `IDENTITY_JWT_PUBLIC_KEY` (PEM), `IDENTITY_JWT_PUBLIC_KEY_PATH`, `IDENTITY_JWT_AUDIENCE` (default `topmate-mcp`), leeway 60s.
- **Claims:** `scope, username, email, aud, exp, iat`; alg RS256 (pinned).
- **G3 policy on header/claim mismatch:** Option A — derive identity from claims AND reject (INVALID) if a *present* header disagrees.
- **Secret key (AWS):** `topmate-bi-secrets` key `identity-jwt-public-key` (optional).
- **D2 shared core:** vendored byte-identical `_identity_core.py` in both repos (NOT a pip package); the P1/P2 async fix + JWT verify land there once. Sync byte-identity guarded by a sha256 check.
- **Docker rig:** `postgres-mcp/docker-compose.test.yml` (redis + throwaway postgres:16 seeded + both MCPs + optional galactus-mock). Never point at prod replica.
- **Tracking (Linear, Loop team):** parent **LOOP-298**; workstream sub-issues — Security G1–G7=**LOOP-299**, Async P1–P4=**LOOP-300**, Scale S1–S7=**LOOP-301**, MCP best-practices M1–M6=**LOOP-302**, DRY D1–D5=**LOOP-303**, Dead-code A1–A5=**LOOP-304**, Infra/Docker=**LOOP-305**. Commits keyed per-finding to the matching sub-issue.

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
