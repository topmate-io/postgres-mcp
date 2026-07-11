# topmate-internal-mcp — Unified Internal Team MCP (Design)

- **Date:** 2026-07-11
- **Status:** Approved by Dharsan (design review 2026-07-11); implementation plan pending
- **Scope:** Consolidation of postgres-mcp + topmate-db-mcp-server into one internal team MCP; topmate-actions-mcp analyzed and explicitly kept separate
- **Inputs:** 15-agent recon across 12 repos (full JSON: session scratchpad `mcp-consolidation-recon.json`); `docs/audits/2026-06-10-mcp-stack-audit.md`; `docs/audits/2026-06-10-remediation-plan.md`

## 1. Context

### 1.1 The fleet is six servers, not three

| Server | Repo | Framework | Tools | Role |
|---|---|---|---|---|
| postgres-mcp | postgres-mcp | mcp SDK ≥1.8 FastMCP | 12 | Postgres data layer on EKS (this repo) |
| topmate-db-mcp-server | topmate-db-mcp-server | mcp SDK ≥1.26 FastMCP | 51 (docs claim 38) | BI/AI layer over postgres-mcp, EKS |
| topmate-actions-mcp | topmate-actions-mcp | fastmcp v2 (different lineage) | 163 | Creator product actions for Loop, EC2 ASG |
| instagram-autodm-mcp | instagram-autodm-v2 (`api/mcp_routes.py`, `mcp_app/`) | hand-rolled JSON-RPC over HTTP | 15 | IG auto-DM product/ops tools |
| website-builder-mcp | webisite-builder-v2 (`mcp/`) | FastMCP | 14 | Builder product tools, risk/scope-gated |
| expert-concierge-mcp | ryl-agents-backend (`mcp-servers/`) | FastMCP | — | Per-expert chatbot tools, Cloud Run |

`ryl-base-platform` (Loop) is the universal MCP **client** that consumes these via its Capability adapter.

### 1.2 Robustness verdict (from the 14-dimension inconsistency matrix)

- **postgres-mcp** — most robust overall. Only repo where docs/manifests/live config agree. Production-incident scars fixed in code with rationale (SSE multi-replica 404s → replicas pinned 1; readiness self-DoS → cheap probe; CPU starvation → limit raise). `SafeSqlDriver` (pglast full-grammar AST allowlist) is the strongest safety engineering in the fleet.
- **topmate-db-mcp-server** — best tests (244, mapped to real hardening history), best AI resilience (per-provider circuit breakers, backpressure, fallback chain), best module layout (per-category `register_X_tools`). Undermined by: spoofable rate limiter (keys off unauthenticated `X-User-Username`), mostly-dead Prometheus code, three conflicting statements of its own tool count, dead deployment docs (Cloud Run target it doesn't run on), `requirements.txt`/Homebrew formula contradicting the pyproject SDK pin.
- **topmate-actions-mcp** — best trust model (zero shared secrets; real per-creator tokens; backend-enforced escalation; LOOP-39 cross-account guard) and best governance (dry-run defaults, auto-generated `docs/TOOLS.csv`, adversarial `COVERAGE_AUDIT.md`). Weakest operationally: no rate limit/IP allowlist/observability/error sanitization, unbounded caches, 11,166-line `server.py`, CI never runs its 94 tests.

### 1.3 Key inconsistencies driving this design

1. Three SDK lineages (mcp ≥1.8 / mcp ≥1.26 / fastmcp v2) with no fleet minimum; merging actions-mcp would be a framework migration.
2. `CallerIdentityMiddleware` duplicated by hand between postgres-mcp and db-mcp — every identity fix lands twice.
3. Shared static `AUTH_TOKEN` impersonation hole live in both DB servers (G1/G3 signed-JWT fix built + tested in both, default-off).
4. Both rate limiters broken differently (unbounded per-IP dict vs spoofable identity header); actions-mcp has none.
5. Three deployment topologies; db-mcp's HPA fan-out (1–3 replicas × N DBs) stresses postgres-mcp's pinned single replica whose pool (max 20) is the whole BI stack's concurrency ceiling.
6. Observability broken three different ways: real-but-metrics-free (postgres-mcp), looks-instrumented-but-dead (db-mcp), absent (actions-mcp).
7. Tool namespace chaos: no shared prefix convention; literal duplicates inside db-mcp (`codebase_search`/`search_codebase`, `get_engineering_pulse`/`engineering_status`); overlapping schema/health tools across servers.
8. Two SQL-parsing safety layers with different guarantees: pglast allowlist (stronger) vs sqlglot write-blocklist (weaker).

## 2. Decisions (design review, 2026-07-11)

| # | Decision | Choice |
|---|---|---|
| D1 | Callers | **Team-only, admin trust.** Per-person identity; no end-user (expert/seeker) traffic. |
| D2 | topmate-actions-mcp | **Kept separate** (product component). Its patterns adopted: no shared secrets, dry-run defaults (v2), TOOLS.csv governance. |
| D3 | Write scope | **Strictly read-only v1.** All writes remain manual (skills/kubectl) until v2. |
| D4 | Hosting | **Hosted on EKS** behind `mcp.gabbanext.run`, streamable-HTTP; SSE retired. |
| D5 | Approach | **A — evolve postgres-mcp chassis**; absorb db-mcp via subtree merge; retire both old deployments. |
| D6 | Loop end-user BI (db-mcp's scope_sql + 12 caller-scoped tools) | **Frozen, not ported.** Not serving real prod traffic yet. If Loop needs expert-facing analytics later, it is a product-side concern (expert-concierge-mcp / actions-mcp). Code preserved in git history only. |

## 3. Target architecture

### 3.1 Shape

```
Claude Code / claude.ai  (per-person tokens)
        │ streamable-HTTP /mcp · stateless · HPA 2–4
        ▼
┌─ topmate-internal-mcp (EKS, evolved from postgres-mcp) ─┐
│ perimeter: RequestID → CORS → IPAllowlist → PersonAuth  │
│            → RateLimiter(identity-keyed) → transport    │
│ + audit log + Prometheus metrics on every tool          │
│ domains: tm_db · fin · igdm · loop · analytics          │
│          · infra(read) · bi(LLM / NL→SQL)               │
│ SafeSqlDriver (pglast allowlist) + connection registry  │
└───┬──────────────────────────────────────────────────────┘
    ▼ direct pooled READ-ONLY connections
 topmate replica · ledger/payment/payout · instagram_auto_dm
 · RYL Cloud SQL · analytics-api (HTTP)

RETIRED: db-mcp deployment · inter-MCP SSE client · /sse endpoint
UNCHANGED: actions-mcp · igdm-mcp · builder-mcp · expert-concierge-mcp
```

### 3.2 Repo & package layout

Repo `postgres-mcp` is renamed `topmate-internal-mcp` (GitHub redirects preserved). db-mcp's code arrives by **git subtree merge** so history survives, then tools are re-homed:

```
src/topmate_internal_mcp/
  core/       server bootstrap, transport wiring, perimeter middleware,
              connection registry, SafeSqlDriver, error sanitizer, audit log
  domains/    tm_db/ fin/ igdm/ loop/ analytics/ infra/ bi/
              (each exposes register_tools(mcp, registry) — db-mcp's pattern)
  ai/         LLM provider chain, circuit breakers, backpressure,
              schema RAG (ported from db-mcp, extended per registry target)
```

### 3.3 Identity & perimeter

- **PersonAuth middleware** replaces both the shared `AUTH_TOKEN` bypass and the full `CallerIdentityMiddleware` two-tier machinery. Per-person bearer tokens; token hashes and the `person → token` map live in AWS Secrets Manager. Staging EC2 / CI get named service identities. Unknown token → 403. This closes the `auth-token-bypass` audit finding for the internal surface.
- **X-User-\*/G1-G3 JWT machinery is not carried over** — there is no forwarded end-user identity on this server (D1, D6). It remains only in product-side servers.
- **Rate limiter rewritten once, correctly:** keyed on the authenticated person (fixes db-mcp's spoofable-header bug), bounded LRU bucket store (fixes postgres-mcp's unbounded per-IP dict), runs after PersonAuth. IP allowlist stays as defense-in-depth with the existing CF-Connecting-IP → XFF[0] extraction.
- **CORS/RequestID** unchanged from postgres-mcp.

### 3.4 Transport & scaling

- Streamable-HTTP `/mcp` only, `stateless_http=True`, `json_response=True`. **SSE endpoints are removed**, which deletes the in-memory session-affinity problem and the `replicas=1` pin.
- HPA 2–4 replicas, existing PDB, existing cheap readiness probe (pool `is_valid`, never acquires a connection — keep the post-incident rationale comment).
- Ingress: canonical path `/internal-mcp`; legacy `/postgres-mcp` and `/db-mcp` prefixes keep routing to the unified server during migration (prefix-stripping middleware already supports this), then are removed.

### 3.5 Connection registry (single source of data-source truth)

Declarative registry; every tool resolves its target through it. No hardcoded DSNs anywhere.

| Key | Adapter | Target | Credential source |
|---|---|---|---|
| `topmate_prod` | Postgres pool | topmate-db-prod-replica RDS, `topmate_db_prod` | AWS SM |
| `fin_ledger` | Postgres pool | transactions-v2 `ledger_db` (read-only user) | AWS SM |
| `fin_payment` | Postgres pool | transactions-v2 `payment_db` (read-only user) | AWS SM |
| `fin_payout` | Postgres pool | transactions-v2 `payout_db` (read-only user; `bank_accounts` cipher columns never decrypted) | AWS SM |
| `igdm` | Postgres pool | `instagram_auto_dm` DB (read-only user) | AWS SM |
| `ryl_beta` | Cloud SQL connector | GCP `robylon` Cloud SQL `ryl-prod-db` → `ryl_beta` | GCP SM (SA key) |
| `loop_pg` | Cloud SQL connector | GCP `robylon` Cloud SQL `loop-pg` → `loop` | GCP SM (SA key) |
| `analytics` | HTTP adapter | topmate-analytics-api REST (ClickHouse is localhost-only on its Hetzner VM; the API is the authoritative surface, with its own Redis cache) | AWS SM (API token) |
| `infra_aws` | boto3 | prod 072528252688 + staging 458586357840 | IRSA read-only role |
| `infra_k8s` | kubernetes client | production-topmate-eks + kingsmead-eks | view-only RBAC service accounts |
| `infra_gcp` | google clients | project `robylon` logging/compute/run | viewer SA |

RYL GCP→AWS migration note: when the cutover lands, only the `ryl_beta`/`loop_pg` registry entries change — tools are untouched.

Pooling: per-target `AsyncConnectionPool` with explicit min/max/timeout (postgres-mcp's proven settings), per-target caps sized against RDS headroom (the existing inline warning becomes registry config), plus one global concurrency semaphore protecting the server. Pool-fatal vs query-level error discrimination is preserved.

### 3.6 Read-only enforcement — four independent layers

1. **Registry level:** no mutating tool exists in v1. CI gate: every registered tool must declare `readOnlyHint=true`; build fails otherwise.
2. **SQL level:** every SQL path (including all `bi_*` LLM-generated SQL) goes through `SafeSqlDriver`'s pglast full-grammar allowlist. db-mcp's sqlglot write-blocklist is dropped, never adopted (weaker guarantee).
3. **DB level:** read-only DB users (SELECT-only grants) and `default_transaction_read_only=on` in connection options; replicas used where they exist.
4. **Cloud level:** infra adapters run under read-only IAM (IRSA ReadOnly, EKS view RBAC, GCP viewer) — enforced outside our code entirely.

Timeouts: one shared constant derives both the DB-side `SET LOCAL statement_timeout` and the app-level asyncio timeout (fixes the current 15s/30s mismatch).

### 3.7 Tool surface (v1, ~85 read-only tools)

Naming: `<domain>_<action>` snake_case (prefix discipline adopted from actions-mcp).

- **`tm_*`** — core Topmate DB (from postgres-mcp's 12): `tm_list_schemas`, `tm_list_objects`, `tm_get_object_details`, `tm_explain_query`, `tm_execute_sql` (read-only enforced), `tm_analyze_workload_indexes`, `tm_analyze_query_indexes`, `tm_analyze_db_health`, `tm_get_top_queries`, `tm_schema_guide`, `tm_troubleshooting_guide`, `tm_business_logic_patterns`. Old unprefixed names registered as deprecated aliases until M4.
- **`fin_*`** (new, transactions-v2): `fin_get_payment_intent`, `fin_get_ledger_balance`, `fin_get_withdrawal_status`, `fin_get_fraud_check_result`, `fin_get_v1v2_cutover_status`, `fin_get_reconciliation_run`, `fin_get_dlq_depth`. (Stuck-withdrawal/payment triage — the highest-frequency support workflow.)
- **`igdm_*`** (new, instagram-autodm-v2): `igdm_get_account_stats`, `igdm_get_run_stats`, `igdm_list_automations`, `igdm_list_approvals`, `igdm_get_campaign_link_clicks`, `igdm_get_queue_health` (SQS/DLQ per worker tier via boto3).
- **`loop_*`** (new, RYL): `loop_get_creator_credits_and_tier`, `loop_list_loops_for_creator`, `loop_get_loop_analytics`, `loop_get_llm_cost_ledger`, `loop_get_dbos_workflow_backlog`, `loop_get_hitl_approval_queue`, `loop_get_conversation_events`. Mem0/memory reads are PII-redacted at the adapter.
- **`analytics_*`** (new, via topmate-analytics-api): `analytics_get_creator_funnel`, `analytics_get_creator_traffic_sources`, `analytics_get_creator_geo_device`, `analytics_get_conversion_intelligence_snapshot`.
- **`infra_*`** (new): `infra_k8s_pods`, `infra_k8s_rollout_status`, `infra_k8s_hpa_status`, `infra_k8s_logs`, `infra_cloudwatch_metrics`, `infra_gcp_logging_search`, `infra_queue_depths` (unified SQS/Celery/Taskiq/DBOS view — no single view exists today), `infra_whoami` (resolved account/cluster sanity check).
- **`bi_*`** (ported from db-mcp, deduped): `bi_ask` (NL→SQL, ex-`ask_topmate_bi`), `bi_business_metrics`, `bi_analyze_trends`, `bi_compare_periods`, `bi_analyze_funnel`, `bi_cohort_analysis`, `bi_detect_anomalies`, `bi_forecast_metric`, the `*_intelligence` set, events/Athena tools, report/export tools (`bi_generate_pdf_report`, `bi_export_csv`, `bi_export_excel`), git/codebase intelligence tools (one canonical of each duplicate pair).

Read-only clarification: export/report tools write **only** to the dedicated internal exports bucket (never to any platform datastore) and carry `readOnlyHint=true` with that carve-out documented in the tool description; this is the sole permitted side effect in v1.

Dedup rules for the merge: one canonical tool per collision — `codebase_search` vs `search_codebase` → one; `get_engineering_pulse` vs `engineering_status` → one; db-mcp's schema-guide/health proxies collapse into the `tm_*` originals; the six near-identical `team_tools` wrappers collapse into their underlying tools.

Governance: `docs/TOOLS.csv` auto-generated from the live registry in CI + a registry snapshot test (count + names + annotations). Tool-count doc drift becomes structurally impossible.

### 3.8 AI/BI layer

Ported whole from db-mcp: multi-provider LLM chain (OpenRouter primary) with per-provider circuit breakers, concurrency backpressure with fast-fail, fallback chain, schema RAG with TTL + refresh guard — extended so RAG indexes are **per registry target** (not just topmate_prod). The missing `topmate/bi-mcp/openrouter-api-key` secret in AWS (known gap: deploy.sh swallows it with `|| true`) is created as part of migration, and the deploy script's silent-failure pattern is removed.

### 3.9 Observability & error handling

- **Metrics wired for real:** db-mcp's Prometheus module (tool duration, LLM latency, breaker state, cache ops, tool errors) attached via a single dispatch wrapper applied at tool registration — all ~85 tools instrumented with zero per-tool code. `/metrics` served as today (outermost, unauthenticated).
- **Audit log:** every tool call emits one structured JSON line — person, tool, redacted args, resolved target, duration, outcome, request ID. Ships to CloudWatch. This is the compensating control that makes internal-surface abuse detectable.
- **Errors:** postgres-mcp's `_sanitize_error` (ordering-aware, tested) extends to all adapters; raw driver/HTTP errors never reach clients.
- **Health:** existing endpoints kept (cheap readiness, diagnostic, liveness).

### 3.10 Config & secrets

- pydantic-settings `Settings` singleton (db-mcp's pattern, including the incident-driven env-alias support). argparse retained only for transport/entrypoint flags.
- `requirements.txt` and `Formula/topmate-mcp.rb` deleted (both contradict pyproject today). Single dependency manifest: `pyproject.toml` + `uv.lock`.
- SDK pinned `mcp>=1.26,<2.0` with db-mcp's `test_sdk_pin.py` guard.
- All secrets from AWS Secrets Manager (+ GCP SM for the Cloud SQL SA); no secret material in manifests or images.

### 3.11 Testing & CI

- Merge both suites (~190 postgres-mcp + ~244 db-mcp); fix or quarantine-with-issue the 2 known-failing `tests/unit/explain` tests; drop tests for frozen scope_sql/caller-identity paths (code not carried).
- CI runs pytest + ruff + pyright + TOOLS.csv regeneration + the readOnlyHint gate on every PR (lesson from actions-mcp, whose CI never ran its tests).
- Existing local-Docker smoke rig (spec_09 DOCKER-VERIFY) extended to the unified image.
- Review agents (`mcp-tool-reviewer`, `security-reviewer`) run on tool/auth diffs as today.

## 4. Migration plan (each increment independently shippable)

- **M1 — Perimeter swap on postgres-mcp as-is:** PersonAuth + rewritten rate limiter + audit log; issue per-person tokens; `/mcp` becomes the promoted path. Rollback: env-flag back to legacy auth.
- **M2 — Absorb db-mcp:** subtree merge; re-home 51 tools into `domains/` with dedup; port AI layer + tests; parity harness compares answers against live db-mcp. db-mcp deployment still running; nothing cut over yet.
- **M3 — New P0 domains:** `fin`, `igdm`, `loop`, `analytics`, `infra` + connection registry + read-only credential provisioning (see §6). Metrics/audit verified under load.
- **M4 — Cutover & retirement:** clients move (eden_gardens `.mcp.json`, teammates' Claude configs, Loop platform capability config); db-mcp deployment retired; `/sse` removed; replicas unpinned (HPA 2–4); repo renamed; root-level Cloud-Run-era rot deleted (`CLOUD_RUN_DEPLOYMENT.md`, `cloudbuild*.yaml`, `deploy-cloud-run*.sh`, `deploy-gke-k8s.sh`, `Dockerfile.cloud-run*`, `Dockerfile.aws`, `Dockerfile.official`, etc.). Rollback at every step: point clients back at the old URL.

## 5. Risks & mitigations

| Risk | Mitigation |
|---|---|
| One deployment fronts ~10 datastores — blast radius up | HPA 2–4 + PDB; per-target pool caps; circuit breakers on HTTP/LLM adapters; global concurrency semaphore; audit + metrics from day one |
| RDS connection headroom shared with Django | Per-target caps in registry config; existing headroom warning preserved as config comment; replica-first policy |
| Cross-cloud Cloud SQL reads (latency, authn) | Official Cloud SQL Python connector + SA; entries flip to RDS when RYL cutover lands |
| ~85 tools may stress LLM tool selection | Domain prefixes, crisp descriptions, per-domain enable/disable env flags |
| Consolidation silently downgrades SQL safety | Explicit rule: pglast allowlist everywhere; sqlglot guard never adopted; tests ported |
| Multi-replica session regression (the old SSE bug re-emerging) | SSE deleted outright; `/mcp` stateless; multi-replica smoke test in CI rig |
| Financial DB exposure (payout `bank_accounts`) | Read-only users; cipher columns never selected by any registered tool; PII redaction layer on outputs |

## 6. Provisioning checklist (feeds the implementation plan)

1. Read-only Postgres users on: transactions-v2 ledger/payment/payout RDS, `instagram_auto_dm`.
2. GCP service account (Cloud SQL Client + viewer + logging viewer) for `robylon`; key in GCP SM, referenced from EKS.
3. IRSA read-only role for the pod (CloudWatch, SQS get-attributes, EKS describe); view-only RBAC on both EKS clusters.
4. topmate-analytics-api access token + confirm its Hetzner firewall admits the EKS NAT egress IPs.
5. `topmate/bi-mcp/openrouter-api-key` secret created in AWS SM; deploy script `|| true` removed.
6. Per-person tokens minted for the team + named service identities for staging EC2 / CI.

## 7. Roadmap after v1

- **v1.1:** builder domain (proxy website-builder-mcp read tools), creator-360 composite reports (creator-analytics skill productized), Freshdesk read tools.
- **v2 (writes):** shared write-gate framework — dry-run-by-default, typed prod acknowledgement (ryl-data-clear pattern), backup-before-write + rollback tool, per-tool `destructiveHint` — then: cache bust, automation toggle, DM approvals, Freshdesk replies; later k8s deploy/rollback, settlement retries, bulk remediation sweeps. Git/PR/Jira flow tools (Jira-key enforcement at the tool layer).
- **Fleet follow-on:** extract perimeter/audit/identity as a small shared internal library for the product MCPs (actions, igdm, builder, concierge), which keep their own deployments and trust model.

## 8. Explicitly out of scope / frozen

- Loop end-user (expert/seeker) BI: scope_sql, CallerIdentityMiddleware two-tier trust, G1/G3 signed-JWT — frozen in git history, not ported (D6).
- topmate-actions-mcp absorption (D2) — its 163 tools stay product-side; only its patterns travel.
- Any mutating tool (D3) until the v2 write-gate framework exists.
