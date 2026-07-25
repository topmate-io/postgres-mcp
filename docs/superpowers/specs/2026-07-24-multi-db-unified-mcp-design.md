# Multi-DB Unified Internal MCP — Domain Routing over Existing Per-DB MCPs

- **Date:** 2026-07-24
- **Tracker:** LOOP-664 (Linear, team Loop) — this is the M3 "new domains" milestone, refined.
- **Status:** Approved design (brainstorming complete). Pending implementation plan.
- **Supersedes (routing approach only):** the connection-registry section (§3.5) of `docs/superpowers/specs/2026-07-11-topmate-internal-mcp-design.md`. That spec proposed the unified server open its own direct read-only Postgres pools per DB. This spec instead **proxies through the existing per-DB MCP deployments**. The M1 perimeter (person-token auth) and the overall LOOP-664 goal are unchanged.

## 1. Problem

`postgres-mcp` connects to exactly one database — `topmate_db_prod` (server `10.0.157.142`, PG 16.13; only `public` + `datadog` user schemas). Callers cannot reach the other production databases through it:

- **Instagram Auto-DM V2** — live data in the separate `instagram_auto_dm` RDS. The `instagram_auto_dm_*` tables that *do* exist in `topmate_db_prod` are a **frozen 2026-02-01 V1 snapshot** and mislead anyone who queries them.
- **Transactions V2** — three separate financial databases (`ledger_db`, `payment_db`, `payout_db`).
- **Loop / RYL** — `ryl_beta` on AWS RDS `ryl-beta-db`.

Today each database is fronted by its own MCP deployment (the per-DB pattern), but they are registered and used piecemeal, and there is no single entry point that (a) exposes every database and (b) helps the model pick the right one for a given request.

## 2. Goal & non-goals

**Goal:** one MCP that can query every internal database, read-only, choosing the right database from the user's request using per-domain schema + business-logic guidance.

**Non-goals (v1):**
- Not absorbing `db-mcp`'s 51 BI tools (that is LOOP-664 M2, separate).
- Not building write paths — strictly read-only.
- No column-level masking / PII redaction — this is an **internal, team-only, read-only** tool; all columns are visible (see §8).
- Not solving cross-VPC networking for `loop` in v1 — `loop` is phase 2.

## 3. Decisions (locked during brainstorming)

| # | Decision |
|---|---|
| D1 | **Routing = guide + `domain` param.** A `get_schema_guide()` tool describes each domain; a single `execute_sql(sql, domain)` runs against the chosen database. |
| D2 | **Proxy, not direct pools.** The router forwards to the existing per-DB crystaldba MCPs; it holds no new DB credentials and inherits their read-only enforcement, credentials, and IP allowlist. |
| D3 | **Extend `postgres-mcp` into the router** (evolve the chassis). `tm` is served by its existing local pool (no extra hop); other domains are proxied. |
| D4 | **`fin` = three domains** (`fin_ledger`, `fin_payment`, `fin_payout`) — the financial data is three physically separate databases and cannot be SQL-joined. |
| D5 | **All columns visible** — internal, read-only tool; no masking. |
| D6 | **v1 scope = `tm` + `igdm` + `fin_ledger` + `fin_payment` + `fin_payout`.** `loop` is phase 2 (needs net-new infra). |
| D7 | **Backward-compat is mandatory** — `db-mcp` depends on `postgres-mcp`; existing behavior must not change. Gated behind a feature flag. |

## 4. Architecture

`postgres-mcp` becomes a domain router. It keeps its own local connection to `topmate_db_prod` for `tm`, and gains outbound MCP-client sessions to the sibling per-DB MCPs for the other domains.

```
caller --(person token)--> postgres-mcp (router)
   get_schema_guide()                 |-- tm          = LOCAL pool (topmate_db_prod)
   execute_sql(sql, domain)           |-- igdm        --(svc token)--> instagram-mcp
                                       |-- fin_ledger  --(svc token)--> postgres-mcp-v2-ledger
                                       |-- fin_payment --(svc token)--> postgres-mcp-v2-payment
                                       |-- fin_payout  --(svc token)--> postgres-mcp-v2-payout
                                       |-- loop (phase 2) --> loop-mcp (in RYL VPC)
```

### 4.1 Connection registry (v1)

Config (env/JSON), one entry per domain: `domain -> { downstream base URL, service-token secret ref, transport }`. `tm` is special-cased to the local pool.

| domain | database | downstream target | reachability |
|---|---|---|---|
| `tm` | `topmate_db_prod` | local pool (no proxy) | in-process |
| `igdm` | `instagram_auto_dm` | `instagram-mcp` | in-cluster |
| `fin_ledger` | `ledger_db` | `postgres-mcp-v2-ledger` | in-cluster |
| `fin_payment` | `payment_db` (`payment_orch`) | `postgres-mcp-v2-payment` | in-cluster |
| `fin_payout` | `payout_db` | `postgres-mcp-v2-payout` | in-cluster |

### 4.2 Tools

- **`get_schema_guide()`** — returns a top-level "which domain for which question" routing table plus a per-domain block (purpose, key tables/columns, enum vocab, business-logic gotchas, cross-domain join keys). Static curated content; MAY be augmented with a live `list_objects` per domain. Content in §6.
- **`execute_sql(sql, domain="tm")`** — `domain` is **optional, default `tm`** (backward-compat, see §5). Validates domain, runs locally for `tm` or proxies to the downstream `execute_sql` for others, returns **raw structured rows** (never LLM-narrated).
- **`list_objects(domain)` / `get_object_details(domain, ...)`** — thin passthroughs for live schema discovery, same routing.

### 4.3 Auth

- **Inbound:** reuse the M1 `PersonAuthMiddleware` (team-only person tokens) already live on `postgres-mcp`.
- **Outbound (verified 2026-07-25, corrects the original assumption):** the downstreams do **not** share one token model, and none of them require a token for the router's calls. Probed from inside the `postgres-mcp` pod, all four downstreams (`instagram-mcp`, `postgres-mcp-v2-ledger/payment/payout`) answer `execute_sql` over `/mcp` with **HTTP 200 and no bearer token**: the cluster pod CIDR is already inside each downstream's IP allowlist, so intra-namespace pod→pod traffic is admitted without a service token. `instagram-mcp` has an `AUTH_TOKEN` env set but still admits the allowlisted in-cluster caller without it; the three fin MCPs have no auth token at all (only `ALLOWED_IPS`). **Therefore no `svc-internal-mcp` token is minted, stored, or presented** — the registry carries no `token_env`, and the router sends no `Authorization` header. Transport is **`streamable_http`** (stateless `/mcp`), deliberately not SSE, to keep internal proxying off the persistent-stream reliability path.
- **The access gate is the router's inbound perimeter.** Because downstreams trust the cluster network, the only thing preventing an arbitrary caller from reading `fin_*`/`igdm` is `postgres-mcp`'s own `PERSON_AUTH_ENABLED=true` person-auth, which every proxied call passes first. This is consistent with the locked design (internal, read-only, team-only). If a downstream must later be reachable by callers who should *not* see fin data, this network-trust model has to be revisited (per-domain tokens / network policy).
- **Accepted tradeoff — audit attribution loss on proxied domains:** the original caller's person identity is authenticated and logged at `postgres-mcp`'s inbound perimeter but is **not** forwarded downstream. A downstream MCP's own audit trail therefore attributes every proxied `igdm`/`fin_*` query to an anonymous in-cluster caller, not to the human who issued it. Conscious v1 tradeoff: the authoritative per-caller record lives in `postgres-mcp`'s logs, and this is a read-only internal tool. If per-caller attribution is later required *inside* a downstream (e.g. a finance-domain audit), the router must forward caller identity (e.g. an `X-On-Behalf-Of` header the downstream trusts) — out of scope for M3. Revisit before exposing `fin_*` beyond the internal team.

## 5. Backward-compatibility (the key risk of D3)

`db-mcp` calls `postgres-mcp`'s `execute_sql` today with no `domain` argument. That path must remain byte-for-byte identical:

- `execute_sql(sql)` with no `domain` → `domain="tm"` → existing local `SqlDriver` path, unchanged.
- New multi-domain behavior is gated by **`MULTI_DOMAIN_ENABLED` (default off)**. When off, `postgres-mcp` behaves exactly as today; a non-`tm` `domain` is rejected. Flip on only after downstream tokens are verified. Rollback = flip off. (Same safe-rollout pattern as M1's `PERSON_AUTH_ENABLED`.)

## 6. `get_schema_guide` content (distilled from repo maps)

Source of truth for each domain's guide, captured during exploration:

### tm (topmate_db_prod)
Reuse the existing `get_topmate_schema_guide` content. Key gotcha to keep: `all_bookings_new` (matview) uses `created_time`/`expert_earning`/`book_currency`, unlike `booking_booking`'s `created`/`expert_earnings`/`currency`.

### igdm (instagram_auto_dm — live V2, ~5.5k connections / ~8.1k automations)
- **Key tables:** `instagram_connections` (root entity), `automations` (unified rule/sequence, replaces 5 V1 rule tables), `dm_sequences` (per-(automation,user) funnel state), `dm_logs`, `webhook_logs` (~1.2M rows), `instagram_subscriptions`, `agent_runs` (agentic path).
- **Creator join key:** `instagram_connections.user_id` (String) — **NOT** the deprecated `topmate_user_id`. `instagram_subscriptions.user_id` uses the same value.
- **"Active" is three different things:** `connections.status='connected'` (OAuth healthy) ≠ `automations.is_active` (rule on) ≠ `instagram_subscriptions.status='active'` (paying).
- **Brain vs rule are mutually exclusive per connection:** `ryl_brain_enabled=true` → look in `agent_runs`, not `dm_sequences`.
- **Funnel stages:** `opening → follow_gate → email → final → followup` (each skippable).
- **Enums:** ConnectionStatus `connected|disconnected|expired|error`; AutomationType `post_reel|dm|story|live`; DMSendStatus `pending|sent|failed|waiting_follow|waiting_email|scheduled|dead_letter|queued`.
- **Gotcha:** `instagram_subscriptions` can drift from the source of truth in transactions-v2.

### fin_ledger (ledger_db)
- **Key tables:** `accounts`, `ledger_entries` (immutable double-entry), `holds`, `v1_snapshots`, `reconciliation_runs`.
- **Balance:** `accounts.balance` is a denormalized running total; **available = `balance − hold_amount`**; never `SUM(ledger_entries)`.
- **Negative balance** is legitimate for `account_type='gateway_settlement'` and refund/reversal source types.
- **Money:** `NUMERIC(20,6)` in **major units** (rupees/dollars), not paise.

### fin_payment (payment_db / payment_orch)
- **Key tables:** `payment_intents`, `subscriptions`, `settlements`, **`v2_user_cutover`** (V1→V2 per-user routing state), `shadow_*` (parallel-run validation — not live state).
- **PaymentState:** `pending|processing|paid|failed|cancelled|refunded|partially_refunded|disputed|settled|resolved|refund_pending|refund_failed`.
- **Cutover:** zero-balance per-user. Lifetime earnings = `v1_snapshots.v1_lifetime_earnings` (frozen, in ledger_db) **+** post-cutover ledger entries; check `v2_user_cutover.enabled/status/phase*` for regime.

### fin_payout (payout_db)
- **Key tables:** `withdrawal_requests`, `bank_accounts`, `tds_records`, `fraud_checks`, `verification_records`, `suspicious_activity_reports`.
- **WithdrawalState:** `pending→verifying→approved|rejected|manual_review→processing→completed→reversed`; terminal `rejected/cancelled/failed` auto-release the linked ledger hold.
- **Columns:** `*_enc` (bank/PAN) are AES-256-GCM ciphertext — visible but unreadable (router has no key). Plaintext PII exists in `v1_snapshots.v1_bank_account` and `verification_records.decision_data` — visible per D5; flagged for awareness.

### Cross-domain (top-level guide note)
The three `fin_*` databases and `igdm` are **separate RDS instances — no SQL joins across them.** To correlate one creator, run one `execute_sql` per domain and stitch on `user_id`/`expert_id` in-model, minding type drift: `String(64)` in most tables, `Integer` in `v1_snapshots`/`v2_user_cutover`, `UUID` in `suspicious_activity_reports`.

## 7. Data flow

1. Model calls `get_schema_guide()` → reads the routing table + domain blocks.
2. Model picks a `domain` and calls `execute_sql(sql, domain)`.
3. Router validates the domain; `tm` runs on the local pool, others proxy to the downstream `execute_sql` with the service token.
4. Raw rows returned verbatim.
5. Cross-DB correlation = multiple `execute_sql` calls stitched by the model (§6 cross-domain note).

## 8. Security

- Read-only guaranteed downstream (`--access-mode=restricted` → `BEGIN TRANSACTION READ ONLY` + pglast allowlist); the router additionally rejects non-SELECT before proxying (defense-in-depth).
- Team-only via M1 person tokens inbound; service tokens outbound.
- Internal tool, all columns visible (D5). Note the plaintext-PII columns in fin_payout above; `*_enc` columns return ciphertext only.

## 9. Error handling

- Unknown/disabled domain → structured error listing valid domains.
- Downstream 401 / timeout / 5xx → surface a **structured error**, never a silent empty result (the `db-mcp` "LLM narrative → `literal_eval` fails → `[]`" breakage must not recur; the router proxies raw rows and propagates errors explicitly).
- Non-SELECT → rejected before proxying.

## 10. Testing

- **Unit:** domain routing; `domain` default=`tm` backward-compat; service-token propagation; non-SELECT rejection; raw-row passthrough; downstream-error surfacing (structured, not `[]`); `MULTI_DOMAIN_ENABLED` off = tm-only.
- **Integration:** against a stub downstream MCP.
- **Smoke:** live `get_schema_guide` + one `execute_sql` per live domain (tm, igdm, fin_ledger, fin_payment, fin_payout).

## 11. Rollout

1. **Verify-first:** confirm the three `postgres-mcp-v2-*` deployments are running **and connected** (deploy.sh provisions `v2-*-database-uri` with `|| true`, so they may be deployed-but-dead).
2. Mint `svc-internal-mcp` token(s); register digests in each downstream's `person-tokens`; add raw token(s) to `postgres-mcp-secrets`.
3. Deploy the new `postgres-mcp` image + registry config, `MULTI_DOMAIN_ENABLED=false`.
4. Flip `MULTI_DOMAIN_ENABLED=true`; run the smoke test.
5. Rollback at any point = `MULTI_DOMAIN_ENABLED=false`.

## 12. Phase 2 — `loop`

`loop` = **`ryl_beta`**, the RYL agents platform DB (creators, campaigns, leads/consumers, conversations, credits, DBOS backlog). Note there is a *separate* `loop` billing DB (Loop Base Platform) co-located on the same RDS instance — it is **out of scope** here; "loop" in this spec always means `ryl_beta`.

`ryl_beta` lives on AWS RDS `ryl-beta-db` (same account `072528252688`) in a **dedicated, isolated VPC (`10.20.0.0/16`) not peered with the EKS/Topmate VPC** — so the EKS-hosted router cannot reach it on 5432. The proxy model resolves this without VPC peering:

- Stand up a `loop-mcp` (crystaldba image, `--access-mode=restricted`) **inside the RYL infra** (co-located with `expert-concierge-mcp` on `mcp-beta-asg`, which already reaches `ryl-beta-db`).
- Connect it as the `ryl_admin` owner → read-only enforced at the MCP layer, and owner status cleanly bypasses RYL's partial/inconsistent RLS (only 6 tables + `lead_state`/`outcomes` have RLS `ENABLE`d, not `FORCE`; a non-owner role would silently see zero rows).
- Register `loop` as a 6th registry entry pointing at the `loop-mcp` HTTPS endpoint. The network hop crosses the boundary at the MCP layer, not the DB layer.
- Optional `loop_dbos` domain over `ryl_beta_dbos_sys` for DBOS-backlog diagnostics (a stuck lead needs both `ryl_beta.lead_state` and the sys DB's `workflow_status`). Mem0 memory stores excluded (conversation-derived PII).

## 13. Open items / risks

- Live-verify the three `fin` downstream deployments are connected (§11.1).
- Confirm `instagram-mcp` and `postgres-mcp-v2-*` accept a `svc-internal-mcp` token (they must, post-M1) and mint accordingly.
- Extending a prod service (`postgres-mcp`) that `db-mcp` depends on — mitigated by D7 backward-compat + `MULTI_DOMAIN_ENABLED`.
- `loop` phase-2 network reachability of `mcp-beta-asg → ryl-beta-db` to be confirmed live.

## 14. Key references

- postgres-mcp: `src/postgres_mcp/server.py` (single `DATABASE_URI`, `DbConnPool`, `SqlDriver`; M1 `PersonAuthMiddleware`), `eks/manifests/base/deployment-postgres-mcp*.yaml`, `eks/deploy.sh`.
- igdm: `instagram-autodm-v2/models.py`, `models_agentic.py`, `mcp_app/`.
- fin: `transactions-v2/services/{ledger,payment-orch,payout}/app/models/*.py`, `shared/{money,encryption}.py`, `docs/plans/2026-03-07-zero-balance-cutover-design.md`.
- loop: `ryl-agents-backend/src/infra/db/models.py`, `deployment/ec2-beta/rds.tf`, `mcp-servers/expert-concierge-mcp`.
- Prior spec: `docs/superpowers/specs/2026-07-11-topmate-internal-mcp-design.md`.
