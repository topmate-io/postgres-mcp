# Loop ↔ Topmate MCP — Caller‑Scoped Access Integration Handover

**For:** Loop base‑platform / `ryl-base-platform` adapter owners
**From:** postgres‑mcp + topmate‑db‑mcp‑server owners
**Status:** Implemented + tested (150 tests), pending deploy. Backward‑compatible: until you send the new headers, nothing changes.
**Contract this implements:** `ryl-base-platform/docs/MCP_INTEGRATION_CONTRACT.md` §"Access control".

---

## TL;DR (what you need to do)

1. **Register `db-mcp` over Streamable HTTP**, not SSE:
   `https://mcp.gabbanext.run/db-mcp/mcp`
2. **Authenticate the adapter with the shared static token** (you become "trusted transport"):
   `Authorization: Bearer <AUTH_TOKEN>` (the existing `topmate-bi-secrets/auth-token`).
3. **Forward the resolved identity on every `tools/call`** as headers:
   `X-User-Scope`, `X-User-Username`, `X-User-Email`.
4. Your adapter already gates by `_meta.loop/minScope` — **no per‑tool config needed**. Exactly **12 tools** are marked `expert`; everything else stays superadmin‑only automatically.

That's it. Experts now see only their own rows; superadmin keeps full access; legacy/un‑headered calls are byte‑for‑byte unchanged.

---

## 1. Endpoint & transport

| Server | Register this URL | Transport | Why |
|---|---|---|---|
| **db‑mcp** (BI tools — the one you scope) | `https://mcp.gabbanext.run/db-mcp/mcp` | **Streamable HTTP** | Per‑request identity only propagates to the tool on the `/mcp` path (stateless). The `/sse` path will **not** scope correctly. |
| postgres‑mcp (raw DB admin) | `https://mcp.gabbanext.run/postgres-mcp/mcp` | Streamable HTTP | Optional. All its tools are admin‑only; any non‑superadmin scope is `403`'d. |

Protocol negotiated: MCP `2024-11-05` (your version) — verified.

---

## 2. How the adapter authenticates (pick Option A)

The server uses a **two‑tier trust model**. The credential you present in `Authorization` decides the tier.

### ✅ Option A — Trusted transport (recommended)

Register with the shared static token; forward identity in `X-User-*`:

```python
from loop_platform.adapter.mcp_adapter import register_mcp_service

register_mcp_service(
    registry,
    "https://mcp.gabbanext.run/db-mcp/mcp",
    service="bi",
    headers={"Authorization": f"Bearer {TOPMATE_MCP_AUTH_TOKEN}"},  # = topmate-bi-secrets/auth-token
)
```

Because you authenticated as the trusted gateway, the server **trusts your `X-User-*` headers verbatim — including `superadmin`**. You already validate the topmate token and resolve scope on your side, so the server does **not** re‑call galactus. No extra server config needed (no allowlists).

### Option B — Pass the end‑user token through (only if you can't use a static secret)

Forward the end user's token instead of the static one:

```
Authorization: Token <topmate-knox-token>
X-User-Scope: expert
X-User-Username: ajay_shenoy
```

The server then validates the token against galactus `GET /profile/` itself and derives `expert`/`seeker`. **superadmin is NOT derivable from galactus** in this mode — it requires the user's email/token to be in the server‑side `SUPERADMIN_EMAILS`/`SUPERADMIN_TOKENS` allowlist. Use Option A unless you have a reason not to.

> You cannot do both at once — `Authorization` holds either the static Bearer **or** the user Token. Option A keeps identity in the `X-User-*` headers, which is cleaner.

---

## 3. Headers to forward (every `tools/call`)

| Header | Required | Example | Meaning |
|---|---|---|---|
| `Authorization: Bearer <AUTH_TOKEN>` | yes (Option A) | `Bearer 8b7f…` | Trusted‑transport credential (the shared secret). |
| `X-User-Scope` | yes | `superadmin` \| `expert` \| `seeker` \| `public` | Resolved tier. Drives all scoping. |
| `X-User-Username` | **for `expert`** | `ajay_shenoy` | The **creator** whose data to return. The server resolves it to the integer `expert_id` and filters every query by it. **This is the only thing that selects the creator — tool arguments are ignored.** |
| `X-User-Email` | optional | `ajay@topmate.io` | The caller, or a superadmin act‑as target. |

**Absent `X-User-Scope` ⇒ legacy ⇒ unchanged behavior.** (This is how db‑mcp's own internal calls to postgres‑mcp keep working.)

---

## 4. What each scope can do

| `X-User-Scope` | db‑mcp behavior | postgres‑mcp behavior |
|---|---|---|
| _(absent)_ | Legacy — full, unscoped (unchanged) | Unchanged |
| `superadmin` | Full, unscoped | Full |
| `expert` | The **12 marked tools** run **filtered to `X-User-Username`'s rows**. Unmarked tools return an error. | **403** (all tools admin‑only) |
| `seeker` / `public` | The 12 marked tools are `minScope:expert`, so your adapter won't route them here anyway; if reached, they error. | **403** |
| invalid / unauthenticated token | `401` | `401` |

Guarantee: there is **no tool argument** by which an `expert` caller can read another creator's data. NL/free‑text tools that reach the LLM are rewritten with a mandatory `WHERE expert_id = <caller>` (AST‑level, UNION/CTE‑proof) or rejected if they can't be constrained.

---

## 5. The 12 expert‑exposable tools (`_meta.loop/minScope: "expert"`)

Your adapter reads `_meta.loop/minScope` from `tools/list` and exposes these to experts automatically. They also carry `annotations.readOnlyHint: true` so they auto‑run (no HITL gate):

```
ask_topmate_bi              expert_intelligence       follower_intelligence
service_intelligence        query_events              conversion_funnel
event_intelligence          get_business_metrics      analyze_trends
compare_periods             analyze_funnel            cohort_analysis
```

Everything else (raw SQL: `data_query_raw`, `query_topmate_data`, `query_athena_sql`; exports; team/NL tools; platform aggregates like `detect_anomalies`, `currency_intelligence`, `geography_intelligence`, `event_trends`) is **unmarked → superadmin‑only** on your side, and additionally server‑side denies non‑superadmin.

For an expert, `X-User-Username` = the expert's own topmate username. (Aggregate metrics like "new platform users" are rejected for experts by design — they can't be constrained to one creator.)

---

## 6. Superadmin & act‑as

- **Option A:** set `X-User-Scope: superadmin` — trusted and honored. To impersonate/act‑as a creator, set `X-User-Scope: superadmin` + `X-User-Username: <target>` (full access, optionally targeted).
- **Option B:** superadmin requires the caller's email in `SUPERADMIN_EMAILS` (or token in `SUPERADMIN_TOKENS`) on the server — tell us which identities and we'll add them.

---

## 7. Server‑side config (ops — already in the deployment manifests)

| Env var | Default | Notes |
|---|---|---|
| `CALLER_SCOPE_ENABLED` | `true` | Master kill‑switch. Set `false` to fully disable (pure pass‑through) if needed. |
| `GALACTUS_PROFILE_URL` | `https://api.galactus.run/profile/` | Only used in Option B. |
| `SUPERADMIN_EMAILS` | _(empty)_ | Comma‑separated. Only needed for Option B superadmin. Secret `topmate-bi-secrets/superadmin-emails`. |
| `SUPERADMIN_TOKENS` | _(empty)_ | Comma‑separated service tokens that are always superadmin (also count as trusted transport). Secret `topmate-bi-secrets/superadmin-tokens`. |

`AUTH_TOKEN` is the existing `topmate-bi-secrets/auth-token` shared secret — the one you put in the `register_mcp_service(headers=...)` call.

---

## 8. Verification checklist (smoke tests after you wire it)

- [ ] **Regression:** call any tool with **no** `X-User-*` headers → identical output to today.
- [ ] **Isolation:** `X-User-Scope: expert`, `X-User-Username: <expertA>` on `get_business_metrics` (gmv) → only A's GMV; repeat passing a different creator id in args → still A's data.
- [ ] **Admin‑only:** `data_query_raw` with `X-User-Scope: expert` → error "superadmin only"; any postgres‑mcp tool with `expert` → `403`.
- [ ] **tools/list:** exactly the 12 tools above carry `_meta.loop/minScope:"expert"` + `readOnlyHint:true`; nothing else.
- [ ] **superadmin:** `X-User-Scope: superadmin` → full, unscoped results.

---

## 9. Open coordination items

1. **Confirm Option A** (static `AUTH_TOKEN` Bearer + `X-User-*`). If you instead forward end‑user `Token`s (Option B), tell us and we'll populate `SUPERADMIN_EMAILS/TOKENS`.
2. **Egress:** if your adapter calls from a non‑allowlisted IP, the static Bearer (Option A) already gets you through the IP gate — nothing extra. If you rely on IP allowlisting instead, send us your egress CIDR.
3. We deploy the two images once you've confirmed (1). The change is dark until you start sending `X-User-Scope`.

---

**Reference:** full design + per‑task detail in `postgres-mcp/docs/superpowers/plans/2026-06-09-caller-scoped-access.md`.
