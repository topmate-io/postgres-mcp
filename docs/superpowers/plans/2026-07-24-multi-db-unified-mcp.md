# Multi-DB Unified Internal MCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `postgres-mcp` into a read-only domain router that answers `execute_sql(sql, domain)` against the right database — `tm` locally, `igdm`/`fin_*` proxied to the existing per-DB MCPs — with a `get_schema_guide()` that tells the model which domain to use.

**Architecture:** `postgres-mcp` keeps its local `topmate_db_prod` pool for `domain="tm"` and gains outbound MCP-client sessions to the sibling crystaldba MCPs (`instagram-mcp`, `postgres-mcp-v2-ledger/payment/payout`) for other domains. A connection registry maps domain → downstream endpoint + service token. All new behavior is gated behind `MULTI_DOMAIN_ENABLED` so the existing `db-mcp → postgres-mcp` path is unchanged.

**Tech Stack:** Python 3.12, FastMCP (`mcp==1.28.1`), `pydantic` (`Field`, `validate_call`), `mcp.client.sse.sse_client` + `ClientSession`, `tenacity`, `pytest`/`pytest-asyncio`.

## Global Constraints

- `mcp` pinned `==1.28.1` (prod-proven; do not bump). — `pyproject.toml`
- Backward-compat is mandatory: `execute_sql(sql)` with **no** `domain` must behave exactly as today (`db-mcp` depends on it). — spec §5
- All new multi-domain behavior gated behind env flag `MULTI_DOMAIN_ENABLED` (default `false`). — spec §5
- Read-only only. Downstream MCPs enforce it (`--access-mode=restricted`); the router adds a defense-in-depth non-SELECT reject on the proxy path. — spec §8
- `execute_sql` must return **raw rows** (via `format_text_response`), never an LLM narrative. — spec §9
- v1 domains only: `tm`, `igdm`, `fin_ledger`, `fin_payment`, `fin_payout`. `loop` is out of scope (phase 2). — spec §2, §12
- Follow existing `server.py` conventions: `@mcp.tool(..., annotations=types.ToolAnnotations(readOnlyHint=True))`, return `ResponseType`, `format_text_response` / `format_error_response`. — `src/postgres_mcp/server.py`

---

## File Structure

**Create:**
- `src/postgres_mcp/domain_registry.py` — parse `MULTI_DOMAIN_ENABLED` + registry env into a validated `{domain: DomainEntry}` map; helpers `multi_domain_enabled()`, `list_domains()`, `get_domain(name)`.
- `src/postgres_mcp/downstream_client.py` — `DownstreamMCPClient` (ported from db-mcp's proven `PostgresMCPClient`) + a process-wide `get_downstream_client(domain)` cache.
- `src/postgres_mcp/domain_guide.py` — `MULTI_DOMAIN_GUIDE` (curated per-domain content) + `build_schema_guide(enabled_domains)`.
- `src/postgres_mcp/readonly_guard.py` — `is_read_only_sql(sql) -> bool` defense-in-depth check for the proxy path.
- Tests: `tests/unit/test_domain_registry.py`, `tests/unit/test_downstream_client.py`, `tests/unit/test_execute_sql_routing.py`, `tests/unit/test_domain_guide.py`, `tests/unit/test_readonly_guard.py`, `tests/smoke/run_multidomain_smoke.sh`.

**Modify:**
- `src/postgres_mcp/server.py` — replace `execute_sql` body with domain routing; add `get_schema_guide` tool; add domain-aware `list_objects`/`get_object_details` passthrough tools.
- `eks/manifests/base/deployment-postgres-mcp.yaml` — add `MULTI_DOMAIN_ENABLED`, `DOMAIN_REGISTRY_JSON`, downstream token secret refs.
- `eks/deploy.sh` — mint/wire `svc-internal-mcp` token(s) into `postgres-mcp-secrets`.

---

### Task 1: Domain registry

**Files:**
- Create: `src/postgres_mcp/domain_registry.py`
- Test: `tests/unit/test_domain_registry.py`

**Interfaces:**
- Produces:
  - `class DomainEntry` with fields `name: str`, `kind: Literal["local","proxy"]`, `base_url: str | None`, `token: str | None`, `transport: str` (default `"sse"`), `database: str`.
  - `multi_domain_enabled() -> bool`
  - `list_domains() -> list[str]`
  - `get_domain(name: str) -> DomainEntry` (raises `KeyError` for unknown)
  - `reload_registry() -> None` (re-reads env; used by tests)

The registry is read from two env vars:
- `MULTI_DOMAIN_ENABLED` — `"true"`/`"false"` (default false).
- `DOMAIN_REGISTRY_JSON` — JSON: `{"igdm": {"base_url": "http://instagram-mcp-service:8000", "token_env": "SVC_INTERNAL_MCP_TOKEN", "database": "instagram_auto_dm"}, ...}`. `tm` is implicit (`kind="local"`) and always present.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_domain_registry.py
import json
import pytest
from postgres_mcp import domain_registry as dr


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("MULTI_DOMAIN_ENABLED", raising=False)
    monkeypatch.delenv("DOMAIN_REGISTRY_JSON", raising=False)
    monkeypatch.setenv("SVC_INTERNAL_MCP_TOKEN", "svc-tok")
    dr.reload_registry()
    yield
    dr.reload_registry()


def test_flag_defaults_off_and_tm_is_always_local():
    dr.reload_registry()
    assert dr.multi_domain_enabled() is False
    tm = dr.get_domain("tm")
    assert tm.kind == "local"
    assert dr.list_domains() == ["tm"]  # no registry configured -> only tm


def test_registry_parses_proxy_domains_and_resolves_token(monkeypatch):
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "true")
    monkeypatch.setenv(
        "DOMAIN_REGISTRY_JSON",
        json.dumps(
            {
                "igdm": {
                    "base_url": "http://instagram-mcp-service:8000",
                    "token_env": "SVC_INTERNAL_MCP_TOKEN",
                    "database": "instagram_auto_dm",
                }
            }
        ),
    )
    dr.reload_registry()
    assert dr.multi_domain_enabled() is True
    assert set(dr.list_domains()) == {"tm", "igdm"}
    igdm = dr.get_domain("igdm")
    assert igdm.kind == "proxy"
    assert igdm.base_url == "http://instagram-mcp-service:8000"
    assert igdm.token == "svc-tok"
    assert igdm.transport == "sse"


def test_unknown_domain_raises():
    dr.reload_registry()
    with pytest.raises(KeyError):
        dr.get_domain("nope")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_domain_registry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'postgres_mcp.domain_registry'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/postgres_mcp/domain_registry.py
"""Domain connection registry for the unified multi-DB router (LOOP-664 M3).

`tm` is always present and served by the local pool. Other domains are proxied
to sibling per-DB MCPs, configured via DOMAIN_REGISTRY_JSON. All multi-domain
behavior is gated by MULTI_DOMAIN_ENABLED (default off) for backward-compat.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DomainEntry:
    name: str
    kind: Literal["local", "proxy"]
    database: str
    base_url: str | None = None
    token: str | None = None
    transport: str = "sse"


_TM = DomainEntry(name="tm", kind="local", database="topmate_db_prod")

_enabled: bool = False
_domains: dict[str, DomainEntry] = {"tm": _TM}


def reload_registry() -> None:
    """(Re)read env into module state. Safe to call repeatedly (tests + startup)."""
    global _enabled, _domains
    _enabled = os.environ.get("MULTI_DOMAIN_ENABLED", "false").strip().lower() == "true"
    domains: dict[str, DomainEntry] = {"tm": _TM}
    raw = os.environ.get("DOMAIN_REGISTRY_JSON", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.error("Invalid DOMAIN_REGISTRY_JSON, ignoring: %s", e)
            parsed = {}
        for name, cfg in parsed.items():
            if name == "tm":
                continue
            token_env = cfg.get("token_env")
            token = os.environ.get(token_env) if token_env else None
            domains[name] = DomainEntry(
                name=name,
                kind="proxy",
                database=cfg.get("database", name),
                base_url=cfg.get("base_url"),
                token=token,
                transport=cfg.get("transport", "sse"),
            )
    _domains = domains


def multi_domain_enabled() -> bool:
    return _enabled


def list_domains() -> list[str]:
    return list(_domains.keys())


def get_domain(name: str) -> DomainEntry:
    return _domains[name]


reload_registry()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_domain_registry.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/postgres_mcp/domain_registry.py tests/unit/test_domain_registry.py
git commit -m "feat(router): LOOP-664 M3 — domain connection registry"
```

---

### Task 2: Read-only guard

**Files:**
- Create: `src/postgres_mcp/readonly_guard.py`
- Test: `tests/unit/test_readonly_guard.py`

**Interfaces:**
- Produces: `is_read_only_sql(sql: str) -> bool` — defense-in-depth for the proxy path (the downstream MCP is the real read-only boundary). Allows `SELECT`, `WITH`, `EXPLAIN` (non-ANALYZE), `SHOW`, `TABLE`, `VALUES`; rejects everything else.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_readonly_guard.py
import pytest
from postgres_mcp.readonly_guard import is_read_only_sql


@pytest.mark.parametrize("sql", [
    "SELECT 1",
    "  select * from t",
    "WITH x AS (SELECT 1) SELECT * FROM x",
    "EXPLAIN SELECT 1",
    "SHOW server_version",
    "-- comment\nSELECT 1",
    "/* c */ TABLE users",
])
def test_read_only_allowed(sql):
    assert is_read_only_sql(sql) is True


@pytest.mark.parametrize("sql", [
    "UPDATE t SET a=1",
    "DELETE FROM t",
    "INSERT INTO t VALUES (1)",
    "DROP TABLE t",
    "EXPLAIN ANALYZE SELECT 1",
    "SELECT 1; DROP TABLE t",
    "",
])
def test_non_read_only_rejected(sql):
    assert is_read_only_sql(sql) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_readonly_guard.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'postgres_mcp.readonly_guard'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/postgres_mcp/readonly_guard.py
"""Lightweight read-only guard for the proxy path (defense-in-depth).

The downstream crystaldba MCP runs with --access-mode=restricted and is the
authoritative read-only boundary. This is a cheap belt-and-braces check so the
router never forwards an obviously-mutating statement.
"""
from __future__ import annotations

import re

_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_COMMENT_LINE = re.compile(r"--[^\n]*")
_ALLOWED_FIRST = ("select", "with", "show", "table", "values", "explain")


def _strip(sql: str) -> str:
    s = _COMMENT_BLOCK.sub(" ", sql)
    s = _COMMENT_LINE.sub(" ", s)
    return s.strip()


def is_read_only_sql(sql: str) -> bool:
    s = _strip(sql)
    if not s:
        return False
    # Reject multi-statement payloads (ignore a single trailing semicolon).
    if ";" in s.rstrip(";"):
        return False
    lowered = s.lower()
    first = lowered.split(None, 1)[0] if lowered.split(None, 1) else ""
    if first not in _ALLOWED_FIRST:
        return False
    if first == "explain" and "analyze" in lowered:
        return False
    return True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_readonly_guard.py -v`
Expected: PASS (all parametrized cases pass)

- [ ] **Step 5: Commit**

```bash
git add src/postgres_mcp/readonly_guard.py tests/unit/test_readonly_guard.py
git commit -m "feat(router): LOOP-664 M3 — proxy-path read-only guard"
```

---

### Task 3: Downstream MCP client

**Files:**
- Create: `src/postgres_mcp/downstream_client.py`
- Test: `tests/unit/test_downstream_client.py`

**Interfaces:**
- Produces:
  - `class DownstreamMCPClient` — ported near-verbatim from db-mcp's proven `topmate-db-mcp-server/src/topmate_mcp/clients/postgres_mcp_client.py`, generalized (constructor `(base_url, transport="sse", timeout=30.0, auth_token=None)`; method `async call_tool(tool_name, arguments=None) -> str`).
  - `async get_downstream_client(domain: str) -> DownstreamMCPClient` — process-wide cache keyed by domain; builds from `domain_registry.get_domain(domain)`.
  - `async close_all_clients() -> None` — disconnect all cached clients (used in server shutdown + tests).

Port the file at `topmate-db-mcp-server/src/topmate_mcp/clients/postgres_mcp_client.py` into `src/postgres_mcp/downstream_client.py` with these edits: rename the class `PostgresMCPClient` → `DownstreamMCPClient`; replace the literal log strings `"postgres-mcp"` with `f"downstream ({self.base_url})"`; keep the `connect`/`_ensure_session`/`_session_lifecycle`/`call_tool`/`disconnect` logic **unchanged** (it already handles the FastMCP-inside-request cancel-scope issue, single-flight reconnect, and tenacity retries). Then append the cache below.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_downstream_client.py
import pytest
from postgres_mcp import downstream_client as dc


class _FakeClient:
    def __init__(self, *a, **k):
        self.calls = []
        self.closed = False

    async def call_tool(self, tool_name, arguments=None):
        self.calls.append((tool_name, arguments))
        return '[{"n": 1}]'

    async def disconnect(self):
        self.closed = True


@pytest.mark.asyncio
async def test_cache_returns_same_client_per_domain(monkeypatch):
    monkeypatch.setattr(dc, "DownstreamMCPClient", _FakeClient)
    import json
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "true")
    monkeypatch.setenv("SVC_INTERNAL_MCP_TOKEN", "t")
    monkeypatch.setenv("DOMAIN_REGISTRY_JSON", json.dumps(
        {"igdm": {"base_url": "http://ig:8000", "token_env": "SVC_INTERNAL_MCP_TOKEN", "database": "instagram_auto_dm"}}))
    dc.domain_registry.reload_registry()
    await dc.close_all_clients()

    c1 = await dc.get_downstream_client("igdm")
    c2 = await dc.get_downstream_client("igdm")
    assert c1 is c2
    out = await c1.call_tool("execute_sql", {"sql": "select 1"})
    assert out == '[{"n": 1}]'
    await dc.close_all_clients()
    assert c1.closed is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_downstream_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'postgres_mcp.downstream_client'`

- [ ] **Step 3: Write minimal implementation**

Port the db-mcp client as described above, then append:

```python
# --- appended to src/postgres_mcp/downstream_client.py ---
import asyncio
from . import domain_registry

_clients: dict[str, "DownstreamMCPClient"] = {}
_clients_lock = asyncio.Lock()


async def get_downstream_client(domain: str) -> "DownstreamMCPClient":
    """Return a cached client for a proxy domain (builds one on first use)."""
    existing = _clients.get(domain)
    if existing is not None:
        return existing
    async with _clients_lock:
        if domain in _clients:
            return _clients[domain]
        entry = domain_registry.get_domain(domain)
        if entry.kind != "proxy" or not entry.base_url:
            raise ValueError(f"domain '{domain}' is not a proxy domain")
        client = DownstreamMCPClient(
            base_url=entry.base_url,
            transport=entry.transport,
            auth_token=entry.token,
        )
        _clients[domain] = client
        return client


async def close_all_clients() -> None:
    async with _clients_lock:
        for client in list(_clients.values()):
            try:
                await client.disconnect()
            except Exception:
                pass
        _clients.clear()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_downstream_client.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add src/postgres_mcp/downstream_client.py tests/unit/test_downstream_client.py
git commit -m "feat(router): LOOP-664 M3 — downstream MCP client + per-domain cache"
```

---

### Task 4: Route `execute_sql(sql, domain)`

**Files:**
- Modify: `src/postgres_mcp/server.py:448-460` (the `execute_sql` function) and `src/postgres_mcp/server.py:1436-1439` (the `add_tool` registration).
- Test: `tests/unit/test_execute_sql_routing.py`

**Interfaces:**
- Consumes: `domain_registry.{multi_domain_enabled,get_domain,list_domains}`, `downstream_client.get_downstream_client`, `readonly_guard.is_read_only_sql`, existing `get_sql_driver`, `format_text_response`, `format_error_response`.
- Produces: `execute_sql(sql: str, domain: str = "tm") -> ResponseType` — `domain="tm"` runs the existing local path unchanged; proxy domains forward to the downstream `execute_sql`, returning its raw text verbatim.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_execute_sql_routing.py
import json
import pytest
from postgres_mcp import server, domain_registry, downstream_client


def _text(resp):
    return "".join(getattr(c, "text", "") for c in resp)


@pytest.fixture(autouse=True)
def _reg(monkeypatch):
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "true")
    monkeypatch.setenv("SVC_INTERNAL_MCP_TOKEN", "t")
    monkeypatch.setenv("DOMAIN_REGISTRY_JSON", json.dumps(
        {"igdm": {"base_url": "http://ig:8000", "token_env": "SVC_INTERNAL_MCP_TOKEN", "database": "instagram_auto_dm"}}))
    domain_registry.reload_registry()
    yield
    domain_registry.reload_registry()


@pytest.mark.asyncio
async def test_default_domain_uses_local_driver(monkeypatch):
    calls = {}

    class _Driver:
        async def execute_query(self, sql):
            calls["sql"] = sql
            class _R: cells = {"n": 1}
            return [_R()]

    async def _get_driver():
        return _Driver()

    monkeypatch.setattr(server, "get_sql_driver", _get_driver)
    resp = await server.execute_sql("select 1")  # no domain -> tm local
    assert calls["sql"] == "select 1"
    assert '"n": 1' in _text(resp) or "'n': 1" in _text(resp)


@pytest.mark.asyncio
async def test_proxy_domain_forwards_raw(monkeypatch):
    class _Client:
        async def call_tool(self, name, arguments=None):
            assert name == "execute_sql"
            return '[{"status": "connected", "c": 982}]'

    async def _get_client(domain):
        assert domain == "igdm"
        return _Client()

    monkeypatch.setattr(downstream_client, "get_downstream_client", _get_client)
    resp = await server.execute_sql("select status from instagram_connections", domain="igdm")
    assert _text(resp) == '[{"status": "connected", "c": 982}]'


@pytest.mark.asyncio
async def test_flag_off_rejects_non_tm(monkeypatch):
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "false")
    domain_registry.reload_registry()
    resp = await server.execute_sql("select 1", domain="igdm")
    assert "multi-domain" in _text(resp).lower()


@pytest.mark.asyncio
async def test_proxy_non_select_rejected():
    resp = await server.execute_sql("update instagram_connections set x=1", domain="igdm")
    assert "read-only" in _text(resp).lower()


@pytest.mark.asyncio
async def test_unknown_domain_lists_valid():
    resp = await server.execute_sql("select 1", domain="bogus")
    assert "bogus" in _text(resp) and "tm" in _text(resp)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_execute_sql_routing.py -v`
Expected: FAIL (proxy/flag/domain branches not implemented; `execute_sql` has no `domain` param)

- [ ] **Step 3: Write minimal implementation**

Replace `execute_sql` (`server.py:448-460`) with:

```python
# Query function declaration without the decorator - we'll add it dynamically based on access mode
async def execute_sql(
    sql: str = Field(description="SQL to run", default="all"),
    domain: str = Field(
        description="Which database to query: 'tm' (Topmate core, default), 'igdm', "
        "'fin_ledger', 'fin_payment', 'fin_payout'. Call get_schema_guide first.",
        default="tm",
    ),
) -> ResponseType:
    """Executes a read-only SQL query against the selected domain's database."""
    from . import domain_registry, downstream_client
    from .readonly_guard import is_read_only_sql

    # Backward-compat: domain defaults to tm -> existing local path, unchanged.
    if domain == "tm":
        try:
            sql_driver = await get_sql_driver()
            rows = await sql_driver.execute_query(sql)  # type: ignore
            if rows is None:
                return format_text_response("No results")
            return format_text_response(list([r.cells for r in rows]))
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            return format_error_response(str(e))

    if not domain_registry.multi_domain_enabled():
        return format_error_response(
            "multi-domain routing is disabled (MULTI_DOMAIN_ENABLED=false); only domain='tm' is available."
        )
    if domain not in domain_registry.list_domains():
        return format_error_response(
            f"unknown domain '{domain}'. Valid domains: {', '.join(domain_registry.list_domains())}."
        )
    if not is_read_only_sql(sql):
        return format_error_response("only read-only (SELECT/WITH/EXPLAIN/SHOW) statements are allowed.")
    try:
        client = await downstream_client.get_downstream_client(domain)
        raw = await client.call_tool("execute_sql", {"sql": sql})
        return format_text_response(raw)
    except Exception as e:
        logger.error(f"Error proxying execute_sql to domain '{domain}': {e}")
        return format_error_response(f"downstream '{domain}' error: {e}")
```

Note: `format_text_response(raw)` where `raw` is already a string passes it through verbatim (no LLM narration) — verify `format_text_response` wraps a `str` as-is (server.py:102). If it re-serializes, pass `raw` unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_execute_sql_routing.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Run the full unit suite for regressions**

Run: `uv run pytest tests/unit -q`
Expected: PASS (no existing tests broken — the no-`domain` path is byte-identical)

- [ ] **Step 6: Commit**

```bash
git add src/postgres_mcp/server.py tests/unit/test_execute_sql_routing.py
git commit -m "feat(router): LOOP-664 M3 — execute_sql(sql, domain) routing behind flag"
```

---

### Task 5: `get_schema_guide` tool + content

**Files:**
- Create: `src/postgres_mcp/domain_guide.py`
- Modify: `src/postgres_mcp/server.py` (add the tool near the other guide tools, ~line 590)
- Test: `tests/unit/test_domain_guide.py`

**Interfaces:**
- Produces: `MULTI_DOMAIN_GUIDE: dict` and `build_schema_guide(enabled_domains: list[str]) -> dict` (filters to enabled domains + always includes the routing table). Tool `get_schema_guide() -> ResponseType`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_domain_guide.py
from postgres_mcp.domain_guide import build_schema_guide, MULTI_DOMAIN_GUIDE


def test_guide_has_all_v1_domains():
    for d in ("tm", "igdm", "fin_ledger", "fin_payment", "fin_payout"):
        assert d in MULTI_DOMAIN_GUIDE


def test_build_filters_to_enabled_and_includes_routing_table():
    guide = build_schema_guide(["tm", "igdm"])
    assert "routing" in guide
    assert set(guide["domains"].keys()) == {"tm", "igdm"}
    # igdm business-logic gotcha is carried
    assert "user_id" in str(guide["domains"]["igdm"]).lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_domain_guide.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'postgres_mcp.domain_guide'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/postgres_mcp/domain_guide.py
"""Curated per-domain schema + business-logic guide (LOOP-664 M3, spec §6)."""
from __future__ import annotations

ROUTING_TABLE = {
    "tm": "Topmate core: bookings, users, GMV, expert earnings.",
    "igdm": "Instagram Auto-DM V2: connections, automations, DM sequences/logs, subscriptions.",
    "fin_ledger": "Finance ledger: accounts, ledger_entries, holds, v1_snapshots, reconciliation.",
    "fin_payment": "Finance payments: payment_intents, subscriptions, settlements, v2_user_cutover.",
    "fin_payout": "Finance payouts: withdrawal_requests, bank_accounts, tds, fraud/KYC checks.",
}

MULTI_DOMAIN_GUIDE = {
    "tm": {
        "database": "topmate_db_prod",
        "purpose": "Topmate core monolith.",
        "gotchas": [
            "all_bookings_new (matview) uses created_time/expert_earning/book_currency; "
            "booking_booking uses created/expert_earnings/currency.",
            "Use get_topmate_schema_guide for full tm detail.",
        ],
    },
    "igdm": {
        "database": "instagram_auto_dm",
        "purpose": "Live Instagram Auto-DM V2 (~5.5k connections, ~8.1k automations).",
        "key_tables": {
            "instagram_connections": "root entity; join key user_id (String) — NOT deprecated topmate_user_id",
            "automations": "unified rule/sequence (is_active = rule on)",
            "dm_sequences": "per-(automation,user) funnel: opening->follow_gate->email->final->followup",
            "dm_logs": "outbound DM attempts",
            "instagram_subscriptions": "billing mirror; status='active' = paying (can drift from transactions-v2)",
            "agent_runs": "agentic path (when connections.ryl_brain_enabled=true)",
        },
        "gotchas": [
            "'active' is three things: connections.status='connected' (OAuth) != automations.is_active != subscription 'active'.",
            "brain vs rule are mutually exclusive per connection; brain-enabled -> look in agent_runs, not dm_sequences.",
            "ConnectionStatus: connected|disconnected|expired|error.",
        ],
    },
    "fin_ledger": {
        "database": "ledger_db",
        "purpose": "Double-entry ledger.",
        "key_tables": {
            "accounts": "available = balance - hold_amount; balance is denormalized (never SUM ledger_entries)",
            "ledger_entries": "immutable double-entry rows",
            "holds": "active->released|expired",
            "v1_snapshots": "frozen V1 cutover snapshot; expert_id is Integer",
        },
        "gotchas": [
            "Money is NUMERIC(20,6) MAJOR units (rupees/dollars), NOT paise.",
            "Negative balance is legitimate for account_type='gateway_settlement' and refund/reversal sources.",
        ],
    },
    "fin_payment": {
        "database": "payment_db",
        "purpose": "Payment orchestration + V1->V2 cutover state.",
        "key_tables": {
            "payment_intents": "PaymentState: pending|processing|paid|failed|cancelled|refunded|...",
            "v2_user_cutover": "per-user routing; expert_id Integer; check enabled/status/phase*",
            "subscriptions": "subscription lifecycle",
        },
        "gotchas": [
            "Lifetime earnings = v1_snapshots.v1_lifetime_earnings (frozen, ledger_db) + post-cutover ledger entries.",
            "shadow_* tables are parallel-run validation, NOT live routing state.",
        ],
    },
    "fin_payout": {
        "database": "payout_db",
        "purpose": "Withdrawals, bank accounts, TDS, fraud/KYC.",
        "key_tables": {
            "withdrawal_requests": "WithdrawalState: pending->verifying->approved|rejected|manual_review->processing->completed->reversed",
            "bank_accounts": "*_enc columns are AES ciphertext (unreadable); *_last4 are safe",
            "tds_records": "Section 194-O withholding",
            "verification_records": "KYC/Didit; decision_data is sensitive JSONB",
        },
        "gotchas": [
            "user_id/expert_id type drift: String(64) most tables, Integer in v1_snapshots/v2_user_cutover, UUID in suspicious_activity_reports.",
        ],
    },
}

CROSS_DOMAIN_NOTE = (
    "fin_ledger/fin_payment/fin_payout and igdm are separate RDS instances — no SQL joins across "
    "them. To correlate one creator, run one execute_sql per domain and stitch on user_id/expert_id "
    "in-model, minding the String/Integer/UUID type drift."
)


def build_schema_guide(enabled_domains: list[str]) -> dict:
    domains = {d: MULTI_DOMAIN_GUIDE[d] for d in enabled_domains if d in MULTI_DOMAIN_GUIDE}
    routing = {d: ROUTING_TABLE[d] for d in enabled_domains if d in ROUTING_TABLE}
    return {"routing": routing, "cross_domain": CROSS_DOMAIN_NOTE, "domains": domains}
```

Add the tool to `server.py` after `get_topmate_schema_guide` (~line 590):

```python
@mcp.tool(
    name="get_schema_guide",
    description="Returns the per-domain routing table + schema/business-logic guide for the unified "
    "multi-DB MCP. Call this FIRST to choose the right `domain` for execute_sql.",
    annotations=types.ToolAnnotations(readOnlyHint=True),
)
async def get_schema_guide() -> ResponseType:
    from . import domain_registry
    from .domain_guide import build_schema_guide

    enabled = domain_registry.list_domains() if domain_registry.multi_domain_enabled() else ["tm"]
    return format_text_response(build_schema_guide(enabled))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_domain_guide.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/postgres_mcp/domain_guide.py src/postgres_mcp/server.py tests/unit/test_domain_guide.py
git commit -m "feat(router): LOOP-664 M3 — get_schema_guide tool + curated domain content"
```

---

### Task 6: Domain-aware `list_objects` / `get_object_details` passthrough

**Files:**
- Modify: `src/postgres_mcp/server.py` (`list_objects` ~164, `get_object_details` ~232)
- Test: `tests/unit/test_discovery_passthrough.py`

**Interfaces:**
- Produces: `list_objects(schema_name, object_type="table", domain="tm")` and `get_object_details(schema_name, object_name, object_type="table", domain="tm")` — `tm` unchanged; proxy domains forward the same-named tool to the downstream.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_discovery_passthrough.py
import json
import pytest
from postgres_mcp import server, domain_registry, downstream_client


def _text(resp):
    return "".join(getattr(c, "text", "") for c in resp)


@pytest.fixture(autouse=True)
def _reg(monkeypatch):
    monkeypatch.setenv("MULTI_DOMAIN_ENABLED", "true")
    monkeypatch.setenv("SVC_INTERNAL_MCP_TOKEN", "t")
    monkeypatch.setenv("DOMAIN_REGISTRY_JSON", json.dumps(
        {"igdm": {"base_url": "http://ig:8000", "token_env": "SVC_INTERNAL_MCP_TOKEN", "database": "instagram_auto_dm"}}))
    domain_registry.reload_registry()
    yield
    domain_registry.reload_registry()


@pytest.mark.asyncio
async def test_list_objects_proxies(monkeypatch):
    class _Client:
        async def call_tool(self, name, arguments=None):
            assert name == "list_objects"
            assert arguments == {"schema_name": "public", "object_type": "table"}
            return '["instagram_connections"]'

    async def _get_client(domain):
        return _Client()

    monkeypatch.setattr(downstream_client, "get_downstream_client", _get_client)
    resp = await server.list_objects(schema_name="public", object_type="table", domain="igdm")
    assert _text(resp) == '["instagram_connections"]'
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_discovery_passthrough.py -v`
Expected: FAIL (`list_objects` has no `domain` param)

- [ ] **Step 3: Write minimal implementation**

Add a shared helper near the top of `server.py` (after `get_sql_driver`):

```python
async def _maybe_proxy(domain: str, tool_name: str, arguments: dict) -> ResponseType | None:
    """Return a proxied ResponseType for non-tm domains, or None to fall through to local."""
    from . import domain_registry, downstream_client
    if domain == "tm":
        return None
    if not domain_registry.multi_domain_enabled():
        return format_error_response("multi-domain routing is disabled; only domain='tm' is available.")
    if domain not in domain_registry.list_domains():
        return format_error_response(f"unknown domain '{domain}'. Valid: {', '.join(domain_registry.list_domains())}.")
    client = await downstream_client.get_downstream_client(domain)
    return format_text_response(await client.call_tool(tool_name, arguments))
```

Add `domain: str = Field(description="Target database domain", default="tm")` to `list_objects` and `get_object_details`, and at the top of each body:

```python
    proxied = await _maybe_proxy(domain, "list_objects", {"schema_name": schema_name, "object_type": object_type})
    if proxied is not None:
        return proxied
```

(and the analogous call for `get_object_details` with its arguments). Leave the existing local body below unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_discovery_passthrough.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add src/postgres_mcp/server.py tests/unit/test_discovery_passthrough.py
git commit -m "feat(router): LOOP-664 M3 — domain-aware list_objects/get_object_details"
```

---

### Task 7: Manifest + deploy.sh wiring

**Files:**
- Modify: `eks/manifests/base/deployment-postgres-mcp.yaml`, `eks/deploy.sh`

**Interfaces:** consumed by the running pod: env `MULTI_DOMAIN_ENABLED`, `DOMAIN_REGISTRY_JSON`, `SVC_INTERNAL_MCP_TOKEN`.

- [ ] **Step 1: Add env to the deployment**

In `eks/manifests/base/deployment-postgres-mcp.yaml`, in the `postgres-mcp` container `env:` list, add (default OFF so rollout is inert until flipped):

```yaml
            - name: MULTI_DOMAIN_ENABLED
              value: "false"
            - name: DOMAIN_REGISTRY_JSON
              value: >-
                {"igdm":{"base_url":"http://instagram-mcp-service:8000","token_env":"SVC_INTERNAL_MCP_TOKEN","database":"instagram_auto_dm"},
                 "fin_ledger":{"base_url":"http://postgres-mcp-v2-ledger-service:8000","token_env":"SVC_INTERNAL_MCP_TOKEN","database":"ledger_db"},
                 "fin_payment":{"base_url":"http://postgres-mcp-v2-payment-service:8000","token_env":"SVC_INTERNAL_MCP_TOKEN","database":"payment_db"},
                 "fin_payout":{"base_url":"http://postgres-mcp-v2-payout-service:8000","token_env":"SVC_INTERNAL_MCP_TOKEN","database":"payout_db"}}
            - name: SVC_INTERNAL_MCP_TOKEN
              valueFrom:
                secretKeyRef:
                  name: postgres-mcp-secrets
                  key: svc-internal-mcp-token
```

Confirm the four downstream service names + ports against `kubectl -n postgres-mcp get svc` before committing (adjust `base_url` to the real ClusterIP service DNS + port).

- [ ] **Step 2: Wire the token in deploy.sh**

In `eks/deploy.sh`, where `postgres-mcp-secrets` keys are assembled, add `svc-internal-mcp-token` (fetched from AWS SM, mirroring the existing `person-tokens` / `db-mcp-postgres-token` handling). Register its digest in each downstream's `person-tokens` (same mechanism M1 used for `svc-db-mcp`).

- [ ] **Step 3: Validate manifests render**

Run: `kubectl kustomize eks/manifests/base >/dev/null && echo OK`
Expected: `OK` (no YAML/kustomize errors)

- [ ] **Step 4: Commit**

```bash
git add eks/manifests/base/deployment-postgres-mcp.yaml eks/deploy.sh
git commit -m "chore(infra): LOOP-664 M3 — wire MULTI_DOMAIN_ENABLED + registry + svc token"
```

---

### Task 8: Live smoke test (rollout gate)

**Files:**
- Create: `tests/smoke/run_multidomain_smoke.sh`

- [ ] **Step 1: Verify-first — the fin downstreams are actually connected**

Run (against prod context), for each of `postgres-mcp-v2-ledger/payment/payout`:
```bash
kubectl -n postgres-mcp exec deploy/postgres-mcp-v2-ledger -- \
  sh -lc 'python -c "import os;print(bool(os.environ.get(\"DATABASE_URI\")))"'
```
Expected: `True` for all three. If any is `False`/missing, its `v2-*-database-uri` secret was never provisioned (deploy.sh `|| true`) — provision it before enabling that domain in the registry.

- [ ] **Step 2: Write the smoke script**

```bash
# tests/smoke/run_multidomain_smoke.sh
#!/usr/bin/env bash
set -euo pipefail
BASE="${MCP_BASE:-https://mcp.gabbanext.run/postgres-mcp}"
TOKEN="${POSTGRES_MCP_TOKEN:?set POSTGRES_MCP_TOKEN}"
for dom in tm igdm fin_ledger fin_payment fin_payout; do
  echo "== $dom =="
  npx -y mcp-remote "$BASE/sse" --header "Authorization: Bearer $TOKEN" \
    --tool execute_sql --args "{\"sql\":\"select 1 as ok\",\"domain\":\"$dom\"}" || {
      echo "FAILED: $dom"; exit 1; }
done
echo "get_schema_guide:"
npx -y mcp-remote "$BASE/sse" --header "Authorization: Bearer $TOKEN" --tool get_schema_guide --args '{}'
echo "SMOKE PASS"
```
(If `mcp-remote` lacks a one-shot `--tool` flag in this environment, invoke via the existing `tests/smoke` python harness pattern instead — mirror `tests/smoke/run_smoke.sh`.)

- [ ] **Step 3: Run after flipping the flag**

```bash
kubectl -n postgres-mcp set env deployment/postgres-mcp MULTI_DOMAIN_ENABLED=true
bash tests/smoke/run_multidomain_smoke.sh
```
Expected: `SMOKE PASS` (all five domains return a row; guide lists all domains). Rollback: `kubectl -n postgres-mcp set env deployment/postgres-mcp MULTI_DOMAIN_ENABLED=false`.

- [ ] **Step 4: Commit**

```bash
git add tests/smoke/run_multidomain_smoke.sh
git commit -m "test(smoke): LOOP-664 M3 — multi-domain live smoke + verify-first"
```

---

## Self-Review

**Spec coverage:** D1 routing (Tasks 4,5) · D2 proxy (Tasks 3,4) · D3 extend postgres-mcp (Task 4 modifies server.py) · D4 three fin domains (Tasks 1,5 registry+guide) · D5 all columns visible (no masking code — nothing to build) · D6 v1 5 domains, loop deferred (registry has no loop entry) · D7 backward-compat + flag (Tasks 1,4) · §6 guide content (Task 5) · §9 raw rows + structured errors (Task 4) · §11 rollout verify-first (Task 8).

**Placeholders:** none — all steps carry runnable code/commands. The one "port an existing file" instruction (Task 3) names the exact source path and the exact edits, and appends the full cache code.

**Type consistency:** `DomainEntry`/`get_domain`/`list_domains`/`multi_domain_enabled` used identically across Tasks 1–6; `get_downstream_client(domain)`/`call_tool(name, arguments)` consistent Tasks 3,4,6; `execute_sql(sql, domain="tm")` and `_maybe_proxy(domain, tool_name, arguments)` consistent.

**Open verification (not blockers):** confirm `format_text_response(str)` passes a string through unwrapped (Task 4 note); confirm the four downstream Service DNS names/ports (Task 7 Step 1); confirm `mcp-remote` one-shot invocation form (Task 8).
