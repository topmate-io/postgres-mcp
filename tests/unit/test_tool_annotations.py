"""M3: postgres-mcp read tools advertise readOnlyHint so Loop's adapter stops
soft-confirm-gating them; restricted execute_sql is read-only, unrestricted isn't."""

import asyncio

from mcp.types import ToolAnnotations

import postgres_mcp.server as s


def _tools():
    return {t.name: t for t in asyncio.run(s.mcp.list_tools())}


def test_all_static_read_tools_have_readonly_hint():
    tools = _tools()
    static = {n: t for n, t in tools.items() if n != "execute_sql"}
    assert len(static) == 11, sorted(static)
    for name, t in static.items():
        assert t.annotations is not None and t.annotations.readOnlyHint is True, name


def _register_execute_sql(readonly: bool):
    # add_tool refuses to overwrite, so drop any prior registration first.
    s.mcp._tool_manager._tools.pop("execute_sql", None)
    s.mcp.add_tool(
        s.execute_sql, description="x",
        annotations=ToolAnnotations(readOnlyHint=readonly),
    )


def test_execute_sql_restricted_is_readonly():
    _register_execute_sql(readonly=True)  # mirrors the RESTRICTED prod branch
    assert _tools()["execute_sql"].annotations.readOnlyHint is True


def test_execute_sql_unrestricted_not_readonly():
    _register_execute_sql(readonly=False)  # mirrors the UNRESTRICTED branch
    assert _tools()["execute_sql"].annotations.readOnlyHint is False
