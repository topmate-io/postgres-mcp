"""Every database-scoped tool must accept `domain`.

Two independent sessions concluded "there is no Loop database" within an hour of
the loop domain going live. Neither was wrong about what it ran: one queried
pg_database, the other called list_schemas -- and both of those answer for `tm`
no matter which database you are actually asking about. A tool that silently
reports the wrong database is worse than one that errors, because the answer
looks authoritative.

These tests pin the split so a newly added tool cannot quietly join the
tm-only set.
"""

import asyncio

import postgres_mcp.server as s

# Tools whose answer depends on WHICH database is being queried. Each must take
# `domain` and proxy on non-tm.
DB_SCOPED = {
    "execute_sql",
    "list_schemas",
    "list_objects",
    "get_object_details",
    "explain_query",
    "analyze_workload_indexes",
    "analyze_query_indexes",
    "analyze_db_health",
    "get_top_queries",
}

# Tools that return curated Topmate prose or router-level metadata rather than a
# result from the selected database. Proxying these would hand back Topmate
# content labelled as another domain's, so they stay tm-only ON PURPOSE and must
# say so, or a model will call them while reasoning about `loop`.
TM_ONLY = {
    "get_schema_guide",  # the multi-domain routing index itself
    "get_topmate_schema_guide",
    "get_topmate_troubleshooting_guide",
    "get_business_logic_patterns",
}


def _tools():
    # execute_sql is registered at startup rather than by decorator (its
    # annotations depend on access mode), so a bare import leaves it out of
    # list_tools(). Register it here if absent so this module does not depend on
    # whether another test happened to add it first.
    if "execute_sql" not in s.mcp._tool_manager._tools:
        s.mcp.add_tool(s.execute_sql, description="execute_sql")
    return {t.name: t for t in asyncio.run(s.mcp.list_tools())}


def _params(tool):
    return (tool.inputSchema or {}).get("properties", {})


def test_the_two_sets_cover_every_tool():
    # Forces a deliberate choice for any newly added tool instead of it silently
    # defaulting to tm-only.
    assert set(_tools()) == DB_SCOPED | TM_ONLY


def test_every_db_scoped_tool_accepts_domain():
    tools = _tools()
    for name in sorted(DB_SCOPED):
        assert "domain" in _params(tools[name]), f"{name} would silently answer for tm"


def test_db_scoped_tools_default_to_tm_for_backward_compat():
    tools = _tools()
    for name in sorted(DB_SCOPED):
        assert _params(tools[name])["domain"].get("default") == "tm", name


def test_every_db_scoped_tool_names_the_domains_it_accepts():
    # A generic "Target database domain" is what let `loop` ship invisible on
    # list_objects/get_object_details: the model could not tell what to pass.
    tools = _tools()
    for name in sorted(DB_SCOPED):
        desc = _params(tools[name])["domain"].get("description", "")
        assert "'loop'" in desc and "'tm'" in desc, f"{name} does not enumerate domains"


def test_tm_only_tools_declare_that_they_are_tm_only():
    tools = _tools()
    for name in sorted(TM_ONLY - {"get_schema_guide"}):
        desc = (tools[name].description or "").lower()
        assert "only" in desc and "tm" in desc, f"{name} does not say it is tm-only"


def test_domain_field_desc_lists_every_configured_domain():
    # The description is a static string (tool schemas are cached client-side, so
    # it must not vary with env). This is the guard that it did not drift behind
    # the registry the way it did when `loop` was added.
    from postgres_mcp import domain_guide

    for d in domain_guide.ROUTING_TABLE:
        assert f"'{d}'" in s.DOMAIN_FIELD_DESC, f"{d} missing from DOMAIN_FIELD_DESC"
