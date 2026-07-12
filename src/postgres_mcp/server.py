# ruff: noqa: B008
import argparse
import asyncio
import contextvars
import hmac
import ipaddress
import logging
import os
import signal
import sys
import uuid
from collections import OrderedDict
from enum import Enum
from typing import Any
from typing import List
from typing import Literal
from typing import Union

import mcp.types as types
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field
from pydantic import validate_call

from postgres_mcp.index.dta_calc import DatabaseTuningAdvisor

from . import caller_identity
from .artifacts import ErrorResult
from .artifacts import ExplainPlanArtifact
from .asgi_utils import get_client_ip
from .asgi_utils import get_path
from .audit import AuditLogMiddleware
from .database_health import DatabaseHealthTool
from .database_health import HealthType
from .explain import ExplainPlanTool
from .index.index_opt_base import MAX_NUM_INDEX_TUNING_QUERIES
from .index.llm_opt import LLMOptimizerTool
from .index.presentation import TextPresentation
from .person_auth import PersonAuthMiddleware
from .person_auth import PersonTokenRegistry
from .person_auth import current_person
from .sql import DbConnPool
from .sql import SafeSqlDriver
from .sql import SqlDriver
from .sql import check_hypopg_installation_status
from .sql import obfuscate_password
from .top_queries import TopQueriesCalc
from .topmate_business_logic import TOPMATE_SCHEMA_GUIDE
from .topmate_business_logic import TROUBLESHOOTING_GUIDE
from .topmate_business_logic import TopmateBuisnessLogic

# S1: stateless_http makes the Streamable-HTTP (/mcp) session manager stateless
# so postgres-mcp can run multiple replicas behind the non-sticky in-cluster
# Service. The SSE (/sse) path stays session-bound (external callers unaffected);
# the inter-MCP db-mcp client must therefore use /mcp (POSTGRES_MCP_TRANSPORT=
# streamable_http) once replicas>1. json_response returns JSON on /mcp (mirrors db-mcp).
mcp = FastMCP("postgres-mcp", stateless_http=True, json_response=True)

# Constants
PG_STAT_STATEMENTS = "pg_stat_statements"
HYPOPG_EXTENSION = "hypopg"

ResponseType = List[types.TextContent | types.ImageContent | types.EmbeddedResource]

logger = logging.getLogger(__name__)


class AccessMode(str, Enum):
    """SQL access modes for the server."""

    UNRESTRICTED = "unrestricted"  # Unrestricted access
    RESTRICTED = "restricted"  # Read-only with safety features


# Global variables
db_connection = DbConnPool()
current_access_mode = AccessMode.UNRESTRICTED
shutdown_in_progress = False

# Initialize TopmateBuisnessLogic with graceful fallback
topmate_logic = None
try:
    topmate_logic = TopmateBuisnessLogic()
    logger.info("TopmateBuisnessLogic initialized")
except Exception as e:
    logger.warning(f"Could not initialize TopmateBuisnessLogic: {e}")
    topmate_logic = None


async def get_sql_driver() -> Union[SqlDriver, SafeSqlDriver]:
    """Get the appropriate SQL driver based on the current access mode."""
    base_driver = SqlDriver(conn=db_connection)

    if current_access_mode == AccessMode.RESTRICTED:
        logger.debug("Using SafeSqlDriver with restrictions (RESTRICTED mode)")
        return SafeSqlDriver(sql_driver=base_driver, timeout=30)  # 30 second timeout
    else:
        logger.debug("Using unrestricted SqlDriver (UNRESTRICTED mode)")
        return base_driver


def format_text_response(text: Any) -> ResponseType:
    """Format a text response."""
    return [types.TextContent(type="text", text=str(text))]


def _sanitize_error(error: str) -> str:
    """Map internal errors to user-friendly messages."""
    e_lower = error.lower()
    # Check specific Postgres error classes BEFORE generic keyword matching,
    # otherwise table names like "instagram_connections" match "connect" and
    # produce a misleading "temporarily unavailable" message.
    if "does not exist" in e_lower:
        return f"Object not found: {error.split('does not exist')[0].strip().split()[-1] if 'does not exist' in error else 'unknown'}"
    if "syntax" in e_lower:
        return "Invalid query syntax. Please check your SQL."
    if "permission" in e_lower or "denied" in e_lower:
        return "Permission denied for this operation."
    if "duplicate" in e_lower:
        return "Duplicate entry — this record already exists."
    if any(
        k in e_lower
        for k in ("connection refused", "could not connect", "connection reset", "name resolution", "network unreachable", "timeout expired")
    ):
        return "Database temporarily unavailable. Please try again in a moment."
    if "timeout" in e_lower or "cancel" in e_lower:
        return "Query took too long. Try a more specific query with filters or a LIMIT clause."
    # Generic fallback — don't leak internals
    logger.debug("Sanitized error (original): %s", error)
    return "An unexpected error occurred. Please try again or refine your query."


def format_error_response(error: str) -> ResponseType:
    """Format a user-friendly error response (sanitized)."""
    return format_text_response(f"Error: {_sanitize_error(error)}")


@mcp.tool(description="List all schemas in the database", annotations=types.ToolAnnotations(readOnlyHint=True))
async def list_schemas() -> ResponseType:
    """List all schemas in the database."""
    try:
        sql_driver = await get_sql_driver()
        rows = await sql_driver.execute_query(
            """
            SELECT
                schema_name,
                schema_owner,
                CASE
                    WHEN schema_name LIKE 'pg_%' THEN 'System Schema'
                    WHEN schema_name = 'information_schema' THEN 'System Information Schema'
                    ELSE 'User Schema'
                END as schema_type
            FROM information_schema.schemata
            ORDER BY schema_type, schema_name
            """
        )
        schemas = [row.cells for row in rows] if rows else []
        return format_text_response(schemas)
    except Exception as e:
        logger.error(f"Error listing schemas: {e}")
        return format_error_response(str(e))


@mcp.tool(description="List objects in a schema", annotations=types.ToolAnnotations(readOnlyHint=True))
async def list_objects(
    schema_name: str = Field(description="Schema name"),
    object_type: str = Field(description="Object type: 'table', 'view', 'sequence', or 'extension'", default="table"),
) -> ResponseType:
    """List objects of a given type in a schema."""
    try:
        sql_driver = await get_sql_driver()

        if object_type in ("table", "view"):
            table_type = "BASE TABLE" if object_type == "table" else "VIEW"
            rows = await SafeSqlDriver.execute_param_query(
                sql_driver,
                """
                SELECT table_schema, table_name, table_type
                FROM information_schema.tables
                WHERE table_schema = {} AND table_type = {}
                ORDER BY table_name
                """,
                [schema_name, table_type],
            )
            objects = (
                [{"schema": row.cells["table_schema"], "name": row.cells["table_name"], "type": row.cells["table_type"]} for row in rows]
                if rows
                else []
            )

        elif object_type == "sequence":
            rows = await SafeSqlDriver.execute_param_query(
                sql_driver,
                """
                SELECT sequence_schema, sequence_name, data_type
                FROM information_schema.sequences
                WHERE sequence_schema = {}
                ORDER BY sequence_name
                """,
                [schema_name],
            )
            objects = (
                [{"schema": row.cells["sequence_schema"], "name": row.cells["sequence_name"], "data_type": row.cells["data_type"]} for row in rows]
                if rows
                else []
            )

        elif object_type == "extension":
            # Extensions are not schema-specific
            rows = await sql_driver.execute_query(
                """
                SELECT extname, extversion, extrelocatable
                FROM pg_extension
                ORDER BY extname
                """
            )
            objects = (
                [{"name": row.cells["extname"], "version": row.cells["extversion"], "relocatable": row.cells["extrelocatable"]} for row in rows]
                if rows
                else []
            )

        else:
            return format_error_response(f"Unsupported object type: {object_type}")

        return format_text_response(objects)
    except Exception as e:
        logger.error(f"Error listing objects: {e}")
        return format_error_response(str(e))


@mcp.tool(description="Show detailed information about a database object", annotations=types.ToolAnnotations(readOnlyHint=True))
async def get_object_details(
    schema_name: str = Field(description="Schema name"),
    object_name: str = Field(description="Object name"),
    object_type: str = Field(description="Object type: 'table', 'view', 'sequence', or 'extension'", default="table"),
) -> ResponseType:
    """Get detailed information about a database object."""
    try:
        sql_driver = await get_sql_driver()

        if object_type in ("table", "view"):
            # Get columns
            col_rows = await SafeSqlDriver.execute_param_query(
                sql_driver,
                """
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = {} AND table_name = {}
                ORDER BY ordinal_position
                """,
                [schema_name, object_name],
            )
            columns = (
                [
                    {
                        "column": r.cells["column_name"],
                        "data_type": r.cells["data_type"],
                        "is_nullable": r.cells["is_nullable"],
                        "default": r.cells["column_default"],
                    }
                    for r in col_rows
                ]
                if col_rows
                else []
            )

            # Get constraints
            con_rows = await SafeSqlDriver.execute_param_query(
                sql_driver,
                """
                SELECT tc.constraint_name, tc.constraint_type, kcu.column_name
                FROM information_schema.table_constraints AS tc
                LEFT JOIN information_schema.key_column_usage AS kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                WHERE tc.table_schema = {} AND tc.table_name = {}
                """,
                [schema_name, object_name],
            )

            constraints = {}
            if con_rows:
                for row in con_rows:
                    cname = row.cells["constraint_name"]
                    ctype = row.cells["constraint_type"]
                    col = row.cells["column_name"]

                    if cname not in constraints:
                        constraints[cname] = {"type": ctype, "columns": []}
                    if col:
                        constraints[cname]["columns"].append(col)

            constraints_list = [{"name": name, **data} for name, data in constraints.items()]

            # Get indexes
            idx_rows = await SafeSqlDriver.execute_param_query(
                sql_driver,
                """
                SELECT indexname, indexdef
                FROM pg_indexes
                WHERE schemaname = {} AND tablename = {}
                """,
                [schema_name, object_name],
            )

            indexes = [{"name": r.cells["indexname"], "definition": r.cells["indexdef"]} for r in idx_rows] if idx_rows else []

            result = {
                "basic": {"schema": schema_name, "name": object_name, "type": object_type},
                "columns": columns,
                "constraints": constraints_list,
                "indexes": indexes,
            }

        elif object_type == "sequence":
            rows = await SafeSqlDriver.execute_param_query(
                sql_driver,
                """
                SELECT sequence_schema, sequence_name, data_type, start_value, increment
                FROM information_schema.sequences
                WHERE sequence_schema = {} AND sequence_name = {}
                """,
                [schema_name, object_name],
            )

            if rows and rows[0]:
                row = rows[0]
                result = {
                    "schema": row.cells["sequence_schema"],
                    "name": row.cells["sequence_name"],
                    "data_type": row.cells["data_type"],
                    "start_value": row.cells["start_value"],
                    "increment": row.cells["increment"],
                }
            else:
                result = {}

        elif object_type == "extension":
            rows = await SafeSqlDriver.execute_param_query(
                sql_driver,
                """
                SELECT extname, extversion, extrelocatable
                FROM pg_extension
                WHERE extname = {}
                """,
                [object_name],
            )

            if rows and rows[0]:
                row = rows[0]
                result = {"name": row.cells["extname"], "version": row.cells["extversion"], "relocatable": row.cells["extrelocatable"]}
            else:
                result = {}

        else:
            return format_error_response(f"Unsupported object type: {object_type}")

        return format_text_response(result)
    except Exception as e:
        logger.error(f"Error getting object details: {e}")
        return format_error_response(str(e))


@mcp.tool(
    description="Explains the execution plan for a SQL query, showing how the database will execute it and provides detailed cost estimates.",
    annotations=types.ToolAnnotations(readOnlyHint=True),
)
async def explain_query(
    sql: str = Field(description="SQL query to explain"),
    analyze: bool = Field(
        description="When True, actually runs the query to show real execution statistics instead of estimates. "
        "Takes longer but provides more accurate information.",
        default=False,
    ),
    hypothetical_indexes: list[dict[str, Any]] = Field(
        description="""A list of hypothetical indexes to simulate. Each index must be a dictionary with these keys:
    - 'table': The table name to add the index to (e.g., 'users')
    - 'columns': List of column names to include in the index (e.g., ['email'] or ['last_name', 'first_name'])
    - 'using': Optional index method (default: 'btree', other options include 'hash', 'gist', etc.)

Examples: [
    {"table": "users", "columns": ["email"], "using": "btree"},
    {"table": "orders", "columns": ["user_id", "created_at"]}
]
If there is no hypothetical index, you can pass an empty list.""",
        default=[],
    ),
) -> ResponseType:
    """
    Explains the execution plan for a SQL query.

    Args:
        sql: The SQL query to explain
        analyze: When True, actually runs the query for real statistics
        hypothetical_indexes: Optional list of indexes to simulate
    """
    try:
        sql_driver = await get_sql_driver()
        explain_tool = ExplainPlanTool(sql_driver=sql_driver)
        result: ExplainPlanArtifact | ErrorResult | None = None

        # If hypothetical indexes are specified, check for HypoPG extension
        if hypothetical_indexes and len(hypothetical_indexes) > 0:
            if analyze:
                return format_error_response("Cannot use analyze and hypothetical indexes together")
            try:
                # Use the common utility function to check if hypopg is installed
                (
                    is_hypopg_installed,
                    hypopg_message,
                ) = await check_hypopg_installation_status(sql_driver)

                # If hypopg is not installed, return the message
                if not is_hypopg_installed:
                    return format_text_response(hypopg_message)

                # HypoPG is installed, proceed with explaining with hypothetical indexes
                result = await explain_tool.explain_with_hypothetical_indexes(sql, hypothetical_indexes)
            except Exception:
                raise  # Re-raise the original exception
        elif analyze:
            try:
                # Use EXPLAIN ANALYZE
                result = await explain_tool.explain_analyze(sql)
            except Exception:
                raise  # Re-raise the original exception
        else:
            try:
                # Use basic EXPLAIN
                result = await explain_tool.explain(sql)
            except Exception:
                raise  # Re-raise the original exception

        if result and isinstance(result, ExplainPlanArtifact):
            return format_text_response(result.to_text())
        else:
            error_message = "Error processing explain plan"
            if isinstance(result, ErrorResult):
                error_message = result.to_text()
            return format_error_response(error_message)
    except Exception as e:
        logger.error(f"Error explaining query: {e}")
        return format_error_response(str(e))


# Query function declaration without the decorator - we'll add it dynamically based on access mode
async def execute_sql(
    sql: str = Field(description="SQL to run", default="all"),
) -> ResponseType:
    """Executes a SQL query against the database."""
    try:
        sql_driver = await get_sql_driver()
        rows = await sql_driver.execute_query(sql)  # type: ignore
        if rows is None:
            return format_text_response("No results")
        return format_text_response(list([r.cells for r in rows]))
    except Exception as e:
        logger.error(f"Error executing query: {e}")
        return format_error_response(str(e))


@mcp.tool(
    description="Analyze frequently executed queries in the database and recommend optimal indexes",
    annotations=types.ToolAnnotations(readOnlyHint=True),
)
@validate_call
async def analyze_workload_indexes(
    max_index_size_mb: int = Field(description="Max index size in MB", default=10000),
    method: Literal["dta", "llm"] = Field(description="Method to use for analysis", default="dta"),
) -> ResponseType:
    """Analyze frequently executed queries in the database and recommend optimal indexes."""
    try:
        sql_driver = await get_sql_driver()
        if method == "dta":
            index_tuning = DatabaseTuningAdvisor(sql_driver)
        else:
            index_tuning = LLMOptimizerTool(sql_driver)
        dta_tool = TextPresentation(sql_driver, index_tuning)
        result = await dta_tool.analyze_workload(max_index_size_mb=max_index_size_mb)
        return format_text_response(result)
    except Exception as e:
        logger.error(f"Error analyzing workload: {e}")
        return format_error_response(str(e))


@mcp.tool(description="Analyze a list of (up to 10) SQL queries and recommend optimal indexes", annotations=types.ToolAnnotations(readOnlyHint=True))
@validate_call
async def analyze_query_indexes(
    queries: list[str] = Field(description="List of Query strings to analyze"),
    max_index_size_mb: int = Field(description="Max index size in MB", default=10000),
    method: Literal["dta", "llm"] = Field(description="Method to use for analysis", default="dta"),
) -> ResponseType:
    """Analyze a list of SQL queries and recommend optimal indexes."""
    if len(queries) == 0:
        return format_error_response("Please provide a non-empty list of queries to analyze.")
    if len(queries) > MAX_NUM_INDEX_TUNING_QUERIES:
        return format_error_response(f"Please provide a list of up to {MAX_NUM_INDEX_TUNING_QUERIES} queries to analyze.")

    try:
        sql_driver = await get_sql_driver()
        if method == "dta":
            index_tuning = DatabaseTuningAdvisor(sql_driver)
        else:
            index_tuning = LLMOptimizerTool(sql_driver)
        dta_tool = TextPresentation(sql_driver, index_tuning)
        result = await dta_tool.analyze_queries(queries=queries, max_index_size_mb=max_index_size_mb)
        return format_text_response(result)
    except Exception as e:
        logger.error(f"Error analyzing queries: {e}")
        return format_error_response(str(e))


@mcp.tool(
    description="Analyzes database health. Here are the available health checks:\n"
    "- index - checks for invalid, duplicate, and bloated indexes\n"
    "- connection - checks the number of connection and their utilization\n"
    "- vacuum - checks vacuum health for transaction id wraparound\n"
    "- sequence - checks sequences at risk of exceeding their maximum value\n"
    "- replication - checks replication health including lag and slots\n"
    "- buffer - checks for buffer cache hit rates for indexes and tables\n"
    "- constraint - checks for invalid constraints\n"
    "- all - runs all checks\n"
    "You can optionally specify a single health check or a comma-separated list of health checks. The default is 'all' checks.",
    annotations=types.ToolAnnotations(readOnlyHint=True),
)
async def analyze_db_health(
    health_type: str = Field(
        description=f"Optional. Valid values are: {', '.join(sorted([t.value for t in HealthType]))}.",
        default="all",
    ),
) -> ResponseType:
    """Analyze database health for specified components.

    Args:
        health_type: Comma-separated list of health check types to perform.
                    Valid values: index, connection, vacuum, sequence, replication, buffer, constraint, all
    """
    health_tool = DatabaseHealthTool(await get_sql_driver())
    result = await health_tool.health(health_type=health_type)
    return format_text_response(result)


@mcp.tool(
    name="get_top_queries",
    description=f"Reports the slowest or most resource-intensive queries using data from the '{PG_STAT_STATEMENTS}' extension.",
    annotations=types.ToolAnnotations(readOnlyHint=True),
)
async def get_top_queries(
    sort_by: str = Field(
        description="Ranking criteria: 'total_time' for total execution time or 'mean_time' for mean execution time per call, or 'resources' "
        "for resource-intensive queries",
        default="resources",
    ),
    limit: int = Field(description="Number of queries to return when ranking based on mean_time or total_time", default=10),
) -> ResponseType:
    try:
        sql_driver = await get_sql_driver()
        top_queries_tool = TopQueriesCalc(sql_driver=sql_driver)

        if sort_by == "resources":
            result = await top_queries_tool.get_top_resource_queries()
            return format_text_response(result)
        elif sort_by == "mean_time" or sort_by == "total_time":
            # Map the sort_by values to what get_top_queries_by_time expects
            result = await top_queries_tool.get_top_queries_by_time(limit=limit, sort_by="mean" if sort_by == "mean_time" else "total")
        else:
            return format_error_response("Invalid sort criteria. Please use 'resources' or 'mean_time' or 'total_time'.")
        return format_text_response(result)
    except Exception as e:
        logger.error(f"Error getting slow queries: {e}")
        return format_error_response(str(e))


@mcp.tool(
    name="get_topmate_schema_guide",
    description="Returns Topmate database schema reference with table descriptions, key columns, "
    "common filters, and pre-built SQL query templates for GMV, bookings, and user metrics.",
    annotations=types.ToolAnnotations(readOnlyHint=True),
)
async def get_topmate_schema_guide() -> ResponseType:
    """Get Topmate database schema guide and SQL patterns.

    This tool provides:
    - Core table descriptions (booking_booking, user_user, services_service, etc.)
    - Key columns and their purposes
    - Common filters for each table
    - Pre-built SQL templates for GMV, expert earnings, user growth
    """
    return format_text_response(TOPMATE_SCHEMA_GUIDE)


@mcp.tool(
    name="get_topmate_troubleshooting_guide",
    description="Provides troubleshooting guidance for common SQL issues when querying Topmate database. "
    "Covers slow queries, incorrect results, complex aggregations, booking queries, and user metrics.",
    annotations=types.ToolAnnotations(readOnlyHint=True),
)
async def get_topmate_troubleshooting_guide() -> ResponseType:
    """Get troubleshooting guide for Topmate SQL queries.

    Returns guidance for common issues including:
    - Slow query optimization
    - Incorrect result debugging
    - Complex aggregation fixes
    - Booking/GMV query patterns
    - User metrics accuracy
    """
    return format_text_response(TROUBLESHOOTING_GUIDE)


@mcp.tool(
    name="get_business_logic_patterns",
    description="Provides comprehensive business logic patterns and SQL query guidance for complex scenarios. "
    "Fetches from Topmate Logic Hub API (requires TOPMATE_LOGIC_HUB_BASE_URL and TOPMATE_LOGIC_HUB_API_KEY environment variables). "
    "Returns business logic patterns, rules, and SQL query guidance.",
    annotations=types.ToolAnnotations(readOnlyHint=True),
)
async def get_business_logic_patterns() -> ResponseType:
    """Get business logic patterns and SQL guidance from Topmate Logic Hub.

    This tool fetches dynamic patterns from the external Topmate Logic Hub API
    when TOPMATE_LOGIC_HUB credentials are configured.
    """
    if topmate_logic is None:
        return format_error_response(
            "TopmateBuisnessLogic service not available. Please check that TOPMATE_LOGIC_HUB_BASE_URL and TOPMATE_LOGIC_HUB_API_KEY environment variables are set."
        )

    try:
        rules = await topmate_logic.get_rules()
        patterns = await topmate_logic.get_patterns()
        return format_text_response(
            {
                "description": "Business logic patterns for complex SQL queries",
                "basic_rules": [rule.get("description") for rule in rules] if isinstance(rules, list) else rules,
                "patterns": {p.get("pattern_name"): p.get("pattern_data") for p in patterns} if isinstance(patterns, list) else patterns,
            }
        )
    except Exception as e:
        logger.error(f"Error getting business logic patterns: {e}")
        return format_error_response(str(e))


# Add health check middleware for load balancers
# FastMCP is an MCP protocol server, not HTTP, so we need ASGI middleware
# to handle health check requests from load balancers


# ---------------------------------------------------------------------------
# Request correlation ID
# ---------------------------------------------------------------------------

_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")


class RequestIDLogFilter(logging.Filter):
    """Inject the current request_id into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id_var.get("")  # type: ignore[attr-defined]
        return True


class RequestIDMiddleware:
    """ASGI middleware that assigns a correlation ID to every HTTP request.

    * Reads ``X-Request-ID`` from the incoming request, or generates a UUID4.
    * Stores the ID in a ``contextvars.ContextVar`` so loggers can include it.
    * Injects ``X-Request-ID`` into the response headers for downstream correlation.
    """

    HEALTH_PATHS = {"/", "/health", "/healthz"}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract or generate request ID
        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        req_id = headers.get(b"x-request-id", b"").decode("latin-1").strip()
        if not req_id:
            req_id = uuid.uuid4().hex[:16]

        token = _request_id_var.set(req_id)
        try:

            async def send_with_request_id(message):
                if message["type"] == "http.response.start":
                    extra = [[b"x-request-id", req_id.encode()]]
                    message = dict(message, headers=list(message.get("headers", [])) + extra)
                await send(message)

            await self.app(scope, receive, send_with_request_id)
        finally:
            _request_id_var.reset(token)


class CORSMiddleware:
    """ASGI middleware that handles CORS preflight and response headers.

    Reads allowed origins from the CORS_ORIGINS env var (comma-separated).
    If CORS_ORIGINS is empty/unset, CORS handling is disabled (server-to-server only).
    """

    def __init__(self, app):
        self.app = app
        raw = os.getenv("CORS_ORIGINS", "").strip()
        self.allowed_origins: set[str] = {o.strip() for o in raw.split(",") if o.strip()} if raw else set()

    async def __call__(self, scope, receive, send):
        if not self.allowed_origins or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers_dict = {name.lower(): value for name, value in scope.get("headers", [])}
        origin = headers_dict.get(b"origin", b"").decode("latin-1")

        if origin not in self.allowed_origins:
            # Not a recognised origin — pass through without CORS headers
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")

        # Preflight
        if method == "OPTIONS":
            await send(
                {
                    "type": "http.response.start",
                    "status": 204,
                    "headers": [
                        [b"access-control-allow-origin", origin.encode()],
                        [b"access-control-allow-methods", b"GET, POST, OPTIONS"],
                        [b"access-control-allow-headers", b"Authorization, Content-Type"],
                        [b"access-control-max-age", b"86400"],
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return

        # Normal request — inject CORS headers into the response
        async def send_with_cors(message):
            if message["type"] == "http.response.start":
                extra = [
                    [b"access-control-allow-origin", origin.encode()],
                ]
                message = dict(message, headers=list(message.get("headers", [])) + extra)
            await send(message)

        await self.app(scope, receive, send_with_cors)


class RateLimiterMiddleware:
    """Token-bucket rate limiter keyed on authenticated identity (LOOP-664 M1).

    Bucket key: ``person:<name>`` when PersonAuth resolved a caller, else
    ``ip:<client-ip>``. Identity comes ONLY from the current_person contextvar
    (set post-authentication) — never from request headers, which callers
    control. The bucket store is a bounded LRU (MAX_BUCKETS) so many distinct
    keys over a pod's lifetime cannot grow memory without bound.

    Exempt paths: health checks. Exceeding the rate returns 429 + Retry-After.
    """

    HEALTH_PATHS = {"/", "/health", "/healthz"}
    MAX_BUCKETS = 1024

    def __init__(self, app, max_requests: int = 30, window_seconds: int = 60):
        self.app = app
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: OrderedDict[str, list] = OrderedDict()  # key -> [tokens, last_refill]
        self._lock = asyncio.Lock()

    def _bucket_key(self, scope) -> str:
        person = current_person.get()
        if person:
            return f"person:{person}"
        return f"ip:{get_client_ip(scope)}"

    def _consume(self, key: str) -> bool:
        import time as _time

        now = _time.monotonic()
        bucket = self._buckets.get(key)
        if bucket is None:
            while len(self._buckets) >= self.MAX_BUCKETS:
                self._buckets.popitem(last=False)  # evict least-recently-used key
            bucket = [float(self.max_requests), now]
            self._buckets[key] = bucket
        else:
            self._buckets.move_to_end(key)
        tokens, last = bucket
        elapsed = now - last
        refill_rate = self.max_requests / self.window_seconds
        tokens = min(self.max_requests, tokens + elapsed * refill_rate)
        bucket[1] = now
        if tokens >= 1.0:
            bucket[0] = tokens - 1.0
            return True
        bucket[0] = tokens
        return False

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = get_path(scope)
            if path not in self.HEALTH_PATHS:
                key = self._bucket_key(scope)
                async with self._lock:
                    allowed = self._consume(key)
                if not allowed:
                    logger.warning("Rate limit exceeded for %s", key)
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 429,
                            "headers": [
                                [b"content-type", b"application/json"],
                                [b"retry-after", str(self.window_seconds).encode()],
                            ],
                        }
                    )
                    await send(
                        {
                            "type": "http.response.body",
                            "body": b'{"error":"too_many_requests","message":"Rate limit exceeded"}',
                        }
                    )
                    return
        await self.app(scope, receive, send)


class IPAllowlistMiddleware:
    """ASGI middleware that restricts access to allowed IPs/CIDRs.

    Three ways to pass:
      1. Client IP is in ``ALLOWED_IPS`` (CIDRs read from env).
      2. Request carries a valid ``Authorization: Bearer <AUTH_TOKEN>`` — the
         shared static token (legacy, retired in M4).
      3. Request carries a valid per-person token (LOOP-664): when a non-empty
         ``PersonTokenRegistry`` is injected, any token it recognises grants the
         same IP bypass. A person token is a stronger, revocable credential, so
         — like ``AUTH_TOKEN`` — it lets a caller reach the service from a
         non-whitelisted host. This is independent of ``PERSON_AUTH_ENABLED``,
         which governs whether a person token is *required*, not whether it
         grants network access.

    Health check paths are always exempt so ALB probes continue working.
    If ``ALLOWED_IPS`` is empty, all traffic is allowed (backwards compatible);
    the bearer bypasses only matter once an allowlist is configured.
    """

    HEALTH_PATHS = {"/", "/health", "/healthz"}

    def __init__(self, app, registry: "PersonTokenRegistry | None" = None):
        self.app = app
        self.allowed_networks = self._load_allowed_ips()
        self._auth_token = os.getenv("AUTH_TOKEN", "").strip()
        self._person_registry = registry
        if self._auth_token:
            logger.info("IP allowlist: static Bearer token bypass enabled")
        if self._person_registry is not None and len(self._person_registry) > 0:
            logger.info(
                "IP allowlist: person-token bypass enabled (%d token(s))",
                len(self._person_registry),
            )

    def _load_allowed_ips(self):
        raw = os.getenv("ALLOWED_IPS", "").strip()
        if not raw:
            return None  # None = allow all
        networks = []
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if "/" not in entry:
                entry += "/32"  # Single IP -> /32 CIDR
            networks.append(ipaddress.ip_network(entry, strict=False))
        if networks:
            logger.info(f"IP allowlist loaded: {[str(n) for n in networks]}")
        return networks if networks else None

    def _get_client_ip(self, scope):
        """Extract real client IP. Priority: CF-Connecting-IP > X-Forwarded-For[0] > ASGI client.

        Traffic flows: Client → Cloudflare → ALB → Pod.
        CF-Connecting-IP is set by Cloudflare and cannot be spoofed by the client.
        X-Forwarded-For[0] is the first (client-set) IP — less trustworthy but
        works when Cloudflare is not in the path.
        """
        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        # Prefer Cloudflare's trusted header
        cf_ip = headers.get(b"cf-connecting-ip")
        if cf_ip:
            return cf_ip.decode("latin-1").strip()
        # Fallback to first XFF IP
        xff = headers.get(b"x-forwarded-for")
        if xff:
            return xff.decode("latin-1").split(",")[0].strip()
        # Fallback to ASGI client
        client = scope.get("client")
        return client[0] if client else None

    def _is_allowed(self, ip_str):
        if self.allowed_networks is None:
            return True
        if not ip_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self.allowed_networks)
        except ValueError:
            return False

    def _get_path(self, scope):
        """Get the request path, stripping known ALB prefixes."""
        path = scope.get("path", "")
        for prefix in ("/postgres-mcp", "/db-mcp", "/instagram-mcp"):
            if path.startswith(prefix):
                return path[len(prefix) :] or "/"
        return path

    @staticmethod
    def _extract_bearer(scope) -> str:
        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        auth = headers.get(b"authorization", b"").decode("latin-1")
        if not auth.startswith("Bearer "):
            return ""
        return auth[len("Bearer ") :].strip()

    def _has_valid_bearer(self, scope) -> bool:
        """Return True when the request carries a bearer that grants an IP bypass.

        Accepts either the shared static ``AUTH_TOKEN`` or any token the injected
        ``PersonTokenRegistry`` recognises. Both comparisons are constant-time
        (``hmac.compare_digest`` directly, and inside ``registry.verify``).
        """
        presented = self._extract_bearer(scope)
        if not presented:
            return False
        if self._auth_token and hmac.compare_digest(presented, self._auth_token):
            return True
        if self._person_registry is not None and self._person_registry.verify(presented) is not None:
            return True
        return False

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and self.allowed_networks is not None:
            path = self._get_path(scope)

            # Always allow health check paths (ALB probes)
            if path not in self.HEALTH_PATHS:
                client_ip = self._get_client_ip(scope)

                if not self._is_allowed(client_ip) and not self._has_valid_bearer(scope):
                    logger.warning(f"Blocked request from {client_ip} to {scope.get('path', '')}")
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 403,
                            "headers": [[b"content-type", b"application/json"]],
                        }
                    )
                    await send(
                        {
                            "type": "http.response.body",
                            "body": b'{"error":"forbidden","message":"IP not allowed"}',
                        }
                    )
                    return

        await self.app(scope, receive, send)


class CallerIdentityMiddleware:
    """Capture the forwarded end-user identity and gate admin-only tools.

    postgres-mcp exposes only DB-admin tools (raw SQL / DB internals) — none can
    be safely per-creator-scoped. Policy:

    * No ``X-User-Scope`` header  -> legacy caller -> pass through unchanged.
    * Authenticated superadmin     -> pass through (full access).
    * ``X-User-Scope`` present but token invalid -> 401.
    * Any other resolved scope     -> 403 (defense-in-depth; admin-only server).

    Disabled entirely when ``CALLER_SCOPE_ENABLED=false``. The decision is made at
    the ASGI layer (works for both SSE and Streamable HTTP), so it does not depend
    on the contextvar reaching the tool coroutine.
    """

    HEALTH_PATHS = {"/", "/health", "/healthz"}

    def __init__(self, app):
        self.app = app
        self.enabled = os.getenv("CALLER_SCOPE_ENABLED", "true").lower() != "false"
        self._auth_token = os.getenv("AUTH_TOKEN", "").strip()
        self._sa_emails = caller_identity.superadmin_emails_from_env()
        self._sa_tokens = caller_identity.superadmin_tokens_from_env()
        # G1/G3 signed-identity gate (default off).
        self._require_signed = caller_identity.require_signed_identity_from_env()
        self._identity_pubkey = caller_identity.identity_jwt_public_key_from_env()
        self._identity_aud = caller_identity.identity_jwt_audience_from_env()
        self._identity_leeway = caller_identity.identity_jwt_leeway_from_env()
        if self._require_signed and not self._identity_pubkey:
            logger.critical(
                "REQUIRE_SIGNED_IDENTITY=true but no IDENTITY_JWT_PUBLIC_KEY[_PATH] "
                "configured; all trusted-transport callers will be rejected (fail-closed)."
            )

    def _get_path(self, scope):
        path = scope.get("path", "")
        for prefix in ("/postgres-mcp", "/db-mcp", "/instagram-mcp"):
            if path.startswith(prefix):
                return path[len(prefix) :] or "/"
        return path

    async def _deny(self, send, status, err, msg):
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [[b"content-type", b"application/json"]],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": f'{{"error":"{err}","message":"{msg}"}}'.encode(),
            }
        )

    async def __call__(self, scope, receive, send):
        if not self.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if self._get_path(scope) in self.HEALTH_PATHS:
            await self.app(scope, receive, send)
            return

        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        transport_trusted = caller_identity.is_transport_trusted(headers, auth_token=self._auth_token, superadmin_tokens=self._sa_tokens)
        # P2: pre-resolve a Tier-2 galactus token OFF the event loop so the
        # blocking HTTP call doesn't freeze the single replica; hand
        # resolve_identity a memoized validator so it stays pure/sync.
        scheme, cred = caller_identity.parse_auth(headers)
        token_validator = caller_identity.validate_token
        if not transport_trusted and scheme == "token" and cred:
            _profile = await caller_identity.validate_token_async(cred)
            token_validator = lambda _t, _p=_profile: _p  # noqa: E731
        # G1/G3: verify the signed identity JWT (CPU-only) when the gate is on.
        signed_claims = None
        if self._require_signed:
            signed_claims = caller_identity.verify_signed_identity(
                headers,
                public_key=self._identity_pubkey,
                audience=self._identity_aud,
                leeway=self._identity_leeway,
            )
        ident = caller_identity.resolve_identity(
            headers,
            validate_token=token_validator,
            transport_trusted=transport_trusted,
            superadmin_emails=self._sa_emails,
            signed_claims=signed_claims,
            require_signed=self._require_signed,
        )
        ctx_token = caller_identity.caller_ctx.set(ident)
        try:
            sc = ident["scope"]
            if sc is None or sc == "superadmin":
                await self.app(scope, receive, send)  # legacy or admin -> unchanged
                return
            if sc == caller_identity.INVALID:
                logger.warning("postgres-mcp: scoped caller presented an invalid end-user token")
                await self._deny(send, 401, "unauthorized", "Invalid end-user token")
                return
            logger.warning("postgres-mcp: rejecting non-superadmin scope=%s on admin-only server", sc)
            await self._deny(send, 403, "forbidden", "postgres-mcp tools are superadmin-only")
            return
        finally:
            caller_identity.caller_ctx.reset(ctx_token)


class SSEKeepAliveMiddleware:
    """ASGI middleware that injects SSE keep-alive pings for long-lived connections.

    Cloud Run and other load balancers terminate idle SSE connections after ~25s.
    This middleware wraps the SSE endpoint's `send` callable to start a background
    task that sends SSE comment pings (`:ping\\n\\n`) every `interval` seconds,
    keeping the connection alive through any intermediary proxy.
    """

    def __init__(self, app, interval: int = 15):
        self.app = app
        self.interval = interval

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        # Only apply keep-alive to the SSE event stream endpoint
        if path != "/sse":
            await self.app(scope, receive, send)
            return

        ping_task = None
        response_started = False

        async def send_wrapper(message):
            nonlocal ping_task, response_started

            if message["type"] == "http.response.start":
                response_started = True
                await send(message)
                return

            if message["type"] == "http.response.body":
                # Start pinging after the first body chunk (SSE stream opened)
                if response_started and ping_task is None and message.get("more_body", True) is not False:
                    ping_task = asyncio.create_task(self._ping_loop(send))
                await send(message)
                return

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            if ping_task is not None:
                ping_task.cancel()
                try:
                    await ping_task
                except asyncio.CancelledError:
                    pass

    async def _ping_loop(self, send):
        """Send SSE comment pings at regular intervals."""
        while True:
            await asyncio.sleep(self.interval)
            try:
                await send(
                    {
                        "type": "http.response.body",
                        "body": b":ping\n\n",
                        "more_body": True,
                    }
                )
            except (OSError, BrokenPipeError, ConnectionResetError, RuntimeError):
                # Connection closed or broken pipe, stop pinging
                logger.debug("SSE ping loop ended: connection closed")
                break
            except asyncio.CancelledError:
                raise


class HealthCheckMiddleware:
    """ASGI middleware to handle health checks and strip path prefixes.

    ALB ingress forwards requests with the full path (e.g. /postgres-mcp/sse).
    This middleware strips known prefixes so FastMCP sees the expected paths.
    """

    PATH_PREFIXES = ("/postgres-mcp", "/db-mcp", "/instagram-mcp")

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            method = scope.get("method", "")

            # Strip ALB ingress path prefix before any routing
            # Set root_path so SSE transport includes the prefix in endpoint URLs
            for prefix in self.PATH_PREFIXES:
                if path.startswith(prefix):
                    path = path[len(prefix) :] or "/"
                    scope = dict(scope, path=path, root_path=prefix)
                    break

            # Simple health check for root path
            if method == "GET" and path == "/":
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            [b"content-type", b"application/json"],
                            [b"cache-control", b"no-store"],
                        ],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b'{"status":"ok"}',
                    }
                )
                return

            # Readiness (k8s readinessProbe + ALB target healthcheck): CHEAP —
            # checks in-memory pool state only, never acquires a pooled
            # connection. The old live `SELECT 1` queued behind a saturated pool
            # past the probe timeout, flipping the pod NotReady and dropping all
            # Service endpoints exactly when busiest (S6 self-DoS).
            if method == "GET" and path == "/health":
                if db_connection.pool is not None and db_connection.is_valid:
                    status_code = 200
                    body = b'{"status":"healthy"}'
                else:
                    status_code = 503
                    body = b'{"status":"unhealthy","reason":"Database pool not ready"}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": status_code,
                        "headers": [
                            [b"content-type", b"application/json"],
                            [b"cache-control", b"no-store"],
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return

            # Diagnostic ONLY (not wired to any probe): live connectivity check.
            if method == "GET" and path == "/health/db":
                try:
                    if db_connection.pool is None:
                        status_code = 503
                        body = b'{"status":"unhealthy","reason":"Database pool not ready"}'
                    else:
                        async with db_connection.pool.connection() as conn:
                            await conn.execute("SELECT 1")
                        status_code = 200
                        body = b'{"status":"healthy"}'
                except Exception as e:
                    logger.debug(f"Health DB check failed: {e}")
                    status_code = 503
                    body = b'{"status":"unhealthy","reason":"Database connectivity check failed"}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": status_code,
                        "headers": [
                            [b"content-type", b"application/json"],
                            [b"cache-control", b"no-store"],
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return

            # Kubernetes liveness probe
            if method == "GET" and path == "/healthz":
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            [b"content-type", b"application/json"],
                        ],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b'{"alive":true}',
                    }
                )
                return

        # Pass through to FastMCP app (with stripped path)
        await self.app(scope, receive, send)


def build_middleware_stack(terminal_app):
    """Compose the full perimeter chain around a terminal ASGI app.

    Single source of truth for middleware ORDER — main() and the integration
    tests both use this, so an ordering regression cannot slip past tests.

    Middleware stack (outermost → innermost):
    0. RequestIDMiddleware — assigns correlation ID to every request
    1. CORSMiddleware — handles OPTIONS preflight + CORS headers
    2. IPAllowlistMiddleware — allows whitelisted IPs OR a valid AUTH_TOKEN /
       person-token Bearer (LOOP-664; AUTH_TOKEN retired in M4)
    3. PersonAuthMiddleware — per-person bearer tokens (LOOP-664 M1, PERSON_AUTH_ENABLED)
    4. AuditLogMiddleware — one JSON audit line per request (LOOP-664 M1)
    5. CallerIdentityMiddleware — legacy end-user identity gating (frozen path, retired in M4)
    6. RateLimiterMiddleware — person-keyed (fallback per-IP) rate limiting
    7. HealthCheckMiddleware — ALB health probes
    8. SSEKeepAliveMiddleware — SSE ping to prevent idle timeouts (SSE retired in M4)

    The person-token registry is parsed ONCE here and shared by the IP allowlist
    (person tokens grant IP bypass) and PersonAuth (person tokens are the identity
    credential), so the two can never disagree on which tokens are valid. A
    malformed ``PERSON_TOKENS`` fails loud at this point.
    """
    registry = PersonTokenRegistry()
    return RequestIDMiddleware(
        CORSMiddleware(
            IPAllowlistMiddleware(
                PersonAuthMiddleware(
                    AuditLogMiddleware(
                        CallerIdentityMiddleware(
                            RateLimiterMiddleware(
                                HealthCheckMiddleware(SSEKeepAliveMiddleware(terminal_app, interval=15)),
                                max_requests=int(os.environ.get("RATE_LIMIT_MAX_REQUESTS", "30")),
                                window_seconds=int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60")),
                            )
                        ),
                        get_request_id=lambda: _request_id_var.get(""),
                    ),
                    registry=registry,
                    get_request_id=lambda: _request_id_var.get(""),
                ),
                registry=registry,
            )
        )
    )


def build_dual_transport_router(mcp_server):
    """ASGI app serving one FastMCP server over BOTH transports — SSE at
    ``/sse`` + ``/messages`` and Streamable-HTTP at ``/mcp`` — while driving the
    Streamable-HTTP session manager's lifespan.

    FastMCP's ``streamable_http_app()`` runs ``session_manager.run()`` inside its
    own app lifespan, but dispatching to that app per-request (below) bypasses
    that lifespan, so the streamable-HTTP task group is never started and every
    ``/mcp`` request 500s with "Task group is not initialized" (LOOP-511). SSE
    has no app-level lifespan (it is per-connection), so only the Streamable-HTTP
    session manager needs starting here.
    """
    sse_app = mcp_server.sse_app()
    http_app = mcp_server.streamable_http_app()  # lazily creates session_manager
    session_cm: dict[str, Any] = {"ctx": None}

    async def route_by_transport(scope, receive, send):
        """Route to SSE or Streamable-HTTP by path; drive the Streamable-HTTP
        session manager on the ASGI lifespan."""
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    try:
                        session_cm["ctx"] = mcp_server.session_manager.run()
                        await session_cm["ctx"].__aenter__()
                    except Exception as exc:  # pragma: no cover
                        await send({"type": "lifespan.startup.failed", "message": str(exc)})
                    else:
                        await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    if session_cm["ctx"] is not None:
                        await session_cm["ctx"].__aexit__(None, None, None)
                        session_cm["ctx"] = None
                    await send({"type": "lifespan.shutdown.complete"})
                    return
            return  # pragma: no cover
        path = scope.get("path", "")
        if path == "/mcp" or path.startswith("/mcp/"):
            await http_app(scope, receive, send)
        else:
            await sse_app(scope, receive, send)

    return route_by_transport


async def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="PostgreSQL MCP Server")
    parser.add_argument("database_url", help="Database connection URL", nargs="?")
    parser.add_argument(
        "--access-mode",
        type=str,
        choices=[mode.value for mode in AccessMode],
        default=AccessMode.UNRESTRICTED.value,
        help="Set SQL access mode: unrestricted (unrestricted) or restricted (read-only with protections)",
    )
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Select MCP transport: stdio (default), sse, or streamable-http",
    )
    parser.add_argument(
        "--sse-host",
        type=str,
        default="localhost",
        help="Host to bind SSE server to (default: localhost)",
    )
    parser.add_argument(
        "--sse-port",
        type=int,
        default=8000,
        help="Port for SSE server (default: 8000)",
    )

    args = parser.parse_args()

    # Store the access mode in the global variable
    global current_access_mode
    current_access_mode = AccessMode(args.access_mode)

    # Add the query tool with a description appropriate to the access mode
    if current_access_mode == AccessMode.UNRESTRICTED:
        mcp.add_tool(execute_sql, description="Execute any SQL query", annotations=types.ToolAnnotations(readOnlyHint=False))
    else:
        mcp.add_tool(execute_sql, description="Execute a read-only SQL query", annotations=types.ToolAnnotations(readOnlyHint=True))

    logger.info(f"Starting PostgreSQL MCP Server in {current_access_mode.upper()} mode")

    # Get database URL from environment variable or command line
    database_url = os.environ.get("DATABASE_URI", args.database_url)

    if not database_url:
        raise ValueError(
            "Error: No database URL provided. Please specify via 'DATABASE_URI' environment variable or command-line argument.",
        )

    # Initialize database connection pool
    try:
        await db_connection.pool_connect(database_url)
        logger.info("Successfully connected to database and initialized connection pool")
    except Exception as e:
        logger.warning(
            f"Could not connect to database: {obfuscate_password(str(e))}",
        )
        logger.warning(
            "The MCP server will start but database operations will fail until a valid connection is established.",
        )

    # Set up proper shutdown handling
    try:
        loop = asyncio.get_running_loop()
        signals = (signal.SIGTERM, signal.SIGINT)
        for s in signals:
            loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(s)))
    except NotImplementedError:
        # Windows doesn't support signals properly
        logger.warning("Signal handling not supported on Windows")
        pass

    # Run the server with the selected transport (always async)
    if args.transport == "stdio":
        await mcp.run_stdio_async()
    else:
        # Update FastMCP settings based on command line arguments
        mcp.settings.host = args.sse_host
        mcp.settings.port = args.sse_port

        # Configure transport security to allow all hosts (like eden_gardens' ALLOWED_HOSTS = "*")
        # This disables DNS rebinding protection for compatibility with load balancers and ingress
        mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)

        import uvicorn

        # Expose both SSE (/sse + /messages, for Claude Code's type:"sse") and
        # Streamable-HTTP (/mcp, for newer MCP clients) from one FastMCP server.
        # build_dual_transport_router also starts the Streamable-HTTP session
        # manager's lifespan, which the previous inline router skipped → every
        # /mcp request 500'd with "Task group is not initialized" (LOOP-511).
        route_by_transport = build_dual_transport_router(mcp)

        wrapped_app = build_middleware_stack(route_by_transport)
        logger.info(
            "Applied middleware stack: RequestID + CORS + IPAllowlist(+TokenBypass) + "
            "PersonAuth + AuditLog + CallerIdentity + RateLimiter + HealthCheck + SSEKeepAlive"
        )

        # Attach request-ID filter to root logger so all log records include it
        logging.getLogger().addFilter(RequestIDLogFilter())

        config = uvicorn.Config(
            wrapped_app,
            host=mcp.settings.host,
            port=mcp.settings.port,
            log_level=mcp.settings.log_level.lower(),
            timeout_keep_alive=120,
            timeout_notify=30,
        )
        server = uvicorn.Server(config)
        await server.serve()


async def shutdown(sig=None):
    """Clean shutdown of the server."""
    global shutdown_in_progress

    if shutdown_in_progress:
        logger.warning("Forcing immediate exit")
        # Use sys.exit instead of os._exit to allow for proper cleanup
        sys.exit(1)

    shutdown_in_progress = True

    if sig:
        logger.info(f"Received exit signal {sig.name}")

    # Close database connections
    try:
        await db_connection.close()
        logger.info("Closed database connections")
    except Exception as e:
        logger.error(f"Error closing database connections: {e}")

    # Exit with appropriate status code
    sys.exit(128 + sig.value if sig is not None else 0)
