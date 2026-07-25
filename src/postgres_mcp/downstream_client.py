"""MCP client for downstream (proxied) domain MCP servers via SSE (primary) or
Streamable HTTP.

Ported near-verbatim from topmate-db-mcp-server's proven
``topmate_mcp/clients/postgres_mcp_client.py`` (LOOP-664 M3): renamed
``PostgresMCPClient`` -> ``DownstreamMCPClient`` and generalized the log
strings to reference the downstream base URL instead of the literal
"postgres-mcp", since this client now talks to any proxied per-domain MCP
(not just postgres-mcp itself). The connect/_ensure_session/
_session_lifecycle/call_tool/disconnect logic is unchanged: it already
handles the FastMCP-inside-request cancel-scope issue, single-flight
reconnect, and tenacity retries.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

import httpx
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from tenacity import retry
from tenacity import retry_if_exception_type
from tenacity import stop_after_attempt
from tenacity import wait_exponential

from . import domain_registry

logger = logging.getLogger(__name__)

# Retryable exceptions for transient network/connection failures
_RETRYABLE = (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout, ConnectionError, OSError)


class DownstreamMCPClient:
    """Async MCP client that connects to a downstream (proxied) MCP server.

    The MCP SDK's ClientSession starts a background _receive_loop via an anyio
    TaskGroup. To avoid cancel-scope nesting issues when called from inside a
    FastMCP request handler, we run the entire session lifecycle in an
    independent asyncio.Task.
    """

    def __init__(
        self,
        base_url: str,
        transport: str = "sse",
        timeout: float = 30.0,
        auth_token: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.transport = transport
        self.timeout = timeout
        # Bearer sent on every transport connection so the downstream MCP admits
        # this caller once it runs with PERSON_AUTH_ENABLED=true (LOOP-664). None ->
        # no Authorization header (unchanged behaviour).
        self._headers: dict[str, str] | None = {"Authorization": f"Bearer {auth_token}"} if auth_token else None
        self.endpoint_url = f"{self.base_url}/{'mcp' if transport == 'streamable_http' else 'sse'}"
        self._session: ClientSession | None = None
        self._lifecycle_task: asyncio.Task | None = None
        self._connect_lock = asyncio.Lock()
        self._connected = asyncio.Event()
        self._connect_error: BaseException | None = None

    async def _connect_locked(self) -> None:
        """Establish a session. ASSUMES ``self._connect_lock`` is already held."""
        if self._session is not None:
            return
        logger.info("Connecting to downstream (%s) at %s (transport=%s)", self.base_url, self.endpoint_url, self.transport)

        self._connected = asyncio.Event()
        self._connect_error = None

        self._lifecycle_task = asyncio.create_task(self._session_lifecycle(), name="downstream-mcp-session")

        # Wait for the background task to signal connection success/failure
        await self._connected.wait()
        if self._connect_error is not None:
            err = self._connect_error
            self._connect_error = None
            self._session = None
            raise err

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=15),
        retry=retry_if_exception_type((*_RETRYABLE, asyncio.CancelledError)),
        reraise=True,
    )
    async def connect(self) -> None:
        """Establish an MCP session with the downstream server (public entry)."""
        async with self._connect_lock:
            await self._connect_locked()

    async def _ensure_session(self) -> ClientSession:
        """Return a live shared session, (re)connecting once if it is missing or
        its lifecycle task has died — single-flight under ``_connect_lock`` so
        concurrent callers don't stampede the single downstream replica (S7)."""
        sess = self._session
        task = self._lifecycle_task
        if sess is not None and task is not None and not task.done():
            return sess
        async with self._connect_lock:
            # Re-check inside the lock: another coroutine may have just reconnected.
            if self._session is not None and self._lifecycle_task is not None and not self._lifecycle_task.done():
                return self._session
            # Drop a dead lifecycle task before reconnecting (idempotent).
            if self._lifecycle_task is not None and self._lifecycle_task.done():
                self._lifecycle_task = None
                self._session = None
            await self._connect_locked()
            if self._session is None:
                raise ConnectionError(f"downstream ({self.base_url}) session unavailable after reconnect")
            return self._session

    async def _session_lifecycle(self) -> None:
        """Run the MCP session in an independent task (avoids cancel-scope nesting).

        This task owns the SSE transport + ClientSession contexts. It stays
        alive (keeping the session open) until cancelled by disconnect().
        """
        ctx = None
        try:
            if self.transport == "streamable_http":
                from mcp.client.streamable_http import streamablehttp_client

                ctx = streamablehttp_client(self.endpoint_url, headers=self._headers)
                read, write, _ = await ctx.__aenter__()
            else:
                ctx = sse_client(
                    self.endpoint_url,
                    headers=self._headers,
                    timeout=self.timeout,
                    sse_read_timeout=300.0,
                )
                read, write = await ctx.__aenter__()

            session = ClientSession(read, write, read_timeout_seconds=timedelta(seconds=self.timeout))
            async with session:
                await session.initialize()
                self._session = session
                logger.info("MCP session established with downstream (%s)", self.base_url)
                self._connected.set()

                # Keep alive until cancelled (disconnect calls task.cancel())
                try:
                    while True:
                        await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    logger.info("downstream (%s) session lifecycle cancelled, shutting down", self.base_url)

        except BaseException as exc:
            logger.error("Failed to connect to downstream (%s): %s: %s", self.base_url, type(exc).__name__, exc)
            self._connect_error = exc
            self._connected.set()
        finally:
            self._session = None
            if ctx is not None:
                try:
                    await ctx.__aexit__(None, None, None)
                except Exception:
                    logger.debug("downstream (%s) transport teardown error", self.base_url, exc_info=True)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(_RETRYABLE),
        reraise=True,
    )
    async def call_tool(self, tool_name: str, arguments: dict | None = None) -> str:
        """Call a tool on the downstream server with automatic retries."""
        session = await self._ensure_session()
        try:
            result = await session.call_tool(
                name=tool_name,
                arguments=arguments or {},
                read_timeout_seconds=timedelta(seconds=self.timeout),
            )
            return "\n".join(c.text for c in result.content if hasattr(c, "text"))
        except _RETRYABLE:
            # Do NOT tear down the shared session — other concurrent calls are
            # multiplexing over it. tenacity retries this call; if the session
            # itself is dead, _ensure_session() rebuilds it once under the lock
            # on the next attempt (S7).
            logger.warning("Transient error calling %s (will retry on shared session)", tool_name)
            raise
        except Exception:
            logger.exception("Non-retryable error calling tool %s", tool_name)
            raise

    async def disconnect(self) -> None:
        """Tear down the MCP session by cancelling the lifecycle task (shutdown
        only — no longer called per-call on a transient error, see S7)."""
        self._session = None
        if self._lifecycle_task and not self._lifecycle_task.done():
            self._lifecycle_task.cancel()
            try:
                await self._lifecycle_task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.debug("downstream (%s) lifecycle task error during disconnect", self.base_url, exc_info=True)
        self._lifecycle_task = None


# --- Module-level client cache: one DownstreamMCPClient per proxy domain ---

_clients: dict[str, DownstreamMCPClient] = {}
_clients_lock = asyncio.Lock()


async def get_downstream_client(domain: str) -> DownstreamMCPClient:
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
