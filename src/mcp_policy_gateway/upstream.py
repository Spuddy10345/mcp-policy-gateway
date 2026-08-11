"""Connections to the MCP servers being fronted.

The pool owns one client per configured upstream and presents them as a single
flat tool namespace. Namespacing matters for policy: two upstreams can both
export `search`, and a rule that allowed `search` without knowing which server
answered it would be a rule nobody could audit.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Self, TextIO, TypeAlias, cast

import anyio
import mcp.types as types
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from .config import GatewayConfig, HttpUpstream, ServerConfig, StdioUpstream
from .errors import UpstreamError

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

#: Resolves an upstream to something `mcp.Client` can connect to: a transport,
#: a URL, or an in-process `Server`.
ConnectTarget: TypeAlias = Callable[[str, "StdioUpstream | HttpUpstream"], Any]


@dataclass(frozen=True)
class NamespacedTool:
    """An upstream tool as the gateway presents it."""

    #: Name clients see, e.g. `hass__ha_restart`.
    gateway_name: str
    #: Name the upstream knows, e.g. `ha_restart`.
    upstream_name: str
    upstream: str
    tool: types.Tool

    def as_advertised(self) -> types.Tool:
        """The tool renamed into the gateway namespace."""
        if self.gateway_name == self.upstream_name:
            return self.tool
        return self.tool.model_copy(update={"name": self.gateway_name})


class UpstreamConnection:
    """One live client session, plus the metadata the gateway caches for it."""

    def __init__(self, name: str, client: Client) -> None:
        self.name = name
        self.client = client
        self._tools: list[types.Tool] | None = None

    async def list_tools(self, *, refresh: bool = False) -> list[types.Tool]:
        """Tools this upstream exports, cached after the first call.

        The cache is what makes `tools/list` cheap enough to filter per policy
        on every request; `refresh=True` drops it when an upstream signals a
        change.
        """
        if self._tools is None or refresh:
            result = await self.client.list_tools()
            self._tools = list(result.tools)
        return self._tools

    def invalidate(self) -> None:
        self._tools = None

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None,
        *,
        # A deadline enforced here with a cancel scope, not a value handed onward.
        timeout: float,  # noqa: ASYNC109
    ) -> types.CallToolResult:
        with anyio.fail_after(timeout):
            return await self.client.call_tool(name, arguments)


class UpstreamPool:
    """Connects to every configured upstream and routes calls to them.

    Enter it as an async context manager; every connection is torn down in
    reverse order on exit, including subprocesses started for stdio upstreams.
    """

    def __init__(self, config: GatewayConfig, *, connect_to: ConnectTarget | None = None) -> None:
        """
        Args:
            config: the parsed gateway config.
            connect_to: overrides how an upstream is reached. Returning an
                in-process `mcp.server.lowlevel.Server` wires the gateway to it
                directly, with no subprocess and no socket — which is how the
                test suite exercises the real proxy path end to end.
        """
        self._config = config
        self._server_config: ServerConfig = config.server
        self._connect_to = connect_to
        self._connections: dict[str, UpstreamConnection] = {}
        self._exit_stack = AsyncExitStack()
        self._routes: dict[str, NamespacedTool] = {}

    @property
    def connections(self) -> dict[str, UpstreamConnection]:
        return self._connections

    async def __aenter__(self) -> Self:
        try:
            for name, upstream in self._config.upstreams.items():
                client = await self._connect(name, upstream)
                self._connections[name] = UpstreamConnection(name, client)
        except BaseException:
            await self._exit_stack.aclose()
            raise
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        self._connections.clear()
        self._routes.clear()
        await self._exit_stack.aclose()

    async def _connect(self, name: str, upstream: StdioUpstream | HttpUpstream) -> Client:
        try:
            target = (
                self._connect_to(name, upstream)
                if self._connect_to
                else self._build_transport(name, upstream)
            )
            client = Client(target, read_timeout_seconds=self._server_config.upstream_timeout)
            return await self._exit_stack.enter_async_context(client)
        except Exception as exc:
            raise UpstreamError(f"upstream {name!r}: could not connect: {exc}") from exc

    def _build_transport(self, name: str, upstream: StdioUpstream | HttpUpstream) -> Any:
        if isinstance(upstream, StdioUpstream):
            parameters = StdioServerParameters(
                command=upstream.command,
                args=upstream.args,
                env=upstream.resolved_env(),
                cwd=upstream.cwd,
            )
            # An upstream's stderr must not reach the gateway's stdout: under
            # stdio transport that stream is the MCP channel itself, and one
            # stray line of upstream logging would corrupt the framing.
            return stdio_client(parameters, errlog=cast("TextIO", _upstream_errlog(name)))

        http_client = create_mcp_http_client(
            headers=upstream.resolved_headers(),
            timeout=_httpx_timeout(upstream.timeout),
        )
        return streamable_http_client(upstream.resolved_url(), http_client=http_client)

    def namespace_for(self, upstream: str, tool_name: str) -> str:
        """The gateway-facing name for an upstream tool."""
        mode = self._server_config.namespace
        prefixed = mode == "always" or (mode == "auto" and len(self._config.upstreams) > 1)
        if not prefixed:
            return tool_name
        return f"{upstream}{self._server_config.namespace_separator}{tool_name}"

    async def catalogue(self, *, refresh: bool = False) -> list[NamespacedTool]:
        """Every tool from every upstream, in the gateway namespace.

        Collisions are dropped rather than silently shadowing one another: two
        upstreams claiming one gateway name means the operator has disabled
        namespacing on a config that needs it, and routing the call to whichever
        upstream happened to connect first would be a routing decision made by
        dict ordering.
        """
        candidates: list[NamespacedTool] = []
        claimants: dict[str, list[str]] = {}

        for name, connection in self._connections.items():
            try:
                upstream_tools = await connection.list_tools(refresh=refresh)
            except Exception as exc:
                logger.warning("upstream %r failed to list tools: %s", name, exc)
                continue

            for tool in upstream_tools:
                gateway_name = self.namespace_for(name, tool.name)
                claimants.setdefault(gateway_name, []).append(name)
                candidates.append(
                    NamespacedTool(
                        gateway_name=gateway_name,
                        upstream_name=tool.name,
                        upstream=name,
                        tool=tool,
                    )
                )

        # Collect first, then drop contested names. Keeping whichever arrived
        # first would resolve the conflict by connection order, which is not a
        # decision the operator made.
        for gateway_name, owners in claimants.items():
            if len(owners) > 1:
                logger.error(
                    "tool name collision: %r is exported by %s; all of them are hidden. "
                    "Set server.namespace: always to disambiguate.",
                    gateway_name,
                    ", ".join(repr(owner) for owner in owners),
                )

        tools = [entry for entry in candidates if len(claimants[entry.gateway_name]) == 1]
        self._routes = {entry.gateway_name: entry for entry in tools}
        return tools

    async def resolve(self, gateway_name: str) -> NamespacedTool:
        """Find the upstream tool a gateway-facing name refers to."""
        if gateway_name not in self._routes:
            await self.catalogue()
        try:
            return self._routes[gateway_name]
        except KeyError:
            raise UpstreamError(f"unknown tool {gateway_name!r}") from None

    async def call(self, target: NamespacedTool, arguments: dict[str, Any] | None) -> types.CallToolResult:
        connection = self._connections.get(target.upstream)
        if connection is None:  # pragma: no cover - routes are built from connections
            raise UpstreamError(f"upstream {target.upstream!r} is not connected")

        try:
            return await connection.call_tool(
                target.upstream_name,
                arguments,
                timeout=self._server_config.upstream_timeout,
            )
        except TimeoutError as exc:
            raise UpstreamError(
                f"upstream {target.upstream!r} did not respond within {self._server_config.upstream_timeout}s"
            ) from exc

    def invalidate(self, names: Iterable[str] | None = None) -> None:
        for name in names if names is not None else list(self._connections):
            connection = self._connections.get(name)
            if connection is not None:
                connection.invalidate()
        self._routes.clear()


def _upstream_errlog(name: str):
    """Route an upstream's stderr into the gateway's logger."""
    import io

    class _LoggingStream(io.TextIOBase):
        def write(self, text: str) -> int:
            for line in text.splitlines():
                if line.strip():
                    logger.debug("[%s] %s", name, line)
            return len(text)

    return _LoggingStream()


def _httpx_timeout(seconds: float):
    import httpx2

    return httpx2.Timeout(seconds)
