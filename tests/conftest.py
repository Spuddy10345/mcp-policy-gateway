"""Shared fixtures.

The interesting one is `gateway_client`: it stands up a real gateway in front
of a real (if small) MCP server and hands back a real MCP client, all in one
process. Nothing is mocked, so the tests exercise the same handler path a
Claude Desktop config would.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import mcp.types as types
import pytest
from mcp import Client
from mcp.server.lowlevel import Server

from mcp_policy_gateway.audit import AuditLog
from mcp_policy_gateway.config import AuditConfig, GatewayConfig
from mcp_policy_gateway.gateway import Gateway
from mcp_policy_gateway.identity import Identity, reset_ambient_identity, set_ambient_identity
from mcp_policy_gateway.ratelimit import RateLimiter
from mcp_policy_gateway.upstream import UpstreamPool


@dataclass
class FakeUpstream:
    """A minimal MCP server that records what it was actually asked to do.

    `calls` is the assertion that matters throughout the suite: a denied call
    must never appear in it. Checking only the gateway's response would pass
    even if the gateway forwarded the call and then discarded the result.
    """

    name: str = "hass"
    tools: list[types.Tool] = field(default_factory=list)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    #: Tool name -> response text. Anything not listed echoes its arguments.
    responses: dict[str, str] = field(default_factory=dict)
    #: Tool names that should raise when called.
    failing: set[str] = field(default_factory=set)

    def server(self) -> Server[None]:
        async def on_list_tools(context: Any, params: Any) -> types.ListToolsResult:
            return types.ListToolsResult(tools=self.tools)

        async def on_call_tool(context: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
            arguments = dict(params.arguments or {})
            self.calls.append((params.name, arguments))
            if params.name in self.failing:
                raise RuntimeError(f"upstream blew up handling {params.name}")
            text = self.responses.get(params.name, f"{params.name} ok: {arguments}")
            return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

        return Server(
            name=self.name,
            version="1.0.0",
            on_list_tools=on_list_tools,
            on_call_tool=on_call_tool,
        )

    def called(self, tool: str) -> bool:
        return any(name == tool for name, _ in self.calls)


def tool(name: str, description: str = "") -> types.Tool:
    return types.Tool(
        name=name,
        description=description or f"the {name} tool",
        inputSchema={"type": "object", "properties": {}},
    )


HASS_TOOLS = [
    tool("ha_get_state", "read the state of an entity"),
    tool("ha_get_overview", "summarise the house"),
    tool("ha_call_service", "call any Home Assistant service"),
    tool("ha_restart", "restart Home Assistant"),
    tool("ha_remove_entity", "permanently delete an entity"),
    tool("ha_config_set_automation", "create or update an automation"),
]


@pytest.fixture
def fake_upstream() -> FakeUpstream:
    return FakeUpstream(tools=list(HASS_TOOLS))


def make_config(policies: dict[str, Any], **overrides: Any) -> GatewayConfig:
    """Build a config in memory, skipping YAML."""
    data: dict[str, Any] = {
        "version": 1,
        "upstreams": {
            "hass": {"transport": "stdio", "command": "/bin/false", "args": []},
        },
        "policies": policies,
        "server": {"namespace": "never"},
    }
    data.update(overrides)
    return GatewayConfig.model_validate(data)


@asynccontextmanager
async def running_gateway(
    config: GatewayConfig,
    upstream: FakeUpstream,
    identity: Identity,
    *,
    audit_config: AuditConfig | None = None,
    clock: Callable[[], float] | None = None,
) -> AsyncIterator[tuple[Client, Gateway, AuditLog]]:
    """Run gateway -> fake upstream, and yield a client connected to the gateway."""
    upstream_server = upstream.server()

    async with AsyncExitStack() as stack:
        pool = await stack.enter_async_context(
            UpstreamPool(config, connect_to=lambda name, spec: upstream_server)
        )
        # No path: records are kept in memory for assertions.
        audit = await stack.enter_async_context(
            AuditLog(audit_config or AuditConfig(path=None, hash_chain=True))
        )
        limiter = RateLimiter(config.rate_limits, clock=clock) if clock else RateLimiter(config.rate_limits)
        gateway = Gateway(config, pool, audit, limiter=limiter)

        # Set before the client starts the server task, so handler tasks
        # inherit the identity the same way the stdio runner arranges it.
        context_token = set_ambient_identity(identity)
        try:
            client = await stack.enter_async_context(Client(gateway.build_server()))
            yield client, gateway, audit
        finally:
            reset_ambient_identity(context_token)


@pytest.fixture
def assistant() -> Identity:
    return Identity(name="test-assistant", policy="assistant")


def text_of(result: types.CallToolResult) -> str:
    """Concatenate the text content of a tool result."""
    return "\n".join(block.text for block in result.content if isinstance(block, types.TextContent))
