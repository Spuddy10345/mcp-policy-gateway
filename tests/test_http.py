"""HTTP transport, end to end over a real socket.

These start an actual uvicorn server and connect a real MCP client to it, so
the bearer-token path is exercised as deployed rather than simulated. This is
where the multi-tenant claim is tested: two callers, two tokens, two different
sets of tools, one gateway process.
"""

from __future__ import annotations

import socket
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager, closing

import anyio
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from conftest import HASS_TOOLS, FakeUpstream, text_of
from mcp_policy_gateway.audit import AuditLog
from mcp_policy_gateway.config import AuditConfig, GatewayConfig
from mcp_policy_gateway.errors import ConfigError
from mcp_policy_gateway.gateway import Gateway
from mcp_policy_gateway.identity import token_digest
from mcp_policy_gateway.server import build_http_app
from mcp_policy_gateway.upstream import UpstreamPool

ASSISTANT_TOKEN = "assistant-token-value"
ADMIN_TOKEN = "admin-token-value"

CONFIG = {
    "version": 1,
    "server": {"namespace": "never"},
    "upstreams": {"hass": {"transport": "stdio", "command": "x"}},
    "policies": {
        "assistant": {
            "default": "deny",
            "rules": [{"name": "reads", "effect": "allow", "tools": ["ha_get_*"]}],
        },
        "admin": {
            "default": "allow",
            "rules": [{"name": "everything", "effect": "allow", "tools": ["*"], "reason": "admin"}],
        },
    },
    "tokens": [
        {"name": "laptop", "policy": "assistant", "sha256": token_digest(ASSISTANT_TOKEN)},
        {"name": "console", "policy": "admin", "sha256": token_digest(ADMIN_TOKEN)},
    ],
}


def free_port() -> int:
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@asynccontextmanager
async def serving(upstream: FakeUpstream, config_data: dict | None = None) -> AsyncIterator[str]:
    """Run the gateway over HTTP on a free port; yield its URL."""
    import uvicorn

    config = GatewayConfig.model_validate(config_data or CONFIG)
    upstream_server = upstream.server()
    port = free_port()

    async with AsyncExitStack() as stack:
        pool = await stack.enter_async_context(
            UpstreamPool(config, connect_to=lambda name, spec: upstream_server)
        )
        audit = await stack.enter_async_context(AuditLog(AuditConfig(path=None)))
        gateway = Gateway(config, pool, audit)
        app = build_http_app(config, gateway, host="127.0.0.1", path="/mcp")

        server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", access_log=False)
        )

        async with anyio.create_task_group() as group:
            group.start_soon(server.serve)
            with anyio.fail_after(10):
                while not server.started:  # noqa: ASYNC110 - uvicorn exposes a flag, not an event
                    await anyio.sleep(0.02)
            try:
                yield f"http://127.0.0.1:{port}/mcp"
            finally:
                server.should_exit = True


@asynccontextmanager
async def connect(url: str, token: str | None) -> AsyncIterator[Client]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    http_client = create_mcp_http_client(headers=headers)
    async with Client(streamable_http_client(url, http_client=http_client)) as client:
        yield client


@pytest.fixture
def upstream() -> FakeUpstream:
    return FakeUpstream(tools=list(HASS_TOOLS))


async def test_a_valid_token_reaches_its_policy(upstream):
    async with serving(upstream) as url, connect(url, ASSISTANT_TOKEN) as client:
        result = await client.call_tool("ha_get_state", {"entity_id": "light.kitchen"})

    assert not result.is_error
    assert upstream.calls == [("ha_get_state", {"entity_id": "light.kitchen"})]


async def test_policy_is_enforced_over_http(upstream):
    async with serving(upstream) as url, connect(url, ASSISTANT_TOKEN) as client:
        result = await client.call_tool("ha_restart", {})

    assert result.is_error
    assert "Denied by gateway policy" in text_of(result)
    assert upstream.calls == []


async def test_two_tokens_get_different_toolboxes_from_one_process(upstream):
    """The multi-tenant claim: identity is per request, not per process."""
    async with serving(upstream) as url:
        async with connect(url, ASSISTANT_TOKEN) as client:
            assistant_tools = {tool.name for tool in (await client.list_tools()).tools}
        async with connect(url, ADMIN_TOKEN) as client:
            admin_tools = {tool.name for tool in (await client.list_tools()).tools}
            allowed = await client.call_tool("ha_restart", {})

    assert "ha_restart" not in assistant_tools
    assert "ha_restart" in admin_tools
    assert not allowed.is_error
    assert upstream.called("ha_restart")


async def test_a_request_with_no_token_is_rejected(upstream):
    async with serving(upstream) as url:
        with pytest.raises(Exception):
            async with connect(url, None) as client:
                await client.list_tools()

    assert upstream.calls == []


async def test_a_request_with_a_bad_token_is_rejected(upstream):
    async with serving(upstream) as url:
        with pytest.raises(Exception):
            async with connect(url, "not-a-real-token") as client:
                await client.list_tools()

    assert upstream.calls == []


async def test_http_transport_requires_configured_tokens(upstream):
    """Without tokens there is no way to tell callers apart, so refuse to start
    rather than serve everyone as nobody."""
    config_data = dict(CONFIG, tokens=[])
    config = GatewayConfig.model_validate(config_data)

    async with AsyncExitStack() as stack:
        pool = await stack.enter_async_context(
            UpstreamPool(config, connect_to=lambda name, spec: upstream.server())
        )
        audit = await stack.enter_async_context(AuditLog(AuditConfig(path=None)))
        gateway = Gateway(config, pool, audit)

        with pytest.raises(ConfigError, match="requires at least one configured token"):
            build_http_app(config, gateway, host="127.0.0.1", path="/mcp")
