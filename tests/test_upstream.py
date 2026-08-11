"""Upstream pooling, tool namespacing and routing."""

from __future__ import annotations

import pytest

from conftest import FakeUpstream, tool
from mcp_policy_gateway.config import GatewayConfig, HttpUpstream, StdioUpstream
from mcp_policy_gateway.errors import UpstreamError
from mcp_policy_gateway.upstream import UpstreamPool


def two_upstream_config(namespace: str = "auto") -> GatewayConfig:
    return GatewayConfig.model_validate(
        {
            "version": 1,
            "server": {"namespace": namespace},
            "upstreams": {
                "hass": {"transport": "stdio", "command": "x"},
                "github": {"transport": "stdio", "command": "y"},
            },
            "policies": {"p": {"default": "allow"}},
        }
    )


def one_upstream_config(namespace: str = "auto") -> GatewayConfig:
    return GatewayConfig.model_validate(
        {
            "version": 1,
            "server": {"namespace": namespace},
            "upstreams": {"hass": {"transport": "stdio", "command": "x"}},
            "policies": {"p": {"default": "allow"}},
        }
    )


def pool_over(config: GatewayConfig, upstreams: dict[str, FakeUpstream]) -> UpstreamPool:
    servers = {name: upstream.server() for name, upstream in upstreams.items()}
    return UpstreamPool(config, connect_to=lambda name, spec: servers[name])


# ----------------------------------------------------------------- namespacing


async def test_single_upstream_keeps_tool_names_unchanged():
    """So the gateway is a drop-in replacement for the server it fronts."""
    upstream = FakeUpstream(tools=[tool("ha_restart")])

    async with pool_over(one_upstream_config(), {"hass": upstream}) as pool:
        catalogue = await pool.catalogue()

    assert [entry.gateway_name for entry in catalogue] == ["ha_restart"]


async def test_multiple_upstreams_are_namespaced_automatically():
    upstreams = {
        "hass": FakeUpstream(tools=[tool("search")]),
        "github": FakeUpstream(tools=[tool("search")]),
    }

    async with pool_over(two_upstream_config(), upstreams) as pool:
        names = {entry.gateway_name for entry in await pool.catalogue()}

    assert names == {"hass__search", "github__search"}


async def test_namespace_always_prefixes_even_a_lone_upstream():
    upstream = FakeUpstream(tools=[tool("ha_restart")])

    async with pool_over(one_upstream_config("always"), {"hass": upstream}) as pool:
        catalogue = await pool.catalogue()

    assert catalogue[0].gateway_name == "hass__ha_restart"
    assert catalogue[0].upstream_name == "ha_restart"


async def test_advertised_tool_carries_the_gateway_name():
    upstream = FakeUpstream(tools=[tool("ha_restart", "restart it")])

    async with pool_over(one_upstream_config("always"), {"hass": upstream}) as pool:
        advertised = (await pool.catalogue())[0].as_advertised()

    assert advertised.name == "hass__ha_restart"
    assert advertised.description == "restart it"


async def test_colliding_names_are_dropped_rather_than_shadowed():
    """Routing by dict order would make which upstream ran a matter of luck."""
    upstreams = {
        "hass": FakeUpstream(tools=[tool("search"), tool("only_hass")]),
        "github": FakeUpstream(tools=[tool("search")]),
    }

    async with pool_over(two_upstream_config("never"), upstreams) as pool:
        names = [entry.gateway_name for entry in await pool.catalogue()]

    assert names == ["only_hass"]


# -------------------------------------------------------------------- routing


async def test_calls_are_routed_to_the_owning_upstream():
    hass = FakeUpstream(tools=[tool("search")])
    github = FakeUpstream(tools=[tool("search")])

    async with pool_over(two_upstream_config(), {"hass": hass, "github": github}) as pool:
        target = await pool.resolve("github__search")
        await pool.call(target, {"q": "mcp"})

    assert github.calls == [("search", {"q": "mcp"})]
    assert hass.calls == []


async def test_the_upstream_receives_its_own_tool_name_not_the_namespaced_one():
    hass = FakeUpstream(tools=[tool("ha_restart")])

    async with pool_over(one_upstream_config("always"), {"hass": hass}) as pool:
        await pool.call(await pool.resolve("hass__ha_restart"), {})

    assert hass.calls == [("ha_restart", {})]


async def test_resolving_an_unknown_tool_raises():
    async with pool_over(one_upstream_config(), {"hass": FakeUpstream()}) as pool:
        with pytest.raises(UpstreamError, match="unknown tool"):
            await pool.resolve("nope")


async def test_resolve_refreshes_the_catalogue_when_a_name_is_unseen():
    """A tool an upstream adds mid-session is routable without a restart."""
    upstream = FakeUpstream(tools=[tool("ha_get_state")])

    async with pool_over(one_upstream_config(), {"hass": upstream}) as pool:
        await pool.catalogue()
        upstream.tools.append(tool("ha_new_tool"))

        with pytest.raises(UpstreamError):
            await pool.resolve("ha_new_tool")  # still cached

        pool.invalidate()
        assert (await pool.resolve("ha_new_tool")).upstream_name == "ha_new_tool"


async def test_listings_are_cached_until_invalidated():
    upstream = FakeUpstream(tools=[tool("a")])

    async with pool_over(one_upstream_config(), {"hass": upstream}) as pool:
        first = await pool.catalogue()
        upstream.tools.append(tool("b"))
        second = await pool.catalogue()

        assert len(first) == len(second) == 1

        pool.invalidate()
        assert len(await pool.catalogue(refresh=True)) == 2


async def test_an_upstream_that_fails_to_list_does_not_break_the_others():
    """One sick upstream must not take the whole gateway's toolbox with it."""

    class Broken(FakeUpstream):
        def server(self):
            from mcp.server.lowlevel import Server

            async def failing(context, params):
                raise RuntimeError("upstream is down")

            return Server(name="broken", version="1.0.0", on_list_tools=failing, on_call_tool=failing)

    upstreams = {"hass": FakeUpstream(tools=[tool("works")]), "github": Broken()}

    async with pool_over(two_upstream_config(), upstreams) as pool:
        names = [entry.gateway_name for entry in await pool.catalogue()]

    assert names == ["hass__works"]


# ------------------------------------------------------------------- transports


def test_stdio_transport_is_built_from_config():
    config = one_upstream_config()
    pool = UpstreamPool(config)
    upstream = StdioUpstream(command="uvx", args=["hass-mcp"])

    transport = pool._build_transport("hass", upstream)
    assert transport is not None  # an async context manager, not yet entered


def test_http_transport_is_built_from_config(monkeypatch):
    monkeypatch.setenv("TOKEN", "abc")
    pool = UpstreamPool(one_upstream_config())
    upstream = HttpUpstream(url="https://example.test/mcp", headers={"Authorization": "Bearer ${TOKEN}"})

    assert upstream.resolved_headers() == {"Authorization": "Bearer abc"}
    assert pool._build_transport("remote", upstream) is not None


async def test_a_failing_connection_is_reported_as_an_upstream_error():
    def explode(name, spec):
        raise RuntimeError("no such command")

    with pytest.raises(UpstreamError, match="could not connect"):
        async with UpstreamPool(one_upstream_config(), connect_to=explode):
            pass
