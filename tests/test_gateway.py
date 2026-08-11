"""End-to-end tests through a real MCP client, gateway, and upstream.

Every test here asserts on `upstream.calls` as well as on the response. The
gateway's job is not to return a refusal string; it is to make sure the call
never reaches the thing that would have executed it.
"""

from __future__ import annotations

from itertools import pairwise

import pytest

from conftest import make_config, running_gateway, text_of
from mcp_policy_gateway.config import AuditConfig
from mcp_policy_gateway.identity import Identity

ASSISTANT_POLICY = {
    "assistant": {
        "default": "deny",
        "rules": [
            {"name": "reads", "effect": "allow", "tools": ["ha_get_*"]},
            {
                "name": "safe-actuation",
                "effect": "allow",
                "tools": ["ha_call_service"],
                "when": {"args.domain": {"in": ["light", "climate"]}},
                "reason": "actuation limited to non-safety-critical domains",
            },
            {
                "name": "no-destruction",
                "effect": "deny",
                "tools": ["ha_restart", "ha_remove_entity"],
                "reason": "destructive",
            },
        ],
    }
}


@pytest.fixture
def config():
    return make_config(ASSISTANT_POLICY)


async def test_allowed_call_reaches_upstream(config, fake_upstream, assistant):
    async with running_gateway(config, fake_upstream, assistant) as (client, _, audit):
        result = await client.call_tool("ha_get_state", {"entity_id": "light.kitchen"})

    assert not result.is_error
    assert fake_upstream.calls == [("ha_get_state", {"entity_id": "light.kitchen"})]
    assert audit.records[-1]["outcome"] == "allowed"


async def test_denied_call_never_reaches_upstream(config, fake_upstream, assistant):
    """The central claim of the whole project."""
    async with running_gateway(config, fake_upstream, assistant) as (client, _, audit):
        result = await client.call_tool("ha_remove_entity", {"entity_id": "light.kitchen"})

    assert result.is_error
    assert "Denied by gateway policy" in text_of(result)
    assert fake_upstream.calls == []

    record = audit.records[-1]
    assert record["outcome"] == "denied"
    assert record["tool"] == "ha_remove_entity"
    assert record["rule"] == "no-destruction"


async def test_denial_is_a_tool_result_not_a_protocol_error(config, fake_upstream, assistant):
    """An agent must be able to read the refusal and report it.

    Raising a JSON-RPC error would surface to most clients as a transport
    failure and be retried; `is_error` on the result is a message the model
    sees.
    """
    async with running_gateway(config, fake_upstream, assistant) as (client, _, _):
        result = await client.call_tool("ha_restart", {})

    assert result.is_error
    assert "Report it to the user" in text_of(result)


async def test_argument_level_policy_allows_and_denies_the_same_tool(config, fake_upstream, assistant):
    """One tool, two verdicts, decided by the arguments.

    This is what tool-name allow-listing cannot express, and the reason the
    policy language reaches into arguments at all.
    """
    async with running_gateway(config, fake_upstream, assistant) as (client, _, _):
        allowed = await client.call_tool("ha_call_service", {"domain": "light", "service": "turn_on"})
        denied = await client.call_tool("ha_call_service", {"domain": "lock", "service": "unlock"})

    assert not allowed.is_error
    assert denied.is_error
    assert fake_upstream.calls == [("ha_call_service", {"domain": "light", "service": "turn_on"})]


async def test_unconditionally_denied_tools_are_hidden_from_listing(config, fake_upstream, assistant):
    async with running_gateway(config, fake_upstream, assistant) as (client, _, _):
        listed = {tool.name for tool in (await client.list_tools()).tools}

    assert "ha_get_state" in listed
    assert "ha_restart" not in listed
    assert "ha_remove_entity" not in listed
    # Conditionally allowed: the model needs to see it to use it legitimately.
    assert "ha_call_service" in listed
    # Denied only by the policy default, so also never advertised.
    assert "ha_config_set_automation" not in listed


async def test_hidden_tool_is_still_enforced_when_called_by_name(config, fake_upstream, assistant):
    """Hiding is blast-radius reduction; the control is enforcement at call time."""
    async with running_gateway(config, fake_upstream, assistant) as (client, _, _):
        listed = {tool.name for tool in (await client.list_tools()).tools}
        result = await client.call_tool("ha_restart", {})

    assert "ha_restart" not in listed
    assert result.is_error
    assert fake_upstream.calls == []


async def test_hide_denied_tools_false_lists_everything_but_still_blocks(fake_upstream, assistant):
    policy = {"assistant": dict(ASSISTANT_POLICY["assistant"], hide_denied_tools=False)}
    config = make_config(policy)

    async with running_gateway(config, fake_upstream, assistant) as (client, _, _):
        listed = {tool.name for tool in (await client.list_tools()).tools}
        result = await client.call_tool("ha_restart", {})

    assert "ha_restart" in listed
    assert result.is_error
    assert fake_upstream.calls == []


async def test_policy_default_deny_blocks_unknown_tools(config, fake_upstream, assistant):
    """A tool an upstream adds tomorrow is denied today."""
    async with running_gateway(config, fake_upstream, assistant) as (client, _, audit):
        result = await client.call_tool("ha_config_set_automation", {"alias": "x"})

    assert result.is_error
    assert fake_upstream.calls == []
    assert audit.records[-1]["reason"].startswith("no rule matched")


async def test_unknown_tool_is_reported_not_forwarded(config, fake_upstream, assistant):
    async with running_gateway(config, fake_upstream, assistant) as (client, _, audit):
        result = await client.call_tool("ha_nonexistent", {})

    assert result.is_error
    assert "unknown tool" in text_of(result)
    assert audit.records[-1]["outcome"] == "error"


# --------------------------------------------------------------------- dry-run


async def test_dry_run_forwards_what_it_would_have_blocked(fake_upstream, assistant):
    config = make_config(ASSISTANT_POLICY, mode="dry-run")

    async with running_gateway(config, fake_upstream, assistant) as (client, _, audit):
        result = await client.call_tool("ha_remove_entity", {"entity_id": "light.kitchen"})

    assert not result.is_error
    assert fake_upstream.called("ha_remove_entity")

    record = audit.records[-1]
    assert record["outcome"] == "dry-run-allowed"
    assert record["mode"] == "dry-run"
    assert "would deny" in record["reason"]


async def test_per_policy_mode_overrides_the_gateway_default(fake_upstream, assistant):
    """A policy under test can run in dry-run while the rest stay enforced."""
    policy = {"assistant": dict(ASSISTANT_POLICY["assistant"], mode="dry-run")}
    config = make_config(policy, mode="enforce")

    async with running_gateway(config, fake_upstream, assistant) as (client, _, _):
        result = await client.call_tool("ha_restart", {})

    assert not result.is_error
    assert fake_upstream.called("ha_restart")


# ----------------------------------------------------------------- rate limits


async def test_rate_limit_blocks_after_burst_is_spent(fake_upstream, assistant):
    now = [1000.0]
    config = make_config(
        {
            "assistant": {
                "default": "deny",
                "rules": [
                    {
                        "name": "actuation",
                        "effect": "allow",
                        "tools": ["ha_call_service"],
                        "rate_limits": ["actuation"],
                    }
                ],
            }
        },
        rate_limits={"actuation": {"rate": 2, "per": "1m", "burst": 2}},
    )

    async with running_gateway(config, fake_upstream, assistant, clock=lambda: now[0]) as (
        client,
        _,
        audit,
    ):
        first = await client.call_tool("ha_call_service", {"domain": "light"})
        second = await client.call_tool("ha_call_service", {"domain": "light"})
        third = await client.call_tool("ha_call_service", {"domain": "light"})

        assert not first.is_error
        assert not second.is_error
        assert third.is_error
        assert "Rate limited" in text_of(third)
        assert len(fake_upstream.calls) == 2
        assert audit.records[-1]["outcome"] == "rate_limited"

        # Half a minute later the bucket has refilled one token.
        now[0] += 30.0
        fourth = await client.call_tool("ha_call_service", {"domain": "light"})

    assert not fourth.is_error
    assert len(fake_upstream.calls) == 3


async def test_denied_calls_do_not_consume_rate_limit(fake_upstream, assistant):
    """Budget is spent by calls that happen, not by calls that are refused."""
    config = make_config(
        {
            "assistant": {
                "default": "deny",
                "rules": [
                    {
                        "name": "lights-only",
                        "effect": "allow",
                        "tools": ["ha_call_service"],
                        "when": {"args.domain": {"eq": "light"}},
                        "rate_limits": ["actuation"],
                    }
                ],
            }
        },
        rate_limits={"actuation": {"rate": 1, "per": "1h", "burst": 1}},
    )

    async with running_gateway(config, fake_upstream, assistant) as (client, _, _):
        for _ in range(5):
            denied = await client.call_tool("ha_call_service", {"domain": "lock"})
            assert denied.is_error

        allowed = await client.call_tool("ha_call_service", {"domain": "light"})

    assert not allowed.is_error


# --------------------------------------------------------------------- upstream


async def test_upstream_failure_is_reported_without_leaking_internals(config, fake_upstream, assistant):
    fake_upstream.failing.add("ha_get_state")

    async with running_gateway(config, fake_upstream, assistant) as (client, _, audit):
        result = await client.call_tool("ha_get_state", {"entity_id": "light.kitchen"})

    assert result.is_error
    assert "blew up" not in text_of(result)
    assert audit.records[-1]["outcome"] == "error"


# --------------------------------------------------------------------- identity


async def test_identity_naming_an_unknown_policy_fails_closed(config, fake_upstream):
    """A token that outlived a policy rename gets nothing, not everything."""
    stranger = Identity(name="stranger", policy="does-not-exist")

    async with running_gateway(config, fake_upstream, stranger) as (client, _, audit):
        listed = await client.list_tools()
        result = await client.call_tool("ha_get_state", {})

    assert listed.tools == []
    assert result.is_error
    assert "misconfigured" in text_of(result)
    assert fake_upstream.calls == []
    assert audit.records[-1]["outcome"] == "error"


# ------------------------------------------------------------------ audit trail


async def test_audit_records_identity_rule_and_arguments(config, fake_upstream, assistant):
    async with running_gateway(config, fake_upstream, assistant) as (client, _, audit):
        await client.call_tool("ha_call_service", {"domain": "light", "service": "turn_on"})

    record = audit.records[-1]
    assert record["token"] == "test-assistant"
    assert record["policy"] == "assistant"
    assert record["upstream"] == "hass"
    assert record["tool"] == "ha_call_service"
    assert record["rule"] == "safe-actuation"
    assert record["arguments"] == {"domain": "light", "service": "turn_on"}
    assert record["duration_ms"] >= 0


async def test_audit_redacts_credential_shaped_arguments(config, fake_upstream, assistant):
    audit_config = AuditConfig(path=None, redact=["args.entity_id"])

    async with running_gateway(config, fake_upstream, assistant, audit_config=audit_config) as (
        client,
        _,
        audit,
    ):
        await client.call_tool("ha_get_state", {"entity_id": "light.kitchen", "api_key": "super-secret"})

    arguments = audit.records[-1]["arguments"]
    assert arguments["entity_id"].startswith("[redacted:")
    assert arguments["api_key"].startswith("[redacted:")
    assert "super-secret" not in str(arguments)


async def test_audit_chain_is_continuous_across_calls(config, fake_upstream, assistant):
    async with running_gateway(config, fake_upstream, assistant) as (client, _, audit):
        await client.call_tool("ha_get_state", {})
        await client.call_tool("ha_restart", {})
        await client.call_tool("ha_get_overview", {})

    records = audit.records
    assert [record["seq"] for record in records] == [1, 2, 3]
    for previous, current in pairwise(records):
        assert current["prev"] == previous["hash"]


async def test_denial_records_the_constraint_that_failed(fake_upstream, assistant):
    config = make_config(ASSISTANT_POLICY)

    async with running_gateway(config, fake_upstream, assistant) as (client, _, audit):
        await client.call_tool("ha_call_service", {"domain": "lock", "service": "unlock"})

    trace = audit.records[-1]["trace"]
    assert any("args.domain" in line and "FAIL" in line for line in trace)
