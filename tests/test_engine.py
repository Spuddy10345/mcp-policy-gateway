"""Rule ordering, defaults, and tool visibility."""

from __future__ import annotations

import pytest

from mcp_policy_gateway.config import Policy
from mcp_policy_gateway.engine import PolicyEngine
from mcp_policy_gateway.matching import MatchContext


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


def policy(**data) -> Policy:
    return Policy.model_validate(data)


def call(tool: str, upstream: str = "hass", **arguments) -> MatchContext:
    return MatchContext(tool=tool, upstream=upstream, arguments=arguments)


# ------------------------------------------------------------------- ordering


def test_first_matching_rule_wins(engine):
    subject = policy(
        default="deny",
        rules=[
            {"name": "allow-all-reads", "effect": "allow", "tools": ["ha_get_*"]},
            {"name": "deny-secrets", "effect": "deny", "tools": ["ha_get_secret"]},
        ],
    )
    # The deny rule is unreachable: the allow above it already matched.
    decision = engine.evaluate(subject, call("ha_get_secret"))
    assert decision.allowed
    assert decision.rule_name == "allow-all-reads"


def test_ordering_the_other_way_round_denies(engine):
    subject = policy(
        default="deny",
        rules=[
            {"name": "deny-secrets", "effect": "deny", "tools": ["ha_get_secret"]},
            {"name": "allow-all-reads", "effect": "allow", "tools": ["ha_get_*"]},
        ],
    )
    assert not engine.evaluate(subject, call("ha_get_secret")).allowed
    assert engine.evaluate(subject, call("ha_get_state")).allowed


def test_default_applies_when_nothing_matches(engine):
    subject = policy(default="deny", rules=[{"effect": "allow", "tools": ["ha_get_*"]}])
    decision = engine.evaluate(subject, call("ha_restart"))

    assert not decision.allowed
    assert not decision.matched_rule
    assert decision.rule_name is None
    assert "policy default is deny" in decision.reason


def test_default_is_deny_when_unspecified(engine):
    assert not engine.evaluate(policy(), call("anything")).allowed


def test_default_allow_is_honoured_when_asked_for(engine):
    subject = policy(default="allow", rules=[{"effect": "deny", "tools": ["ha_restart"]}])
    assert engine.evaluate(subject, call("ha_get_state")).allowed
    assert not engine.evaluate(subject, call("ha_restart")).allowed


def test_unnamed_rules_are_identified_by_position(engine):
    subject = policy(default="deny", rules=[{"effect": "allow", "tools": ["ha_get_*"]}])
    assert engine.evaluate(subject, call("ha_get_state")).rule_name == "allow rule #0"


# ----------------------------------------------------------------- constraints


def test_rule_matches_only_when_every_constraint_holds(engine):
    subject = policy(
        default="deny",
        rules=[
            {
                "name": "safe",
                "effect": "allow",
                "tools": ["ha_call_service"],
                "when": {"args.domain": {"eq": "light"}, "args.service": {"in": ["turn_on", "turn_off"]}},
            }
        ],
    )
    assert engine.evaluate(subject, call("ha_call_service", domain="light", service="turn_on")).allowed
    assert not engine.evaluate(subject, call("ha_call_service", domain="light", service="delete")).allowed
    assert not engine.evaluate(subject, call("ha_call_service", domain="lock", service="turn_on")).allowed


def test_upstream_pattern_narrows_a_rule(engine):
    subject = policy(
        default="deny",
        rules=[{"effect": "allow", "tools": ["search"], "upstreams": ["brave*"]}],
    )
    assert engine.evaluate(subject, call("search", upstream="brave-search")).allowed
    assert not engine.evaluate(subject, call("search", upstream="hass")).allowed


def test_rate_limits_are_carried_only_by_allow_decisions(engine):
    subject = policy(
        default="deny",
        rules=[{"effect": "allow", "tools": ["ha_call_service"], "rate_limits": ["actuation"]}],
    )
    assert engine.evaluate(subject, call("ha_call_service")).rate_limits == ("actuation",)
    assert engine.evaluate(subject, call("ha_restart")).rate_limits == ()


def test_trace_attributes_each_check_to_its_rule(engine):
    subject = policy(
        default="deny",
        rules=[
            {
                "name": "lights",
                "effect": "allow",
                "tools": ["ha_call_service"],
                "when": {"args.domain": {"eq": "light"}},
            },
            {
                "name": "locks",
                "effect": "deny",
                "tools": ["ha_call_service"],
                "when": {"args.domain": {"eq": "lock"}},
            },
        ],
    )
    decision = engine.evaluate(subject, call("ha_call_service", domain="lock"))

    assert decision.rule_name == "locks"
    assert decision.trace[0].startswith("[lights] FAIL")
    assert decision.trace[1].startswith("[locks] PASS")


def test_custom_reason_replaces_the_derived_one(engine):
    subject = policy(
        default="deny",
        rules=[{"name": "no", "effect": "deny", "tools": ["ha_restart"], "reason": "ask a human"}],
    )
    assert engine.evaluate(subject, call("ha_restart")).reason == "ask a human"


# ------------------------------------------------------------------ visibility


def test_unconditional_deny_hides_a_tool(engine):
    subject = policy(default="deny", rules=[{"effect": "deny", "tools": ["ha_restart"]}])
    assert engine.is_visible(subject, "ha_restart", "hass") is False


def test_default_deny_hides_everything_not_explicitly_allowed(engine):
    subject = policy(default="deny", rules=[{"effect": "allow", "tools": ["ha_get_*"]}])
    assert engine.is_visible(subject, "ha_get_state", "hass") is True
    assert engine.is_visible(subject, "ha_restart", "hass") is False


def test_conditionally_allowed_tool_stays_visible(engine):
    """The model has to see it to use it for the case that is permitted."""
    subject = policy(
        default="deny",
        rules=[
            {"effect": "allow", "tools": ["ha_call_service"], "when": {"args.domain": {"eq": "light"}}},
        ],
    )
    assert engine.is_visible(subject, "ha_call_service", "hass") is True


def test_conditional_deny_does_not_hide_a_tool_a_later_rule_allows(engine):
    subject = policy(
        default="deny",
        rules=[
            {"effect": "deny", "tools": ["ha_call_service"], "when": {"args.domain": {"eq": "lock"}}},
            {"effect": "allow", "tools": ["ha_call_service"]},
        ],
    )
    assert engine.is_visible(subject, "ha_call_service", "hass") is True


def test_visibility_respects_rule_order(engine):
    """An unconditional deny above an allow settles it."""
    subject = policy(
        default="deny",
        rules=[
            {"effect": "deny", "tools": ["ha_call_service"]},
            {"effect": "allow", "tools": ["ha_call_service"]},
        ],
    )
    assert engine.is_visible(subject, "ha_call_service", "hass") is False


def test_visibility_and_enforcement_agree_for_unconditional_rules(engine):
    """Anything listed must be callable with *some* arguments, and anything
    hidden must be callable with none."""
    subject = policy(
        default="deny",
        rules=[
            {"effect": "allow", "tools": ["ha_get_*"]},
            {"effect": "deny", "tools": ["ha_restart"]},
        ],
    )
    for tool, expected in [("ha_get_state", True), ("ha_restart", False), ("ha_unknown", False)]:
        assert engine.is_visible(subject, tool, "hass") is expected
        assert engine.evaluate(subject, call(tool)).allowed is expected
