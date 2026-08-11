"""Static checks over configs.

Every finding here corresponds to a policy that parses, starts, and enforces
less than its author intended.
"""

from __future__ import annotations

from typing import Any

from mcp_policy_gateway.config import GatewayConfig
from mcp_policy_gateway.lint import lint


def config_with(policies: dict[str, Any], **extra: Any) -> GatewayConfig:
    data = {
        "version": 1,
        "upstreams": {"hass": {"transport": "stdio", "command": "x"}},
        "policies": policies,
    }
    data.update(extra)
    return GatewayConfig.model_validate(data)


def messages(config: GatewayConfig, severity: str | None = None) -> list[str]:
    return [finding.message for finding in lint(config) if severity is None or finding.severity == severity]


def test_unconstrained_allow_rule_is_an_error():
    config = config_with({"p": {"default": "deny", "rules": [{"effect": "allow"}]}})
    assert any("allows every tool with no constraints" in message for message in messages(config, "error"))


def test_wildcard_allow_is_a_warning():
    config = config_with({"p": {"default": "deny", "rules": [{"effect": "allow", "tools": ["*"]}]}})
    assert any("allows all tools" in message for message in messages(config, "warning"))


def test_default_allow_is_a_warning():
    config = config_with({"p": {"default": "allow"}})
    assert any("default is 'allow'" in message for message in messages(config, "warning"))


def test_empty_policy_is_a_warning():
    config = config_with({"p": {"default": "deny"}})
    assert any("no rules" in message for message in messages(config, "warning"))


def test_unreachable_rule_is_flagged():
    """Rules are first-match-wins, so a deny below a broad allow never fires."""
    config = config_with(
        {
            "p": {
                "default": "deny",
                "rules": [
                    {"name": "reads", "effect": "allow", "tools": ["ha_get_*"]},
                    {"name": "no-secrets", "effect": "deny", "tools": ["ha_get_secret"]},
                ],
            }
        }
    )
    assert any("unreachable" in message for message in messages(config, "warning"))


def test_correctly_ordered_rules_are_not_flagged_as_unreachable():
    config = config_with(
        {
            "p": {
                "default": "deny",
                "rules": [
                    {"name": "no-secrets", "effect": "deny", "tools": ["ha_get_secret"]},
                    {"name": "reads", "effect": "allow", "tools": ["ha_get_*"]},
                ],
            }
        }
    )
    assert not any("unreachable" in message for message in messages(config))


def test_a_conditional_rule_does_not_shadow_what_follows():
    config = config_with(
        {
            "p": {
                "default": "deny",
                "rules": [
                    {"effect": "allow", "tools": ["ha_*"], "when": {"args.domain": {"eq": "light"}}},
                    {"effect": "deny", "tools": ["ha_restart"]},
                ],
            }
        }
    )
    assert not any("unreachable" in message for message in messages(config))


def test_regex_in_a_glob_field_is_flagged():
    config = config_with({"p": {"rules": [{"effect": "deny", "tools": ["^ha_.*$"]}]}})
    assert any("looks like a regular expression" in message for message in messages(config, "warning"))


def test_redundant_anchors_are_noted():
    config = config_with(
        {
            "p": {
                "rules": [
                    {"effect": "allow", "tools": ["t"], "when": {"args.x": {"matches": "^light\\..*$"}}}
                ]
            }
        }
    )
    assert any("anchors" in message for message in messages(config, "note"))


def test_a_constraint_that_narrows_nothing_is_flagged():
    config = config_with(
        {"p": {"rules": [{"effect": "allow", "tools": ["t"], "when": {"args.x": {"matches": ".*"}}}]}}
    )
    assert any("does not narrow anything" in message for message in messages(config, "warning"))


def test_optional_in_an_allow_rule_is_flagged():
    config = config_with(
        {
            "p": {
                "rules": [
                    {
                        "effect": "allow",
                        "tools": ["t"],
                        "when": {"args.x": {"eq": "a", "optional": True}},
                    }
                ]
            }
        }
    )
    assert any("optional" in message for message in messages(config, "warning"))


def test_any_quantifier_in_an_allow_rule_is_flagged():
    config = config_with(
        {
            "p": {
                "rules": [
                    {
                        "effect": "allow",
                        "tools": ["t"],
                        "when": {"args.x[*]": {"eq": "a", "quantifier": "any"}},
                    }
                ]
            }
        }
    )
    assert any("were not checked" in message for message in messages(config, "warning"))


def test_unused_rate_limit_is_noted():
    config = config_with(
        {"p": {"rules": [{"effect": "allow", "tools": ["t"]}]}},
        rate_limits={"unused": {"rate": 1, "per": 60}},
    )
    assert any("no rule consumes it" in message for message in messages(config, "note"))


def test_a_sound_policy_produces_no_errors_or_warnings():
    config = config_with(
        {
            "p": {
                "default": "deny",
                "rules": [
                    {"name": "no-restart", "effect": "deny", "tools": ["ha_restart"]},
                    {"name": "reads", "effect": "allow", "tools": ["ha_get_*"]},
                    {
                        "name": "lights",
                        "effect": "allow",
                        "tools": ["ha_call_service"],
                        "when": {"args.domain": {"eq": "light"}},
                    },
                ],
            }
        }
    )
    assert messages(config, "error") == []
    assert messages(config, "warning") == []


def test_findings_are_ordered_most_severe_first():
    config = config_with({"p": {"default": "allow", "rules": [{"effect": "allow"}]}})
    severities = [finding.severity for finding in lint(config)]
    assert severities == sorted(severities, key=lambda s: {"error": 0, "warning": 1, "note": 2}[s])
