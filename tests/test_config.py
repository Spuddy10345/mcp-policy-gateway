"""Config parsing and validation.

The theme: every one of these mistakes, left unchecked, produces a gateway
that starts cleanly and enforces less than its author believed.
"""

from __future__ import annotations

import textwrap

import pytest

from mcp_policy_gateway.config import GatewayConfig, StdioUpstream, load_config, parse_duration
from mcp_policy_gateway.errors import ConfigError

MINIMAL = """
version: 1
upstreams:
  hass:
    transport: stdio
    command: uvx
    args: [hass-mcp]
policies:
  readonly:
    default: deny
    rules:
      - effect: allow
        tools: [ha_get_*]
"""


def write(tmp_path, text: str):
    path = tmp_path / "policy.yaml"
    path.write_text(textwrap.dedent(text))
    return path


def test_minimal_config_loads(tmp_path):
    config = load_config(write(tmp_path, MINIMAL))

    assert config.mode == "enforce"
    assert set(config.upstreams) == {"hass"}
    assert config.policies["readonly"].default == "deny"
    assert config.source_path is not None


def test_missing_file_is_reported_clearly(tmp_path):
    with pytest.raises(ConfigError, match="cannot read config"):
        load_config(tmp_path / "nope.yaml")


def test_invalid_yaml_is_reported_clearly(tmp_path):
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(write(tmp_path, "upstreams: [unclosed"))


def test_non_mapping_top_level_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="mapping at the top level"):
        load_config(write(tmp_path, "- a\n- b\n"))


def test_unknown_keys_are_rejected(tmp_path):
    """A typo must never fail open: `deney:` silently ignored leaves the rule
    allowing everything it was meant to block."""
    config = MINIMAL.replace("      - effect: allow", "      - effect: allow\n        deney: [x]")
    with pytest.raises(ConfigError, match=r"[Ee]xtra"):
        load_config(write(tmp_path, config))


def test_a_config_with_no_upstreams_is_rejected(tmp_path):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, "version: 1\nupstreams: {}\npolicies: {}\n"))


# ------------------------------------------------------------------ references


def test_token_pointing_at_a_missing_policy_is_rejected(tmp_path):
    config = (
        MINIMAL
        + """
tokens:
  - name: laptop
    policy: does-not-exist
    sha256: %s
"""
        % ("a" * 64)
    )
    with pytest.raises(ConfigError, match="unknown policy"):
        load_config(write(tmp_path, config))


def test_rule_naming_a_missing_rate_limit_is_rejected(tmp_path):
    config = MINIMAL + "        rate_limits: [ghost]\n"
    with pytest.raises(ConfigError, match="unknown rate limit"):
        load_config(write(tmp_path, config))


def test_rate_limit_on_a_deny_rule_is_rejected(tmp_path):
    """It reads as if it throttles the denial; it does nothing at all."""
    config = MINIMAL.replace("effect: allow", "effect: deny") + "        rate_limits: [slow]\n"
    config += "rate_limits:\n  slow:\n    rate: 1\n    per: 60s\n"
    with pytest.raises(ConfigError, match="no effect"):
        load_config(write(tmp_path, config))


def test_upstream_pattern_matching_nothing_is_rejected(tmp_path):
    config = MINIMAL + "        upstreams: [typo-*]\n"
    with pytest.raises(ConfigError, match="matches no configured upstream"):
        load_config(write(tmp_path, config))


def test_duplicate_token_names_are_rejected(tmp_path):
    config = (
        MINIMAL
        + f"""
tokens:
  - name: laptop
    policy: readonly
    sha256: {"a" * 64}
  - name: laptop
    policy: readonly
    sha256: {"b" * 64}
"""
    )
    with pytest.raises(ConfigError, match="duplicate token"):
        load_config(write(tmp_path, config))


# --------------------------------------------------------------------- tokens


def test_token_needs_exactly_one_secret_source(tmp_path):
    both = (
        MINIMAL
        + f"""
tokens:
  - name: laptop
    policy: readonly
    sha256: {"a" * 64}
    env: MPG_TOKEN
"""
    )
    with pytest.raises(ConfigError, match="exactly one"):
        load_config(write(tmp_path, both))

    neither = MINIMAL + "\ntokens:\n  - name: laptop\n    policy: readonly\n"
    with pytest.raises(ConfigError, match="exactly one"):
        load_config(write(tmp_path, neither))


def test_malformed_digest_is_rejected(tmp_path):
    config = MINIMAL + "\ntokens:\n  - name: laptop\n    policy: readonly\n    sha256: nothex\n"
    with pytest.raises(ConfigError, match="64-character hex"):
        load_config(write(tmp_path, config))


# -------------------------------------------------------- environment expansion


def test_env_references_are_expanded(monkeypatch):
    monkeypatch.setenv("HA_TOKEN", "secret-value")
    upstream = StdioUpstream(command="uvx", env={"HA_TOKEN": "${HA_TOKEN}"})
    assert upstream.resolved_env() == {"HA_TOKEN": "secret-value"}


def test_missing_env_reference_is_an_error_not_an_empty_string(monkeypatch):
    """Expanding a credential to "" is how a gateway ends up talking to an
    upstream unauthenticated."""
    monkeypatch.delenv("ABSENT_VAR", raising=False)
    upstream = StdioUpstream(command="uvx", env={"HA_TOKEN": "${ABSENT_VAR}"})
    with pytest.raises(ConfigError, match="ABSENT_VAR"):
        upstream.resolved_env()


def test_upstream_env_is_not_inherited_by_default(monkeypatch):
    """An upstream must not see the gateway's own credentials."""
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "very-secret")
    assert StdioUpstream(command="uvx").resolved_env() == {}


def test_inherit_env_passes_named_variables_through(monkeypatch):
    monkeypatch.setenv("PATH_LIKE", "/usr/bin")
    upstream = StdioUpstream(command="uvx", inherit_env=["PATH_LIKE"])
    assert upstream.resolved_env() == {"PATH_LIKE": "/usr/bin"}


# ------------------------------------------------------------------- durations


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("500ms", 0.5), ("30s", 30.0), ("5m", 300.0), ("1h", 3600.0), ("45", 45.0), (12, 12.0)],
)
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "soon", "5 fortnights", "-5s"])
def test_invalid_durations_are_rejected(text):
    with pytest.raises(ConfigError):
        parse_duration(text)


def test_durations_in_config_accept_suffixes(tmp_path):
    config = MINIMAL + "rate_limits:\n  slow:\n    rate: 5\n    per: 10m\n"
    loaded = load_config(write(tmp_path, config))
    assert loaded.rate_limits["slow"].per == 600.0
    assert loaded.rate_limits["slow"].refill_per_second == pytest.approx(5 / 600)


# ------------------------------------------------------------------- shorthand


def test_scalar_when_value_is_shorthand_for_eq():
    policy = GatewayConfig.model_validate(
        {
            "version": 1,
            "upstreams": {"hass": {"transport": "stdio", "command": "x"}},
            "policies": {
                "p": {"rules": [{"effect": "allow", "tools": ["t"], "when": {"args.domain": "light"}}]}
            },
        }
    ).policies["p"]

    assert policy.rules[0].when["args.domain"].eq == "light"


def test_empty_pattern_list_is_rejected():
    """`tools: []` reads as "no tools" but would match everything."""
    with pytest.raises(ValueError, match="omit the key"):
        GatewayConfig.model_validate(
            {
                "version": 1,
                "upstreams": {"hass": {"transport": "stdio", "command": "x"}},
                "policies": {"p": {"rules": [{"effect": "allow", "tools": []}]}},
            }
        )


def test_effective_mode_prefers_the_policy_override(tmp_path):
    config = load_config(write(tmp_path, MINIMAL + "    mode: dry-run\n"))
    assert config.mode == "enforce"
    assert config.effective_mode(config.policies["readonly"]) == "dry-run"


def test_policy_for_rejects_an_unknown_name(tmp_path):
    config = load_config(write(tmp_path, MINIMAL))
    with pytest.raises(ConfigError, match="unknown policy"):
        config.policy_for("ghost")
