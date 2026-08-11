"""Token verification and identity resolution."""

from __future__ import annotations

import pytest

from mcp_policy_gateway.config import GatewayConfig, TokenConfig
from mcp_policy_gateway.errors import AuthenticationError, ConfigError
from mcp_policy_gateway.identity import (
    Identity,
    TokenRegistry,
    bearer_token,
    current_identity,
    identity_from_headers,
    reset_ambient_identity,
    resolve_launch_identity,
    set_ambient_identity,
    token_digest,
)

SECRET = "correct-horse-battery-staple"
DIGEST = token_digest(SECRET)


def registry(*tokens: TokenConfig) -> TokenRegistry:
    return TokenRegistry(list(tokens))


def token(name: str = "laptop", policy: str = "assistant", **overrides) -> TokenConfig:
    return TokenConfig(name=name, policy=policy, sha256=overrides.pop("sha256", DIGEST), **overrides)


def test_a_valid_token_resolves_to_its_identity():
    identity = registry(token()).verify(SECRET)
    assert identity == Identity(name="laptop", policy="assistant")


def test_an_unknown_token_is_rejected():
    with pytest.raises(AuthenticationError, match="unknown or revoked"):
        registry(token()).verify("not-the-token")


def test_surrounding_whitespace_is_tolerated():
    assert registry(token()).verify(f"  {SECRET}\n").name == "laptop"


def test_the_plaintext_is_never_stored():
    """The digest is all the gateway needs, so it is all the gateway keeps."""
    instance = registry(token())
    assert SECRET not in repr(vars(instance))


def test_env_sourced_tokens_are_digested_at_startup(monkeypatch):
    monkeypatch.setenv("MPG_TOKEN_LAPTOP", SECRET)
    instance = registry(TokenConfig(name="laptop", policy="assistant", env="MPG_TOKEN_LAPTOP"))
    assert instance.verify(SECRET).name == "laptop"


def test_missing_env_token_is_a_startup_error(monkeypatch):
    monkeypatch.delenv("MPG_TOKEN_LAPTOP", raising=False)
    with pytest.raises(ConfigError, match="is not set"):
        registry(TokenConfig(name="laptop", policy="assistant", env="MPG_TOKEN_LAPTOP"))


def test_two_tokens_with_the_same_value_are_rejected():
    """Otherwise one silently shadows the other and the audit log names the
    wrong caller."""
    with pytest.raises(ConfigError, match="same value"):
        registry(token("laptop"), token("phone"))


def test_lookup_by_name():
    instance = registry(token("laptop"))
    assert instance.by_name("laptop").policy == "assistant"
    with pytest.raises(ConfigError, match="unknown token name"):
        instance.by_name("desktop")


# ------------------------------------------------------------------- headers


@pytest.mark.parametrize(
    "header",
    ["Bearer " + SECRET, "bearer " + SECRET, "BEARER  " + SECRET + " "],
)
def test_bearer_token_is_extracted_case_insensitively(header):
    assert bearer_token({"authorization": header}) == SECRET


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"authorization": ""},
        {"authorization": "Bearer"},
        {"authorization": "Bearer   "},
        {"authorization": f"Basic {SECRET}"},
        {"authorization": SECRET},
    ],
)
def test_malformed_authorization_headers_are_rejected(headers):
    with pytest.raises(AuthenticationError):
        bearer_token(headers)


def test_identity_from_headers_resolves_a_valid_token():
    identity = identity_from_headers({"authorization": f"Bearer {SECRET}"}, registry(token()))
    assert identity.name == "laptop"


def test_identity_from_headers_without_a_registry_fails_closed():
    """An HTTP gateway with no tokens cannot identify anyone, so it serves nobody."""
    with pytest.raises(AuthenticationError, match="cannot identify callers"):
        identity_from_headers({"authorization": f"Bearer {SECRET}"}, None)


def test_identity_renders_readably_for_logs():
    assert str(Identity(name="laptop", policy="readonly")) == "laptop (policy readonly)"


# ------------------------------------------------------------- ambient identity


def test_current_identity_reads_the_ambient_value():
    identity = Identity(name="stdio:readonly", policy="readonly")
    context_token = set_ambient_identity(identity)
    try:
        assert current_identity() == identity
    finally:
        reset_ambient_identity(context_token)


def test_current_identity_raises_when_nothing_is_set():
    context_token = set_ambient_identity(None)
    try:
        with pytest.raises(AuthenticationError, match="no credential"):
            current_identity()
    finally:
        reset_ambient_identity(context_token)


# ------------------------------------------------------------ launch identity


def config_with(policies: list[str], tokens: list[TokenConfig] | None = None) -> GatewayConfig:
    return GatewayConfig.model_validate(
        {
            "version": 1,
            "upstreams": {"hass": {"transport": "stdio", "command": "x"}},
            "policies": {name: {"default": "deny"} for name in policies},
            "tokens": [t.model_dump(exclude_none=True) for t in (tokens or [])],
        }
    )


def test_policy_flag_yields_a_synthetic_identity():
    config = config_with(["readonly"])
    identity = resolve_launch_identity(config, token_name=None, policy_name="readonly")
    assert identity == Identity(name="stdio:readonly", policy="readonly")


def test_token_flag_yields_the_configured_identity():
    config = config_with(["assistant"], [token("laptop", "assistant")])
    identity = resolve_launch_identity(config, token_name="laptop", policy_name=None)
    assert identity == Identity(name="laptop", policy="assistant")


def test_exactly_one_of_token_or_policy_is_required():
    config = config_with(["readonly"])
    with pytest.raises(ConfigError, match="exactly one"):
        resolve_launch_identity(config, token_name=None, policy_name=None)
    with pytest.raises(ConfigError, match="exactly one"):
        resolve_launch_identity(config, token_name="laptop", policy_name="readonly")


def test_unknown_policy_at_launch_lists_the_valid_ones():
    config = config_with(["readonly", "assistant"])
    with pytest.raises(ConfigError, match="assistant, readonly"):
        resolve_launch_identity(config, token_name=None, policy_name="typo")
