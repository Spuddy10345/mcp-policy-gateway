"""Caller identity: who is on the other end of a request, and what may they do.

The gateway has two transports and therefore two ways of establishing identity:

* **HTTP** — a bearer token per request, verified against the configured
  digests. One gateway process serves many callers, each with its own policy.
* **stdio** — the client *launches* the gateway as a subprocess, so identity is
  fixed for the life of that process and is chosen at launch (`--token` or
  `--policy`). There is no per-request credential to check because there is
  only ever one caller.

Both paths converge on `Identity`, so nothing downstream needs to care which
transport a request arrived on.
"""

from __future__ import annotations

import contextvars
import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass

from .config import GatewayConfig, TokenConfig
from .errors import AuthenticationError, ConfigError


@dataclass(frozen=True)
class Identity:
    """An authenticated caller, bound to exactly one policy."""

    name: str
    policy: str

    def __str__(self) -> str:
        return f"{self.name} (policy {self.policy})"


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TokenRegistry:
    """Maps bearer tokens to identities by SHA-256 digest.

    The gateway never stores a plaintext token: `env`-sourced tokens are
    digested at startup and the plaintext is dropped. Lookup is a dict hit on
    the digest of what was presented, so it neither branches on nor compares
    secret material.
    """

    def __init__(self, tokens: list[TokenConfig]) -> None:
        self._by_digest: dict[str, Identity] = {}
        self._by_name: dict[str, Identity] = {}
        collisions: list[str] = []

        for token in tokens:
            identity = Identity(name=token.name, policy=token.policy)
            digest = self._digest_for(token)
            if digest in self._by_digest:
                collisions.append(
                    f"tokens {self._by_digest[digest].name!r} and {token.name!r} have the same value"
                )
            self._by_digest[digest] = identity
            self._by_name[token.name] = identity

        if collisions:
            raise ConfigError("; ".join(collisions))

    @staticmethod
    def _digest_for(token: TokenConfig) -> str:
        if token.sha256 is not None:
            return token.sha256
        assert token.env is not None  # guaranteed by TokenConfig validation
        secret = os.environ.get(token.env)
        if not secret:
            raise ConfigError(f"token {token.name!r}: environment variable {token.env} is not set")
        return token_digest(secret)

    def __len__(self) -> int:
        return len(self._by_digest)

    @property
    def names(self) -> list[str]:
        return list(self._by_name)

    def verify(self, presented: str) -> Identity:
        """Resolve a presented bearer token, or raise `AuthenticationError`."""
        identity = self._by_digest.get(token_digest(presented.strip()))
        if identity is None:
            raise AuthenticationError("unknown or revoked token")
        return identity

    def by_name(self, name: str) -> Identity:
        try:
            return self._by_name[name]
        except KeyError:
            known = ", ".join(sorted(self._by_name)) or "none configured"
            raise ConfigError(f"unknown token name {name!r}; configured tokens: {known}") from None


#: Identity for transports that fix it at launch (stdio). Unset under HTTP,
#: where the per-request bearer token is authoritative.
_ambient_identity: contextvars.ContextVar[Identity | None] = contextvars.ContextVar(
    "mcp_policy_gateway_identity", default=None
)


def set_ambient_identity(identity: Identity | None) -> contextvars.Token[Identity | None]:
    return _ambient_identity.set(identity)


def reset_ambient_identity(token: contextvars.Token[Identity | None]) -> None:
    _ambient_identity.reset(token)


def current_identity() -> Identity:
    """The identity fixed at launch, for transports that have one (stdio).

    Raises rather than defaulting to anything: a request whose caller cannot be
    established has no business reaching an upstream.
    """
    ambient = _ambient_identity.get()
    if ambient is not None:
        return ambient

    raise AuthenticationError("no credential presented and no ambient identity configured")


def bearer_token(headers: Mapping[str, str]) -> str:
    """Extract a bearer credential from an `Authorization` header."""
    raw = headers.get("authorization") or headers.get("Authorization")
    if not raw:
        raise AuthenticationError("no Authorization header")

    scheme, _, credential = raw.partition(" ")
    if scheme.lower() != "bearer" or not credential.strip():
        raise AuthenticationError("Authorization header is not a bearer token")
    return credential.strip()


def identity_from_headers(headers: Mapping[str, str], registry: TokenRegistry | None) -> Identity:
    """Resolve the caller of an HTTP request from its headers.

    Read per request rather than lifted from a context variable set by
    middleware: under streamable HTTP a request is handed to a session task,
    and a context variable set in the ASGI chain does not reliably follow it.
    Deriving identity from the request that is actually in hand removes the
    chance of a call being authorised as whoever was served last.
    """
    if registry is None:
        raise AuthenticationError("no tokens are configured; the gateway cannot identify callers")
    return registry.verify(bearer_token(headers))


def resolve_launch_identity(
    config: GatewayConfig,
    *,
    token_name: str | None,
    policy_name: str | None,
) -> Identity:
    """Work out the fixed identity for a stdio gateway.

    Exactly one of `--token` or `--policy` is required. `--policy` exists so a
    single-user stdio deployment does not have to invent a credential it would
    then store in a client config file in plaintext; the operating system's
    process boundary is the authentication.
    """
    if (token_name is None) == (policy_name is None):
        raise ConfigError("stdio transport needs exactly one of --token or --policy")

    if token_name is not None:
        return TokenRegistry(config.tokens).by_name(token_name)

    assert policy_name is not None
    if policy_name not in config.policies:
        known = ", ".join(sorted(config.policies))
        raise ConfigError(f"unknown policy {policy_name!r}; configured policies: {known}")
    return Identity(name=f"stdio:{policy_name}", policy=policy_name)
