"""Exception types shared across the gateway."""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for every error this package raises deliberately."""


class ConfigError(GatewayError):
    """The config file is missing, malformed, or internally inconsistent."""


class AuthenticationError(GatewayError):
    """The presented credential did not map to a known token."""


class PolicyDenied(GatewayError):
    """A call was refused by policy.

    Carries the human-readable reason that is safe to return to the caller.
    Rule internals stay in the audit log; the caller learns that it was denied
    and why in general terms, not the shape of the rule that caught it.
    """

    def __init__(self, message: str, *, tool: str, rule: str | None = None) -> None:
        super().__init__(message)
        self.tool = tool
        self.rule = rule


class RateLimited(GatewayError):
    """A call was refused because a token bucket was empty."""

    def __init__(self, message: str, *, bucket: str, retry_after: float) -> None:
        super().__init__(message)
        self.bucket = bucket
        self.retry_after = retry_after


class UpstreamError(GatewayError):
    """An upstream server failed to start, connect, or respond."""


class AuditIntegrityError(GatewayError):
    """The audit log's hash chain does not verify."""
