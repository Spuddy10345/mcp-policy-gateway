"""An authorising reverse proxy for MCP servers.

The gateway sits between an agent and the MCP servers it can reach, and decides
per call whether the call happens. It exists because "the model decided to call
this tool" and "this tool ran" are two different events, and nothing in the MCP
stack separates them by default.

Typical use::

    from mcp_policy_gateway import load_config, Gateway, UpstreamPool, AuditLog

    config = load_config("policy.yaml")
    async with UpstreamPool(config) as pool, AuditLog(config.audit) as audit:
        server = Gateway(config, pool, audit).build_server()
"""

from __future__ import annotations

__version__ = "0.1.0"

from .audit import AuditLog, AuditRecord, verify_chain
from .config import GatewayConfig, Policy, Rule, load_config
from .engine import Decision, PolicyEngine
from .errors import (
    AuditIntegrityError,
    AuthenticationError,
    ConfigError,
    GatewayError,
    PolicyDenied,
    RateLimited,
    UpstreamError,
)
from .gateway import Gateway
from .identity import Identity, TokenRegistry
from .lint import Finding, lint
from .matching import MatchContext
from .ratelimit import RateLimiter
from .upstream import UpstreamPool

__all__ = [
    "AuditIntegrityError",
    "AuditLog",
    "AuditRecord",
    "AuthenticationError",
    "ConfigError",
    "Decision",
    "Finding",
    "Gateway",
    "GatewayConfig",
    "GatewayError",
    "Identity",
    "MatchContext",
    "Policy",
    "PolicyDenied",
    "PolicyEngine",
    "RateLimited",
    "RateLimiter",
    "Rule",
    "TokenRegistry",
    "UpstreamError",
    "UpstreamPool",
    "__version__",
    "lint",
    "load_config",
    "verify_chain",
]
