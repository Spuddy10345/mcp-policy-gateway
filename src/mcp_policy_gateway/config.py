"""Configuration schema for the gateway.

The whole file is declarative and safe to commit to a repository: secrets are
referenced by environment variable or stored as a SHA-256 digest, never inline
(see `TokenConfig`). `load_config` is the only entry point callers need.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .errors import ConfigError

Effect = Literal["allow", "deny"]
Mode = Literal["enforce", "dry-run"]

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_DURATION_PATTERN = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?\s*$")
_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def _expand_env(value: str, *, where: str) -> str:
    """Substitute `${VAR}` references from the process environment.

    Missing variables are a hard error rather than an empty string: silently
    expanding a credential to `""` is how a gateway ends up talking to an
    upstream unauthenticated.
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        try:
            return os.environ[name]
        except KeyError:
            raise ConfigError(f"{where}: environment variable ${{{name}}} is not set") from None

    return _ENV_PATTERN.sub(replace, value)


def parse_duration(value: str | float | int) -> float:
    """Parse `"30s"`, `"500ms"`, `"5m"`, `"1h"` or a bare number of seconds."""
    if isinstance(value, int | float):
        return float(value)
    match = _DURATION_PATTERN.match(value)
    if not match:
        raise ConfigError(f"invalid duration {value!r}; expected e.g. '30s', '500ms', '5m', '1h'")
    amount = float(match.group(1))
    unit = match.group(2) or "s"
    return amount * {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}[unit]


Duration = Annotated[float, Field(gt=0)]


class StrictModel(BaseModel):
    """Base model that rejects unknown keys.

    A typo in a policy file must never fail open. `deney:` silently ignored
    would leave the rule allowing everything it was meant to block.
    """

    model_config = ConfigDict(extra="forbid")


class StdioUpstream(StrictModel):
    """An MCP server launched as a subprocess and spoken to over stdio."""

    transport: Literal["stdio"] = "stdio"
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    #: Environment variables inherited from the gateway process. Empty by
    #: default: an upstream should not see the gateway's own credentials.
    inherit_env: list[str] = Field(default_factory=list)

    def resolved_env(self) -> dict[str, str]:
        env = {k: _expand_env(v, where=f"upstream env {k}") for k, v in self.env.items()}
        for key in self.inherit_env:
            if key in os.environ:
                env.setdefault(key, os.environ[key])
        return env


class HttpUpstream(StrictModel):
    """A remote MCP server reachable over streamable HTTP."""

    transport: Literal["http"] = "http"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float = 30.0

    def resolved_url(self) -> str:
        return _expand_env(self.url, where="upstream url")

    def resolved_headers(self) -> dict[str, str]:
        return {k: _expand_env(v, where=f"upstream header {k}") for k, v in self.headers.items()}


Upstream = Annotated[StdioUpstream | HttpUpstream, Field(discriminator="transport")]


class Constraint(StrictModel):
    """A predicate applied to one selector path of a tool call.

    Every operator that is set must hold. A selector that resolves to nothing
    fails the constraint unless `optional` is set or the only operator is
    `absent` — an argument that is simply missing must not satisfy a rule that
    was written to constrain it.
    """

    eq: Any = None
    ne: Any = None
    in_: list[Any] | None = Field(default=None, alias="in")
    not_in: list[Any] | None = None
    matches: str | None = None
    not_matches: str | None = None
    contains: Any = None
    gt: float | None = None
    gte: float | None = None
    lt: float | None = None
    lte: float | None = None
    present: bool | None = None
    absent: bool | None = None
    max_length: int | None = None
    #: With a wildcard selector (`args.items[*].id`), require the operators to
    #: hold for every match (`all`, the default) or at least one (`any`).
    #: `all` is the default because a rule that constrains a batch operation
    #: must not be satisfiable by smuggling one permitted element alongside
    #: forbidden ones.
    quantifier: Literal["all", "any"] = "all"
    #: Treat a selector that resolves to nothing as satisfied.
    optional: bool = False

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @field_validator("matches", "not_matches")
    @classmethod
    def _validate_regex(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid regular expression {value!r}: {exc}") from exc
        return value

    @model_validator(mode="after")
    def _at_least_one_operator(self) -> Constraint:
        if not self.operators():
            raise ValueError("constraint has no operators; expected at least one of eq/in/matches/...")
        return self

    def operators(self) -> dict[str, Any]:
        """The operators actually set on this constraint, in evaluation order."""
        names = (
            "eq",
            "ne",
            "in_",
            "not_in",
            "matches",
            "not_matches",
            "contains",
            "gt",
            "gte",
            "lt",
            "lte",
            "present",
            "absent",
            "max_length",
        )
        return {name: getattr(self, name) for name in names if getattr(self, name) is not None}


def _coerce_constraint(value: Any) -> Any:
    """Allow `args.domain: light` as shorthand for `args.domain: {eq: light}`."""
    if isinstance(value, dict):
        return value
    return {"eq": value}


class Rule(StrictModel):
    """One ordered allow/deny rule inside a policy."""

    name: str | None = None
    effect: Effect
    #: Glob patterns matched against the gateway-facing tool name. Omitted
    #: means "every tool".
    tools: list[str] | None = None
    #: Glob patterns matched against the upstream name.
    upstreams: list[str] | None = None
    #: Selector path -> constraint. All entries must hold for the rule to match.
    when: dict[str, Constraint] = Field(default_factory=dict)
    #: Rate-limit buckets consumed when this rule allows a call.
    rate_limits: list[str] = Field(default_factory=list)
    #: Human-readable justification surfaced in the audit log and in the error
    #: returned to the caller when the rule denies.
    reason: str | None = None

    @field_validator("when", mode="before")
    @classmethod
    def _coerce_shorthand(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: _coerce_constraint(v) for k, v in value.items()}
        return value

    @field_validator("tools", "upstreams")
    @classmethod
    def _reject_empty_pattern_list(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and not value:
            raise ValueError("pattern list is empty; omit the key to match everything")
        return value

    def describe(self, index: int) -> str:
        return self.name or f"{self.effect} rule #{index}"


class Policy(StrictModel):
    """A named capability set that tokens are bound to."""

    description: str | None = None
    #: Effect applied when no rule matches. Deny by default: a policy that
    #: fails open is not a policy.
    default: Effect = "deny"
    rules: list[Rule] = Field(default_factory=list)
    #: Hide tools this policy would deny from `tools/list` entirely, so a
    #: compromised or injected model never learns they exist. Defence in
    #: depth: `tools/call` is enforced regardless of this setting.
    hide_denied_tools: bool = True
    #: Override the gateway-wide mode for this policy.
    mode: Mode | None = None


class RateLimit(StrictModel):
    """A token bucket shared by every rule that names it."""

    #: Sustained rate, in calls per `per`.
    rate: float = Field(gt=0)
    per: Duration = 60.0
    #: Bucket capacity. Defaults to `rate`, i.e. no burst above the average.
    burst: float | None = Field(default=None, gt=0)
    #: Bucket scope. `token` keeps one bucket per caller (the default);
    #: `global` shares one bucket across every caller, which is what you want
    #: for protecting a fragile upstream rather than a single client.
    scope: Literal["token", "global"] = "token"

    @field_validator("per", mode="before")
    @classmethod
    def _parse(cls, value: Any) -> Any:
        return parse_duration(value) if isinstance(value, str) else value

    @property
    def capacity(self) -> float:
        return self.burst if self.burst is not None else self.rate

    @property
    def refill_per_second(self) -> float:
        return self.rate / self.per


class TokenConfig(StrictModel):
    """A credential bound to exactly one policy.

    Exactly one of `sha256` or `env` must be given. `sha256` is preferred: it
    lets the whole config live in version control, and the gateway never holds
    the plaintext of a credential it only needs to compare.
    """

    name: str
    policy: str
    #: Hex SHA-256 digest of the bearer token.
    sha256: str | None = None
    #: Name of an environment variable holding the plaintext token.
    env: str | None = None
    description: str | None = None

    @field_validator("sha256")
    @classmethod
    def _validate_digest(cls, value: str | None) -> str | None:
        if value is None:
            return None
        digest = value.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("sha256 must be a 64-character hex digest")
        return digest

    @model_validator(mode="after")
    def _exactly_one_source(self) -> TokenConfig:
        if (self.sha256 is None) == (self.env is None):
            raise ValueError(f"token {self.name!r}: set exactly one of 'sha256' or 'env'")
        return self


class AuditConfig(StrictModel):
    """Where decisions are written and how much of the payload survives."""

    path: Path | None = Path("audit.jsonl")
    #: Chain each record to its predecessor by hash, so a deleted or edited
    #: record can be detected with `mcp-policy-gateway audit verify`.
    hash_chain: bool = True
    #: Selector paths whose values are replaced by a salted digest.
    redact: list[str] = Field(default_factory=list)
    #: Argument *keys* matching any of these patterns are redacted wherever
    #: they appear. The defaults catch the usual credential names.
    redact_key_patterns: list[str] = Field(
        default_factory=lambda: [r"(?i)(pass(word|wd)|secret|token|api[-_ ]?key|authorization|credential)"]
    )
    #: Record arguments at all. Turning this off keeps the decision trail but
    #: drops payloads, for upstreams that handle regulated data.
    include_arguments: bool = True
    #: Truncate any single stringified value to this many characters.
    max_value_length: int = 512

    @field_validator("redact_key_patterns")
    @classmethod
    def _validate_patterns(cls, value: list[str]) -> list[str]:
        for pattern in value:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid redact_key_pattern {pattern!r}: {exc}") from exc
        return value


class ServerConfig(StrictModel):
    """How the gateway itself is exposed."""

    name: str = "mcp-policy-gateway"
    version: str = "0.1.0"
    instructions: str | None = None
    #: Separator between upstream name and tool name in the gateway-facing
    #: namespace, e.g. `hass__ha_restart`.
    namespace_separator: str = "__"
    #: Prefix tool names with the upstream name. `auto` prefixes only when more
    #: than one upstream is configured, keeping single-upstream deployments a
    #: drop-in replacement for the server they front.
    namespace: Literal["auto", "always", "never"] = "auto"
    #: Per-call timeout applied to upstream requests.
    upstream_timeout: Duration = 30.0

    @field_validator("upstream_timeout", mode="before")
    @classmethod
    def _parse(cls, value: Any) -> Any:
        return parse_duration(value) if isinstance(value, str) else value


class GatewayConfig(StrictModel):
    """The parsed contents of a gateway config file."""

    version: Literal[1] = 1
    mode: Mode = "enforce"
    server: ServerConfig = Field(default_factory=ServerConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    upstreams: dict[str, Upstream]
    policies: dict[str, Policy]
    tokens: list[TokenConfig] = Field(default_factory=list)
    rate_limits: dict[str, RateLimit] = Field(default_factory=dict)
    #: Path the config was loaded from, for error messages. Not settable in YAML.
    source_path: Path | None = Field(default=None, exclude=True)

    @field_validator("upstreams", "policies", "rate_limits")
    @classmethod
    def _validate_names(cls, value: dict[str, Any]) -> dict[str, Any]:
        for name in value:
            if not _NAME_PATTERN.match(name):
                raise ValueError(f"invalid name {name!r}: expected letters, digits, '.', '_' or '-'")
        return value

    @model_validator(mode="after")
    def _check_references(self) -> GatewayConfig:
        """Fail closed on dangling references.

        A token pointing at a policy that does not exist, or a rule naming a
        rate limit that was renamed, must not start the gateway.
        """
        errors: list[str] = []

        if not self.upstreams:
            errors.append("no upstreams configured")

        seen_tokens: set[str] = set()
        for token in self.tokens:
            if token.name in seen_tokens:
                errors.append(f"duplicate token name {token.name!r}")
            seen_tokens.add(token.name)
            if token.policy not in self.policies:
                errors.append(f"token {token.name!r} references unknown policy {token.policy!r}")

        for policy_name, policy in self.policies.items():
            for index, rule in enumerate(policy.rules):
                where = f"policy {policy_name!r} {rule.describe(index)}"
                for limit in rule.rate_limits:
                    if limit not in self.rate_limits:
                        errors.append(f"{where} references unknown rate limit {limit!r}")
                if rule.effect == "deny" and rule.rate_limits:
                    errors.append(f"{where}: rate_limits on a deny rule have no effect")
                for pattern in rule.upstreams or []:
                    if not any(_glob_could_match(pattern, name) for name in self.upstreams):
                        errors.append(f"{where}: upstream pattern {pattern!r} matches no configured upstream")

        if errors:
            raise ValueError("; ".join(errors))
        return self

    def policy_for(self, name: str) -> Policy:
        try:
            return self.policies[name]
        except KeyError:
            raise ConfigError(f"unknown policy {name!r}") from None

    def effective_mode(self, policy: Policy) -> Mode:
        return policy.mode or self.mode


def _glob_could_match(pattern: str, name: str) -> bool:
    from fnmatch import fnmatchcase

    return fnmatchcase(name, pattern)


def load_config(path: str | Path) -> GatewayConfig:
    """Read, parse and validate a gateway config file."""
    path = Path(path).expanduser()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a YAML mapping at the top level")

    try:
        config = GatewayConfig.model_validate(data)
    except ConfigError:
        raise
    except ValidationError as exc:
        raise ConfigError(f"{path}: {_format_validation_error(exc)}") from exc

    return config.model_copy(update={"source_path": path})


def _format_validation_error(exc: ValidationError) -> str:
    """Render a pydantic error as something a human can act on.

    The default rendering leads with the model class and a docs URL; what a
    config author needs is the path into their file and what was wrong with it.
    """
    lines = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ())) or "<root>"
        lines.append(f"{location}: {error.get('msg', '')}")
    return "\n  " + "\n  ".join(lines) if lines else str(exc)
