"""Argument redaction for the audit log.

An audit log that records the arguments of every call is a second copy of
every secret those calls carried. Redaction replaces a value with a keyed
digest, so two occurrences of the same secret are still visibly the same
without the log revealing either.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import Any

from .config import AuditConfig
from .matching import MatchContext, parse_selector

#: Environment variable holding the redaction key. Set it to a stable value to
#: keep digests comparable across restarts; leave it unset and each run gets a
#: fresh random key, which is the safer default for a log that may be shared.
SALT_ENV_VAR = "MPG_REDACTION_KEY"

TRUNCATION_SUFFIX = "...[truncated]"


def _load_key() -> bytes:
    configured = os.environ.get(SALT_ENV_VAR)
    if configured:
        return configured.encode("utf-8")
    return secrets.token_bytes(32)


class Redactor:
    """Applies an `AuditConfig`'s redaction rules to call arguments."""

    def __init__(self, config: AuditConfig, *, key: bytes | None = None) -> None:
        self._config = config
        self._key = key if key is not None else _load_key()
        self._key_patterns = [re.compile(pattern) for pattern in config.redact_key_patterns]
        # Selector paths are pre-parsed so a malformed one fails at startup,
        # not on the first call that happens to traverse it.
        self._paths = [tuple(parse_selector(selector)) for selector in config.redact]

    def digest(self, value: Any) -> str:
        """A stable, non-reversible stand-in for a value."""
        material = repr(value).encode("utf-8", errors="replace")
        mac = hmac.new(self._key, material, hashlib.sha256).hexdigest()
        return f"[redacted:{mac[:16]}]"

    def redact_arguments(self, arguments: dict[str, Any], *, tool: str, upstream: str) -> Any:
        """Return a copy of `arguments` safe to write to disk."""
        if not self._config.include_arguments:
            return "[arguments not recorded]"

        targets = self._selector_targets(arguments, tool=tool, upstream=upstream)
        return self._walk(arguments, path=("args",), targets=targets)

    def _selector_targets(
        self, arguments: dict[str, Any], *, tool: str, upstream: str
    ) -> set[tuple[Any, ...]]:
        """Expand configured selectors into concrete paths for this call.

        Wildcards mean one selector can name many paths, so they are resolved
        against the actual arguments rather than matched structurally.
        """
        if not self._paths:
            return set()
        context = MatchContext(tool=tool, upstream=upstream, arguments=arguments)
        targets: set[tuple[Any, ...]] = set()
        for parts in self._paths:
            targets.update(_expand(parts, context.root(str(parts[0])), (str(parts[0]),)))
        return targets

    def _walk(self, value: Any, *, path: tuple[Any, ...], targets: set[tuple[Any, ...]]) -> Any:
        if path in targets:
            return self.digest(value)

        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, item in value.items():
                if self._key_is_sensitive(str(key)):
                    result[str(key)] = self.digest(item)
                else:
                    result[str(key)] = self._walk(item, path=(*path, key), targets=targets)
            return result

        if isinstance(value, list):
            return [
                self._walk(item, path=(*path, index), targets=targets) for index, item in enumerate(value)
            ]

        return self._truncate(value)

    def _key_is_sensitive(self, key: str) -> bool:
        return any(pattern.search(key) for pattern in self._key_patterns)

    def _truncate(self, value: Any) -> Any:
        limit = self._config.max_value_length
        if isinstance(value, str) and len(value) > limit:
            return value[:limit] + TRUNCATION_SUFFIX
        return value


def _expand(parts: tuple[Any, ...], value: Any, prefix: tuple[Any, ...]) -> set[tuple[Any, ...]]:
    """Resolve a parsed selector into every concrete path it addresses."""
    if len(parts) == 1:
        return {prefix}

    head, rest = parts[1], parts[1:]
    if head == "*":
        if isinstance(value, list):
            items = enumerate(value)
        elif isinstance(value, dict):
            items = value.items()  # type: ignore[assignment]
        else:
            return set()
        return {path for key, item in items for path in _expand(rest, item, (*prefix, key))}

    if isinstance(head, int):
        if isinstance(value, list) and -len(value) <= head < len(value):
            index = head if head >= 0 else len(value) + head
            return _expand(rest, value[index], (*prefix, index))
        return set()

    if isinstance(value, dict) and head in value:
        return _expand(rest, value[head], (*prefix, head))
    return set()
