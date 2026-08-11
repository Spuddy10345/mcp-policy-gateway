"""Structured, append-only, tamper-evident audit log.

Every decision the gateway makes lands here as one JSON object per line.
Records are optionally chained: each carries the SHA-256 of its predecessor,
so removing or editing an entry breaks the chain from that point on and
`mcp-policy-gateway audit verify` reports exactly where.

This does not stop an attacker with write access from truncating the log and
rebuilding it — nothing local can, short of a co-signing service. It does mean
that selectively deleting the one record that incriminates you is no longer a
quiet operation, which is the realistic threat for a log stored beside the
process that writes it.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Self, TextIO

import anyio

from .config import AuditConfig
from .errors import AuditIntegrityError
from .redaction import Redactor

GENESIS_HASH = "0" * 64

Outcome = Literal["allowed", "denied", "rate_limited", "error", "dry-run-allowed"]


@dataclass
class AuditRecord:
    """One decision, with enough context to answer "who did what, and did it run?"."""

    timestamp: str
    event: str
    token: str
    policy: str
    upstream: str | None
    tool: str | None
    outcome: Outcome
    reason: str
    mode: str = "enforce"
    rule: str | None = None
    arguments: Any = None
    duration_ms: float | None = None
    request_id: str | None = None
    error: str | None = None
    #: Populated only for denials, where the failed constraint is the point.
    trace: list[str] = field(default_factory=list)
    seq: int = 0
    prev: str = GENESIS_HASH
    hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value not in (None, [], "")}


def canonical_hash(record: dict[str, Any], *, prev: str) -> str:
    """Hash a record's content plus its predecessor's hash.

    Serialisation is sorted and separator-normalised so the digest depends on
    the data, not on how the JSON happened to be formatted.
    """
    payload = {key: value for key, value in record.items() if key != "hash"}
    payload["prev"] = prev
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class AuditLog:
    """Writes `AuditRecord`s to a JSONL file (or a stream, or nowhere).

    Use as an async context manager; `write` is safe to call concurrently and
    serialises through a lock so the chain stays consistent.
    """

    def __init__(
        self,
        config: AuditConfig,
        *,
        stream: TextIO | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self._config = config
        self._redactor = redactor if redactor is not None else Redactor(config)
        self._explicit_stream = stream
        self._stream: TextIO | None = stream
        self._owns_stream = False
        self._lock = anyio.Lock()
        self._seq = 0
        self._prev = GENESIS_HASH
        self._records: list[dict[str, Any]] = []

    @property
    def redactor(self) -> Redactor:
        return self._redactor

    @property
    def records(self) -> list[dict[str, Any]]:
        """Records written by this instance, for tests and `--dry-run` output."""
        return self._records

    async def __aenter__(self) -> Self:
        self.open()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        self.close()

    def open(self) -> None:
        if self._stream is not None:
            return
        path = self._config.path
        if path is None:
            return

        path = Path(path).expanduser()
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)

        if self._config.hash_chain and path.exists():
            self._seq, self._prev = _tail_chain_state(path)

        # 0o600: the log holds tool arguments and identity names.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._stream = os.fdopen(descriptor, "a", encoding="utf-8")
        self._owns_stream = True

    def close(self) -> None:
        if self._owns_stream and self._stream is not None:
            self._stream.close()
        self._stream = self._explicit_stream
        self._owns_stream = False

    async def write(self, record: AuditRecord) -> dict[str, Any]:
        """Append a record, returning the dict actually written."""
        async with self._lock:
            self._seq += 1
            record.seq = self._seq
            payload = record.to_dict()

            if self._config.hash_chain:
                payload["prev"] = self._prev
                payload["hash"] = canonical_hash(payload, prev=self._prev)
                self._prev = payload["hash"]
            else:
                payload.pop("prev", None)
                payload.pop("hash", None)

            self._records.append(payload)
            if self._stream is not None:
                self._stream.write(json.dumps(payload, default=str) + "\n")
                self._stream.flush()
            return payload

    def redact(self, arguments: dict[str, Any] | None, *, tool: str, upstream: str) -> Any:
        if arguments is None:
            return None
        return self._redactor.redact_arguments(arguments, tool=tool, upstream=upstream)


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _tail_chain_state(path: Path) -> tuple[int, str]:
    """Recover `(seq, prev_hash)` from an existing log so appends keep chaining."""
    last: dict[str, Any] | None = None
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                # A partial final line from a hard kill. Verification will
                # flag it; appending after it is still the right move.
                continue

    if last is None:
        return 0, GENESIS_HASH
    return int(last.get("seq", 0)), str(last.get("hash", GENESIS_HASH))


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of checking a log's hash chain."""

    ok: bool
    checked: int
    problems: list[str]

    def summary(self) -> str:
        if self.ok:
            return f"OK: {self.checked} records, chain intact"
        return f"FAILED: {len(self.problems)} problem(s) across {self.checked} records"


def read_records(path: str | Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield `(line_number, record)` for each parsable line."""
    path = Path(path).expanduser()
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_number, json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditIntegrityError(f"{path}:{line_number}: not valid JSON: {exc}") from exc


def verify_chain(path: str | Path) -> VerificationResult:
    """Recompute every hash and check the links and sequence numbers."""
    problems: list[str] = []
    expected_prev = GENESIS_HASH
    expected_seq = 1
    checked = 0

    try:
        entries = list(read_records(path))
    except AuditIntegrityError as exc:
        return VerificationResult(ok=False, checked=0, problems=[str(exc)])

    for line_number, record in entries:
        checked += 1
        if "hash" not in record:
            problems.append(f"line {line_number}: record has no hash (chaining disabled when written?)")
            continue

        if record.get("prev") != expected_prev:
            problems.append(
                f"line {line_number}: prev={_short(record.get('prev'))} "
                f"but previous record hashed to {_short(expected_prev)} — a record was removed or altered"
            )

        recomputed = canonical_hash(record, prev=str(record.get("prev", GENESIS_HASH)))
        if recomputed != record["hash"]:
            problems.append(
                f"line {line_number}: content does not match its hash "
                f"(stored {_short(record['hash'])}, recomputed {_short(recomputed)}) — record was edited"
            )

        if record.get("seq") != expected_seq:
            problems.append(f"line {line_number}: seq={record.get('seq')}, expected {expected_seq}")

        expected_prev = str(record["hash"])
        expected_seq = int(record.get("seq", expected_seq)) + 1

    return VerificationResult(ok=not problems, checked=checked, problems=problems)


def _short(value: object) -> str:
    text = str(value)
    return text[:12] + "..." if len(text) > 12 else text


def stderr_log() -> TextIO:
    """The default sink when no audit path is configured."""
    return sys.stderr
