"""Token-bucket rate limiting.

A rule may name several buckets (say `destructive` and `per-upstream`). They
are consumed atomically: if any bucket is empty, none are debited. Charging a
caller for a request that was then refused would let a client exhaust an
unrelated budget by hammering one it has already drained.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

import anyio

from .config import RateLimit


@dataclass
class Bucket:
    """A single token bucket, refilled continuously rather than on a tick."""

    capacity: float
    refill_per_second: float
    tokens: float
    updated_at: float

    def _refill(self, now: float) -> None:
        elapsed = now - self.updated_at
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
            self.updated_at = now

    def available(self, now: float) -> float:
        self._refill(now)
        return self.tokens

    def retry_after(self, now: float, cost: float = 1.0) -> float:
        """Seconds until `cost` tokens are available."""
        self._refill(now)
        shortfall = cost - self.tokens
        if shortfall <= 0:
            return 0.0
        return shortfall / self.refill_per_second

    def consume(self, now: float, cost: float = 1.0) -> None:
        self._refill(now)
        self.tokens -= cost


@dataclass(frozen=True)
class RateLimitVerdict:
    """Whether a set of buckets admitted a call."""

    allowed: bool
    bucket: str | None = None
    retry_after: float = 0.0

    def __bool__(self) -> bool:
        return self.allowed


class RateLimiter:
    """Holds every bucket for the process.

    Buckets are created lazily on first use, so a limit that is configured but
    never hit costs nothing.
    """

    def __init__(
        self,
        limits: dict[str, RateLimit],
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limits = limits
        self._clock = clock
        self._buckets: dict[tuple[str, str], Bucket] = {}
        self._lock = anyio.Lock()

    def _key(self, name: str, identity: str) -> tuple[str, str]:
        limit = self._limits[name]
        return (name, "*" if limit.scope == "global" else identity)

    def _bucket(self, name: str, identity: str) -> Bucket:
        key = self._key(name, identity)
        bucket = self._buckets.get(key)
        if bucket is None:
            limit = self._limits[name]
            bucket = Bucket(
                capacity=limit.capacity,
                refill_per_second=limit.refill_per_second,
                tokens=limit.capacity,
                updated_at=self._clock(),
            )
            self._buckets[key] = bucket
        return bucket

    async def acquire(self, names: Sequence[str], identity: str) -> RateLimitVerdict:
        """Consume one token from every named bucket, or none of them."""
        if not names:
            return RateLimitVerdict(allowed=True)

        async with self._lock:
            now = self._clock()
            buckets = [(name, self._bucket(name, identity)) for name in _unique(names)]

            for name, bucket in buckets:
                if bucket.available(now) < 1.0:
                    return RateLimitVerdict(
                        allowed=False,
                        bucket=name,
                        retry_after=round(bucket.retry_after(now), 3),
                    )

            for _, bucket in buckets:
                bucket.consume(now)

        return RateLimitVerdict(allowed=True)

    def snapshot(self) -> dict[str, float]:
        """Current token counts, for diagnostics and tests."""
        now = self._clock()
        return {
            f"{name}:{identity}": bucket.available(now) for (name, identity), bucket in self._buckets.items()
        }


def _unique(names: Iterable[str]) -> list[str]:
    """Preserve order while dropping duplicates, so a bucket is debited once."""
    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result
