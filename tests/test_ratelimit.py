"""Token bucket behaviour."""

from __future__ import annotations

import pytest

from mcp_policy_gateway.config import RateLimit
from mcp_policy_gateway.ratelimit import RateLimiter


class Clock:
    """A hand-cranked monotonic clock, so timing tests do not sleep."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


def limiter(clock: Clock, **limits) -> RateLimiter:
    return RateLimiter({name: RateLimit.model_validate(spec) for name, spec in limits.items()}, clock=clock)


async def test_burst_is_spent_then_refused(clock):
    limits = limiter(clock, slow={"rate": 10, "per": 60, "burst": 3})

    for _ in range(3):
        assert await limits.acquire(["slow"], "alice")

    verdict = await limits.acquire(["slow"], "alice")
    assert not verdict
    assert verdict.bucket == "slow"
    assert verdict.retry_after > 0


async def test_bucket_refills_over_time(clock):
    limits = limiter(clock, slow={"rate": 60, "per": 60, "burst": 1})

    assert await limits.acquire(["slow"], "alice")
    assert not await limits.acquire(["slow"], "alice")

    clock.advance(1.0)  # one token per second
    assert await limits.acquire(["slow"], "alice")


async def test_retry_after_predicts_when_the_next_token_lands(clock):
    limits = limiter(clock, slow={"rate": 60, "per": 60, "burst": 1})
    await limits.acquire(["slow"], "alice")

    verdict = await limits.acquire(["slow"], "alice")
    assert verdict.retry_after == pytest.approx(1.0, abs=0.01)

    clock.advance(verdict.retry_after)
    assert await limits.acquire(["slow"], "alice")


async def test_refill_is_capped_at_capacity(clock):
    limits = limiter(clock, slow={"rate": 60, "per": 60, "burst": 2})
    await limits.acquire(["slow"], "alice")

    clock.advance(3600)  # an hour of idleness does not bank an hour of calls
    assert await limits.acquire(["slow"], "alice")
    assert await limits.acquire(["slow"], "alice")
    assert not await limits.acquire(["slow"], "alice")


async def test_burst_defaults_to_the_rate(clock):
    limits = limiter(clock, slow={"rate": 2, "per": 60})
    assert await limits.acquire(["slow"], "alice")
    assert await limits.acquire(["slow"], "alice")
    assert not await limits.acquire(["slow"], "alice")


# ---------------------------------------------------------------------- scope


async def test_token_scope_gives_each_caller_its_own_budget(clock):
    limits = limiter(clock, slow={"rate": 1, "per": 60, "burst": 1, "scope": "token"})

    assert await limits.acquire(["slow"], "alice")
    assert not await limits.acquire(["slow"], "alice")
    assert await limits.acquire(["slow"], "bob")


async def test_global_scope_shares_one_budget(clock):
    """For protecting a fragile upstream rather than throttling one client."""
    limits = limiter(clock, slow={"rate": 1, "per": 60, "burst": 1, "scope": "global"})

    assert await limits.acquire(["slow"], "alice")
    assert not await limits.acquire(["slow"], "bob")


# -------------------------------------------------------------------- atomicity


async def test_multiple_buckets_are_all_debited(clock):
    limits = limiter(
        clock,
        a={"rate": 10, "per": 60, "burst": 10},
        b={"rate": 10, "per": 60, "burst": 10},
    )
    await limits.acquire(["a", "b"], "alice")

    assert limits.snapshot()["a:alice"] == pytest.approx(9)
    assert limits.snapshot()["b:alice"] == pytest.approx(9)


async def test_an_empty_bucket_refunds_the_others(clock):
    """Charging for a call that was then refused would let a client drain an
    unrelated budget by hammering one it has already exhausted."""
    limits = limiter(
        clock,
        plenty={"rate": 100, "per": 60, "burst": 100},
        scarce={"rate": 1, "per": 60, "burst": 1},
    )

    assert await limits.acquire(["plenty", "scarce"], "alice")
    before = limits.snapshot()["plenty:alice"]

    for _ in range(10):
        assert not await limits.acquire(["plenty", "scarce"], "alice")

    assert limits.snapshot()["plenty:alice"] == pytest.approx(before)


async def test_a_bucket_named_twice_is_debited_once(clock):
    limits = limiter(clock, a={"rate": 10, "per": 60, "burst": 10})
    await limits.acquire(["a", "a"], "alice")
    assert limits.snapshot()["a:alice"] == pytest.approx(9)


async def test_no_buckets_always_admits(clock):
    assert await limiter(clock).acquire([], "alice")


async def test_concurrent_acquires_do_not_oversell_the_bucket(clock):
    """The check-then-debit sequence must not interleave."""
    import anyio

    limits = limiter(clock, slow={"rate": 5, "per": 60, "burst": 5})
    granted: list[bool] = []

    async def attempt() -> None:
        granted.append(bool(await limits.acquire(["slow"], "alice")))

    async with anyio.create_task_group() as group:
        for _ in range(20):
            group.start_soon(attempt)

    assert sum(granted) == 5
