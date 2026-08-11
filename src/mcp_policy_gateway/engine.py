"""The policy decision point.

Rules are evaluated **in order, first match wins**, falling through to the
policy's `default` (which is `deny` unless the author says otherwise). That is
the only ordering semantics in the system: no priority numbers, no implicit
"deny overrides allow" pass. A reviewer reads the rules top to bottom and knows
what happens, which matters more than expressive power.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .config import Effect, Policy, Rule
from .matching import MatchContext, evaluate_constraint, matches_any

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating one call against one policy."""

    effect: Effect
    reason: str
    #: `None` when no rule matched and the policy default applied.
    rule_name: str | None = None
    rule_index: int | None = None
    #: Rate-limit buckets this call should consume, in order.
    rate_limits: tuple[str, ...] = ()
    #: The constraint evaluations that were performed, newest rule last. Kept
    #: for `explain`, and for the audit record when a call is denied.
    trace: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"

    @property
    def matched_rule(self) -> bool:
        return self.rule_index is not None

    def describe(self) -> str:
        source = self.rule_name if self.rule_name else "policy default"
        return f"{self.effect} by {source}: {self.reason}"


@dataclass
class _RuleOutcome:
    """Whether a rule applies to a call, and why."""

    applies: bool
    #: True when applicability could not be decided because arguments were not
    #: available (visibility checks only).
    indeterminate: bool = False
    reason: str = ""
    trace: list[str] = field(default_factory=list)


class PolicyEngine:
    """Evaluates calls against a `Policy`.

    Stateless and cheap: the same engine can serve every request. Rate limiting
    lives in `ratelimit.RateLimiter` because it is the one part of enforcement
    that must hold state.
    """

    def evaluate(self, policy: Policy, context: MatchContext) -> Decision:
        """Decide whether `context` is permitted under `policy`."""
        trace: list[str] = []

        for index, rule in enumerate(policy.rules):
            outcome = self._rule_applies(rule, context)
            # Attribute each line to its rule: a trace that interleaves the
            # constraint checks of several rules without saying which is which
            # reads as if one rule both passed and failed.
            trace.extend(f"[{rule.describe(index)}] {line}" for line in outcome.trace)
            if not outcome.applies:
                continue
            return Decision(
                effect=rule.effect,
                reason=rule.reason or outcome.reason,
                rule_name=rule.describe(index),
                rule_index=index,
                rate_limits=tuple(rule.rate_limits) if rule.effect == "allow" else (),
                trace=tuple(trace),
            )

        return Decision(
            effect=policy.default,
            reason=f"no rule matched; policy default is {policy.default}",
            trace=tuple(trace),
        )

    def is_visible(self, policy: Policy, tool: str, upstream: str) -> bool:
        """Whether `tool` may appear in `tools/list` for this policy.

        Argument-dependent rules cannot be settled without a call to inspect,
        so this answers the weaker question "could any arguments make this
        allowed?". A conditionally-denied tool stays listed — the model needs
        to see it to use it legitimately — while an unconditionally-denied one
        is never advertised at all.

        Hiding is a usability and blast-radius measure, not the control:
        `tools/call` is enforced independently, so a client that calls a hidden
        tool by name is still refused.
        """
        probe = MatchContext(tool=tool, upstream=upstream, arguments={})

        for rule in policy.rules:
            if not self._patterns_match(rule, probe):
                continue
            if not rule.when:
                # Unconditional: this rule settles the question.
                return rule.effect == "allow"
            if rule.effect == "allow":
                # Some arguments might satisfy it.
                return True
            # A conditional deny leaves the tool reachable via a later rule.

        return policy.default == "allow"

    def _patterns_match(self, rule: Rule, context: MatchContext) -> bool:
        return matches_any(context.tool, rule.tools) and matches_any(context.upstream, rule.upstreams)

    def _rule_applies(self, rule: Rule, context: MatchContext) -> _RuleOutcome:
        if not self._patterns_match(rule, context):
            return _RuleOutcome(applies=False)

        if not rule.when:
            return _RuleOutcome(applies=True, reason=f"tool {context.tool!r} matched")

        trace: list[str] = []
        for selector, constraint in rule.when.items():
            result = evaluate_constraint(selector, constraint, context)
            trace.append(f"{'PASS' if result.satisfied else 'FAIL'} {result.detail}")
            if not result.satisfied:
                return _RuleOutcome(applies=False, reason=result.detail, trace=trace)

        return _RuleOutcome(
            applies=True,
            reason="; ".join(detail.removeprefix("PASS ") for detail in trace),
            trace=trace,
        )


def visible_tools(engine: PolicyEngine, policy: Policy, tools: Iterable[tuple[str, str, Any]]) -> list[Any]:
    """Filter `(gateway_name, upstream_name, tool)` triples down to what a policy shows."""
    if not policy.hide_denied_tools:
        return [tool for _, _, tool in tools]
    return [tool for name, upstream, tool in tools if engine.is_visible(policy, name, upstream)]
