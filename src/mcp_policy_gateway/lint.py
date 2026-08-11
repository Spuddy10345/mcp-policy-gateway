"""Static checks over a config file.

A policy language is only useful if you can tell what a policy does without
running it. These checks catch the mistakes that are invisible at runtime
precisely because they fail *open*: a rule that never fires, an allow rule with
no constraints, a regex that reads as if it were anchored somewhere it is not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal

from .config import GatewayConfig, Policy, Rule

Severity = Literal["error", "warning", "note"]


@dataclass(frozen=True)
class Finding:
    """One problem found in a config."""

    severity: Severity
    where: str
    message: str

    def format(self) -> str:
        marker = {"error": "error", "warning": "warn ", "note": "note "}[self.severity]
        return f"{marker}  {self.where}: {self.message}"


def lint(config: GatewayConfig) -> list[Finding]:
    """Run every check and return the findings, most severe first."""
    findings: list[Finding] = []

    for name, policy in config.policies.items():
        findings.extend(_lint_policy(name, policy))

    findings.extend(_lint_tokens(config))
    findings.extend(_lint_rate_limits(config))

    order = {"error": 0, "warning": 1, "note": 2}
    return sorted(findings, key=lambda finding: order[finding.severity])


def _lint_policy(name: str, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    where = f"policy {name!r}"

    if policy.default == "allow":
        findings.append(
            Finding(
                "warning",
                where,
                "default is 'allow', so any tool an upstream adds later is permitted "
                "without the policy changing. Prefer 'deny' plus explicit allow rules.",
            )
        )

    if not policy.rules:
        findings.append(
            Finding(
                "warning",
                where,
                f"has no rules; every call resolves to the default ({policy.default})",
            )
        )

    for index, rule in enumerate(policy.rules):
        findings.extend(_lint_rule(where, index, rule))
        findings.extend(_check_reachability(where, index, rule, policy.rules[:index]))

    return findings


def _lint_rule(policy_where: str, index: int, rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    where = f"{policy_where} {rule.describe(index)}"

    if rule.effect == "allow" and rule.tools is None and not rule.when:
        findings.append(
            Finding(
                "error",
                where,
                "allows every tool with no constraints. If that is intended, say so with "
                "tools: ['*'] and a reason; as written it is indistinguishable from a mistake.",
            )
        )

    for pattern in rule.tools or []:
        if pattern == "*" and rule.effect == "allow" and not rule.when:
            findings.append(Finding("warning", where, "allows all tools unconditionally"))
        if _looks_like_regex(pattern):
            findings.append(
                Finding(
                    "warning",
                    where,
                    f"tool pattern {pattern!r} looks like a regular expression, but tool "
                    "patterns are globs (* and ?). Use 'when' with 'matches' for regexes.",
                )
            )

    for selector, constraint in rule.when.items():
        for field in ("matches", "not_matches"):
            pattern = getattr(constraint, field)
            if pattern is None:
                continue
            if pattern.startswith("^") or pattern.endswith("$"):
                findings.append(
                    Finding(
                        "note",
                        where,
                        f"{selector}.{field}: anchors in {pattern!r} are redundant — patterns are "
                        "matched against the whole value, never a substring.",
                    )
                )
            if _is_unbounded(pattern):
                findings.append(
                    Finding(
                        "warning",
                        where,
                        f"{selector}.{field}: {pattern!r} accepts any value, so the constraint "
                        "does not narrow anything.",
                    )
                )

        if rule.effect == "allow" and constraint.optional:
            findings.append(
                Finding(
                    "warning",
                    where,
                    f"{selector} is optional in an allow rule, so a call that omits it entirely "
                    "satisfies the constraint. Drop 'optional' unless that is intended.",
                )
            )

        if rule.effect == "allow" and constraint.quantifier == "any":
            findings.append(
                Finding(
                    "warning",
                    where,
                    f"{selector} uses quantifier 'any' in an allow rule: one acceptable element "
                    "permits a call whose other elements were not checked.",
                )
            )

    return findings


def _check_reachability(policy_where: str, index: int, rule: Rule, earlier: list[Rule]) -> list[Finding]:
    """Flag a rule that an earlier unconditional rule already settles."""
    for earlier_index, candidate in enumerate(earlier):
        if candidate.when:
            continue
        if not _covers(candidate.tools, rule.tools):
            continue
        if not _covers(candidate.upstreams, rule.upstreams):
            continue
        return [
            Finding(
                "warning",
                f"{policy_where} {rule.describe(index)}",
                f"is unreachable: {candidate.describe(earlier_index)} already matches everything "
                "this rule would, unconditionally. Rules are evaluated in order, first match wins.",
            )
        ]
    return []


def _covers(broad: list[str] | None, narrow: list[str] | None) -> bool:
    """Whether every name matched by `narrow` is also matched by `broad`.

    Approximate by design: it compares literal patterns rather than deciding
    glob containment in general, so it reports a rule as unreachable only when
    that is plainly true.
    """
    if broad is None:
        return True
    if narrow is None:
        return False
    return all(any(fnmatchcase(pattern, wide) or pattern == wide for wide in broad) for pattern in narrow)


def _lint_tokens(config: GatewayConfig) -> list[Finding]:
    findings: list[Finding] = []

    used_policies = {token.policy for token in config.tokens}
    for name in config.policies:
        if name not in used_policies:
            findings.append(
                Finding(
                    "note",
                    f"policy {name!r}",
                    "is not referenced by any token. That is fine for stdio (--policy selects it "
                    "directly) but means nothing can reach it over HTTP.",
                )
            )

    for token in config.tokens:
        if token.env is not None:
            findings.append(
                Finding(
                    "note",
                    f"token {token.name!r}",
                    f"reads its value from ${token.env} at startup. Storing 'sha256' instead lets "
                    "this file be committed without the secret being present anywhere.",
                )
            )

    return findings


def _lint_rate_limits(config: GatewayConfig) -> list[Finding]:
    used = {
        limit for policy in config.policies.values() for rule in policy.rules for limit in rule.rate_limits
    }
    return [
        Finding("note", f"rate limit {name!r}", "is defined but no rule consumes it")
        for name in config.rate_limits
        if name not in used
    ]


def _looks_like_regex(pattern: str) -> bool:
    return any(character in pattern for character in r"^$+()|\\") or ".*" in pattern


def _is_unbounded(pattern: str) -> bool:
    """Whether a pattern matches every string."""
    stripped = pattern.strip("^$")
    return stripped in (".*", ".*?", "(.*)", "[\\s\\S]*") or re.fullmatch(r"\.\*", stripped) is not None
