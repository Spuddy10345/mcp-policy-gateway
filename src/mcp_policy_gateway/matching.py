"""Selector resolution and constraint evaluation.

Two small languages live here:

* **Selectors** address values inside a tool call: `args.entity_id`,
  `args.targets[*].id`, `args.items[0]`, or the bare `tool` / `upstream`.
* **Constraints** (see `config.Constraint`) are predicates over the values a
  selector resolved to.

Both are deliberately tiny. A policy engine whose expression language can do
arbitrary computation is a policy engine nobody can review, and reviewability
is the entire point of writing the rules down.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from .config import Constraint

#: Values longer than this are not handed to a regular expression, and a
#: `matches` constraint on an over-long value fails closed.
#:
#: This is a cap on input size, *not* on work. Backtracking is exponential in
#: the input length, so a pattern that can backtrack catastrophically will hang
#: long before it reaches this bound — 30 characters is already enough. The
#: defence against that is `unsafe_repetition`, which refuses such patterns when
#: the config loads; this cap only keeps well-formed patterns from being handed
#: megabyte-sized arguments.
MAX_REGEX_INPUT = 4096

#: The roots a selector may start from. Kept next to `MatchContext.root`, which
#: is the thing that has to agree with it, and exported so config validation can
#: reject a typo'd root before the gateway starts rather than on the first call.
SELECTOR_ROOTS = frozenset({"args", "tool", "resource", "prompt", "upstream"})

_SEGMENT = re.compile(r"([^.\[\]]+)|\[(\*|-?\d+)\]")


class SelectorError(ValueError):
    """A selector path is syntactically invalid."""


@dataclass(frozen=True)
class MatchContext:
    """Everything a rule may be written against."""

    upstream: str
    tool: str | None = None
    resource: str | None = None
    prompt: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)

    def root(self, name: str) -> Any:
        if name == "args":
            return self.arguments
        if name == "tool":
            return self.tool
        if name == "resource":
            return self.resource
        if name == "prompt":
            return self.prompt
        if name == "upstream":
            return self.upstream
        raise SelectorError(_unknown_root_message(name))


def parse_selector(selector: str) -> list[str | int]:
    """Split `args.targets[*].id` into `['args', 'targets', '*', 'id']`.

    List indices are returned as ints, `[*]` as the string `'*'`, and mapping
    keys as strings.
    """
    if not selector or selector.strip() != selector:
        raise SelectorError(f"invalid selector {selector!r}")

    parts: list[str | int] = []
    position = 0
    # A '.' is only legal *between* segments, never leading, trailing or
    # doubled: `.args` and `args..b` would otherwise parse as `args`, silently
    # turning a typo into a selector that resolves.
    expect_separator = False

    while position < len(selector):
        character = selector[position]

        if character == ".":
            if not expect_separator:
                raise SelectorError(f"invalid selector {selector!r}: unexpected '.' at offset {position}")
            expect_separator = False
            position += 1
            if position >= len(selector):
                raise SelectorError(f"invalid selector {selector!r}: trailing '.'")
            continue

        if character != "[" and expect_separator:
            raise SelectorError(f"invalid selector {selector!r}: expected '.' or '[' at offset {position}")

        match = _SEGMENT.match(selector, position)
        if not match:
            raise SelectorError(f"invalid selector {selector!r} at offset {position}")

        key, index = match.groups()
        if key is not None:
            parts.append(key)
        elif index == "*":
            parts.append("*")
        else:
            parts.append(int(index))

        expect_separator = True
        position = match.end()

    if not parts or not expect_separator:
        raise SelectorError(f"invalid selector {selector!r}")
    return parts


def _unknown_root_message(name: str) -> str:
    expected = ", ".join(repr(root) for root in sorted(SELECTOR_ROOTS))
    return f"unknown selector root {name!r}; expected one of {expected}"


def validate_selector(selector: str) -> list[str | int]:
    """Parse a selector *and* check its root, raising `SelectorError` if either fails.

    `parse_selector` alone is not enough for config validation: `argz.domain`
    parses perfectly well and only fails when `MatchContext.root` is asked for
    `argz`, which happens on the first call that reaches the rule. A wrong root
    is the likeliest selector typo, so it has to be caught at load time too.
    """
    parts = parse_selector(selector)
    root = parts[0]
    if not isinstance(root, str):
        raise SelectorError(f"invalid selector {selector!r}: must start with a name")
    if root not in SELECTOR_ROOTS:
        raise SelectorError(f"invalid selector {selector!r}: {_unknown_root_message(root)}")
    return parts


def resolve(selector: str, context: MatchContext) -> list[Any]:
    """Return every value the selector addresses.

    An empty list means the path is absent, which callers must treat as
    "constraint not satisfied" rather than "vacuously true".
    """
    parts = parse_selector(selector)
    root_name = parts[0]
    if not isinstance(root_name, str):
        raise SelectorError(f"invalid selector {selector!r}: must start with a name")

    current: list[Any] = [context.root(root_name)]
    for part in parts[1:]:
        current = _step(current, part)
        if not current:
            return []
    return current


def _step(values: list[Any], part: str | int) -> list[Any]:
    result: list[Any] = []
    for value in values:
        if part == "*":
            if isinstance(value, list):
                result.extend(value)
            elif isinstance(value, dict):
                result.extend(value.values())
        elif isinstance(part, int):
            if isinstance(value, list) and -len(value) <= part < len(value):
                result.append(value[part])
        elif isinstance(value, dict) and part in value:
            result.append(value[part])
    return result


_UNBOUNDED_QUANTIFIER = re.compile(r"\{\d+,\}")


def _quantifier_at(pattern: str, position: int) -> str | None:
    """The unbounded quantifier starting at `position`, if there is one."""
    if position >= len(pattern):
        return None
    if pattern[position] in "*+":
        return pattern[position]
    match = _UNBOUNDED_QUANTIFIER.match(pattern, position)
    return match.group(0) if match else None


def _contains_unbounded_quantifier(body: str) -> bool:
    """Whether `body` repeats something without a ceiling, ignoring escapes and classes."""
    position = 0
    in_class = False
    while position < len(body):
        character = body[position]
        if character == "\\":
            position += 2
            continue
        if in_class:
            in_class = character != "]"
            position += 1
            continue
        if character == "[":
            in_class = True
            position += 1
            continue
        if _quantifier_at(body, position):
            return True
        position += 1
    return False


def unsafe_repetition(pattern: str) -> str | None:
    """Return the offending fragment if `pattern` can backtrack catastrophically.

    Looks for the dominant shape — an unbounded quantifier applied to a group
    that already repeats something unbounded, as in `(a+)+` or `(\\d*x)*`. Those
    take time exponential in the input length, which no cap on input size can
    make safe, so they are refused when the config loads instead.

    Conservative in both directions and deliberately so: it accepts `(https?)+`
    (the inner `?` has a ceiling) and it does not catch overlapping alternations
    like `(a|ab)*`. It is a cheap check for the mistake policy authors actually
    make, not a decision procedure.
    """
    stack: list[int] = []
    position = 0
    in_class = False

    while position < len(pattern):
        character = pattern[position]
        if character == "\\":
            position += 2
            continue
        if in_class:
            in_class = character != "]"
            position += 1
            continue
        if character == "[":
            in_class = True
        elif character == "(":
            stack.append(position)
        elif character == ")" and stack:
            start = stack.pop()
            quantifier = _quantifier_at(pattern, position + 1)
            if quantifier and _contains_unbounded_quantifier(pattern[start + 1 : position]):
                return pattern[start : position + 1 + len(quantifier)]
        position += 1

    return None


@dataclass(frozen=True)
class ConstraintResult:
    """Whether a constraint held, and a reason to put in the audit log."""

    satisfied: bool
    #: Why. Never contains a caller-supplied value: this string is copied into
    #: the audit log's `trace` and into the refusal handed back to the caller,
    #: neither of which goes through `redaction.Redactor`. The value that failed
    #: is in the record's `arguments`, redacted according to policy.
    detail: str

    def __bool__(self) -> bool:
        return self.satisfied


def evaluate_constraint(selector: str, constraint: Constraint, context: MatchContext) -> ConstraintResult:
    """Evaluate one `selector: constraint` pair against a call."""
    values = resolve(selector, context)
    operators = constraint.operators()

    if not values:
        if constraint.absent:
            return ConstraintResult(True, f"{selector} absent")
        if constraint.optional:
            return ConstraintResult(True, f"{selector} absent (optional)")
        return ConstraintResult(False, f"{selector} is absent")

    if constraint.absent:
        return ConstraintResult(False, f"{selector} is present but required to be absent")

    # `absent` is handled above. `present` (always `true` — the negated form is
    # rejected at config load) means "resolves to a non-null value", which the
    # operator table checks explicitly rather than treating as a no-op.
    checks = {name: value for name, value in operators.items() if name != "absent"}
    if not checks:
        return ConstraintResult(True, f"{selector} present")

    outcomes = [(value, _check_value(value, checks)) for value in values]
    failures = [(value, detail) for value, (ok, detail) in outcomes if not ok]

    if constraint.quantifier == "any":
        if len(failures) < len(outcomes):
            return ConstraintResult(True, f"{selector} satisfied by at least one value")
        return ConstraintResult(False, f"{selector}: no value satisfied the constraint")

    if failures:
        value, detail = failures[0]
        suffix = f" ({len(failures)} of {len(outcomes)} values failed)" if len(outcomes) > 1 else ""
        return ConstraintResult(False, f"{selector} ({_describe(value)}) {detail}{suffix}")
    return ConstraintResult(True, f"{selector} satisfied")


def _check_value(value: Any, checks: dict[str, Any]) -> tuple[bool, str]:
    for name, operand in checks.items():
        ok, detail = _OPERATORS[name](value, operand)
        if not ok:
            return False, detail
    return True, "ok"


def _op_eq(value: Any, operand: Any) -> tuple[bool, str]:
    return value == operand, f"!= {_render(operand)}"


def _op_ne(value: Any, operand: Any) -> tuple[bool, str]:
    return value != operand, f"== {_render(operand)} (excluded)"


def _op_in(value: Any, operand: list[Any]) -> tuple[bool, str]:
    return value in operand, f"not in {_render(operand)}"


def _op_not_in(value: Any, operand: list[Any]) -> tuple[bool, str]:
    return value not in operand, f"in excluded set {_render(operand)}"


def _regex_input(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if len(value) > MAX_REGEX_INPUT:
        return None
    return value


def _op_matches(value: Any, operand: str) -> tuple[bool, str]:
    text = _regex_input(value)
    if text is None:
        return False, f"is not a string of at most {MAX_REGEX_INPUT} characters"
    # Full match, not search: an allow rule written as `light\.` must not also
    # permit `switch.light_bypass`. See docs/policy-language.md.
    return re.fullmatch(operand, text) is not None, f"does not match /{operand}/"


def _op_not_matches(value: Any, operand: str) -> tuple[bool, str]:
    text = _regex_input(value)
    if text is None:
        # Fail closed: an over-long value cannot be shown to be safe.
        return False, f"is not a string of at most {MAX_REGEX_INPUT} characters"
    return re.fullmatch(operand, text) is None, f"matches excluded pattern /{operand}/"


def _op_contains(value: Any, operand: Any) -> tuple[bool, str]:
    if isinstance(value, str):
        return (isinstance(operand, str) and operand in value), f"does not contain {_render(operand)}"
    if isinstance(value, list | tuple | set):
        return operand in value, f"does not contain {_render(operand)}"
    if isinstance(value, dict):
        return operand in value, f"has no key {_render(operand)}"
    return False, "is not a container"


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def _compare(symbol: str, test: Any) -> Any:
    def operator(value: Any, operand: float) -> tuple[bool, str]:
        number = _numeric(value)
        if number is None:
            return False, "is not a number"
        return test(number, operand), f"is not {symbol} {operand}"

    return operator


def _op_max_length(value: Any, operand: int) -> tuple[bool, str]:
    try:
        length = len(value)
    except TypeError:
        return False, "has no length"
    return length <= operand, f"is longer than {operand}"


def _op_present(value: Any, operand: bool) -> tuple[bool, str]:
    return (value is not None) == operand, "presence mismatch"


_OPERATORS: dict[str, Any] = {
    "eq": _op_eq,
    "ne": _op_ne,
    "in_": _op_in,
    "not_in": _op_not_in,
    "matches": _op_matches,
    "not_matches": _op_not_matches,
    "contains": _op_contains,
    "gt": _compare(">", lambda a, b: a > b),
    "gte": _compare(">=", lambda a, b: a >= b),
    "lt": _compare("<", lambda a, b: a < b),
    "lte": _compare("<=", lambda a, b: a <= b),
    "max_length": _op_max_length,
    "present": _op_present,
}


def _render(value: Any) -> str:
    """Compact, bounded rendering of a value for a decision reason.

    Only ever applied to operands, which come from the policy file. Caller-
    supplied values go through `_describe` instead.
    """
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


def _describe(value: Any) -> str:
    """Say what a caller-supplied value *was like*, never what it was.

    Constraint details end up in the audit log's `trace` and in the text handed
    back to the caller. Neither passes through `redaction.Redactor`, so putting
    the value itself here wrote tool arguments to disk in the clear — past both
    the configured redaction rules and `include_arguments: false`. The shape of
    the value is enough to debug a policy; the value is in `arguments`.
    """
    if value is None or isinstance(value, bool):
        return repr(value)
    if isinstance(value, int | float):
        return "a number"
    if isinstance(value, str):
        return f"a {len(value)}-character string"
    if isinstance(value, list | tuple):
        return f"a {len(value)}-element list"
    if isinstance(value, dict):
        return f"an object with {len(value)} key(s)"
    return type(value).__name__


def matches_any(name: str, patterns: list[str] | None) -> bool:
    """Case-sensitive glob match, where `None` means "no restriction"."""
    if patterns is None:
        return True
    return any(fnmatchcase(name, pattern) for pattern in patterns)
