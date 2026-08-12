"""Selector and constraint semantics.

Most of these are bypass tests: for each way a rule could be written, the
question is whether some argument shape satisfies it that the author did not
intend.
"""

from __future__ import annotations

import pytest

from mcp_policy_gateway.config import Constraint
from mcp_policy_gateway.matching import (
    MAX_REGEX_INPUT,
    MatchContext,
    SelectorError,
    evaluate_constraint,
    matches_any,
    parse_selector,
    resolve,
)


def context(**arguments) -> MatchContext:
    return MatchContext(tool="ha_call_service", upstream="hass", arguments=arguments)


def check(selector: str, spec: dict, **arguments) -> bool:
    return bool(evaluate_constraint(selector, Constraint.model_validate(spec), context(**arguments)))


# --------------------------------------------------------------------- parsing


@pytest.mark.parametrize(
    ("selector", "expected"),
    [
        ("args", ["args"]),
        ("args.domain", ["args", "domain"]),
        ("args.a.b.c", ["args", "a", "b", "c"]),
        ("args.items[*]", ["args", "items", "*"]),
        ("args.items[0].id", ["args", "items", 0, "id"]),
        ("args.items[-1]", ["args", "items", -1]),
        ("target", ["target"]),
    ],
)
def test_parse_selector(selector, expected):
    assert parse_selector(selector) == expected


@pytest.mark.parametrize("selector", ["", "args.", ".args", "args..b", "args[", "args[a]"])
def test_invalid_selectors_are_rejected(selector):
    with pytest.raises(SelectorError):
        parse_selector(selector)


def test_unknown_selector_root_is_rejected():
    with pytest.raises(SelectorError, match="unknown selector root"):
        resolve("environ.SECRET", context(domain="light"))


# ------------------------------------------------------------------ resolution


def test_resolve_reads_nested_values():
    ctx = context(target={"entity_id": "light.kitchen"})
    assert resolve("args.target.entity_id", ctx) == ["light.kitchen"]


def test_resolve_wildcard_collects_every_element():
    ctx = context(items=[{"id": "a"}, {"id": "b"}])
    assert resolve("args.items[*].id", ctx) == ["a", "b"]


def test_resolve_missing_path_is_empty():
    assert resolve("args.nope", context(domain="light")) == []


def test_resolve_reads_tool_and_upstream():
    ctx = context()
    assert resolve("tool", ctx) == ["ha_call_service"]
    assert resolve("upstream", ctx) == ["hass"]


# --------------------------------------------------------------- absent values


def test_missing_argument_fails_a_constraint_rather_than_passing_vacuously():
    """The bug this prevents: `when: {args.domain: {in: [light]}}` on a call
    that omits `domain` entirely must not match an allow rule."""
    assert check("args.domain", {"in": ["light"]}, service="turn_on") is False


def test_optional_lets_a_missing_argument_pass():
    assert check("args.domain", {"in": ["light"], "optional": True}, service="x") is True


def test_absent_requires_the_argument_to_be_missing():
    assert check("args.force", {"absent": True}, domain="light") is True
    assert check("args.force", {"absent": True}, domain="light", force=True) is False


def test_present_requires_the_argument_to_exist():
    assert check("args.domain", {"present": True}, domain="light") is True
    assert check("args.domain", {"present": True}, service="x") is False


# ------------------------------------------------------------------- operators


@pytest.mark.parametrize(
    ("spec", "arguments", "expected"),
    [
        ({"eq": "light"}, {"domain": "light"}, True),
        ({"eq": "light"}, {"domain": "lock"}, False),
        ({"ne": "lock"}, {"domain": "light"}, True),
        ({"in": ["light", "climate"]}, {"domain": "climate"}, True),
        ({"in": ["light"]}, {"domain": "lock"}, False),
        ({"not_in": ["lock"]}, {"domain": "light"}, True),
        ({"not_in": ["lock"]}, {"domain": "lock"}, False),
        ({"contains": "kitchen"}, {"domain": "light.kitchen"}, True),
        ({"max_length": 5}, {"domain": "light"}, True),
        ({"max_length": 3}, {"domain": "light"}, False),
    ],
)
def test_operators(spec, arguments, expected):
    assert check("args.domain", spec, **arguments) is expected


@pytest.mark.parametrize(
    ("spec", "value", "expected"),
    [
        ({"gt": 5}, 6, True),
        ({"gt": 5}, 5, False),
        ({"gte": 5}, 5, True),
        ({"lt": 5}, 4, True),
        ({"lte": 5}, 5, True),
        ({"lt": 5}, "4", False),  # a string is not a number
        ({"gt": 0}, True, False),  # bool is not treated as numeric
    ],
)
def test_numeric_operators(spec, value, expected):
    assert check("args.brightness", spec, brightness=value) is expected


def test_all_operators_in_one_constraint_must_hold():
    spec = {"matches": "light\\..+", "max_length": 20}
    assert check("args.entity_id", spec, entity_id="light.kitchen") is True
    assert check("args.entity_id", spec, entity_id="light." + "x" * 40) is False


# ----------------------------------------------------------------------- regex


def test_matches_is_a_full_match_not_a_search():
    """The bypass this closes: an allow rule for `light\\..*` must not also
    permit an entity whose id merely *contains* that substring."""
    assert check("args.entity_id", {"matches": "light\\..*"}, entity_id="light.kitchen") is True
    assert check("args.entity_id", {"matches": "light\\..*"}, entity_id="x/light.kitchen") is False


def test_anchors_are_harmless_because_matching_is_already_anchored():
    assert check("args.entity_id", {"matches": "^light\\..*$"}, entity_id="light.kitchen") is True


def test_not_matches_excludes():
    assert check("args.entity_id", {"not_matches": "lock\\..*"}, entity_id="light.a") is True
    assert check("args.entity_id", {"not_matches": "lock\\..*"}, entity_id="lock.a") is False


def test_regex_against_a_non_string_fails_closed():
    assert check("args.entity_id", {"matches": ".+"}, entity_id=42) is False


def test_oversized_value_is_not_handed_to_the_regex_engine():
    """Tool arguments are attacker-influenced under prompt injection; an
    unbounded value plus a backtracking pattern is a denial of service."""
    payload = "a" * (MAX_REGEX_INPUT + 1)
    assert check("args.entity_id", {"matches": "a*"}, entity_id=payload) is False
    # And the exclusion form fails closed too, rather than concluding "safe".
    assert check("args.entity_id", {"not_matches": "evil"}, entity_id=payload) is False


# ------------------------------------------------------------------ quantifiers


def test_wildcard_defaults_to_requiring_every_element_to_pass():
    """Smuggling test: one permitted entity must not carry a batch of others."""
    spec = {"matches": "light\\..*"}
    assert check("args.entity_id[*]", spec, entity_id=["light.a", "light.b"]) is True
    assert check("args.entity_id[*]", spec, entity_id=["light.a", "lock.front"]) is False


def test_any_quantifier_accepts_a_single_passing_element():
    spec = {"matches": "light\\..*", "quantifier": "any"}
    assert check("args.entity_id[*]", spec, entity_id=["lock.front", "light.a"]) is True
    assert check("args.entity_id[*]", spec, entity_id=["lock.front"]) is False


def test_failure_detail_names_the_offending_value():
    result = evaluate_constraint(
        "args.entity_id[*]",
        Constraint.model_validate({"matches": "light\\..*"}),
        context(entity_id=["light.a", "lock.front"]),
    )
    assert not result.satisfied
    assert "lock.front" in result.detail
    assert "1 of 2" in result.detail


# ------------------------------------------------------------------ tool globs


@pytest.mark.parametrize(
    ("name", "patterns", "expected"),
    [
        ("ha_restart", ["ha_restart"], True),
        ("ha_get_state", ["ha_get_*"], True),
        ("ha_set_state", ["ha_get_*"], False),
        ("ha_restart", None, True),
        ("ha_restart", ["*"], True),
        ("HA_RESTART", ["ha_restart"], False),  # matching is case-sensitive
    ],
)
def test_matches_any(name, patterns, expected):
    assert matches_any(name, patterns) is expected


def test_constraint_with_no_operators_is_rejected_at_parse_time():
    with pytest.raises(ValueError, match="no operators"):
        Constraint.model_validate({})


def test_invalid_regex_is_rejected_at_parse_time():
    with pytest.raises(ValueError, match="invalid regular expression"):
        Constraint.model_validate({"matches": "([unclosed"})
