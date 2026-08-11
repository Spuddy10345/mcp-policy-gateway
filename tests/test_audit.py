"""Audit log: chaining, tamper detection, redaction, restart behaviour."""

from __future__ import annotations

import json
from itertools import pairwise

import pytest

from mcp_policy_gateway.audit import (
    GENESIS_HASH,
    AuditLog,
    AuditRecord,
    now_iso,
    read_records,
    verify_chain,
)
from mcp_policy_gateway.config import AuditConfig
from mcp_policy_gateway.redaction import Redactor


def record(tool: str = "ha_restart", outcome: str = "denied", **overrides) -> AuditRecord:
    data = {
        "timestamp": now_iso(),
        "event": "tools/call",
        "token": "assistant",
        "policy": "general",
        "upstream": "hass",
        "tool": tool,
        "outcome": outcome,
        "reason": "destructive",
    }
    data.update(overrides)
    return AuditRecord(**data)


async def write_all(log: AuditLog, count: int) -> None:
    for index in range(count):
        await log.write(record(tool=f"tool_{index}"))


# ---------------------------------------------------------------- basic output


async def test_records_are_one_json_object_per_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 3)

    lines = path.read_text().strip().split("\n")
    assert len(lines) == 3
    assert [json.loads(line)["tool"] for line in lines] == ["tool_0", "tool_1", "tool_2"]


async def test_log_file_is_not_world_readable(tmp_path):
    """It contains tool arguments and identity names."""
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 1)

    assert path.stat().st_mode & 0o077 == 0


async def test_parent_directory_is_created(tmp_path):
    path = tmp_path / "nested" / "deeper" / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 1)

    assert path.exists()


async def test_empty_fields_are_omitted(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        await log.write(record())

    written = json.loads(path.read_text().strip())
    assert "error" not in written
    assert "trace" not in written


# ----------------------------------------------------------------- hash chain


async def test_chain_links_each_record_to_its_predecessor(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 4)

    records = [entry for _, entry in read_records(path)]
    assert records[0]["prev"] == GENESIS_HASH
    for previous, current in pairwise(records):
        assert current["prev"] == previous["hash"]
    assert [entry["seq"] for entry in records] == [1, 2, 3, 4]


async def test_verify_accepts_an_untouched_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 5)

    result = verify_chain(path)
    assert result.ok
    assert result.checked == 5
    assert result.problems == []


async def test_verify_detects_an_edited_record(tmp_path):
    """The realistic attack: change one field, leave everything else alone."""
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 5)

    lines = path.read_text().strip().split("\n")
    tampered = json.loads(lines[2])
    tampered["outcome"] = "allowed"
    lines[2] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n")

    result = verify_chain(path)
    assert not result.ok
    assert any("was edited" in problem for problem in result.problems)
    assert any("line 3" in problem for problem in result.problems)


async def test_verify_detects_a_deleted_record(tmp_path):
    """Deleting the one line that incriminates you breaks every link after it."""
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 5)

    lines = path.read_text().strip().split("\n")
    del lines[2]
    path.write_text("\n".join(lines) + "\n")

    result = verify_chain(path)
    assert not result.ok
    assert any("removed or altered" in problem for problem in result.problems)


async def test_verify_detects_a_reordered_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 4)

    lines = path.read_text().strip().split("\n")
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")

    assert not verify_chain(path).ok


async def test_verify_reports_a_truncated_log_as_intact(tmp_path):
    """A known limitation, asserted so it stays known.

    Chaining proves nothing was changed *within* what remains. Detecting that
    the tail was lopped off needs an external anchor — an offsite copy, or a
    counter the log cannot roll back.
    """
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 5)

    lines = path.read_text().strip().split("\n")
    path.write_text("\n".join(lines[:3]) + "\n")

    assert verify_chain(path).ok is True


async def test_chain_continues_across_a_restart(tmp_path):
    path = tmp_path / "audit.jsonl"

    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 2)
    async with AuditLog(AuditConfig(path=path)) as log:
        await write_all(log, 2)

    result = verify_chain(path)
    assert result.ok
    assert result.checked == 4
    assert [entry["seq"] for _, entry in read_records(path)] == [1, 2, 3, 4]


async def test_chaining_can_be_switched_off(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path, hash_chain=False)) as log:
        await write_all(log, 2)

    records = [entry for _, entry in read_records(path)]
    assert all("hash" not in entry for entry in records)
    assert not verify_chain(path).ok  # verification needs hashes to check


def test_verify_rejects_a_corrupt_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"seq": 1}\nnot json at all\n')

    result = verify_chain(path)
    assert not result.ok
    assert "not valid JSON" in result.problems[0]


# ------------------------------------------------------------------ redaction


def redactor(**overrides) -> Redactor:
    return Redactor(AuditConfig(path=None, **overrides), key=b"fixed-test-key")


def test_credential_shaped_keys_are_redacted_by_default():
    result = redactor().redact_arguments(
        {"entity_id": "light.kitchen", "api_key": "sk-1234", "password": "hunter2"},
        tool="t",
        upstream="u",
    )
    assert result["entity_id"] == "light.kitchen"
    assert result["api_key"].startswith("[redacted:")
    assert result["password"].startswith("[redacted:")


def test_nested_credentials_are_found():
    result = redactor().redact_arguments(
        {"config": {"auth": {"token": "secret-value"}}}, tool="t", upstream="u"
    )
    assert "secret-value" not in json.dumps(result)


def test_configured_selectors_are_redacted():
    result = redactor(redact=["args.template"]).redact_arguments(
        {"template": "{{ states('sensor.x') }}"}, tool="t", upstream="u"
    )
    assert result["template"].startswith("[redacted:")


def test_wildcard_selectors_redact_every_element():
    result = redactor(redact=["args.items[*].value"]).redact_arguments(
        {"items": [{"value": "a"}, {"value": "b"}]}, tool="t", upstream="u"
    )
    assert all(item["value"].startswith("[redacted:") for item in result["items"])


def test_the_same_value_digests_identically():
    """So an investigator can correlate occurrences without seeing the value."""
    instance = redactor()
    first = instance.redact_arguments({"password": "same"}, tool="t", upstream="u")
    second = instance.redact_arguments({"password": "same"}, tool="t", upstream="u")
    assert first["password"] == second["password"]

    different = instance.redact_arguments({"password": "other"}, tool="t", upstream="u")
    assert different["password"] != first["password"]


def test_different_keys_produce_different_digests():
    """Two gateways cannot correlate each other's logs unless they share a key."""
    config = AuditConfig(path=None)
    assert Redactor(config, key=b"a").digest("x") != Redactor(config, key=b"b").digest("x")


def test_key_is_random_per_process_when_unset(monkeypatch):
    monkeypatch.delenv("MPG_REDACTION_KEY", raising=False)
    config = AuditConfig(path=None)
    assert Redactor(config).digest("x") != Redactor(config).digest("x")


def test_key_from_the_environment_is_stable_across_instances(monkeypatch):
    monkeypatch.setenv("MPG_REDACTION_KEY", "shared-key")
    config = AuditConfig(path=None)
    assert Redactor(config).digest("x") == Redactor(config).digest("x")


def test_long_values_are_truncated():
    result = redactor(max_value_length=10).redact_arguments({"note": "x" * 100}, tool="t", upstream="u")
    assert result["note"].startswith("x" * 10)
    assert result["note"].endswith("[truncated]")


def test_arguments_can_be_dropped_entirely():
    result = redactor(include_arguments=False).redact_arguments(
        {"password": "hunter2"}, tool="t", upstream="u"
    )
    assert result == "[arguments not recorded]"


def test_malformed_redact_selector_fails_at_construction():
    with pytest.raises(ValueError):
        Redactor(AuditConfig(path=None, redact=["args..broken"]))
