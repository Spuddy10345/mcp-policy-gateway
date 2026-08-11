"""CLI behaviour, including the exit codes CI depends on."""

from __future__ import annotations

import json
import textwrap

import pytest

from mcp_policy_gateway.audit import AuditLog, AuditRecord, now_iso
from mcp_policy_gateway.cli import EXIT_DENIED, EXIT_FINDINGS, EXIT_OK, main
from mcp_policy_gateway.config import AuditConfig
from mcp_policy_gateway.identity import token_digest

CONFIG = """
version: 1
upstreams:
  hass:
    transport: stdio
    command: uvx
    args: [hass-mcp]
policies:
  assistant:
    default: deny
    rules:
      - name: reads
        effect: allow
        tools: [ha_get_*]
      - name: lights-only
        effect: allow
        tools: [ha_call_service]
        when:
          args.domain: light
        reason: actuation limited to lights
      - name: no-restart
        effect: deny
        tools: [ha_restart]
        reason: destructive
"""


@pytest.fixture
def config_path(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(textwrap.dedent(CONFIG))
    return path


# ------------------------------------------------------------------- validate


def test_validate_accepts_a_sound_config(config_path, capsys):
    assert main(["validate", "-c", str(config_path)]) == EXIT_OK
    assert "config is valid" in capsys.readouterr().out


def test_validate_reports_errors_with_a_distinct_exit_code(tmp_path, capsys):
    path = tmp_path / "bad.yaml"
    path.write_text(
        "version: 1\n"
        "upstreams: {hass: {transport: stdio, command: x}}\n"
        "policies: {p: {default: deny, rules: [{effect: allow}]}}\n"
    )
    assert main(["validate", "-c", str(path)]) == EXIT_FINDINGS
    assert "allows every tool" in capsys.readouterr().out


def test_validate_strict_fails_on_warnings(tmp_path):
    path = tmp_path / "warn.yaml"
    path.write_text(
        "version: 1\nupstreams: {hass: {transport: stdio, command: x}}\npolicies: {p: {default: allow}}\n"
    )
    assert main(["validate", "-c", str(path)]) == EXIT_OK
    assert main(["validate", "-c", str(path), "--strict"]) == EXIT_FINDINGS


def test_validate_reports_a_broken_config_as_an_error(tmp_path, capsys):
    path = tmp_path / "broken.yaml"
    path.write_text("version: 1\nupstreams: {}\npolicies: {}\n")
    assert main(["validate", "-c", str(path)]) != EXIT_OK
    assert "error" in capsys.readouterr().err


# -------------------------------------------------------------------- explain


def test_explain_reports_an_allowed_call(config_path, capsys):
    exit_code = main(["explain", "-c", str(config_path), "--policy", "assistant", "--tool", "ha_get_state"])
    output = capsys.readouterr().out

    assert exit_code == EXIT_OK
    assert output.startswith("ALLOW")
    assert "reads" in output


def test_explain_exits_non_zero_on_a_denial(config_path, capsys):
    """So a policy can be asserted in CI: `explain ... || echo blocked`."""
    exit_code = main(["explain", "-c", str(config_path), "--policy", "assistant", "--tool", "ha_restart"])
    output = capsys.readouterr().out

    assert exit_code == EXIT_DENIED
    assert output.startswith("DENY")
    assert "destructive" in output
    assert "hidden from tools/list" in output


def test_explain_decides_on_arguments(config_path, capsys):
    allowed = main(
        [
            "explain",
            "-c",
            str(config_path),
            "--policy",
            "assistant",
            "--tool",
            "ha_call_service",
            "--args",
            '{"domain": "light"}',
        ]
    )
    denied = main(
        [
            "explain",
            "-c",
            str(config_path),
            "--policy",
            "assistant",
            "--tool",
            "ha_call_service",
            "--args",
            '{"domain": "lock"}',
        ]
    )

    assert allowed == EXIT_OK
    assert denied == EXIT_DENIED
    assert "FAIL" in capsys.readouterr().out


def test_explain_json_output_is_machine_readable(config_path, capsys):
    main(
        [
            "explain",
            "-c",
            str(config_path),
            "--policy",
            "assistant",
            "--tool",
            "ha_restart",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert payload["effect"] == "deny"
    assert payload["rule"] == "no-restart"
    assert payload["listed"] is False
    assert payload["enforced"] is True


def test_explain_rejects_malformed_arguments(config_path, capsys):
    exit_code = main(
        [
            "explain",
            "-c",
            str(config_path),
            "--policy",
            "assistant",
            "--tool",
            "ha_get_state",
            "--args",
            "{not json",
        ]
    )
    assert exit_code != EXIT_OK
    assert "not valid JSON" in capsys.readouterr().err


def test_explain_rejects_a_non_object_argument_payload(config_path, capsys):
    exit_code = main(
        [
            "explain",
            "-c",
            str(config_path),
            "--policy",
            "assistant",
            "--tool",
            "ha_get_state",
            "--args",
            "[1, 2]",
        ]
    )
    assert exit_code != EXIT_OK
    assert "must be a JSON object" in capsys.readouterr().err


def test_explain_rejects_an_unknown_policy(config_path, capsys):
    assert main(["explain", "-c", str(config_path), "--policy", "ghost", "--tool", "x"]) != EXIT_OK
    assert "unknown policy" in capsys.readouterr().err


# ---------------------------------------------------------------------- audit


@pytest.fixture
async def audit_path(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(AuditConfig(path=path)) as log:
        for index in range(3):
            await log.write(
                AuditRecord(
                    timestamp=now_iso(),
                    event="tools/call",
                    token="assistant",
                    policy="assistant",
                    upstream="hass",
                    tool="ha_get_state" if index else "ha_restart",
                    outcome="allowed" if index else "denied",
                    reason="destructive" if not index else "ok",
                )
            )
    return path


async def test_audit_verify_accepts_an_intact_log(audit_path, capsys):
    assert main(["audit", "verify", str(audit_path)]) == EXIT_OK
    assert "chain intact" in capsys.readouterr().out


async def test_audit_verify_flags_tampering(audit_path, capsys):
    lines = audit_path.read_text().strip().split("\n")
    record = json.loads(lines[0])
    record["outcome"] = "allowed"
    lines[0] = json.dumps(record)
    audit_path.write_text("\n".join(lines) + "\n")

    assert main(["audit", "verify", str(audit_path)]) == EXIT_FINDINGS
    assert "FAILED" in capsys.readouterr().out


async def test_audit_summary_counts_by_outcome(audit_path, capsys):
    assert main(["audit", "summary", str(audit_path)]) == EXIT_OK
    output = capsys.readouterr().out

    assert "3 record(s)" in output
    assert "ha_restart" in output
    assert "most recent denials" in output


async def test_audit_summary_filters_by_outcome(audit_path, capsys):
    main(["audit", "summary", str(audit_path), "--outcome", "denied"])
    assert "1 record(s)" in capsys.readouterr().out


# ---------------------------------------------------------------------- token


def test_token_new_prints_a_pasteable_stanza_and_the_secret(capsys):
    assert main(["token", "new", "laptop", "--policy", "assistant"]) == EXIT_OK
    output = capsys.readouterr().out

    assert "name: laptop" in output
    assert "policy: assistant" in output

    digest = next(line.split("sha256:")[1].strip() for line in output.splitlines() if "sha256:" in line)
    secret = output.strip().splitlines()[-1]
    assert token_digest(secret) == digest


def test_token_hash_digests_stdin(capsys, monkeypatch):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("my-token\n"))
    assert main(["token", "hash"]) == EXIT_OK
    assert capsys.readouterr().out.strip() == token_digest("my-token")


def test_token_hash_rejects_empty_input(capsys, monkeypatch):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("  \n"))
    assert main(["token", "hash"]) != EXIT_OK
    assert "no token on stdin" in capsys.readouterr().err


# ------------------------------------------------------------------- run flags


def test_run_over_http_rejects_stdio_only_flags(config_path, capsys):
    exit_code = main(["run", "-c", str(config_path), "--transport", "http", "--policy", "assistant"])
    assert exit_code != EXIT_OK
    assert "stdio only" in capsys.readouterr().err


def test_run_over_stdio_requires_an_identity(config_path, capsys):
    assert main(["run", "-c", str(config_path)]) != EXIT_OK
    assert "exactly one of --token or --policy" in capsys.readouterr().err
