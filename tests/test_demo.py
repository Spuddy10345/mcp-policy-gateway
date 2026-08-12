"""The README's demo is a claim about the software, so it is tested like one.

A demo that has drifted from the code is worse than no demo: it is a promise
the project no longer keeps, made in the most prominent place in the README.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from mcp_policy_gateway import load_config
from mcp_policy_gateway.lint import lint

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "demo" / "prompt_injection.py"
DEMO_CONFIG = ROOT / "demo" / "policy.yaml"


@pytest.fixture(scope="module")
def demo_run(tmp_path_factory) -> subprocess.CompletedProcess[str]:
    """Run the demo once, with its audit log redirected out of the repo."""
    workdir = tmp_path_factory.mktemp("demo")
    (workdir / "demo").mkdir()
    result = subprocess.run(
        [sys.executable, str(DEMO)],
        capture_output=True,
        text=True,
        cwd=workdir,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            f"Demo script failed with {result.returncode}:\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result


def test_demo_exits_successfully(demo_run):
    """It returns non-zero if the gateway failed to stop the attack."""
    assert demo_run.returncode == 0, demo_run.stdout + demo_run.stderr


def test_demo_shows_the_attack_succeeding_without_the_gateway(demo_run):
    """If this stops being true the demo is no longer demonstrating anything."""
    round_one = demo_run.stdout.split("Round 2")[0]
    assert "EXECUTED" in round_one
    assert "permanently removed" in round_one


def test_demo_shows_the_attack_blocked_with_the_gateway(demo_run):
    round_two = demo_run.stdout.split("Round 2")[1].split("The house afterwards")[0]
    assert "EXECUTED" not in round_two
    assert round_two.count("BLOCKED") == 3


def test_demo_reports_an_unharmed_house(demo_run):
    afterwards = demo_run.stdout.split("The house afterwards")[1]
    assert "locked" in afterwards
    assert "unlocked" in afterwards  # the no-gateway column


def test_demo_writes_the_denials_to_the_audit_log(demo_run):
    trail = demo_run.stdout.split("What the gateway wrote down")[1]
    for tool in ("ha_remove_entity", "ha_call_service", "ha_restart"):
        assert tool in trail
    assert "hash-chained" in trail


def test_demo_policy_passes_strict_validation():
    """The policy shipped as an example has to survive the project's own linter."""
    findings = lint(load_config(DEMO_CONFIG))
    serious = [finding for finding in findings if finding.severity in ("error", "warning")]
    assert serious == [], "\n".join(finding.format() for finding in serious)


def test_shipped_example_policy_passes_strict_validation(monkeypatch):
    monkeypatch.setenv("HA_URL", "http://homeassistant.local:8123")
    monkeypatch.setenv("HA_TOKEN", "not-a-real-token")

    findings = lint(load_config(ROOT / "examples" / "home-assistant.yaml"))
    errors = [finding for finding in findings if finding.severity == "error"]
    assert errors == [], "\n".join(finding.format() for finding in errors)
