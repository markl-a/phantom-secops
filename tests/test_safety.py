"""Tests for the centralised lab-network gate.

Defense-in-depth: every active tool must defer to phantom_secops.mcp.safety
to validate targets. The whitelist must include the documented lab services.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from phantom_secops.mcp import safety  # type: ignore[import-not-found]


def test_whitelist_contains_documented_services() -> None:
    for name in ("juice-shop", "dvwa", "dvwa-db", "metasploitable", "attacker"):
        assert name in safety.KNOWN_LAB_SERVICES


def test_is_lab_service_rejects_external() -> None:
    assert not safety.is_lab_service("scanme.nmap.org")
    assert not safety.is_lab_service("example.com")
    assert not safety.is_lab_service("juice-shop.example.com")  # exact match required


def test_is_lab_url_accepts_lab_hosts() -> None:
    assert safety.is_lab_url("http://juice-shop:3000/")
    assert safety.is_lab_url("http://dvwa/login.php")


def test_is_lab_url_rejects_external() -> None:
    assert not safety.is_lab_url("http://example.com/")


def test_assert_lab_target_raises_on_external() -> None:
    import pytest
    with pytest.raises(safety.LabTargetRefused) as exc_info:
        safety.assert_lab_target("scanme.nmap.org")
    assert exc_info.value.target == "scanme.nmap.org"


def test_refusal_envelope_shape() -> None:
    env = safety.refusal_envelope("evil.example.com")
    assert env["error"] == "not_a_lab_target"
    assert "lab_services" in env["context"]
