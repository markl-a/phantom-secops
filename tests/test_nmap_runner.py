"""Tests for the nmap_runner tool wrapper.

The wrapper must refuse non-lab targets (defense-in-depth: even if an agent
prompt tries to pivot to a real-world host, the tool layer says no).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import nmap_runner  # type: ignore[import-not-found]


def test_refuses_non_lab_target() -> None:
    result = nmap_runner.run("scanme.nmap.org")
    assert "error" in result, "external target must be refused"
    assert "lab_services" in result, "error response must list allowed services"


def test_accepts_lab_targets() -> None:
    """Just checks the gate, not the full run (no docker in CI)."""
    # We don't actually run nmap here; we just confirm the gate doesn't reject.
    # The real run() returns an error from the docker exec call when no
    # container is up, but it does NOT return the 'refusing to scan' error.
    result = nmap_runner.run("juice-shop")
    refused = ("error" in result
               and isinstance(result.get("error"), str)
               and "refusing to scan" in result["error"])
    assert not refused, "lab target should pass the gate"


def test_known_lab_services_includes_juice_shop() -> None:
    services = nmap_runner._known_lab_services()
    assert "juice-shop" in services
    assert "dvwa" in services
