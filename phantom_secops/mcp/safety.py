"""Centralised lab-network gate.

Every tool that does network work — recon_host, vuln_scan_web, lab_up/down —
must validate its target against the lab whitelist before acting. This module
is the single source of truth.

Defense-in-depth: the gate is enforced both at the MCP boundary (so bad inputs
never reach the wrappers) and inside the wrappers themselves (so direct
imports cannot bypass it).
"""

from __future__ import annotations

# Hard-coded whitelist. Matches docker-compose.yml service names.
KNOWN_LAB_SERVICES: tuple[str, ...] = (
    "juice-shop",
    "dvwa",
    "dvwa-db",
    "metasploitable",
    "attacker",
)


class LabTargetRefused(ValueError):
    """Raised when a tool is called with a non-lab target."""

    def __init__(self, target: str) -> None:
        super().__init__(f"refusing to act on '{target}' — not a known lab service")
        self.target = target


def is_lab_service(target: str) -> bool:
    return target in KNOWN_LAB_SERVICES


def is_lab_url(url: str) -> bool:
    """Loose check: URL must contain a lab service hostname.

    Used by vuln_scan_web. Looser than is_lab_service because URLs include
    schemes, ports, and paths.
    """
    return any(host in url for host in KNOWN_LAB_SERVICES)


def assert_lab_target(target: str) -> None:
    """Raise LabTargetRefused if the target is not in the whitelist."""
    if not is_lab_service(target):
        raise LabTargetRefused(target)


def assert_lab_url(url: str) -> None:
    if not is_lab_url(url):
        raise LabTargetRefused(url)


def refusal_envelope(target: str) -> dict[str, object]:
    """Return the standard error envelope for refused targets.

    Tools that prefer error returns over exceptions (legacy wrappers) use this.
    """
    return {
        "error": "not_a_lab_target",
        "message": f"refusing to act on '{target}' — not a known lab service",
        "context": {"lab_services": list(KNOWN_LAB_SERVICES)},
    }


# ─── Prose safety: enforce the no-runnable-POC invariant ─────────────────

import re as _re

# Patterns that suggest runnable shell content. Used to reject LLM output
# before it ever reaches `suggest_exploit_prose`'s markdown.
_FORBIDDEN_LINE_PATTERNS = (
    r"^\s*\$\s",           # `$ command`
    r"^\s*sudo\s",
    r"^\s*curl\s+-X",
    r"^\s*wget\s",
    r"^\s*nc\s+-",
    r"^\s*python\s+-c",
    r"^\s*bash\s+-c",
    r"^\s*sh\s+-c",
    r"^\s*docker\s+exec\s",
)

_FORBIDDEN_FENCES = ("```bash", "```sh", "```shell", "```zsh")


def is_safe_prose(text: str) -> bool:
    """Return False if `text` contains patterns that look executable.

    Used both by tests/test_no_runnable_poc.py and by the LLM-augmented path
    in core.suggest_exploit_prose. Single source of truth: change this and the
    invariant test follows.
    """
    if not text:
        return True
    for fence in _FORBIDDEN_FENCES:
        if fence in text:
            return False
    for pat in _FORBIDDEN_LINE_PATTERNS:
        if _re.search(pat, text, _re.MULTILINE):
            return False
    return True
