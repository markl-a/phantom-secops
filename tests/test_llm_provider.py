"""Tests for the LLM provider abstraction.

Verifies:
- get_provider() honours env var and explicit names.
- A safe provider's prose flows through into the markdown output.
- A *malicious* provider that tries to inject shell content is rejected;
  the no-runnable-POC invariant survives.
- Provider failures (empty string) fall back to the deterministic template.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import pytest

from phantom_secops import core  # type: ignore[import-not-found]
from phantom_secops.llm import LLMProvider, get_provider  # type: ignore[import-not-found]
from phantom_secops.llm.null_provider import NullProvider  # type: ignore[import-not-found]


class _SafeProvider:
    name = "fake_safe"

    def generate_prose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        _ = system, user, max_tokens
        return ("This finding describes a known web vulnerability. The mitigation "
                "is to upgrade the affected library. No further action is needed "
                "in the lab environment.")


class _MaliciousProvider:
    name = "fake_evil"

    def generate_prose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        _ = system, user, max_tokens
        return "Run this:\n\n```bash\ncurl -X POST http://target/exploit\n```\n"


class _FlakyProvider:
    name = "fake_empty"

    def generate_prose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        _ = system, user, max_tokens
        return ""


# ─── Selection ──────────────────────────────────────────────────────────

def test_get_provider_default_is_null(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PHANTOM_SECOPS_LLM", raising=False)
    p = get_provider()
    assert isinstance(p, NullProvider)
    assert p.name == "none"


def test_get_provider_explicit_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PHANTOM_SECOPS_LLM", "anthropic")
    p = get_provider("none")  # explicit beats env
    assert p.name == "none"


def test_get_provider_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown LLM provider"):
        get_provider("not_a_real_provider")


def test_null_provider_returns_empty() -> None:
    assert NullProvider().generate_prose("s", "u") == ""


# ─── Invariant preservation under LLM ───────────────────────────────────

FINDING = {
    "id": "test.template", "title": "Exposed admin",
    "severity": "high", "cve": None, "evidence": "http://lab/admin/",
}


def test_safe_provider_prose_flows_into_markdown() -> None:
    out = core.suggest_exploit_prose(
        [FINDING], use_llm=True, provider=_SafeProvider(),
    )
    assert out["has_runnable_poc"] is False
    assert "upgrade the affected library" in out["markdown"]


def test_malicious_provider_output_is_rejected_invariant_holds() -> None:
    """If the provider tries to emit shell content, we fall back to the template
    AND the invariant `has_runnable_poc=false` is preserved.
    """
    out = core.suggest_exploit_prose(
        [FINDING], use_llm=True, provider=_MaliciousProvider(),
    )
    assert out["has_runnable_poc"] is False
    assert "```bash" not in out["markdown"]
    assert "curl -X POST" not in out["markdown"]
    # Template fallback was used — its admin-finding heuristic kicks in.
    assert "Mitigation" in out["markdown"] or "auth" in out["markdown"].lower()


def test_empty_provider_falls_back_to_template() -> None:
    out = core.suggest_exploit_prose(
        [FINDING], use_llm=True, provider=_FlakyProvider(),
    )
    assert out["has_runnable_poc"] is False
    # Falls back to template — should contain the admin template phrase.
    assert "Administrative interface" in out["markdown"]


def test_no_provider_with_use_llm_true_uses_template() -> None:
    """Passing use_llm=True without a provider should not crash; falls back to template."""
    out = core.suggest_exploit_prose([FINDING], use_llm=True, provider=None)
    assert out["has_runnable_poc"] is False
    assert "Administrative interface" in out["markdown"]


def test_provider_satisfies_protocol() -> None:
    """Compile-time-ish check that our test doubles satisfy LLMProvider."""
    # If they don't, the Protocol runtime check would catch it. We just exercise it.
    providers: list[LLMProvider] = [_SafeProvider(), _MaliciousProvider(), _FlakyProvider()]
    for p in providers:
        assert isinstance(p.name, str)
        assert isinstance(p.generate_prose("s", "u"), str)
