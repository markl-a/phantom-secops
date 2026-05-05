"""LLM provider abstraction for prose-augmented reports.

Selection happens via the `PHANTOM_SECOPS_LLM` env var or an explicit
provider name. Providers are loaded lazily so a no-deps install can still
run the template path.

Selection order:
- `PHANTOM_SECOPS_LLM=phantom_mesh` → PhantomMeshProvider (HTTP, requires `phantom serve` running)
- `PHANTOM_SECOPS_LLM=anthropic`    → AnthropicProvider (requires `anthropic` SDK + API key)
- `PHANTOM_SECOPS_LLM=none` (default) → NullProvider (returns empty; callers use templates)
"""

from __future__ import annotations

import os
from typing import Protocol


class LLMProvider(Protocol):
    """Minimal prose-generation surface.

    Providers must:
    - Return a string (possibly empty on error or null implementation).
    - Never raise on transient failures — return "" so the caller can fall back to templates.
    - Honour `max_tokens` as a soft cap; exceeding it is acceptable but tokens beyond the cap may be truncated.
    """

    name: str

    def generate_prose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        ...


def get_provider(name: str | None = None) -> LLMProvider:
    """Return a provider by name (or env var default)."""
    chosen = (name or os.environ.get("PHANTOM_SECOPS_LLM") or "none").lower()
    if chosen in ("none", ""):
        from phantom_secops.llm.null_provider import NullProvider  # noqa: PLC0415
        return NullProvider()
    if chosen == "anthropic":
        from phantom_secops.llm.anthropic_provider import AnthropicProvider  # noqa: PLC0415
        return AnthropicProvider()
    if chosen == "phantom_mesh":
        from phantom_secops.llm.phantom_mesh_provider import PhantomMeshProvider  # noqa: PLC0415
        return PhantomMeshProvider()
    raise ValueError(f"unknown LLM provider: {chosen!r} (valid: none, anthropic, phantom_mesh)")


__all__ = ["LLMProvider", "get_provider"]
