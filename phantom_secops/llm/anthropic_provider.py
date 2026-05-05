"""Anthropic provider — direct calls to the Claude API.

Requires:
- `pip install anthropic`
- `ANTHROPIC_API_KEY` in the environment.

Model defaults to Claude Sonnet 4.6 (the current default for cost-effective
prose generation). Override via `PHANTOM_SECOPS_ANTHROPIC_MODEL`.
"""

from __future__ import annotations

import os
import sys

DEFAULT_MODEL = "claude-sonnet-4-6"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self) -> None:
        try:
            import anthropic  # noqa: PLC0415
        except ImportError as exc:
            raise SystemExit(
                "anthropic SDK not installed. Run: pip install anthropic\n"
                "Or unset PHANTOM_SECOPS_LLM to use the template-only path."
            ) from exc
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise SystemExit(
                "ANTHROPIC_API_KEY is not set. Export it or unset PHANTOM_SECOPS_LLM."
            )
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = os.environ.get("PHANTOM_SECOPS_ANTHROPIC_MODEL", DEFAULT_MODEL)

    def generate_prose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        try:
            msg = self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as exc:  # noqa: BLE001
            # Be lenient: log and return empty so the caller falls back to templates.
            print(f"  [llm:anthropic] error: {exc}", file=sys.stderr)
            return ""

        # Concatenate all text blocks (the SDK returns a list of content blocks).
        out: list[str] = []
        for block in msg.content:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                out.append(text)
        return "".join(out).strip()
