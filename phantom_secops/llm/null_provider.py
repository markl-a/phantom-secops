"""Null provider — returns empty string. Callers fall back to templates.

This is the default and the only provider that ships with no extra dependencies.
"""

from __future__ import annotations


class NullProvider:
    name = "none"

    def generate_prose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        _ = system, user, max_tokens
        return ""
