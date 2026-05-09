"""Helpers for embedding x-phantom.* metadata into MCP tool definitions.

The mcp Python SDK accepts a `metadata` dict on Tool definitions which
is forwarded verbatim to the client. We use that channel to declare
classification + capability hints that phantom-mesh's policy enforcer
reads.
"""

from __future__ import annotations

from typing import Any

_CLASSIFICATION_ORDER = {"internal": 0, "blue": 1, "red": 2}


def validate_classification(classification: str) -> int:
    """Return the numeric ordering of a classification, raising on unknown."""
    if classification not in _CLASSIFICATION_ORDER:
        raise ValueError(
            f"unknown x-phantom classification {classification!r}; "
            f"expected one of {sorted(_CLASSIFICATION_ORDER)}"
        )
    return _CLASSIFICATION_ORDER[classification]


def xphantom_metadata(
    classification: str,
    capabilities: list[str],
    *,
    read_only: bool,
) -> dict[str, Any]:
    """Build the x-phantom.* metadata dict for an MCP Tool.

    Pass the result as the `metadata` arg to mcp's Tool() so it survives
    serialization to tools/list.
    """
    validate_classification(classification)
    if not isinstance(capabilities, list) or not all(isinstance(c, str) for c in capabilities):
        raise TypeError("capabilities must be list[str]")
    return {
        "x-phantom.classification": classification,
        "x-phantom.capabilities": list(capabilities),
        "x-phantom.read_only": bool(read_only),
    }
