"""phantom-mesh HTTP provider.

Posts a chat-completion request to `phantom serve` (default
http://127.0.0.1:7878). The endpoint shape is **provisional**: phantom-mesh's
HTTP API spec isn't published yet (binary closed-source until June 2026).
This implementation uses a best-effort guess and degrades gracefully when
phantom-mesh is unreachable or the response shape is unrecognised.

Override the endpoint via `PHANTOM_MESH_URL`.

When phantom-tools (Phase 1) and phantom-runtime (Phase 2) ship in May–June
2026, revisit this file: align the request shape with the documented API,
keep the same generate_prose signature.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:7878"
GENERATE_PATH = "/v1/generate"


class PhantomMeshProvider:
    name = "phantom_mesh"

    def __init__(self) -> None:
        self._base_url = os.environ.get("PHANTOM_MESH_URL", DEFAULT_URL).rstrip("/")
        self._endpoint = self._base_url + GENERATE_PATH
        self._timeout_s = float(os.environ.get("PHANTOM_MESH_TIMEOUT_S", "30"))

    def generate_prose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        payload = {
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "max_tokens": max_tokens,
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout_s) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            print(
                f"  [llm:phantom_mesh] unreachable at {self._endpoint}: {exc}\n"
                f"  [llm:phantom_mesh] start phantom-mesh with `phantom serve` or unset "
                f"PHANTOM_SECOPS_LLM to use templates.",
                file=sys.stderr,
            )
            return ""
        except Exception as exc:  # noqa: BLE001
            print(f"  [llm:phantom_mesh] error: {exc}", file=sys.stderr)
            return ""

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            print(f"  [llm:phantom_mesh] non-JSON response: {raw[:200]!r}", file=sys.stderr)
            return ""

        # Try common shapes — the spec isn't fixed yet.
        for path in (("text",), ("output", "text"), ("choices", 0, "text"),
                     ("messages", 0, "content"), ("content",)):
            value = _dig(data, path)
            if isinstance(value, str) and value.strip():
                return value.strip()
        print(f"  [llm:phantom_mesh] unrecognised response shape, keys={list(data) if isinstance(data, dict) else type(data)}",
              file=sys.stderr)
        return ""


def _dig(obj: object, path: tuple[object, ...]) -> object:
    cur = obj
    for key in path:
        if isinstance(key, int) and isinstance(cur, list) and 0 <= key < len(cur):
            cur = cur[key]
        elif isinstance(key, str) and isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return None
        if cur is None:
            return None
    return cur
