"""Cross-turn state for the agent-loop kill-chain façade.

From the agent loop's perspective each composite tool call is an independent
invocation, so pipeline state — recon/vuln artifacts, the running timeline, and
the two simulated per-side clocks — must persist OUT OF BAND between calls. We
use a JSON state file (SECOPS_MCP_STATE_FILE), not stdout: phantom-mesh
interleaves tool stdout with its own ANSI / cost / token chatter, so parsing
results back out of stdout would be brittle. The file is the single channel.

The per-side clock mirrors scenarios.run_kill_chain.Clock's MOCK branch exactly
(same canned durations from phantom_secops.killchain). Because each side has an
independent clock and step durations are fixed, the per-side event times — and
therefore the MTTD — are fully determined by each side's own event sequence,
independent of how the agent interleaves red and blue tool calls. That is what
makes agent-driven MTTD equal the direct driver's by construction (M1 parity).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Timeline entries are [t, side, label]. Stored as JSON lists; killchain's
# _metrics / renderers unpack them positionally, so lists and tuples both work.
TimelineEntry = list


@dataclass
class KillChainState:
    """Accumulating state for one agent-driven kill-chain run."""

    target: str = "juice-shop"
    mock: bool = True
    out_dir: str | None = None
    clock: dict[str, float] = field(default_factory=lambda: {"red": 0.0, "blue": 0.0})
    timeline: list[list[Any]] = field(default_factory=list)
    # Pipeline artifacts, populated step by step. None == "this step not run yet",
    # which the later tools check to refuse out-of-order calls (drift guard).
    recon: dict[str, Any] | None = None
    vuln: dict[str, Any] | None = None
    suggestions: str | None = None
    alerts: list[dict[str, Any]] | None = None
    triaged: list[dict[str, Any]] | None = None
    correlation: list[dict[str, Any]] | None = None
    reports: dict[str, str] = field(default_factory=dict)

    # ── persistence ──────────────────────────────────────────────────────
    @classmethod
    def load(cls, path: str | Path) -> "KillChainState":
        """Load state from `path`, or return a fresh default if it doesn't exist."""
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(**data)

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(self.__dict__, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # ── simulated two-clock timeline (mirrors Clock's mock branch) ────────
    def now(self, side: str) -> float:
        return self.clock.get(side, 0.0)

    def advance(self, side: str, secs: float) -> None:
        if side in self.clock:
            self.clock[side] += secs

    def event(self, side: str, label: str, advance: float = 0.0) -> float:
        """Record a timeline event for `side`, then advance that side's clock.

        Returns the event time (the side's clock BEFORE advancing), matching
        run_kill_chain.event so milestone extraction in killchain._metrics lines
        up identically.
        """
        t = self.now(side)
        self.timeline.append([t, side, label])
        self.advance(side, advance)
        return t

    def end_event(self) -> float:
        """Append the terminal 'done' marker at max(red, blue), like _run_pipeline."""
        end_t = max(self.now("red"), self.now("blue"))
        self.timeline.append([end_t, "sys", "done"])
        return end_t
