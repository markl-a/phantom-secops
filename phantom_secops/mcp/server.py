"""MCP server for phantom-secops.

Exposes the 10 tools and 2 resource schemes documented in
docs/MCP-INTERFACE.md. The server is the runtime-agnostic entry point —
phantom-mesh, Claude Code, Cursor, or any other MCP client can drive
exactly the same workflow that scenarios/run_kill_chain.py drives directly.

Run via stdio:
    python -m phantom_secops.mcp.server

Run via the MCP dev inspector:
    mcp dev phantom_secops/mcp/server.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "mcp package not installed. Run: pip install 'mcp[cli]>=1.2'"
    ) from exc

from phantom_secops import core
from phantom_secops.mcp import lab, safety

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RUNS_DIR = REPO_ROOT / "reports" / "runs"
MOCKS_DIR = REPO_ROOT / "lab" / "mocks"

mcp = FastMCP("phantom-secops")


# ─── Active in-lab tools ─────────────────────────────────────────────────

@mcp.tool()
def recon_host(
    target: str,
    ports: str = "top-1000",
    scan_type: str = "-sV",
) -> dict[str, Any]:
    """Scan an in-lab host with nmap. Refuses non-lab targets.

    Returns: {target, open_ports: [{port, protocol, service, version}], scan_type}
    """
    if not safety.is_lab_service(target):
        return safety.refusal_envelope(target)
    from tools import nmap_runner  # noqa: PLC0415
    return nmap_runner.run(target, ports=ports, scan_type=scan_type)


@mcp.tool()
def vuln_scan_web(
    target_url: str,
    severity: str = "low,medium,high,critical",
    timeout_s: int = 90,
) -> dict[str, Any]:
    """Run nuclei against an in-lab HTTP target. Refuses non-lab URLs.

    Returns: {target, findings: [{id, cve, severity, title, evidence, tool, raw}]}
    """
    if not safety.is_lab_url(target_url):
        return safety.refusal_envelope(target_url)
    from tools import nuclei_runner  # noqa: PLC0415
    return nuclei_runner.run(target_url, severity=severity, timeout_s=timeout_s)


# ─── Read-only blue-pipeline tools ───────────────────────────────────────

@mcp.tool()
def scan_logs_for_anomalies(
    source: str = "lab_logs",
    log_path: str | None = None,
) -> dict[str, Any]:
    """Pattern-match access logs into raw alerts. URL-decodes lines first.

    source: "lab_logs" (default) reads reports/lab-logs/, "mock" reads canned data.
    Returns: {alerts: [{ts, source_ip, asset, category, evidence, severity_hint}], source}
    """
    return core.scan_logs_for_anomalies(source=source, log_path=log_path)


@mcp.tool()
def triage_alerts(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Group raw alerts by (source_ip, category) and assign P1/P2/P3 priority.

    Returns: {triaged: [{ts, priority, asset, summary, count, evidence}]}
    """
    return core.triage_alerts(alerts)


@mcp.tool()
def correlate_threats(triaged: list[dict[str, Any]]) -> dict[str, Any]:
    """Join triaged alerts into per-actor narratives with ATT&CK phase tags.

    Returns: {actors: [{actor, first_seen, last_seen, phases_observed,
                        alert_summaries, narrative, confidence}]}
    """
    return core.correlate_threats(triaged)


# ─── Safety-critical: prose-only ─────────────────────────────────────────

@mcp.tool()
def suggest_exploit_prose(
    findings: list[dict[str, Any]],
    use_llm: bool = False,
) -> dict[str, Any]:
    """Generate text-only exploit explanations from vuln-scan findings.

    INVARIANT: never returns runnable payloads. The output always carries
    has_runnable_poc=False; tests/test_no_runnable_poc.py asserts this.

    When use_llm=True, the provider is selected via the PHANTOM_SECOPS_LLM
    env var on the server process (none, anthropic, phantom_mesh).

    Returns: {markdown, has_runnable_poc: false}
    """
    provider = None
    if use_llm:
        from phantom_secops.llm import get_provider  # noqa: PLC0415
        provider = get_provider()
    return core.suggest_exploit_prose(findings, use_llm=use_llm, provider=provider)


# ─── Report composition ──────────────────────────────────────────────────

@mcp.tool()
def compose_pentest_report(
    recon: dict[str, Any],
    vuln: dict[str, Any],
    exploit_suggestions_md: str,
    timeline: list[list[str]],
) -> dict[str, Any]:
    """Render the red-team-side markdown report.

    Returns: {markdown, byte_size}
    """
    tl = [(t[0], t[1]) for t in timeline]
    return core.compose_pentest_report(recon, vuln, exploit_suggestions_md, tl)


@mcp.tool()
def compose_incident_report(
    triaged: list[dict[str, Any]],
    actors: list[dict[str, Any]],
    timeline: list[list[str]],
) -> dict[str, Any]:
    """Render the blue-team-side markdown report.

    Returns: {markdown, byte_size, mttd_seconds}
    """
    tl = [(t[0], t[1]) for t in timeline]
    return core.compose_incident_report(triaged, actors, tl)


# ─── Lifecycle (require confirm=True) ────────────────────────────────────

@mcp.tool()
def lab_status() -> dict[str, Any]:
    """Report docker lab health. Read-only.

    Returns: {network_present, services: [{name, state, health}]}
    """
    return lab.status()


@mcp.tool()
def lab_up(confirm: bool = False) -> dict[str, Any]:
    """Bring up the isolated docker lab. Requires confirm=True.

    Returns: {ok, log}
    """
    return lab.up(confirm)


@mcp.tool()
def lab_down(confirm: bool = False) -> dict[str, Any]:
    """Tear down the docker lab. Requires confirm=True.

    Removes containers and volumes; preserves reports/runs/ on host.
    Returns: {ok, log}
    """
    return lab.down(confirm)


# ─── Resources ────────────────────────────────────────────────────────────

@mcp.resource("phantom-secops://runs/{run_id}/{filename}")
def read_run_artifact(run_id: str, filename: str) -> str:
    """Read an artifact from a previous kill-chain run.

    run_id="latest" resolves to the newest run dir at fetch time.
    Allowed filenames: see docs/MCP-INTERFACE.md.
    """
    if run_id == "latest":
        run_dir = _latest_run_dir()
        if run_dir is None:
            return ""
    else:
        run_dir = RUNS_DIR / run_id

    target = (run_dir / filename).resolve()
    # Ensure the resolved path is still inside RUNS_DIR.
    if RUNS_DIR.resolve() not in target.parents:
        return ""
    if not target.exists():
        return ""
    return target.read_text(encoding="utf-8")


@mcp.resource("phantom-secops://mocks/{name}")
def read_mock(name: str) -> str:
    """Read canned mock data."""
    target = (MOCKS_DIR / name).resolve()
    if MOCKS_DIR.resolve() not in target.parents:
        return ""
    if not target.exists():
        return ""
    return target.read_text(encoding="utf-8")


def _latest_run_dir() -> Path | None:
    if not RUNS_DIR.exists():
        return None
    candidates = sorted([p for p in RUNS_DIR.iterdir() if p.is_dir()])
    return candidates[-1] if candidates else None


def main() -> None:
    """Entry point for `python -m phantom_secops.mcp.server`."""
    mcp.run()


if __name__ == "__main__":
    main()
