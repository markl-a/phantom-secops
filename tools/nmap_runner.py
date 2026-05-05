"""nmap tool wrapper for the red-recon agent.

Runs nmap inside the `secops-attacker` container so attack tooling stays off
the host. Returns a parsed JSON dict the agent can reason over.

Usage (called by phantom-mesh tool dispatch):
    nmap_runner.run(target="juice-shop", ports="top-1000", scan_type="-sV")
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from phantom_secops.mcp import safety  # noqa: E402

ATTACKER_CONTAINER = "secops-attacker"
LAB_NETWORK = "secops-lab"


def run(target: str, ports: str = "top-1000", scan_type: str = "-sV") -> dict[str, Any]:
    """Run nmap against an in-lab target. Refuses non-lab targets."""
    if not safety.is_lab_service(target):
        return {
            "error": f"refusing to scan '{target}' — not a known lab service",
            "lab_services": list(safety.KNOWN_LAB_SERVICES),
        }

    port_flag = "--top-ports 1000" if ports == "top-1000" else f"-p {shlex.quote(ports)}"
    cmd = [
        "docker", "exec", ATTACKER_CONTAINER,
        "bash", "-c",
        f"nmap {scan_type} {port_flag} -oX - {shlex.quote(target)}",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "nmap scan exceeded 120s timeout", "target": target}

    if result.returncode != 0:
        return {
            "error": "nmap exited non-zero",
            "stderr": result.stderr.strip()[:500],
            "target": target,
        }

    return _parse_nmap_xml(result.stdout, target)


def _known_lab_services() -> list[str]:
    """Compatibility shim for tests; prefer phantom_secops.mcp.safety."""
    return list(safety.KNOWN_LAB_SERVICES)


def _parse_nmap_xml(xml_text: str, target: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return {"error": f"nmap XML parse failed: {exc}", "target": target}

    open_ports: list[dict[str, Any]] = []
    for port in root.iterfind(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        open_ports.append({
            "port": int(port.get("portid", "0")),
            "protocol": port.get("protocol", ""),
            "service": service.get("name", "") if service is not None else "",
            "version": (
                f"{service.get('product', '')} {service.get('version', '')}".strip()
                if service is not None else ""
            ) or None,
        })

    return {
        "target": target,
        "open_ports": open_ports,
        "scan_type": "nmap",
    }


if __name__ == "__main__":
    # Quick sanity check; intended to be called by phantom, not directly.
    print(json.dumps(run("juice-shop"), indent=2))
