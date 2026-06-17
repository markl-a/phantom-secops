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
import xml.etree.ElementTree as ET
from typing import Any

ATTACKER_CONTAINER = "secops-attacker"
LAB_NETWORK = "secops-lab"


def run(target: str, ports: str = "top-1000", scan_type: str = "-sV") -> dict[str, Any]:
    """Run nmap against an in-lab target. Refuses non-lab targets."""
    if not _target_in_lab(target):
        return {
            "error": f"refusing to scan '{target}' — not a known lab service",
            "lab_services": _known_lab_services(),
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
    except OSError as exc:
        # docker binary missing / not on PATH (the offline case) — degrade to a
        # structured error so callers keep running rather than crashing.
        return {"error": f"could not launch docker: {exc}", "target": target}

    if result.returncode != 0:
        return {
            "error": "nmap exited non-zero",
            "stderr": result.stderr.strip()[:500],
            "target": target,
        }

    return _parse_nmap_xml(result.stdout, target)


def _target_in_lab(target: str) -> bool:
    """Refuse anything that isn't a known lab service name."""
    return target in _known_lab_services()


def _known_lab_services() -> list[str]:
    return ["juice-shop", "dvwa", "dvwa-db", "metasploitable", "attacker"]


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
