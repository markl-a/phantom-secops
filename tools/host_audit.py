"""Read-only host security-posture checks for Windows and macOS.

Every check shells out through an injected ``run(args) -> CmdResult`` callable
so the logic is unit-testable with canned output and the production path never
mutates the host — these are *queries only*.

A check returns a finding dict::

    {"check": str, "status": "pass|warn|fail|unknown|skipped",
     "severity": "info|low|medium|high", "detail": str}

``audit_host()`` runs the platform's registry and adds a status summary.
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass
class CmdResult:
    code: int
    out: str
    err: str = ""


Run = Callable[[list], CmdResult]


def _default_run(args: list) -> CmdResult:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=30)
        return CmdResult(code=p.returncode, out=p.stdout, err=p.stderr)
    except Exception as e:  # noqa: BLE001 — surface any spawn failure as a result
        return CmdResult(code=127, out="", err=str(e))


def _finding(check: str, status: str, severity: str, detail: str) -> dict:
    return {"check": check, "status": status, "severity": severity, "detail": detail}


def _unknown(check: str, r: CmdResult) -> dict:
    reason = (r.err.strip() or r.out.strip() or f"exit {r.code}")[:200]
    return _finding(check, "unknown", "info", f"could not query: {reason}")


def _ps(command: str) -> list:
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]


def _parse_kv(text: str) -> dict:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line:
            k, v = line.rsplit("=", 1)
            out[k.strip()] = v.strip()
    return out


# ── Windows checks ────────────────────────────────────────────────────────────

def check_win_firewall(run: Run) -> dict:
    r = run(_ps("Get-NetFirewallProfile | ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }"))
    if r.code != 0:
        return _unknown("firewall_profiles", r)
    kv = _parse_kv(r.out)
    disabled = [name for name, val in kv.items() if val.lower() != "true"]
    if disabled:
        return _finding("firewall_profiles", "fail", "high",
                        f"firewall disabled for profile(s): {', '.join(disabled)}")
    return _finding("firewall_profiles", "pass", "info",
                    f"all firewall profiles enabled ({', '.join(kv) or 'none reported'})")


def check_win_defender(run: Run) -> dict:
    r = run(_ps(
        "$s=Get-MpComputerStatus; "
        "\"RealTimeProtectionEnabled=$($s.RealTimeProtectionEnabled)\"; "
        "\"AntivirusEnabled=$($s.AntivirusEnabled)\"; "
        "\"AntivirusSignatureAge=$($s.AntivirusSignatureAge)\""
    ))
    if r.code != 0:
        return _unknown("defender_realtime", r)
    kv = _parse_kv(r.out)
    realtime = kv.get("RealTimeProtectionEnabled", "").lower() == "true"
    av = kv.get("AntivirusEnabled", "").lower() == "true"
    if not realtime or not av:
        return _finding("defender_realtime", "fail", "high",
                        f"realtime={kv.get('RealTimeProtectionEnabled')} "
                        f"antivirus={kv.get('AntivirusEnabled')}")
    try:
        age = int(kv.get("AntivirusSignatureAge", "0"))
    except ValueError:
        age = 0
    if age > 7:
        return _finding("defender_realtime", "warn", "medium",
                        f"antivirus signatures are {age} days old")
    return _finding("defender_realtime", "pass", "info",
                    f"realtime protection on, signatures {age} day(s) old")


def check_win_uac(run: Run) -> dict:
    r = run(_ps(
        "\"EnableLUA=$((Get-ItemProperty "
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA)\""
    ))
    if r.code != 0:
        return _unknown("uac_enabled", r)
    val = _parse_kv(r.out).get("EnableLUA", "")
    if val == "1":
        return _finding("uac_enabled", "pass", "info", "UAC (EnableLUA) is on")
    return _finding("uac_enabled", "fail", "high", f"UAC disabled (EnableLUA={val or 'unset'})")


def check_win_listening_ports(run: Run) -> dict:
    r = run(_ps(
        "Get-NetTCPConnection -State Listen | "
        "ForEach-Object { \"$($_.LocalAddress)=$($_.LocalPort)\" }"
    ))
    if r.code != 0:
        return _unknown("listening_ports", r)
    wildcard = []
    total = 0
    for line in r.out.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        total += 1
        addr, port = line.rsplit("=", 1)
        if addr.strip() in ("0.0.0.0", "::"):
            wildcard.append(port.strip())
    if wildcard:
        ports = ", ".join(sorted(set(wildcard), key=lambda p: int(p) if p.isdigit() else 0))
        return _finding("listening_ports", "warn", "medium",
                        f"{len(wildcard)} port(s) listening on all interfaces: {ports}")
    return _finding("listening_ports", "pass", "info",
                    f"{total} listening port(s), none bound to all interfaces")


def check_win_bitlocker(run: Run) -> dict:
    r = run(_ps(
        "\"ProtectionStatus=$((Get-BitLockerVolume -MountPoint $env:SystemDrive)"
        ".ProtectionStatus)\""
    ))
    if r.code != 0:
        return _unknown("bitlocker", r)
    val = _parse_kv(r.out).get("ProtectionStatus", "").lower()
    if val == "on":
        return _finding("bitlocker", "pass", "info", "system drive is BitLocker-encrypted")
    if val == "off":
        return _finding("bitlocker", "fail", "high", "system drive is not BitLocker-encrypted")
    # Empty/unexpected value usually means the query ran without elevation.
    return _unknown("bitlocker", r)


def check_win_rdp(run: Run) -> dict:
    r = run(_ps(
        "\"fDenyTSConnections=$((Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server')"
        ".fDenyTSConnections)\""
    ))
    if r.code != 0:
        return _unknown("rdp_enabled", r)
    val = _parse_kv(r.out).get("fDenyTSConnections", "")
    if val == "1":
        return _finding("rdp_enabled", "pass", "info", "Remote Desktop is disabled")
    return _finding("rdp_enabled", "warn", "medium",
                    "Remote Desktop is enabled; ensure it is restricted and patched")


def check_win_guest_account(run: Run) -> dict:
    r = run(_ps("\"GuestEnabled=$((Get-LocalUser -Name 'Guest').Enabled)\""))
    if r.code != 0:
        return _unknown("guest_account", r)
    val = _parse_kv(r.out).get("GuestEnabled", "").lower()
    if val == "false":
        return _finding("guest_account", "pass", "info", "Guest account is disabled")
    return _finding("guest_account", "fail", "high", "Guest account is enabled")


def check_win_av_products(run: Run) -> dict:
    # SecurityCenter2 lists every registered AV — this disambiguates a Defender
    # "off" reading caused by a third-party AV stepping in. Workstation SKUs only.
    r = run(_ps(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
        "| ForEach-Object { \"Product=$($_.displayName)\" }"
    ))
    if r.code != 0:
        return _unknown("antivirus_registered", r)
    names = [v for k, v in (
        line.rsplit("=", 1) for line in r.out.splitlines() if "=" in line
    ) if k.strip() == "Product" and v.strip()]
    if names:
        return _finding("antivirus_registered", "pass", "info",
                        f"registered AV product(s): {', '.join(n.strip() for n in names)}")
    return _finding("antivirus_registered", "fail", "high",
                    "no antivirus product registered with Windows Security Center")


# ── macOS checks ──────────────────────────────────────────────────────────────

def check_mac_filevault(run: Run) -> dict:
    r = run(["fdesetup", "status"])
    if r.code != 0:
        return _unknown("filevault", r)
    if "on" in r.out.lower():
        return _finding("filevault", "pass", "info", "FileVault disk encryption is on")
    return _finding("filevault", "fail", "high", "FileVault disk encryption is off")


def check_mac_firewall(run: Run) -> dict:
    r = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    if r.code != 0:
        return _unknown("application_firewall", r)
    text = r.out.lower()
    if "enabled" in text or "state = 1" in text or "state = 2" in text:
        return _finding("application_firewall", "pass", "info", "application firewall enabled")
    return _finding("application_firewall", "fail", "high", "application firewall disabled")


def check_mac_sip(run: Run) -> dict:
    r = run(["csrutil", "status"])
    if r.code != 0:
        return _unknown("system_integrity_protection", r)
    if "enabled" in r.out.lower():
        return _finding("system_integrity_protection", "pass", "info", "SIP enabled")
    return _finding("system_integrity_protection", "warn", "high", "SIP is disabled")


# ── Registry + orchestration ──────────────────────────────────────────────────

WINDOWS_CHECKS = [
    check_win_firewall,
    check_win_defender,
    check_win_av_products,
    check_win_bitlocker,
    check_win_uac,
    check_win_rdp,
    check_win_guest_account,
    check_win_listening_ports,
]

MACOS_CHECKS = [
    check_mac_filevault,
    check_mac_firewall,
    check_mac_sip,
]

_REGISTRY = {"windows": WINDOWS_CHECKS, "darwin": MACOS_CHECKS}

_STATUSES = ("pass", "warn", "fail", "unknown", "skipped")


def _summary(findings: list) -> dict:
    counts = {s: 0 for s in _STATUSES}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    counts["total"] = len(findings)
    return counts


def audit_host(platform_name: str | None = None,
               run: Run | None = None,
               checks: list | None = None) -> dict:
    """Run read-only posture checks for the platform and summarise the results."""
    name = (platform_name or platform.system()).lower()
    run = run or _default_run
    if checks is None:
        checks = _REGISTRY.get(name)
    if checks is None:
        return {"platform": name, "checks": [], "summary": _summary([]),
                "note": f"unsupported platform: {name}"}
    findings = [c(run) for c in checks]
    return {"platform": name, "checks": findings, "summary": _summary(findings)}
