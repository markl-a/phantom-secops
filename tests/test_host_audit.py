"""Tests for tools.host_audit — read-only cross-platform host posture checks.

Every check shells out through an injected `run(args) -> CmdResult` callable,
so these tests feed canned command output and never touch the real OS.
"""

from __future__ import annotations

import pytest

import sys

from tools.host_audit import (
    CmdResult,
    audit_host,
    detect_elevation,
    _default_run,
    check_mac_filevault,
    check_mac_firewall,
    check_mac_sip,
    check_win_av_products,
    check_win_bitlocker,
    check_win_defender,
    check_win_firewall,
    check_win_guest_account,
    check_win_listening_ports,
    check_win_rdp,
    check_win_uac,
)


def fixed_run(out: str = "", code: int = 0, err: str = ""):
    """A run() that ignores args and always returns the same result."""
    return lambda args: CmdResult(code=code, out=out, err=err)


# ── Windows checks ────────────────────────────────────────────────────────────

def test_win_firewall_all_enabled_passes():
    out = "Domain=True\nPrivate=True\nPublic=True\n"
    f = check_win_firewall(fixed_run(out))
    assert f["check"] == "firewall_profiles"
    assert f["status"] == "pass"


def test_win_firewall_one_disabled_fails():
    out = "Domain=True\nPrivate=True\nPublic=False\n"
    f = check_win_firewall(fixed_run(out))
    assert f["status"] == "fail"
    assert f["severity"] == "high"
    assert "Public" in f["detail"]


def test_win_defender_realtime_on_passes():
    out = "RealTimeProtectionEnabled=True\nAntivirusEnabled=True\nAntivirusSignatureAge=2\n"
    f = check_win_defender(fixed_run(out))
    assert f["status"] == "pass"


def test_win_defender_realtime_off_fails():
    out = "RealTimeProtectionEnabled=False\nAntivirusEnabled=True\nAntivirusSignatureAge=2\n"
    f = check_win_defender(fixed_run(out))
    assert f["status"] == "fail"
    assert f["severity"] == "high"


def test_win_defender_stale_signatures_warns():
    out = "RealTimeProtectionEnabled=True\nAntivirusEnabled=True\nAntivirusSignatureAge=30\n"
    f = check_win_defender(fixed_run(out))
    assert f["status"] == "warn"


def test_win_uac_enabled_passes():
    f = check_win_uac(fixed_run("EnableLUA=1\n"))
    assert f["status"] == "pass"


def test_win_uac_disabled_fails():
    f = check_win_uac(fixed_run("EnableLUA=0\n"))
    assert f["status"] == "fail"
    assert f["severity"] == "high"


def test_win_listening_ports_wildcard_bind_warns():
    out = "0.0.0.0=445\n127.0.0.1=5432\n"
    f = check_win_listening_ports(fixed_run(out))
    assert f["status"] == "warn"
    assert "445" in f["detail"]


def test_win_listening_ports_localhost_only_passes():
    out = "127.0.0.1=5432\n::1=5433\n"
    f = check_win_listening_ports(fixed_run(out))
    assert f["status"] == "pass"


def test_check_degrades_to_unknown_on_command_error():
    # Non-zero exit (e.g. needs admin) → unknown, never a crash or false pass.
    f = check_win_defender(fixed_run(out="", code=1, err="Access is denied"))
    assert f["status"] == "unknown"


def test_win_bitlocker_on_passes():
    f = check_win_bitlocker(fixed_run("ProtectionStatus=On\n"))
    assert f["status"] == "pass"


def test_win_bitlocker_off_fails():
    f = check_win_bitlocker(fixed_run("ProtectionStatus=Off\n"))
    assert f["status"] == "fail"
    assert f["severity"] == "high"


def test_win_bitlocker_no_admin_unknown():
    # Get-BitLockerVolume requires elevation; a non-zero exit must degrade.
    f = check_win_bitlocker(fixed_run(out="", code=1, err="requires elevation"))
    assert f["status"] == "unknown"


def test_win_bitlocker_empty_status_is_unknown_not_fail():
    # Exit 0 but no ProtectionStatus value (e.g. ran unelevated) must NOT be
    # reported as "not encrypted" — that would be a misleading false alarm.
    f = check_win_bitlocker(fixed_run("ProtectionStatus=\n"))
    assert f["status"] == "unknown"


def test_win_rdp_disabled_passes():
    f = check_win_rdp(fixed_run("fDenyTSConnections=1\n"))
    assert f["status"] == "pass"


def test_win_rdp_enabled_warns():
    f = check_win_rdp(fixed_run("fDenyTSConnections=0\n"))
    assert f["status"] == "warn"
    assert f["severity"] == "medium"


def test_win_guest_disabled_passes():
    f = check_win_guest_account(fixed_run("GuestEnabled=False\n"))
    assert f["status"] == "pass"


def test_win_guest_enabled_fails():
    f = check_win_guest_account(fixed_run("GuestEnabled=True\n"))
    assert f["status"] == "fail"
    assert f["severity"] == "high"


def test_win_av_products_present_passes():
    out = "Product=Windows Defender\nProduct=Norton Security\n"
    f = check_win_av_products(fixed_run(out))
    assert f["status"] == "pass"
    assert "Norton Security" in f["detail"]


def test_win_av_products_none_fails():
    f = check_win_av_products(fixed_run(""))
    assert f["status"] == "fail"
    assert f["severity"] == "high"


# ── macOS checks ──────────────────────────────────────────────────────────────

def test_mac_filevault_on_passes():
    f = check_mac_filevault(fixed_run("FileVault is On.\n"))
    assert f["status"] == "pass"


def test_mac_filevault_off_fails():
    f = check_mac_filevault(fixed_run("FileVault is Off.\n"))
    assert f["status"] == "fail"
    assert f["severity"] == "high"


def test_mac_firewall_enabled_passes():
    f = check_mac_firewall(fixed_run("Firewall is enabled. (State = 1)\n"))
    assert f["status"] == "pass"


def test_mac_firewall_disabled_fails():
    f = check_mac_firewall(fixed_run("Firewall is disabled. (State = 0)\n"))
    assert f["status"] == "fail"


def test_mac_sip_enabled_passes():
    f = check_mac_sip(fixed_run("System Integrity Protection status: enabled.\n"))
    assert f["status"] == "pass"


def test_mac_sip_disabled_warns():
    f = check_mac_sip(fixed_run("System Integrity Protection status: disabled.\n"))
    assert f["status"] == "warn"


# ── Orchestration ─────────────────────────────────────────────────────────────

def _stub_check(name, status):
    return lambda run: {"check": name, "status": status, "severity": "info", "detail": ""}


def test_audit_host_summarises_counts():
    checks = [
        _stub_check("a", "pass"),
        _stub_check("b", "fail"),
        _stub_check("c", "pass"),
        _stub_check("d", "unknown"),
    ]
    result = audit_host(platform_name="windows", run=fixed_run(), checks=checks)
    assert result["platform"] == "windows"
    assert len(result["checks"]) == 4
    assert result["summary"]["pass"] == 2
    assert result["summary"]["fail"] == 1
    assert result["summary"]["unknown"] == 1
    assert result["summary"]["total"] == 4


def test_audit_host_unsupported_platform_is_graceful():
    result = audit_host(platform_name="plan9", run=fixed_run())
    assert result["platform"] == "plan9"
    assert result["checks"] == []
    assert "unsupported" in result["note"].lower()


# ── Elevation detection ───────────────────────────────────────────────────────

def test_detect_elevation_windows_admin():
    assert detect_elevation("windows", fixed_run("Elevated=True\n")) is True


def test_detect_elevation_windows_nonadmin():
    assert detect_elevation("windows", fixed_run("Elevated=False\n")) is False


def test_detect_elevation_mac_root():
    assert detect_elevation("darwin", fixed_run("0\n")) is True


def test_detect_elevation_mac_nonroot():
    assert detect_elevation("darwin", fixed_run("501\n")) is False


def test_detect_elevation_unsupported_is_none():
    assert detect_elevation("plan9", fixed_run("whatever\n")) is None


def test_detect_elevation_query_error_is_none():
    assert detect_elevation("windows", fixed_run(out="", code=1)) is None


def test_audit_host_reports_elevation():
    r = audit_host("windows", run=fixed_run("Elevated=False\n"),
                   checks=[_stub_check("a", "pass")])
    assert r["elevation"]["elevated"] is False


def test_audit_host_unelevated_hints_admin_when_unknown_present():
    r = audit_host("windows", run=fixed_run("Elevated=False\n"),
                   checks=[_stub_check("bitlocker", "unknown")])
    assert "hint" in r
    assert "administrator" in r["hint"].lower()


def test_audit_host_no_hint_when_all_known():
    r = audit_host("windows", run=fixed_run("Elevated=False\n"),
                   checks=[_stub_check("a", "pass"), _stub_check("b", "fail")])
    assert "hint" not in r


# ── Runner encoding robustness ────────────────────────────────────────────────

def test_default_run_decodes_bad_bytes_without_crashing():
    # zh-TW Windows emits cp950 error text; the runner must not raise on bytes
    # that are invalid under the assumed encoding. Bad bytes degrade, ASCII survives.
    r = _default_run([sys.executable, "-c",
                      "import sys; sys.stdout.buffer.write(b'\\xff\\xfeOK')"])
    assert r.code == 0
    assert "OK" in r.out


def test_audit_host_dispatches_by_platform():
    # Real (default) check registry for each platform should be non-empty.
    win = audit_host(platform_name="windows", run=fixed_run("Domain=True\nPrivate=True\nPublic=True\n"))
    mac = audit_host(platform_name="darwin", run=fixed_run("FileVault is On.\n"))
    assert len(win["checks"]) > 0
    assert len(mac["checks"]) > 0
