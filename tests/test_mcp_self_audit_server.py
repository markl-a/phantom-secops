"""Tests for the secops_self_audit MCP server."""

from __future__ import annotations

from pathlib import Path

from phantom_secops.mcp import secops_self_audit_server


def test_list_tools_includes_xphantom_metadata():
    tools = secops_self_audit_server.tool_definitions()
    assert any(t.name == "audit_local_config" for t in tools)
    md = next(t for t in tools if t.name == "audit_local_config").metadata
    assert md["x-phantom.classification"] == "internal"
    assert "read.config.local" in md["x-phantom.capabilities"]
    assert "target.self_only" in md["x-phantom.capabilities"]
    assert md["x-phantom.read_only"] is True


def test_detects_plaintext_provider_key(tmp_path: Path):
    cfg = tmp_path / "agents.toml"
    cfg.write_text(
        '[providers.groq]\n'
        'type = "groq"\n'
        'api_key = "literal-provider-key-for-test"\n'
        'default_model = "llama-3.3-70b-versatile"\n'
    )
    out = secops_self_audit_server.audit_impl({"path": str(cfg)})
    findings = out["findings"]
    assert any(f["check"] == "plaintext_api_key" and f["section"] == "providers.groq" for f in findings)
    # the key VALUE must not be echoed back to the caller
    assert "literal-provider-key-for-test" not in str(findings)


def test_detects_weak_cluster_secret(tmp_path: Path):
    cfg = tmp_path / "agents.toml"
    cfg.write_text(
        '[cluster]\n'
        'cluster_secret = "short"\n'
    )
    out = secops_self_audit_server.audit_impl({"path": str(cfg)})
    assert any(f["check"] == "weak_cluster_secret" for f in out["findings"])


def test_detects_zero_dot_zero_listener(tmp_path: Path):
    cfg = tmp_path / "agents.toml"
    cfg.write_text(
        '[core]\n'
        'host = "0.0.0.0"\n'
        'port = 7878\n'
    )
    out = secops_self_audit_server.audit_impl({"path": str(cfg)})
    assert any(f["check"] == "exposed_listener" for f in out["findings"])


def test_unreadable_path_degrades_to_finding(tmp_path: Path):
    # A directory (or otherwise unreadable path) must degrade to a structured
    # finding, not raise PermissionError/IsADirectoryError out of the MCP call.
    out = secops_self_audit_server.audit_impl({"path": str(tmp_path)})  # a directory
    assert out["findings"], "expected a structured 'unreadable' finding"
    assert any(f["check"] == "unreadable_file" for f in out["findings"])
    assert "scanned" in out


def test_non_utf8_file_degrades_to_finding(tmp_path: Path):
    # A non-UTF-8 agents.toml must not crash the audit with UnicodeDecodeError.
    cfg = tmp_path / "agents.toml"
    cfg.write_bytes(b'[core]\nhost = "\xff\xfe"\n')
    out = secops_self_audit_server.audit_impl({"path": str(cfg)})
    assert any(f["check"] == "unreadable_file" for f in out["findings"])


def test_clean_config_returns_no_findings(tmp_path: Path):
    cfg = tmp_path / "agents.toml"
    cfg.write_text(
        '[core]\n'
        'host = "127.0.0.1"\n'
        '\n'
        '[cluster]\n'
        'cluster_secret = "this_is_a_long_enough_secret_2026"\n'
        '\n'
        '[providers.groq]\n'
        'type = "groq"\n'
        'api_key_env = "GROQ_API_KEY"\n'
    )
    out = secops_self_audit_server.audit_impl({"path": str(cfg)})
    assert out["findings"] == []
