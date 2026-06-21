"""Tests for the --driver=mesh path of the kill-chain orchestrator.

The real mesh run shells out to `phantom exec` and needs a provider key — that
end-to-end run is a manual gate (see Makefile demo-mock-mesh). Here we mock the
subprocess to SIMULATE what the agent+server do (drive the secops_mcp steps over
the run's state file) so the driver's own logic — env wiring, state readback,
parity with the direct driver, and the failure paths — is covered in CI without
docker, a provider, or the phantom binary.
"""

from __future__ import annotations

import argparse
import subprocess

import pytest

from phantom_secops import killchain as kc
from scenarios import run_kill_chain as rk
from secops_mcp import steps
from secops_mcp.state import KillChainState


def _mesh_args(out_dir):
    return argparse.Namespace(
        target="juice-shop", mock=True, use_llm=False,
        out=str(out_dir), driver="mesh", severity=kc.NUCLEI_SEVERITY,
    )


def _fake_phantom_success(cmd, env=None, **kwargs):
    """Stand in for `phantom exec`: drive the façade steps over the run state,
    exactly as the agent calling the MCP tools in order would."""
    st = KillChainState(
        target=env["SECOPS_MCP_TARGET"],
        mock=env["SECOPS_MCP_MOCK"] == "1",
        out_dir=env["SECOPS_MCP_OUT_DIR"],
    )
    steps.recon(st)
    steps.vuln_scan(st)
    steps.detect(st)
    steps.respond(st)
    st.save(env["SECOPS_MCP_STATE_FILE"])
    return subprocess.CompletedProcess(cmd, 0)


def test_mesh_driver_matches_direct_driver_mttd(tmp_path, monkeypatch):
    monkeypatch.setattr(rk.shutil, "which", lambda _b: "/usr/bin/phantom")
    monkeypatch.setattr(rk.subprocess, "run", _fake_phantom_success)

    mesh_dir = tmp_path / "mesh"
    mesh_dir.mkdir(parents=True)
    timeline, pentest, incident = rk._run_mesh(_mesh_args(mesh_dir), mesh_dir)

    # direct reference run
    direct_dir = tmp_path / "direct"
    direct_dir.mkdir(parents=True)
    direct_args = argparse.Namespace(
        target="juice-shop", mock=True, use_llm=False,
        out=str(direct_dir), severity=kc.NUCLEI_SEVERITY,
    )
    direct_tl, _, _ = rk._run_pipeline(direct_args, direct_dir)

    assert kc._metrics(timeline) == kc._metrics(direct_tl)
    assert kc._metrics(timeline)["mttd"] == 15
    assert "Pentest Report" in pentest and "Incident Report" in incident


def test_mesh_driver_errors_when_phantom_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(rk.shutil, "which", lambda _b: None)
    d = tmp_path / "mesh"
    d.mkdir(parents=True)
    with pytest.raises(RuntimeError, match="phantom-mesh CLI"):
        rk._run_mesh(_mesh_args(d), d)


def test_mesh_driver_errors_on_nonzero_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(rk.shutil, "which", lambda _b: "/usr/bin/phantom")
    monkeypatch.setattr(rk.subprocess, "run",
                        lambda cmd, env=None, **kw: subprocess.CompletedProcess(cmd, 1))
    d = tmp_path / "mesh"
    d.mkdir(parents=True)
    with pytest.raises(RuntimeError, match="exited 1"):
        rk._run_mesh(_mesh_args(d), d)


def test_mesh_driver_errors_on_incomplete_run(tmp_path, monkeypatch):
    """Agent exits 0 but never reached respond → no reports → honest failure."""
    monkeypatch.setattr(rk.shutil, "which", lambda _b: "/usr/bin/phantom")

    def _partial(cmd, env=None, **kw):
        st = KillChainState(target=env["SECOPS_MCP_TARGET"], mock=True,
                            out_dir=env["SECOPS_MCP_OUT_DIR"])
        steps.recon(st)  # stops early — no vuln/detect/respond
        st.save(env["SECOPS_MCP_STATE_FILE"])
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(rk.subprocess, "run", _partial)
    d = tmp_path / "mesh"
    d.mkdir(parents=True)
    with pytest.raises(RuntimeError, match="did not complete"):
        rk._run_mesh(_mesh_args(d), d)
