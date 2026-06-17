"""Tests for scripts/lint.py — the dependency-free repo linter.

The linter is meant to run "on a fresh Python 3.10+" including the author's
zh-TW Windows box where the default text encoding is cp950. It must read source
files as UTF-8 (the repo's source files contain non-ASCII: em-dashes, arrows,
check marks) rather than the locale codec, or it crashes with a
UnicodeDecodeError before it can lint anything.

These tests import lint as a module and exercise its helpers directly.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_LINT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "lint.py"
_spec = importlib.util.spec_from_file_location("secops_lint", _LINT_PATH)
lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint)


def test_read_decodes_utf8_regardless_of_locale(tmp_path: Path):
    # A file with non-ASCII bytes (UTF-8) must read cleanly even though the
    # platform default codec (cp950 on zh-TW Windows) would choke on these bytes.
    f = tmp_path / "u.py"
    f.write_text("# arrows → and check ✓ and em-dash —\nx = 1\n", encoding="utf-8")
    text = lint._read(f)
    assert "→" in text and "✓" in text


def test_lint_repo_passes_on_clean_repo():
    # The real repo must lint clean (all source parses, all TOML parses). This is
    # the regression guard: before the fix this raised UnicodeDecodeError on the
    # first non-ASCII source file under cp950.
    errors = lint.lint_repo()
    assert errors == [], f"unexpected lint errors: {errors}"


def test_lint_repo_covers_phantom_secops_package():
    # The linter must also check the phantom_secops/ package and scripts/, not
    # just tools/scenarios/tests — otherwise a syntax error in an MCP server
    # would sail through.
    files = lint._python_files()
    rels = {str(p).replace("\\", "/") for p in files}
    assert any("phantom_secops/mcp/" in r for r in rels)
    assert any("scripts/" in r for r in rels)


def test_lint_repo_flags_a_syntax_error(tmp_path: Path):
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:\n", encoding="utf-8")
    errors = lint._check_python([bad])
    assert errors and "bad.py" in errors[0]


def test_lint_repo_flags_undecodable_non_utf8(tmp_path: Path):
    # A genuinely non-UTF-8 file should be reported as an error, not crash the run.
    bad = tmp_path / "latin1.py"
    bad.write_bytes(b"x = '\xff\xfe not utf8'\n")
    errors = lint._check_python([bad])
    assert errors and "latin1.py" in errors[0]
