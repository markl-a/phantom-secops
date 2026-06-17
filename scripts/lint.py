"""Minimal linter for phantom-secops.

Checks:
- All .py files parse with the standard library `ast` module.
- All agents/**/*.toml files parse (via tomllib on 3.11+, else just basic read).

No external dependencies. Designed to run on a fresh Python 3.10+, including
machines whose default text encoding is not UTF-8 (e.g. cp950 on zh-TW Windows):
all reads force UTF-8 and all console output is ASCII so the linter never
crashes on its own I/O before it can report a real problem.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _read(path: Path) -> str:
    """Read a source file as UTF-8 regardless of the platform locale codec.

    The repo's sources contain non-ASCII (em-dashes, arrows). On a cp950 box the
    default `Path.read_text()` raises UnicodeDecodeError on those bytes, which
    previously crashed the linter outright. Forcing UTF-8 fixes that; a file that
    is genuinely not UTF-8 still raises UnicodeDecodeError, which callers catch
    and report as a lint error rather than a traceback.
    """
    return path.read_text(encoding="utf-8")


def _python_files() -> list[Path]:
    """Every first-party Python file the linter should parse."""
    return sorted(
        list(REPO.glob("tools/*.py"))
        + list(REPO.glob("scenarios/*.py"))
        + list(REPO.glob("tests/*.py"))
        + list(REPO.glob("scripts/*.py"))
        + list(REPO.glob("phantom_secops/**/*.py"))
    )


def _toml_files() -> list[Path]:
    return sorted(REPO.rglob("agents/**/*.toml"))


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO))
    except ValueError:
        return str(path)


def _check_python(py_files: list[Path]) -> list[str]:
    errors: list[str] = []
    for f in py_files:
        try:
            ast.parse(_read(f))
        except (SyntaxError, UnicodeDecodeError) as exc:
            errors.append(f"  x {_rel(f)}: {exc}")
    return errors


def _check_toml(toml_files: list[Path]) -> tuple[list[str], bool]:
    """Return (errors, deep) — deep is False when tomllib is unavailable."""
    errors: list[str] = []
    try:
        import tomllib  # type: ignore[import-not-found]
    except ImportError:
        for f in toml_files:
            try:
                _read(f)
            except (OSError, UnicodeDecodeError) as exc:
                errors.append(f"  x {_rel(f)}: {exc}")
        return errors, False
    for f in toml_files:
        try:
            tomllib.loads(_read(f))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError) as exc:
            errors.append(f"  x {_rel(f)}: {exc}")
    return errors, True


def lint_repo() -> list[str]:
    """Lint the whole repo and return a list of error strings (empty == clean)."""
    errors = _check_python(_python_files())
    toml_errors, _deep = _check_toml(_toml_files())
    return errors + toml_errors


def main() -> int:
    print("-> python syntax check...")
    py_files = _python_files()
    py_errors = _check_python(py_files)
    if not py_errors:
        print(f"  ok {len(py_files)} python files parse")

    print("-> toml syntax check...")
    toml_files = _toml_files()
    toml_errors, deep = _check_toml(toml_files)
    if not toml_errors:
        kind = "parse (deep)" if deep else "readable (skip: tomllib needs Python 3.11+)"
        print(f"  ok {len(toml_files)} TOML files {kind}")

    errors = py_errors + toml_errors
    if errors:
        print()
        print("ERRORS:")
        for e in errors:
            print(e)
        return 1
    print()
    print("all clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
