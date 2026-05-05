"""Minimal linter for phantom-secops.

Checks:
- All .py files parse with the standard library `ast` module.
- All agents/**/*.toml files parse (via tomllib on 3.11+, else just basic read).

No external dependencies. Designed to run on a fresh Python 3.10+.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def main() -> int:
    errors: list[str] = []

    print("→ python syntax check...")
    py_files = (
        list(REPO.glob("tools/*.py"))
        + list(REPO.glob("scenarios/*.py"))
        + list(REPO.glob("tests/*.py"))
        + list(REPO.glob("phantom_secops/**/*.py"))
    )
    for f in py_files:
        try:
            ast.parse(f.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            errors.append(f"  ✗ {f.relative_to(REPO)}: {exc}")
    if not errors:
        print(f"  ✓ {len(py_files)} python files parse")

    print("→ toml syntax check...")
    toml_files = list(REPO.rglob("agents/**/*.toml"))
    try:
        import tomllib  # type: ignore[import-not-found]
        toml_errors_before = len(errors)
        for f in toml_files:
            try:
                tomllib.loads(f.read_text(encoding="utf-8"))
            except Exception as exc:
                errors.append(f"  ✗ {f.relative_to(REPO)}: {exc}")
        if len(errors) == toml_errors_before:
            print(f"  ✓ {len(toml_files)} TOML files parse (deep)")
    except ImportError:
        # Python <3.11: just confirm files are readable.
        for f in toml_files:
            try:
                _ = f.read_text(encoding="utf-8")
            except Exception as exc:
                errors.append(f"  ✗ {f.relative_to(REPO)}: {exc}")
        print(f"  ✓ {len(toml_files)} TOML files readable (skip: tomllib needs Python 3.11+)")

    if errors:
        print()
        print("ERRORS:")
        for e in errors:
            print(e)
        return 1
    print()
    print("✓ all clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
