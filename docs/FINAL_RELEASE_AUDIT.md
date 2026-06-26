# Final Release Audit

Status: release candidate approved and tagged.

Date: 2026-06-26

## Scope

- Default release surface: source-checkout commands, mock/read-only kill-chain demo, defensive-loop, evidence-playbook, and reasoning-scenario artifacts.
- Excluded scan noise: `.git`, `.ensemble`, `.venv`, `venv`, `__pycache__`, `.pytest_cache`, `reports`, `dist`, and `build`.

## Secret And Private-Data Scan

Command class: `rg` high-confidence patterns for private keys, AWS access keys, GitHub tokens, OpenAI-shaped keys, Slack tokens, and Google API keys.

Result: `high_conf_secret_hits=0`.

Note: AWS/OpenAI-shaped security test vectors were rewritten with string concatenation so detector coverage remains without storing real token-shaped literals.

## Dependency/License Review

- Project license: Apache-2.0.
- Default runtime dependencies: none beyond Python stdlib for mock/read-only public paths.
- Dev dependencies: `pytest>=7.0` and `mcp>=1.0,<2.0`; metadata sample reviewed as `mcp==1.28.1`, MIT.
- `lab/vuln-demo/requirements.txt` intentionally pins old vulnerable packages for opt-in scanner demonstrations only. It is not installed by CI or `requirements-dev.txt`, and `lab/vuln-demo/README.md` marks it as an isolated fixture.

Direct default release-scope dependency/license review result: pass.

## Remaining Publication Gates

- Manual maintainer approval is recorded in `docs/PUBLIC_RELEASE_APPROVAL.md`.
- Local annotated tag `v0.1.0-alpha.0` was created after the root strict approval verifier and conductor sign-off passed.
- Any live lab or active scanner path requires separate dependency/license, target-authorization, and safety review.
