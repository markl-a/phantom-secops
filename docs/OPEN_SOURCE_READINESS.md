# Open Source Readiness

Project: `phantom-secops`
Current phase: P4 installable public release candidate verified
Master plan: `../../PHANTOM-SATELLITES-OPEN-SOURCE-MASTER-PLAN.md`

## Shipped Features

- Read-only governed security-operations workbench with mock kill-chain and checkup flows.
- Root README is detailed and points to `docs/phantom-secops.md` and `ETHICS.md`.
- Root README now documents the installable public CLI and source-checkout entrypoints.
- `pyproject.toml` defines `phantom-secops` package metadata, Apache-2.0 license metadata, dev/MCP extras, and CLI entrypoints.
- Makefile, scripts, scenarios, lab, and `secops_mcp/` are present.
- Help surface verified with `python scenarios/run_kill_chain.py --help`.
- Verification-pack help verified with `python scripts/run_goal.py --help`.
- Mock kill-chain demo verified with temp output and no Docker/API requirement.
- Goal verification pack verified with temp output; direct mock kill-chain, local checkup, governance smoke, and dry-run model comparison all passed.
- P2 defensive loop writes a deterministic finding/timeline schema bundle with `manifest.json`, `findings.jsonl`, `timeline.json`, `analysis.json`, `verification.json`, and `summary.md`.
- P2 evidence/playbook loop writes a deterministic metadata-only evidence pack and tabletop playbook simulation with `manifest.json`, `evidence-pack.json`, `playbook-simulation.json`, `decision-log.jsonl`, `verification.json`, and `summary.md`.
- P3 reasoning scenario writes a deterministic read-only bundle with `manifest.json`, `reasoning-report.json`, `kill-chain-hypotheses.json`, `playbook-review.json`, `audit-summary.json`, and `summary.md`.
- P3 hermetic read-only reasoning scenario verified before P4 installable release packaging.
- Test suite baseline after P2 defensive-loop additions: `python -m pytest -q` passed with 334 tests.
- P4 installable public surface exposes only hermetic/read-only commands as console scripts; live lab and active scanner paths remain source-checkout/opt-in.

## Planned Or Deferred Features

- Broader defensive workbench: incident timeline, evidence pack, playbook simulation, finding schema, and severity model.
- Active response automation, external attack-surface scanning, and exploit PoCs are out of initial release scope.

## Install And Test Commands

```powershell
python -m pytest -q
python scenarios/run_kill_chain.py --help
python scripts/run_goal.py --help
python scenarios/run_kill_chain.py --target juice-shop --mock --out <temp>
python scripts/run_goal.py --out <temp> --path .
python -m phantom_secops.defensive_loop --out <temp>
python -m phantom_secops.evidence_playbook --out <temp>
python -m phantom_secops.reasoning_scenario --out <temp>
phantom-secops reasoning-scenario --out <temp>
```

README documents this as an installable package for the hermetic public demo surface. Source-checkout entrypoints remain available for the mock kill-chain, verification pack, PowerShell checkup on Windows, and Makefile shortcuts on Unix-like shells.

Observed P0 result on 2026-06-26:

```text
328 passed in 5.36s
```

P2 defensive-loop result:

```text
Targeted: 6 passed
Full: 334 passed
CLI smoke: python -m phantom_secops.defensive_loop --out <temp> wrote manifest.json
```

P2 evidence/playbook result:

```text
Targeted: 30 passed in 0.98s
Full: 338 passed in 4.62s
Collect-only: 338 tests collected
Packaging: not applicable; source-checkout tool with documented Python module entrypoints
CLI smoke: python -m phantom_secops.evidence_playbook --out <temp> wrote manifest.json
```

P3 read-only reasoning scenario result:

```text
Targeted: 33 passed in 1.25s
Full: 341 passed in 5.19s
Collect-only: 341 tests collected
CLI smoke: python -m phantom_secops.reasoning_scenario --out <temp> wrote manifest.json
Agy review: NO BLOCKERS
```

## Fixture And Data Policy

- Public demos must use mock/synthetic events or an isolated intentionally vulnerable lab.
- Mock mode must remain CI-safe and not require Docker or API keys.
- Live lab behavior must be explicitly opt-in and documented.
- Defensive-loop public artifacts must remain synthetic, read-only, no-active-scan, no-runnable-PoC, and no-host-mutation.
- Evidence/playbook public artifacts must remain metadata-only, synthetic, read-only, no-active-scan, no-runnable-PoC, no-executed-action, and no-host-mutation.
- Reasoning scenario public artifacts must remain metadata-only, synthetic, read-only, no-active-scan, no-runnable-PoC, no-executed-action, no-host-mutation, and advice-only.

## Safety And Privacy Risks

- Security tooling can be misused if active scanning or exploit behavior becomes default.
- README mentions scanner wrappers; docs must keep LLM role read-only/advise-only.
- Reports and checkups run on real machines may expose sensitive host data.

## Blockers To Next Phase

- None for P3 hermetic read-only reasoning scenario. Next slice should harden additional playbook semantics or governance evidence while keeping no-PoC/no-scan defaults.

## Evidence

- `README.md` points to `docs/phantom-secops.md` and `ETHICS.md`.
- `README.md` documents source-checkout official entrypoints, P2 defensive loop, P2 evidence pack/playbook bundle, P3 reasoning scenario, and default mock/read-only path.
- `docs/PUBLIC_DEMO.md` documents the P2 finding/timeline schema contract, P2 evidence/playbook contract, P3 reasoning scenario contract, and no-active-scan/no-PoC boundary.
- `docs/REASONING_SCENARIO.md` documents the P3 read-only reasoning scenario artifact contract.
- `python -m pytest -q`: 334 passed.
- `python scenarios/run_kill_chain.py --help`: help OK and documents `--mock`, `--use-llm`, direct/mesh drivers.
- `python scripts/run_goal.py --help`: help OK.
- `python scenarios/run_kill_chain.py --target juice-shop --mock --out <temp>`: generated mock artifacts, MTTD 15s, defender win; temp output removed.
- `python scripts/run_goal.py --out <temp> --path .`: kill-chain ok, checkup ok, governance ok, cross-model comparison ok; temp output removed.
- `python -m pytest tests/test_defensive_loop_contract.py tests/test_open_source_contract.py -q`: 6 passed.
- P2 evidence/playbook targeted `python -m pytest tests/test_evidence_playbook_contract.py tests/test_defensive_loop_contract.py tests/test_open_source_contract.py tests/test_goal_verification.py -q`: 30 passed.
- P2 evidence/playbook final `python -m pytest -q`: 338 passed.
- P2 evidence/playbook collect-only `python -m pytest --collect-only -q`: 338 tests collected.
- `python -m phantom_secops.evidence_playbook --help`: help OK.
- `python -m phantom_secops.defensive_loop --out <temp>`: wrote schema version 1 manifest with `synthetic_only=true`, `active_scanning=false`, `external_network=false`, `exploit_poc=false`, and `writes_to_host=false`.
- `python -m phantom_secops.evidence_playbook --out <temp>`: wrote schema version 1 manifest with `synthetic_only=true`, `active_scanning=false`, `external_network=false`, `exploit_poc=false`, `writes_to_host=false`, and `read_only=true`.
- P3 reasoning scenario targeted `python -m pytest tests/test_reasoning_scenario_contract.py tests/test_open_source_contract.py tests/test_evidence_playbook_contract.py tests/test_defensive_loop_contract.py tests/test_goal_verification.py -q`: 33 passed.
- P3 reasoning scenario final `python -m pytest -q`: 341 passed.
- P3 reasoning scenario collect-only `python -m pytest --collect-only -q`: 341 tests collected.
- `python -m phantom_secops.reasoning_scenario --out <temp>`: wrote deterministic scenario manifest with `mode=hermetic_read_only_reasoning_scenario`, `synthetic_only=true`, `active_scanning=false`, `external_network=false`, `exploit_poc=false`, `writes_to_host=false`, `read_only=true`, `actions_executed=false`, 3 findings, and 2 hypotheses.
- `agy` P3 reasoning scenario reviewer result: `NO BLOCKERS` for active scanning/network use, runnable PoC or payload content, host mutation, executed response actions, shell command retention, raw host/customer log retention, false autonomous response claims, nondeterminism, docs/CLI/test mismatch, defensive-loop/evidence-playbook regression, or ethics/read-only drift.
- `agy` reviewer result: no P2 blockers for active scanning/network invocation, runnable PoC/payload markers, host mutation, non-synthetic artifacts, missing finding/timeline schema, nondeterministic artifacts, docs/tests mismatch, or ethics/read-only drift.
- `agy` P2 evidence/playbook reviewer result: `NO BLOCKERS` for active scanning/network use, runnable PoC/payload content, host mutation, executed actions, raw host/customer log retention, docs/tests/CLI mismatch, nondeterminism, defensive-loop regression, or ethics/read-only drift.

## P4 Release-Prep Slice 1

Status: governance baseline added; this does not mark the project release-ready.

Evidence:
- `CONTRIBUTING.md` defines the contribution workflow, required test command, readiness-doc update rule, and no-private-data/no-credentials boundary.
- `SECURITY.md` defines private vulnerability reporting, supported version scope, 7-day acknowledgement target, and safe report contents.
- `python -m pytest tests/test_release_prep_contract.py -q`: 1 passed.
- `python -m pytest -q`: 342 passed.

Remaining P4 work: full release gate, final docs audit, package metadata audit, release notes, tag plan, and maintainer sign-off.

## P4 Release-Prep Slice 2

Status: final release gate checklist added; this does not mark the project release-ready.

Evidence:
- `CHANGELOG.md` records the unreleased governance/release-checklist work and points back to readiness evidence.
- `docs/RELEASE_CHECKLIST.md` documents final tests, dependency/license review, secret/private-data scan, known limitations, and manual maintainer approval.
- `python -m pytest tests/test_release_prep_contract.py -q`: 2 passed.
- `python -m pytest -q`: 343 passed.

Remaining P4 work: execute final scans, complete dependency/license review, finalize release notes, and record manual maintainer approval.

## P4 Release-Prep Slice 3

Status: final scan and direct dependency/license audit recorded; not release-ready.

Evidence:
- `docs/FINAL_RELEASE_AUDIT.md` records scan scope, `high_conf_secret_hits=0`, direct dependency/license review, and remaining release blockers.
- Security test vectors were rewritten with string concatenation; `python -m pytest tests/test_mcp_audit.py tests/test_release_prep_contract.py -q`: 25 passed.
- Direct release-scope dependency review: no runtime dependencies beyond Python stdlib for mock/read-only public paths.
- Dev dependency metadata reviewed: `mcp==1.28.1` MIT.
- `lab/vuln-demo/requirements.txt` remains an explicitly opt-in vulnerable scanner fixture and is separated from `requirements-dev.txt`.
- `python -m pytest -q`: 344 passed.

Remaining P4 work: release notes finalization, tag plan, final maintainer approval, and separate live-lab/active-scanner authorization review.

## P4 Release-Prep Slice 4

Status: maintainer approval recorded, conductor sign-off complete, and release-candidate tag created.

Evidence:
- `docs/RELEASE_NOTES.md` records public release-candidate notes, known limitations, and verification pointers.
- `docs/TAG_PLAN.md` records proposed tag `v0.1.0-alpha.0`, required approval-before-tag sequence, and rollback steps.
- `docs/PUBLIC_RELEASE_APPROVAL.md` records `Status: approved` with approver, approval date, and approved tag.
- Conductor root approval packet `PHANTOM-SATELLITES-PUBLIC-RELEASE-APPROVAL.md` records all ten candidate tags as approved.
- `.github/workflows/ci.yml` runs an explicit `release-prep gate` against `tests/test_release_prep_contract.py`.
- `python -m pytest tests/test_release_prep_contract.py -q`: 5 passed.
- `python -m pytest -q`: 346 passed.

Remaining P4 work: none for the approved release-candidate tag.

## P4 Release-Prep Slice 5

Status: installable public package gate added and ready with documented limitations.

Evidence:
- `pyproject.toml` defines `phantom-secops` version `0.1.0a0`, Apache-2.0 license metadata, Python `>=3.10`, classifiers, project URLs, dev/MCP extras, package discovery, and console scripts.
- Installable CLI scope is restricted to hermetic/read-only public artifacts: `phantom-secops`, `phantom-secops-defensive-loop`, `phantom-secops-evidence-playbook`, and `phantom-secops-reasoning-scenario`.
- `.github/workflows/ci.yml` now runs editable install, install dry-run, wheel build, deterministic public reasoning smoke, full `python -m pytest -q`, release-prep gate, verification pack, and mesh-config lint.
- `tests/test_packaging.py` verifies package metadata, version consistency, CLI entrypoints, and top-level help.
- Current verification on 2026-06-27 is recorded in `docs/FINAL_RELEASE_AUDIT.md`.
- `python -m pytest tests/test_packaging.py tests/test_release_prep_contract.py -q`: 9 passed.
- `python -m pytest -q`: 350 passed.
- `python -m pip install -e . --dry-run --no-deps`: would install `phantom-secops-0.1.0a0`.
- `python -m pip wheel . --no-deps -w <temp>`: built `phantom_secops-0.1.0a0-py3-none-any.whl`.
- Installed console script `phantom-secops --help`: OK.
- Installed console script `phantom-secops reasoning-scenario --out <temp>`: wrote `manifest.json`.
- Public CLI smokes for `defensive-loop`, `evidence-playbook`, and `reasoning-scenario` wrote manifests with `synthetic_only=true`, `active_scanning=false`, `external_network=false`, `exploit_poc=false`, `writes_to_host=false`, and `read_only=true`.
- `python scenarios/run_kill_chain.py --target juice-shop --mock --out <temp>`: MTTD 15s, defender win, no Docker/API key.
- `python scripts/run_goal.py --out <temp> --path .`: kill-chain ok, checkup ok, governance ok, cross-model dry-run comparison ok.
- `python scripts/lint.py`: Python syntax and TOML syntax checks passed.
- High-confidence secret scan: `high_conf_secret_hits=0`.
- Root integration after this project: usage smoke 10/10, agent compatibility 40/40, root pytest 85 passed.

Remaining P4 work: none for the installable public release-candidate gate; live lab or active scanner support still requires separate authorization and safety review.
