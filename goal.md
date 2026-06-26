# /goal（phantom-secops 對等驗證）

## 目標
- 讓衛星專案成為主專案可對等驗證的最小標準：先驗證 mock/local 可重現，再逐步上到 mesh。
- 建立兩層 `/goal`：
  - `mock baseline`（快速門檻）
  - `strict parity`（主專案對齊門檻）

## 成功條件（Baseline）
- `goal-manifest.json`、`killchain-validation.json`、`checkup-validation.json`、`governance-validation.json`、`cross-model-comparison.json` 皆存在。
- `goal-manifest.audit_summary.killchain` 包含：`mttd / outcome / detect_margin / first_detect / time_to_impact / first_action / outcome / timeline`
- `KILL-CHAIN` artifacts 完整：`summary.json / recon.json / vuln-scan.json / alerts.jsonl / triage-queue.jsonl / kill-chains.jsonl / exploit-suggestions.md / pentest-report.md / incident-report.md`
- `checkup` 文字輸出必含四段：
  - `== HOST POSTURE ==`
  - `== VULNERABILITIES ==`
  - `== INTRUSION DETECTION ==`
  - `== PRIORITISED ACTIONS ==`
- `governance` 必有 `denied-role` 與 `denied-approval`；`exploit-suggestions.md` 不含 payload marker。

## 成功條件（Strict / 對等）
- 必須加上 `--require-governance` 與 `--require-parity`。
- 嚴格模式下，`codex/claude/hermes` 三模型都要有對應 runner（不接受 dry-run）。
- 每次 run 全部模型比較不得有差異：
  - `cross-model-comparison.killchain.ok == true`
  - `cross-model-comparison.checkup.ok == true`
- 只要任一模型未實際跑出結果或比較失敗，`strict` 直接 fail。

## 輸入與執行參數
- `--out`：輸出目錄根目錄（建議 `reports/verification`）
- `--target`：kill-chain 測試目標（預設 `juice-shop`）
- `--path`：checkup 掃描路徑（預設 `.`）
- `--models`：模型清單字串，預設 `codex,claude,hermes`
- `--mesh` / `--provider`：切換到 phantom-mesh 驗證
- `--require-governance` / `--require-parity`
- `PHANTOM_PROVIDER`（若走 mesh）
- `GOAL_MODEL_RUNNER_CODEX/GOAL_MODEL_RUNNER_CLAUDE/GOAL_MODEL_RUNNER_HERMES`（Strict 下必備）

## /goal 可執行流程（建議）
1) 基線跑法：
```powershell
python scripts/run_goal.py --out reports/verification
```
2) strict 對等跑法（建議，主專案上線前）：
```powershell
$env:GOAL_MODEL_RUNNER_CODEX="python scripts/run_goal_model_runner.py --model codex --scenario {scenario} --out_dir {out_dir} --target {target} --path {path}"
$env:GOAL_MODEL_RUNNER_CLAUDE="python scripts/run_goal_model_runner.py --model claude --scenario {scenario} --out_dir {out_dir} --target {target} --path {path}"
$env:GOAL_MODEL_RUNNER_HERMES="python scripts/run_goal_model_runner.py --model hermes --scenario {scenario} --out_dir {out_dir} --target {target} --path {path}"
python scripts/run_goal.py --out reports/verification --require-governance --require-parity
```
3) mesh 路徑（主專案可用後）：
```powershell
python scripts/run_goal.py --out reports/verification --mesh --provider <PHANTOM_PROVIDER> --require-governance --require-parity
```
4) 測試快速核對：
```powershell
python -m pytest tests/test_goal_verification.py -q
```

## 交付輸出（每次 run 需固定）
- `reports/verification/<timestamp>/goal-manifest.json`
- `.../killchain-validation.json`
- `.../checkup-validation.json`
- `.../governance-validation.json`
- `.../cross-model-comparison.json`
- `.../killchain/*` 全部 artifact
- `.../checkup/checkup.txt`
- `.../governance/governance.log` / `.../governance/governance.jsonl`
