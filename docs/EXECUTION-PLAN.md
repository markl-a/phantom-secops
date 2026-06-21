# phantom-secops — 執行計畫(Phase 1→3,月級)

> 前瞻執行計畫;**現況真相**以 [`docs/phantom-secops.md`](phantom-secops.md) 的〈狀態與視覺路線圖〉為準,**法律界線**見 [`/ETHICS.md`](../ETHICS.md)。本檔回答「接下來怎麼做」,主文件回答「現在是什麼」。
>
> 圖例:✅ 已完成 ｜ 🚧 進行中 ｜ ⬜ 未開始 ｜ 🔴 高優先 ｜ 🧪 需真環境 ｜ 👤 需操作者決策。

## 排序原則(沿用 SSOT)
① 便宜高值優先 ② **護城河優先於廣度** ③ 需真環境/真錢/操作者決策的排後並標明 ④ 守住永久紅線。

**目標映射**:每個里程碑同時推進 **A(資安工程面試/作品集 — 外部北極星)** 與 **B(本機自用 — 基底)**;**C(可售產品)** 僅當「別關門」的輕約束。

## 起點狀態
- ✅ **Phase 0(G2)已關閉** — live `nmap`+`nuclei` 端到端驗證(~79s 乾淨 run),229 tests,main `e8f1539`。
- 基礎設施齊備:8 引擎、7 MCP server(`phantom_secops/mcp/`)、x-phantom 能力中繼資料(目前是「廣告」非「強制」)、agent loop(`secops-agent.toml`,Cerebras `gpt-oss-120b` 主 + groq/gemini fallback,`max_tool_calls=6`)已 e2e 驗證。
- ✅ **M1 已完成(2026-06-21)** — `secops_mcp/` façade 建好,kill-chain 由 phantom-mesh 代理迴圈驅動(`--driver=mesh`),對拍直驅 orchestrator(實機驗證 + CI 對拍綠)。
- 缺口:phantom-mesh `core/src/mcp_client.rs` 的 Rust x-phantom 強制器**尚未實作**(M4);治理面 governor + 手機核可**尚未接**(M2)。

## 依賴與序列
```
M1 façade + agent-loop  ──►  M2 governance(governor + 手機核可 + x-phantom 強制)
        │                              │
        │                              └──►  M4 跨庫 Rust 強制器(phantom-mesh)+ 注入分類對齊
        └──►  M3 LLM-judge / 分流層   (M3 不依賴治理面,可與 M2 並行)
```
**A-呈現軌** 與 **永久護欄軌** 貫穿全程(非獨立階段)。

---

## M1 — Phase 1a:façade + 讓 kill-chain 由 agent loop 驅動  ✅ 🔴 (完成 2026-06-21)
**目的**:把頭號展示從確定性 Python orchestrator 升級為真·代理迴圈 —— Phase 1 前置,也是最強 A 故事素材。

**任務**
- [x] 建 `secops_mcp/` façade:`state.py`(跨回合 JSON 狀態)+ `steps.py`(recon/vuln_scan/detect/respond 四 composite 步驟,委派 `phantom_secops/killchain.py`)+ `server.py`(`mcp.server.Server` + `xphantom_metadata`)。
- [x] 紅藍步驟抽到 `phantom_secops/killchain.py` 單一真相,直驅(`scenarios/run_kill_chain.py`)與代理驅動共用 → parity 結構性成立。
- [x] `secops-demo.toml` 的 Cerebras agent loop 驅動同一條 kill-chain(`--driver=mesh`,`max_tool_calls=6`)。
- [x] **對拍測試(parity)**:`tests/test_demo_mock_parity.py` 斷言 timeline/recon/vuln byte-一致、MTTD/summary 指標相等、reports/triage/correlation 容許時間戳差異後相等;drift guard 拒絕亂序呼叫;`has_runnable_poc` 不變式穿過 façade。

**退出條件**:✅ `phantom exec`(0.6.0-rc.1 + Cerebras gpt-oss-120b)跑出 MTTD=15s / defender-win,reports 與 `make demo-mock` byte-一致(僅差時間戳);CI 對拍測試綠(249 tests)。
**風險/前置**:provider 配額(`max_tool_calls=6` 防迴圈,已生效);tool-call 漂移 → `StepOrderError` 回 error JSON 讓 agent 自我收斂(已驗證 agent 會重試前置工具)。
**踩到的坑(已記錄於 config 註解)**:phantom 0.6.0 **不展開** `[[mcp_servers]].env` 內的 `${VAR}`(會傳字面字串),但**會繼承父行程環境** → 由 `--driver=mesh` 設一次 env,server 繼承。
**A 產物**:[`docs/demos/m1-agent-loop.md`](demos/m1-agent-loop.md) —— 實機 transcript「LLM 代理自己依序呼叫四工具跑完一條 kill-chain」+ asciinema 錄製指令。
**charter**:差異化substance;不踩自主紅線(只跑既有唯讀工具)。

## M2 — Phase 1b:受治理代理迴圈(governor + 手機核可 + x-phantom 廣告→強制)  ⬜ 🔴 👤
**目的**:做出別人都沒有的示範 —— **會徵求許可的 agentic 資安**。這是利基本身。

**任務**
- [ ] 接 phantom-mesh governor + 手機核可平面:高風險步驟(如 live 掃描)需核可才放行。
- [ ] x-phantom 強制(本庫層先做):blue 代理被**結構性拒用** red 工具(能力模型從廣告變強制)。
- [ ] 👤 明列治理界線:哪些動作需核可、哪些自動放行。

**退出條件**:demo 中 (a) blue 試呼叫 red 工具被擋並記錄;(b) 一個 live 掃描步驟暫停等手機核可後才續跑。
**風險/前置**:👤 治理界線決策(需操作者拍板);MCP 是攻擊面(工具下毒/越權)→ 強制需可靠 + 測試。前置 = M1。
**A 產物**:「agentic security that asks permission」demo + talk-track 新段落。
**charter**:**這就是利基**;每往自主走一步即抹除利基 —— 護欄軌在此最關鍵。

## M3 — Phase 2:LLM-judge / 分流層(可與 M2 並行)  ⬜
**目的**:在 fused 發現上加信心分數 + 誤報過濾(Semgrep-Assistant 模式),直接強化 **B 自用**訊號品質。

**任務**
- [ ] 在 `posture_fusion.fuse_posture` 輸出**之上**加 judge 層(信心分 + FP 過濾);**確定性脊椎不變**。
- [ ] 不變式測試:斷言 `posture_fusion` 仍**不含 LLM**;judge 只重排/標註,不新增未經引擎確認的發現。

**退出條件**:judge 能壓制一個已知誤報類別(如簽章模組 manifest 類)同時保住真陽性;脊椎-無-LLM 測試綠。
**風險**:無標註資料集做校準 → 先用規則式信心 + 少量人工標註種子;守住「LLM 不取代脊椎」。
**A 產物**:before/after 報告(同機器,雜訊↓、優先序更準)。
**charter**:對齊「引擎找事實、LLM 分級」先例;B 自用直接受益。

## M4 — Phase 3:跨庫 x-phantom Rust 強制器 + 注入分類對齊(護城河兌現)  ⬜ 🧪
**目的**:把 x-phantom 從「本庫示範」變成「**任何 MCP 資安工具都能用的治理範式**」—— 最深的護城河。

**任務**
- [ ] 在 phantom-mesh `core/src/mcp_client.rs` 落地 Rust 政策強制器(跨庫;此 enforcer 從未實作,屬本里程碑核心)。
- [ ] 注入偵測器規則對齊 garak / PyRIT 分類(**引用不重造**)。

**退出條件**:phantom-mesh 端能跨庫強制一條被拒能力;注入規則映射到既有 taxonomy。
**風險/前置**:跨庫 + Rust;需 phantom-mesh 端協調。前置 = M2 能力模型穩定。
**A 產物**:架構 writeup「from advisory to enforced, cross-repo」。
**charter**:**這就是利基**的最終兌現。

---

## 貫穿全程的兩條軌
**A-呈現軌(每個里程碑都交付)**:demo artifact(HTML 報告 / 錄影)+ talk-track delta + 架構/決策 writeup delta。滿足憲章「主要 A 工作是呈現」而不需獨立階段。

**永久護欄軌(每個 PR 必檢,Phase 1 尤其高危)**:
- `has_runnable_poc == false` 不變式測試
- 不外部掃描 / 不 auto-remediation / 不漂向自主 / 低假陽性
- ⚠ M1/M2 引入 agent loop 時最容易漂向自主 —— 這條軌是煞車。

## 工程實踐(延續既有)
可注入 runner + TDD(測試零真實掃描)、誠實降級(`unknown` 不假 `fail`、缺工具顯 DEGRADED)、feed-don't-rescan、文件 SSOT(每階段更新 `docs/phantom-secops.md`)、provider key 僅 `api_key_env`。

## 刻意不在此計畫(維持永久紅線,見 ETHICS.md)
可執行 PoC / exploit、外部掃描、auto-remediation、自主找 0-day、重造掃描引擎、vendor AGPL Vulnhuntr。

---
*本檔為 living document:每完成一個里程碑,更新其狀態標記並把對應「已出貨」項回填 `docs/phantom-secops.md` 的狀態表。*
