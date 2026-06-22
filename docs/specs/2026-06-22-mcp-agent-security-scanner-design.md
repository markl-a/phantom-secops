# phantom-secops — 離線 MCP / agent 資安掃描器(Phase 1)設計

- **日期:** 2026-06-22
- **狀態:** DRAFT(待 owner review → 進 writing-plans)
- **作者:** Claude Code(brainstorming 流程;依據 4 路研究 — 安全執行層 OSS + bug-bounty 現實 + AI×資安 solo 營利 + 多 AI 意見 — 與 owner 拍板)
- **關係:** 本文是 `docs/phantom-secops.md` 既有路線圖的**具體化第一塊**(對應主文件「📅 近期/🔭 之後」中的 MCP 治理方向),**不修改既有紅線**。secops 大目標/紅線以主文件為準;本文只定義 Phase 1 的範圍與設計。

---

## 0. 一句話定位(reframe 確認,未改紅線)

> **phantom-secops = 動作/治理大腦 + 安全執行層** —— 讓 owner 自己的 agent/專案在「沙箱 + 政策 + 加密」下安全運行;同時當「親手做了受治理 agent runtime」的**可信度引擎**與 AI-agent 資安稽核服務的**漏斗頂端**。
> **Phase 1 = 一個離線、唯讀、靜態的 MCP / agent 資安掃描器**:吃本機 MCP 設定 + 工具定義,輸出優先排序、白話的風險報告。

## 1. 為什麼先做 MCP 掃描器(決策依據)

研究(2026-06-22,4 路)結論一致:
- **AI×資安 solo 的錢在「賣服務/工具」不在 outcome。** 最高 EV × 可行性 = **AI-agent 資安稽核服務**(固定範圍 $5-60k+、retainer $5-20k/月),而**免費 OSS 工具當 lead-gen + 可信度**,不是直接賣的產品。
- **最該做的第一步**(成本最低、最快見效):**一個免費、local-first、離線的 MCP/agent 資安掃描器** —— 它打中「**有錢的競品結構上補不了的洞:離線/隱私**」(商用掃描器多在雲端、要把設定上傳第三方),正是 secops 的 ethos。它**自用**(掃自己的 MCP 設定)+ **引流**(導到稽核 offer)+ **守紅線**。
- **bug-bounty 明確不做**:連 XBOW($117M)跑 bounty 都虧錢;台灣刑法 §358/§359 無善意研究豁免、有判刑前例。攻擊性/外部掃描**不進 secops**(若要碰,另開授權-only 專案)。

**威脅模型(掃描器要抓的)**:OWASP MCP Top 10(2025);真實事件 —— mcp-remote RCE(CVE-2025-6514, CVSS 9.6)、MCP Inspector RCE(CVE-2025-49596)、Cursor「MCPoison」持久 rug-pull(CVE-2025-54136)、postmark-mcp 後門(首個野外惡意 MCP server);心智模型 = **lethal trifecta(私資料 + 不可信輸入 + 外洩通道)**。

## 2. 守住既有紅線(關鍵,不可違反)

| secops 永久紅線 | Phase 1 掃描器如何遵守 |
|---|---|
| 唯讀 / 純文字 | 只**讀取 + 靜態分析**本機設定/工具定義;只輸出報告,絕不改任何設定或系統 |
| 不做外部掃描 | **只看本機設定**(owner 自己的或 owner 提供的設定檔);**不連遠端 MCP server 去探測**。Phase 1 純靜態 |
| 不出可執行 PoC | 只描述風險(散文 + 規則命中),`has_runnable_poc` 概念永為 false |
| 不自主化 | 一次性 CLI 掃描,人讀報告後自己決定 |

→ MCP 掃描器是**防禦、本機、唯讀**的延伸,**完全在護城河內**。

## 3. 三層界線 + 角色(對應 owner 的跨衛星原則)

| 層 | 不接任何東西 | 接 4 AI | 接 mesh / 主專案 |
|---|---|---|---|
| 能力 | 規則式靜態掃 MCP 設定 → 確定性優先排序白話報告(**純本機離線可跑**) | LLM 當 **triager**:信心分數、去重、白話化解釋(預設可關、離線安全) | 把治理決策接 phantom-mesh governor + 手機核可(→ Phase 2/3 PDP) |
| 角色 | **自用 + 引流(站得住)** | 更聰明 | 更有未來 |
| 營利角色 | 免費 OSS = 可信度 + 漏斗頂端 → 導到稽核服務(**不單獨當產品賣**) | | |

## 4. 架構取向

**延伸 secops 既有模式,不另起爐灶**:
- 既有引擎都在 `tools/*.py`(`host_audit` / `vuln_scan` / `ids_scan` / … / `posture_fusion`),各為**可注入 runner 的純模組**,單元測試用 canned 輸入、零真實 I/O。
- 既有 `tools/posture_fusion.py` 把多引擎發現合併成**單一排序、白話、無 LLM** 的行動清單(`== PRIORITISED ACTIONS ==`)。
- 既有 `x-phantom` 能力模型:每個 MCP 工具帶 `{"x-phantom.classification": "internal|blue|red", "x-phantom.capabilities": [...], "x-phantom.read_only": bool}`(`phantom_secops/mcp/_xphantom.py`)。

新增(沿用上述模式):
- **`tools/mcp_audit.py`** — 新引擎(純、確定性、可注入):輸入 = 解析後的 MCP 設定 + 工具定義清單;輸出 = `list[Finding]`(每筆:rule_id、severity、server/tool、訊息、OWASP-MCP-Top-10 對應)。**無 LLM。**
- **report/fusion** — 把 `mcp_audit` 的 findings 餵進 `posture_fusion` 風格的排序器(正規化嚴重度、最高風險先、穩定 tiebreak、白話)→ markdown 報告 + `summary.json`。
- **`phantom_secops/mcp/secops_mcp_audit_server.py`** — 把掃描器也包成一個 MCP server(帶 `x-phantom` `classification=blue, read_only=true`),讓 phantom-mesh agent 也能呼叫。
- **CLI / checkup 整合** — 加一個入口(如 `python -m phantom_secops.mcp_audit <config>` 或 `checkup.ps1 -McpConfig`),沿用既有「測試 + 引擎 + fusion + 報告」一鍵流。
- **LLM 只當 triager**(可選、預設可關):對 fused findings 加信心分數 + 去重 + 白話化,**確定性核心不含 LLM**(同 secops 既有原則)。

## 5. Phase 1 掃描範圍 + 檢查目錄(規則)

**輸入(Phase 1 = 本機靜態):** owner 的 MCP 設定 —— phantom-mesh `agents.toml` 的 `[[mcp_servers]]`、`.mcp.json`、或一份 MCP server 清單 + 工具定義(從靜態設定或一次 `tools/list` dump)。

**檢查目錄(每條 = 一個確定性規則,對應 OWASP MCP Top 10):**
1. **Tool poisoning** — 工具**描述/名稱**裡的隱藏指令 / 注入樣式(描述視為敵意輸入;偵測 imperative 指令、"ignore previous"、藏在 unicode/註解的指示)。
2. **過寬能力 / 缺中繼資料** — `x-phantom.capabilities` 過寬、`read_only=false` 但宣稱唯讀、或**完全缺 `x-phantom` 中繼資料**(無法治理)。
3. **未釘住 / 動態註冊** — server 啟動指令未釘 hash/version、用 `npx`/`uvx` 遠端抓取、或允許動態工具註冊(rug-pull 風險,對應 MCPoison)。
4. **SSRF / 私網 / 危險 URL** — server `url` 或工具 args 指向 localhost / 私有 IP / 雲端 metadata endpoint / 任意 URL。
5. **Lethal trifecta** — 同一 agent 同時可達(私資料工具)+(不可信輸入工具)+(外洩/網路工具)→ 旗標該**組合**。
6. **能力/分類違規** — `red` 分類工具被 `blue`/`internal` agent 可達;capabilities 與宣稱 classification 不符。
7. **密鑰外露** — env/args 內聯密鑰(非 `api_key_env`)、明文 token。

**輸出:** 確定性排序的 markdown 報告(`== PRIORITISED MCP RISKS ==`,沿用 posture_fusion 白話風格)+ `summary.json`(機器可讀:rule_id / severity / server / tool / owasp_id);可選 LLM-triage 層加信心 + 去重。報告**明確對應 OWASP MCP Top 10**(這對稽核服務 GTM 很重要 —— 報告就是可交付物)。

## 6. 三階段 arc(Phase 1 = 本文)

- **Phase 1(本文)— 離線靜態 MCP/agent 資安掃描器**(自用 + 引流 + 守紅線)。
- **Phase 2 — PDP(策略決策點)**:用 **Cedar**(Rust、形式化驗證、Apache-2.0)在**執行期**攔截每個工具呼叫 → 風險分類 → allow/deny/ask → append-only 稽核日誌。這是 owner 最初要的「安全執行」核心。
- **Phase 3 — 沙箱抽象 + HITL 手機核可 + 跨工具 toxic-flow**:包 Codex/`srt` 沙箱(Win 走 WSL2)、接 phantom-mesh governor + 手機核可;network-deny-default 當保險底層。

## 7. 與其他專案的分工(不重複)

- **phantom-mesh** = 加密 + 傳輸 + 身分(Ed25519 / ChaCha20-Poly1305 / age / RBAC / injection guard)。secops **消費**它(用其身分簽稽核日誌、用其加密存報告),**不另造加密**。
- **phantom-secure-connector** = **內容**防禦(PHI 去識別、注入偵測、MCP gateway)。secops 做的是**動作/設定/流程**治理(掃描 → 之後 PDP),**不重做** redaction/injection-scan。
- **phantom-secops** = **設定完整性(掃描)→ 執行期動作治理(PDP)→ 沙箱/HITL**。三層不重疊。

## 8. 配套商業動作(非本 spec 範圍,記錄)

掃描器並行(之後另談,不寫進這份程式 spec):一篇利刃文章(「MCP agent 的 tool poisoning 與 prompt injection — 你的稽核漏掉了什麼」)、一個 $5-10k「AI agent 資安快掃」offer、一份 NLnet/NGI Zero 申請(€5-50k,個人/台灣可)。

## 9. 風險與緩解

1. **假陽性會殺信任**(secops 既有原則:低假陽性優先於覆蓋率)。→ 規則保守、描述分析的啟發式結果標為「候選/需人看」、提供 allowlist/抑制機制;對乾淨設定要誠實回「0 高風險」而非硬湊。
2. **描述分析是啟發式**(tool poisoning 偵測本質模糊)。→ 確定性規則打底,LLM-triage 只加信心不取代;明確標注信心等級。
3. **守住「確定性脊椎不含 LLM」**(同 secops 既有原則)。→ `mcp_audit` 引擎 + fusion 全規則式、可離線、單元測試零 LLM;LLM 層可關。

## 10. 待確認 / owner-gated

- Phase 1 先支援哪些設定格式(建議:phantom-mesh `agents.toml` `[[mcp_servers]]` + `.mcp.json` 兩種起步)。
- OWASP MCP Top 10 對應表的版本基準(以 2025 版為準,規則設計成可換 config)。
- 工具定義來源:純靜態設定 vs 允許一次本機 `tools/list` dump(仍本機唯讀;建議 Phase 1 先純靜態設定,dump 列為選配)。
