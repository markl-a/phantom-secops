> ARCHIVED 2026-06-19 — 內容已併入 docs/phantom-secops.md;此為歷史版本。

# 開源生態與建議方向

> **目的。** 調查在開源領域及具代表性的產業案例中（2025–2026），AI agent 如何被用於
> 資安 / 漏洞檢查 / 滲透測試自動化，接著為 **phantom-secops** 建議一個設計方向，
> 以維護其防禦導向、不含可執行 exploit、受治理（governed）、與 phantom-mesh 整合的
> 利基定位。
>
> **狀態：** 研究筆記，撰寫於 2026-06-19。僅文件（Doc-only）。每一項外部宣稱都奠基於
> 一個已擷取的來源（URL 內嵌）；無法獨立驗證的項目標記為 `[UNVERIFIED]`。星數為時間點
> 快照且會變動；請將其視為數量級看待。

---

## 1. phantom-secops 目前的定位（奠基於本 repo）

請先閱讀：[README.md](../README.md)、[ROADMAP.md](../ROADMAP.md)、[ETHICS.md](../ETHICS.md)、
[docs/DECISIONS.md](DECISIONS.md)、[docs/ARCHITECTURE.md](ARCHITECTURE.md)。

**它是什麼。** 一個 Python（3.10+）資安維運專案，建構於作者自有的多 agent 執行環境
[phantom-mesh](https://github.com/markl-a/phantom-mesh) 之上。Apache-2.0。
階段：*Public Alpha* — 在 mock 模式下可端到端實際執行（`make demo-mock`，
<1s，無需 Docker / 無需 API key）。兩大支柱：

1. **SOC 概念示範（紅/藍隊實驗室）。** 一個確定性（deterministic）的 Python 編排器
   （`scenarios/run_kill_chain.py`）以兩個並行時鐘，針對刻意設置的易受攻擊實驗室應用
   （Juice Shop / DVWA / Metasploitable，Docker，無主機埠暴露），執行一條紅隊管線
   （recon → vuln-scan → exploit-*suggest* → pentest-report）與一條藍隊管線
   （log-anomaly → triage → correlate → incident-report）。重點指標是並列對比的
   **平均偵測時間（mean-time-to-detect, MTTD）**，並附帶一份機器可讀的 `summary.json`。
   實際的 `nmap`/`nuclei` 已在程式碼中接好，但**尚未端到端驗證**（gap G2）。
2. **本機優先的端點自檢。** 一條唯讀工具鏈（`checkup.ps1`）作用於*這台*機器：
   主機態勢、相依套件/作業系統套件的 CVE（**Trivy**）、主機入侵偵測
   （一個作用於 Windows 事件日誌的小型 **Sigma** 引擎）、設定自我稽核。一個確定性的
   `posture_fusion` 步驟將各項發現合併為單一已排序的行動清單（不含 LLM），再由一個 LLM
   agent 撰寫已排定優先序的白話報告。一次實際執行在某姊妹專案中揭露了 864 個可修復的 CVE。

**對本分析具重要意義的已交付介面：**
- 位於 `phantom_secops/mcp/` 下的**七個 MCP server**（`secops_host_audit`、`secops_ids`、
  `secops_log_ingest`、`secops_log`、`secops_recon`、`secops_self_audit`、`secops_vuln`）。
- 每個工具上的 **`x-phantom` 能力模型**（`classification` red/blue、
  `capabilities`、`read_only`、`target.self_only|lab`）— 這是 phantom-mesh 中
  per-agent 政策執行器的掛鉤點。
- 每個引擎都是一個**具可注入命令執行器的純模組**，以預製輸出進行單元測試
  （202 個通過的測試，測試中不進行真實掃描）。
- 一個**確定性的 posture-fusion** 層，以及一輪安全強化（以安全的 AST Sigma 評估器
  取代 `eval()`、nmap 注入修補、nuclei 實驗室閘門精確比對）。

**已陳明的永久邊界（任何建議都必須維護）：**
不含可執行 exploit（`has_runnable_poc` 永遠為 `false`；建議器只產出**純文字散文**）、
不進行外部掃描（僅限實驗室/自身，採用拒絕清單）、不自動修復（只建議，絕不變更系統）、
不擷取客戶/內部網路資料。phantom-mesh 增添了一個**治理器（governor）+ 手機核可**層
（受治理的無人值守執行），這正是此處任何 agentic 行為的相關控制平面。

**一句話自我總結：** phantom-secops 是*「別造引擎，造大腦」* —
包裝成熟工具，讓 LLM agent 來編排/關聯/解釋，維持唯讀且受治理。

---

## 2. 開源 / 產業生態（2025–2026）

### 2.1 AI-agent 滲透測試 / 攻擊性資安框架（擁擠的戰場）

| 專案 | 它是什麼 | URL | 成熟度 / 星數 | 語言 | 授權 | 是否執行？ |
|---|---|---|---|---|---|---|
| **PentestGPT** | LLM 引導的滲透測試助手；USENIX Security 2024 論文。本類型的種子。 | https://github.com/GreyDGL/PentestGPT | 成熟、廣受引用 | Python | （依 repo） | 引導人類操作者（半互動式） |
| **CAI (Cybersecurity AI)** — Alias Robotics | 用於攻擊**與**防禦自動化的 ReAct agent 框架；300+ 模型；HITL。 | https://github.com/aliasrobotics/CAI | ~9.2k★，非常活躍（1k+ commits） | Python | Apache-2.0 / MIT（雙授權） | **是 — 會執行**（Linux cmd、程式碼執行、SSH） |
| **Strix** — usestrix | 動態執行程式碼的自主 AI agent，尋找漏洞，**以真實 PoC 驗證**。 | https://github.com/usestrix/strix | ~26k★，成熟（v1.0.x，2026） | Python | Apache-2.0 | **是 — 會執行 PoC** |
| **PentAGI** — vxcontrol | 在 Docker sandbox 中完全自主的多 agent 滲透測試系統。 | https://github.com/vxcontrol/pentagi | ~14.7k★ `[UNVERIFIED count]` | Go | （依 repo） | **是 — 自主** |
| **XBOW**（商業；公開技術文章） | 自主的 web 應用「AI hacker」；在 HackerOne 排行榜登上 #1（2026 年 4 月，1,060+ 已驗證提交）。 | https://xbow.com（writeups） | 正式生產、商業 | — | proprietary | **是 — 完整漏洞利用** |
| **Google「Big Sleep」**（Naptime 框架） | DeepMind + Project Zero 的 LLM agent，用於真實世界 0-day 發掘；在 SQLite 中發現 CVE-2025-6965（in-the-wild）、20 個 OSS 缺陷（FFmpeg、ImageMagick）。 | https://blog.google/innovation-and-ai/technology/safety-security/cybersecurity-updates-summer-2025/ | 正式生產研究 | — | proprietary | **是 — 發掘真實 0-day** |
| **OpenAI「Aardvark」** | GPT-5 的 agentic 資安研究員：監看 commit、尋找漏洞、評估可利用性、**提出修補**。 | https://openai.com/index/introducing-aardvark/ | 私有 beta（2025 年 10 月） | — | proprietary | 分析 + 修補（sandbox 驗證） |

來源：[CAI repo](https://github.com/aliasrobotics/CAI) ·
[CAI arXiv 2504.06017](https://arxiv.org/pdf/2504.06017) ·
[Strix repo](https://github.com/usestrix/strix) ·
[Strix — Help Net Security](https://www.helpnetsecurity.com/2025/11/17/strix-open-source-ai-agents-penetration-testing/) ·
[PentAGI repo](https://github.com/vxcontrol/pentagi) ·
[Big Sleep — Google blog](https://blog.google/innovation-and-ai/technology/safety-security/cybersecurity-updates-summer-2025/) ·
[Big Sleep — The Record](https://therecord.media/google-big-sleep-ai-tool-found-bug) ·
[Aardvark — OpenAI](https://openai.com/index/introducing-aardvark/) ·
[Aardvark — The Hacker News](https://thehackernews.com/2025/10/openai-unveils-aardvark-gpt-5-agent.html)。

**重點結論：** 開源攻擊性 agent 領域龐大、資金充裕，且正競相奔向*完全自主的漏洞利用*
（Strix 26k★、CAI 9.2k★、PentAGI 14.7k★）— 再加上前沿實驗室（Google、OpenAI、XBOW）
掌握著真實 0-day 的前線。**phantom-secops 無法也不該在此競爭** —
它已明確將自己劃出可執行 exploit 之外。那是一項特性，而非缺陷（見 §3）。

### 2.2 用於漏洞偵測 / 程式碼掃描的 AI（LLM-SAST、fuzzing）

| 專案 | 它是什麼 | URL | 成熟度 / 星數 | 語言 | 授權 |
|---|---|---|---|---|---|
| **Vulnhuntr** — Protect AI | LLM + 靜態分析，追蹤完整呼叫鏈（input→sink）；7 種漏洞類別；發現過真實 0-day（ComfyUI、Ragflow）。 | https://github.com/protectai/vulnhuntr | ~2.7k★，利基/活躍；僅 Python | Python | **AGPL-3.0** |
| **xvulnhuntr** — Compass Security | Vulnhuntr 構想的 zero-shot 漏洞發掘分支/變體。 | https://github.com/CompassSecurity/xvulnhuntr | 較小 | Python | （依 repo） |
| **Semgrep + Assistant** | 開源 SAST 引擎 + AI 層，用於自動分流 / 修補建議 / 雜訊過濾。 | https://github.com/semgrep/semgrep | 非常成熟；Assistant 為 SaaS | OCaml/Python | LGPL-2.1（引擎） |
| **Corgea** | AI 原生 AppSec（掃描+分流+修補）；提供一個 **Agent Skill**，讓 Claude Code/Cursor 可掃描/分流/修補。 | https://corgea.com | 商業；CLI 公開 | — | proprietary |
| **Socket** | 供應鏈/SCA + 針對惡意程式、安裝腳本、typosquat 的 AI 偵測；GitHub App。 | https://github.com/SocketDev/socket-basics | 成熟；GitHub 整合 | — | （依 repo） |
| **OSS-Fuzz-Gen**（Google） | 在 OSS-Fuzz 之上以 LLM 生成 fuzz driver；發現 26+ 個新漏洞；正朝自主回報邁進。 | https://github.com/google/oss-fuzz | 正式生產研究 | C++/Python | Apache-2.0 |

來源：[Vulnhuntr repo](https://github.com/protectai/vulnhuntr) ·
[Semgrep repo](https://github.com/semgrep/semgrep) ·
[Semgrep Assistant](https://semgrep.dev/products/semgrep-code/assistant/) ·
[Corgea CLI docs](https://docs.corgea.app/cli) ·
[Socket basics](https://github.com/SocketDev/socket-basics) ·
[OSS-Fuzz + AI — Infosecurity](https://www.infosecurity-magazine.com/news/google-oss-fuzz-ai-expose-26/)。

**重點結論：** 在正式生產中*奏效*的反覆出現模式，是**在確定性引擎之上以 AI 作為分流/解釋者**
（Semgrep Assistant 97% 分流一致率 `[UNVERIFIED %]`、Corgea、Socket）。這正是 phantom-secops
自身的論點，也是其 `posture_fusion` + LLM 報告設計 — 它站在此趨勢的正確一側，而非
自主發掘那一側。

### 2.3 AI + 傳統資安工具編排（MCP 原生）

| 專案 | 它是什麼 | URL | 成熟度 / 星數 | 語言 | 授權 |
|---|---|---|---|---|---|
| **mcp-for-security** — cyproxio | 26 個資安工具（Nmap、Nuclei、SQLmap、FFUF、Masscan、MobSF、WPScan…）作為 MCP server。 | https://github.com/cyproxio/mcp-for-security | ~619★，**已於 2026-03-30 封存**（後繼者：「Bolt」） | TypeScript | MIT |
| **mcp-security-hub** — FuzzingLabs | 將攻擊性工具（Nmap、Ghidra、Nuclei、SQLMap、Hashcat）作為 MCP server 供 AI 助手使用。 | https://github.com/FuzzingLabs/mcp-security-hub | 活躍 | （混合） | （依 repo） |
| **Nuclei-MCP**（社群） | 多種將 Nuclei 暴露為 MCP 的包裝（`addcontent/nuclei-mcp`、`crazyMarky/mcp_nuclei_server`）。 | （多個） | 小型/分散 | TS/Python | （不一） |
| **awesome-mcp-security** — Puliczek | 精選彙整的 MCP 資安工具索引**以及** MCP 協定的資安風險。 | https://github.com/Puliczek/awesome-mcp-security | 精選清單 | — | （清單） |
| **Agentic SOC / 告警分流**（如「AI-SOC-Agent」，Black Hat 2025） | 暴露調查工具（ELK、IRIS）的 MCP server；約 $0.18/告警、約 50s/次調查。 | （研討會/示範） | 示範級 `[UNVERIFIED]` | — | — |

來源：[mcp-for-security repo](https://github.com/cyproxio/mcp-for-security) ·
[mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub) ·
[awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security) ·
[Top MCP servers for cybersecurity 2026 — Levo](https://www.levo.ai/resources/blogs/top-mcp-servers-for-cybersecurity-2026)。

**重點結論：** 此領域正收斂於**將 MCP 作為資安工具整合基底** —
正是 phantom-secops 的架構。但既有的 MCP 套件幾乎全都是
**攻擊性且未受治理**（將原始的 Nmap/SQLMap/Hashcat 暴露給一個沒有政策模型的 agent）。
其中領先者已*封存*。**缺口在於治理 + 一個能力/政策模型 +
基於 MCP 的唯讀立場** — 這恰恰是 phantom-secops 的 `x-phantom` 中繼資料構想，
以及 phantom-mesh 的治理器/手機核可平面。

### 2.4 LLM 紅隊演練 / 模型安全（與注入偵測器相鄰）

| 專案 | 它是什麼 | URL | 星數 | 語言 | 授權 |
|---|---|---|---|---|---|
| **garak**（NVIDIA） | LLM 漏洞掃描器；120+ 個探針（prompt injection、jailbreak、洩漏）。 | https://github.com/NVIDIA/garak | 成熟 | Python | Apache-2.0 |
| **PyRIT**（Microsoft） | 用於多輪對抗式攻擊編排的 Python 框架。 | https://github.com/Azure/PyRIT | 成熟 | Python | MIT |
| **promptfoo** | 評估 + 紅隊演練工具（prompt-injection/jailbreak/data-leak）。OpenAI 於 2026 年 3 月收購，維持 MIT。 | https://github.com/promptfoo/promptfoo | 非常受歡迎 | TypeScript | MIT |
| **DeepTeam**（Confident AI） | 用於 LLM 應用的紅隊框架（涵蓋 agentic/RAG）。 | https://github.com/confident-ai/deepteam | 成長中 | Python | Apache-2.0 |

來源：[How to red-team an LLM — bestaiweb](https://www.bestaiweb.ai/how-to-red-team-an-llm-with-promptfoo-pyrit-and-garak-in-2026/) ·
[PyRIT/Garak guide — aminrj](https://aminrj.com/posts/attack-patterns-red-teaming/)。

**重點結論：** phantom-secops 已有一個**注入偵測器**；這些是標準參考。
別重造它們 — 而是*包裝/引用*（例如在注入偵測器的規則中引用 garak/PyRIT 的分類體系，
或提供一個選用的 `promptfoo`/`garak` 驅動檢查），而非重新發明探針庫。

### 2.5 防禦性 / 藍隊 agent（態勢、日誌分流、偵測工程）

開源藍隊 agent 的領域比攻擊側**明顯稀薄**。最成熟的藍隊自動化要嘛是傳統非 AI
（Sigma、Wazuh、Elastic 偵測規則、OSSEC），要嘛是商業「agentic SOC」
（Dropzone、Prophet、廠商 SOAR copilot）。開放、可自架、*agentic* 的藍隊工具大多為
示範級（例如 Black Hat 2025 的 AI-SOC-Agent MCP server；像 `NousResearch/hermes-agent`
這類 agent 框架中的 SIEM 分流技能問題）。CAI 是少數明確宣稱在攻擊性之外亦具
**防禦**模式的開源框架之一。

來源：[scadastrangelove/awesome-ai-security-tools](https://github.com/scadastrangelove/awesome-ai-security-tools)
（SOC/SIEM-triage 類別） · [CAI repo](https://github.com/aliasrobotics/CAI)。

**重點結論：** **這就是那條開放的賽道。** phantom-secops 的藍隊支柱 —
作用於事件日誌的 Sigma IDS、log-anomaly、確定性的 posture-fusion、MTTD、白話且
已排序的優先報告 — 處在一個比攻擊性 agent 淘金熱*更不擁擠、更具防禦性*的利基。

---

## 3. phantom-secops 的建議設計方向

**論點（一句話）：** *成為**受治理、可稽核、MCP 原生的編排 + 分流 +
LLM-judge 層，疊加於標準資安工具之上** — 一個防禦/教育用途的「大腦」，**而非**
另一個自主漏洞利用者。* 順勢*切入*眾人正在忽略的藍隊 + 端點衛生賽道，
並讓**治理**（phantom-mesh 治理器 + 手機核可 + `x-phantom` 能力政策）成為
那些攻擊性 MCP 套件全都欠缺的差異化關鍵。

### 那 3–6 個要點

- **維持唯讀且純文字；把它當成行銷的強項，而非道歉。** 每個主要的開源競爭者
  （Strix、CAI、PentAGI）都在競相奔向*可執行的漏洞利用*。耐久的利基恰恰相反：
  一個個人開發者 / 小團隊能在自己**自有的**機器與實驗室上執行、且零 CFAA/授權風險的
  工具。將 `has_runnable_poc == false` 維持為一項不變量，並以一個斷言它的測試守護。
- **成為那些攻擊性套件所欠缺的*受治理* MCP 編排層。** 領先的通用資安 MCP 套件
  （`cyproxio/mcp-for-security`）已**封存**，且在**沒有政策模型**下暴露原始攻擊性工具。
  phantom-secops 的 `x-phantom` 能力/分類/唯讀中繼資料 + 一個 phantom-mesh 政策執行器 +
  治理器/手機核可平面，是一個真正具差異化的組合。交付跨 repo 的
  `x-phantom` 執行器（目前在 ROADMAP 中為*規劃中*）— 它就是護城河。
- **加碼藍隊/防禦 + 端點衛生賽道（那條開放賽道）。** 開源*攻擊性* agent 已飽和；
  開源*agentic 藍隊 / 態勢 / 日誌分流*很稀薄。投資於 `posture_fusion`、Sigma IDS、
  log-anomaly→triage→correlate，以及每日自檢報告。要當「可稽核的本機資安 copilot」，
  而非「自主的滲透測試者」。
- **讓 LLM 當解釋者/評審/分流者，絕不當漏洞利用者。** 仿效正式生產中真正奏效的做法
  （Semgrep Assistant、Corgea、Socket）：確定性引擎找出事實；LLM 進行
  **分流、排序、解釋、去重與排定優先序** — 並理想地作為一個
  **針對發現的 LLM-judge**（信心度 + 假陽性過濾），這正是本 repo
  「以低假陽性優先於覆蓋率」的決策所看重的。維持不含 LLM 的
  `posture_fusion` 確定性核心，作為可信任的脊柱。
- **包裝、引用並標註標準工具 — 別重新實作引擎。** 這已是本 repo 陳明的哲學；
  維持它。將 Trivy/Nmap/Nuclei/Sigma 當引擎；為注入偵測器引用 garak/PyRIT 分類體系；
  將 OSS-Fuzz/Vulnhuntr/Big Sleep 視為你會解釋、而非與之競爭的*超出範圍的前沿*。
- **在增添範圍之前，補上 live 模式的誠實缺口（G2）。** 近期最攸關可信度的單一行動，
  是針對 Docker 實驗室端到端驗證實際的 `nmap`/`nuclei` 路徑，使專案的招牌示範是真實的、
  而不僅是 mock。深度先於廣度。

### 該採用 / 原樣包裝 vs 引用 vs 自建

| 決策 | 項目 |
|---|---|
| **作為引擎包裝（已有／持續）** | Trivy（CVE）、Nmap、Nuclei、Sigma（偵測規則）。可選擇將 garak/promptfoo/PyRIT 作為注入偵測器賽道的*選用* LLM 紅隊檢查。 |
| **引用 / 標註（別自建）** | Vulnhuntr / Big Sleep / Aardvark / OSS-Fuzz-Gen（前沿 0-day 發掘 — 明確超出範圍）；Semgrep Assistant 與 Corgea 作為驗證此設計的「AI 分流疊加於引擎之上」前例。 |
| **自建（差異化的部分）** | (1) phantom-mesh 中跨 repo 的 `x-phantom` 政策執行器；(2) 針對發現的 LLM-judge / 信心度 + FP-filter 層；(3) 確定性 posture-fusion 的深度；(4) **在治理器 + 手機核可之下**執行（而非自由放任）的受治理 agent 迴圈（Pillar 1 L2）。 |
| **不要自建** | 任何可執行的 PoC/exploit、自主外部掃描、自動修復、一個通用的「自主滲透測試者」，或一個重新實作的掃描器引擎。 |

### 務實的分階段路徑

1. **Phase 0 — 可信度（現在）。** 補上 G2：針對 Docker 實驗室端到端驗證實際的
   `nmap`+`nuclei`；在測試中斷言 `has_runnable_poc == false` 不變量。*不增添新範圍。*
2. **Phase 1 — 受治理的 agent 迴圈（Pillar 1 L2）。** 透過 phantom-mesh agent 迴圈
   驅動紅/藍 kill-chain，**由治理器 + 手機核可包裝**，並以 `x-phantom`
   對藍隊 agent 執行紅隊工具拒絕。這是別人都沒有的示範：
   *會徵求許可的 agentic 資安。*
3. **Phase 2 — LLM-judge / 分流層。** 在融合後的發現之上增添一個信心度 + 假陽性過濾的評審
   （Semgrep-Assistant 模式），底層維持 `posture_fusion` 為確定性。可選擇加上 HTML 報告 +
   時間軸視覺化。
4. **Phase 3 — 跨 repo 政策執行器 + 注入偵測器分類體系。** 在 phantom-mesh 的
   `mcp_client.rs` 中落地 `x-phantom` Rust 執行器；將注入偵測器與
   garak/PyRIT 類別對齊。這部分能把 phantom-secops 從一個示範轉變為一個
   可重用的、適用於任何 MCP 資安工具的*治理模式*。

---

## 4. 誠實的警告 — 過度建構、倫理、安全

- **別在競爭壓力下漂移向自主性。** 此領域的引力是「讓它自主、讓它去利用漏洞」。
  每一步往那走都會*抹除* phantom-secops 的利基，並*增添*法律/責任面。
  唯讀/純文字/僅限自身或實驗室這條線就是產品本身，而非限制。
  把任何增添可執行 PoC、外部掃描或自動修復的 PR，依章程視為超出範圍。
- **MCP 本身就是一個攻擊面。** 讓此設計優雅的同一個 MCP 基底，也是一個有文獻記載的風險類別
  （見 [awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security)）：
  工具投毒、過於寬泛的能力、注入工具呼叫的 prompt injection。`x-phantom`
  能力模型 + 治理器必須被執行，而非僅供參考 — 一個能被誘騙去呼叫不該呼叫的紅隊工具的
  agent，正是此處務實的失效模式。
- **AGPL 污染風險。** Vulnhuntr 是 **AGPL-3.0**；本 repo 是 Apache-2.0。引用它，
  但不要 vendor/衍生自 AGPL 程式碼，否則授權立場就破功。
- **「自主發現 0-day」的頭條是前沿實驗室 / 重度算力的成果**
  （Big Sleep、OSS-Fuzz-Gen、XBOW）— 並非一個個人 Apache 專案該設為目標的標準。
  在 README/ROADMAP 中誠實設定預期（本 repo 已做得很好；維持下去）。
- **MTTD 與示範數字在 mock 模式下必須維持標註為「simulated」** — 已完成；這份誠實
  是相對於市場上過度宣稱那一端的可信度護城河的一部分。
- **星數 / 基準宣稱變動很快。** 本文件中的計數是時間點快照（2026-06）；
  少數 `[UNVERIFIED]` 的百分比/數字（PentAGI 星數、Semgrep 97% 分流、
  AI-SOC $0.18/告警）來自次級來源 — 在對外引用前請先驗證。

---

### 附錄 — 最值得追蹤的 4–6 個最相關專案

1. **CAI** — https://github.com/aliasrobotics/CAI — 同時具*攻擊與防禦*模式 + HITL 的
   agentic 資安框架的開源參考標竿；哲學上最相近的鄰居
   （但它會執行；phantom-secops 刻意不執行）。
2. **Strix** — https://github.com/usestrix/strix — 帶有真實 PoC 的開源*自主*滲透測試的標竿；
   是 phantom-secops 明確**不是**的那種東西，也是定位上最佳的對照。
3. **cyproxio/mcp-for-security** — https://github.com/cyproxio/mcp-for-security —
   那個（現已封存的）通用資安 MCP 套件；證明了此基底，並暴露了 phantom-secops
   所填補的治理缺口。
4. **Semgrep + Assistant** — https://github.com/semgrep/semgrep /
   https://semgrep.dev/products/semgrep-code/assistant/ — 經正式生產驗證的
   「確定性引擎 + AI 分流」模式，phantom-secops 應仿效。
5. **Vulnhuntr** — https://github.com/protectai/vulnhuntr — 可信的開源 LLM-SAST
   參考（AGPL — 僅供參考，別 vendor）。
6. **garak / PyRIT** — https://github.com/NVIDIA/garak / https://github.com/Azure/PyRIT —
   注入偵測器賽道的標準 LLM 紅隊參考。
