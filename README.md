```
██████╗ ██╗   ██╗███████╗██╗
██╔══██╗██║   ██║██╔════╝██║
██║  ██║██║   ██║█████╗  ██║
██║  ██║██║   ██║██╔══╝  ██║
██████╔╝╚██████╔╝███████╗███████╗
╚═════╝  ╚═════╝ ╚══════╝╚══════╝
```

**Dual Unsupervised Evasion Loop** — an adversarial LLM security research framework where an Attacker and a Defender battle across 38 MITRE ATT&CK and OWASP LLM techniques, generating real Microsoft Sentinel telemetry and KQL detection rules.

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square)
![Ollama](https://img.shields.io/badge/LLM-Ollama-black?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![OWASP LLM](https://img.shields.io/badge/OWASP-LLM%20Top%2010-orange?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-Server-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-grey?style=flat-square)

---

![DUEL in action](demo.gif)

---

## What is DUEL

DUEL is a fully local, offline adversarial security research framework. Two LLM agents — an **Attacker** and a **Defender** — battle across multiple rounds using real Microsoft Sentinel schemas. The Attacker (llama3.1:8b) generates synthetic telemetry that mimics documented MITRE ATT&CK techniques against cloud infrastructure. The Defender (mistral:7b) writes KQL detection rules. A deterministic detection engine scores every round, and the Attacker mutates its telemetry each round based on what got caught.

The framework covers **38 techniques**: 28 MITRE ATT&CK cloud/identity techniques spanning all major Microsoft Sentinel tables (`SigninLogs`, `AuditLogs`, `AzureActivity`, `OfficeActivity`) and the full **OWASP LLM Top 10 2025** for AI/LLM-specific attack simulation. The Attacker carries **persistent memory** across sessions — evasion patterns, dangerous field values, and stable mutation strategies accumulate in `output/attacker_memory.json` and feed every subsequent battle.

DUEL ships with a full-featured **web UI** (6 dashboards), a **MCP Server** that exposes all capabilities as tools for Claude Desktop and Cursor, **autonomous red team mode** where an LLM chooses the attack sequence, **tournament mode** for ranking Ollama models, **campaign mode** for multi-stage kill chains, **PDF report generation**, and one-click **Microsoft Sentinel ARM template export**. Zero external API calls — everything runs on Ollama.

---

## Features

| Capability | Details |
|---|---|
| ⚔ **War Room** | Live battle dashboard — run duels, watch round-by-round telemetry and KQL updates in real time |
| ◈ **Heatmap** | MITRE ATT&CK coverage matrix — evasion rates per technique and tactic |
| ⚡ **Tournament** | Pit multiple Defender models against the same Attacker — automatic ranking table |
| ⛓ **Campaign** | Multi-stage kill chains with attacker context carry-forward between techniques |
| ⬇ **Export** | One-click Microsoft Sentinel ARM template export from surviving KQL rules |
| ★ **Autonomous** | LLM-driven red team — objective-based attack sequencing with no human prompts |
| ⚡ **MCP Server** | 8 tools exposing DUEL to Claude Desktop, Cursor, and any MCP-compatible agent |
| 🔍 **KQL Engine** | Pandas-backed KQL executor: `where`, `project`, `summarize`, `join`, `let`, `make-series`, `mv-expand`, `parse`, `arg_max` |
| 🧠 **Attacker Memory** | Persistent evasion patterns across all battles — attacker starts each run already knowing what worked |
| 🌐 **Threat Intel** | Feodo Tracker integration — Defender optionally enriches rules with live C2 IP data |
| 📄 **PDF Reports** | Auto-generated per-battle PDF with mutation analysis, field stability charts, and surviving KQL |
| 🤖 **GitHub Actions** | Weekly automated battle run against all 38 techniques — results pushed back to the repo |

---

## Architecture

```mermaid
flowchart TD
    subgraph SRC["Inputs"]
        TL["📁 TECHNIQUE LIBRARY<br/>techniques/*.json<br/>techniques/llm/*.json<br/>28 MITRE + 10 OWASP LLM"]
        MEM["🧠 ATTACKER MEMORY<br/>attacker_memory.json<br/>evasion patterns, dangerous fields,<br/>stable mutation strategies"]
        TI["🌐 THREAT INTEL<br/>Feodo Tracker<br/>live C2 IPs and domains"]
    end

    subgraph LOOP["Adversarial Loop"]
        ATT["⚔ ATTACKER AGENT<br/>llama3.1:8b<br/>Round 1 — generate synthetic telemetry<br/>Round N — mutate based on detected fields"]
        DEF["🛡 DEFENDER AGENT<br/>mistral:7b<br/>Round 1 — write KQL detection rule<br/>Round N — harden against evaded logs"]
        KQL["🔍 DETECTION ENGINE<br/>KQL to pandas<br/>where, project, summarize, join<br/>let, make-series, mv-expand, parse"]
        SCR["📊 SCORING ENGINE<br/>detected_count points to Defender<br/>evaded_count points to Attacker"]
    end

    subgraph OUT["Output Artifacts"]
        LOGS["📋 BATTLE LOGS<br/>full_battle_log_*.json<br/>battle_analysis.md<br/>duel_report_*.pdf"]
        ARM["📐 SENTINEL EXPORT<br/>sentinel_export.json<br/>ARM template — direct Sentinel deployment"]
    end

    subgraph WEB["Web Interfaces — FastAPI — server.py"]
        WR["⚔ War Room"]
        HM["◈ Heatmap"]
        TRN["⚡ Tournament"]
        CMP["⛓ Campaign"]
        EXP["⬇ Export"]
        AUT["★ Autonomous"]
    end

    subgraph MCP["MCP Server — mcp_server.py"]
        MCPS["8 tools<br/>run_battle, generate_kql<br/>plan_campaign, export_sentinel<br/>get_memory, list_techniques"]
        CD["Claude Desktop"]
        CUR["Cursor"]
    end

    GHA["🤖 GITHUB ACTIONS<br/>Weekly — every Monday<br/>run_all.py across all 38 techniques"]

    TL -->|technique definition| ATT
    MEM -->|evasion patterns + dangerous fields| ATT
    TI -->|C2 IOC blocklist| DEF
    ATT -->|"attack_logs — synthetic telemetry"| DEF
    ATT -->|attack_logs| KQL
    DEF -->|kql_rule| KQL
    KQL -->|detected_ids and evaded_ids| SCR
    SCR -.->|"detected fields → mutate strategy"| ATT
    SCR -.->|"evaded logs → harden rule"| DEF
    SCR -->|persist evasion intel| MEM
    SCR --> LOGS
    SCR --> ARM
    LOGS --> WEB
    LOGS --> MCPS
    ARM --> EXP
    ARM --> MCPS
    MCPS --> CD
    MCPS --> CUR
    GHA -->|weekly trigger| ATT

    style ATT  fill:#2d0a0a,stroke:#ff3c3c,color:#ff9090
    style MEM  fill:#2d0a0a,stroke:#ff3c3c,color:#ff9090
    style DEF  fill:#050f2d,stroke:#3c8eff,color:#90bcff
    style TI   fill:#050f2d,stroke:#3c8eff,color:#90bcff
    style KQL  fill:#071a07,stroke:#2ea82e,color:#80d080
    style SCR  fill:#071a07,stroke:#2ea82e,color:#80d080
    style LOGS fill:#071a07,stroke:#00cc66,color:#00ff88
    style ARM  fill:#071a07,stroke:#00cc66,color:#00ff88
    style TL   fill:#1a1000,stroke:#cc8800,color:#ffb830
    style GHA  fill:#1a1000,stroke:#cc8800,color:#ffb830
    style WR   fill:#1a1a00,stroke:#ccaa00,color:#ffd700
    style HM   fill:#1a1a00,stroke:#ccaa00,color:#ffd700
    style TRN  fill:#1a1a00,stroke:#ccaa00,color:#ffd700
    style CMP  fill:#1a1a00,stroke:#ccaa00,color:#ffd700
    style EXP  fill:#1a1a00,stroke:#ccaa00,color:#ffd700
    style AUT  fill:#1a1a00,stroke:#ccaa00,color:#ffd700
    style MCPS fill:#14002d,stroke:#a855f7,color:#c084fc
    style CD   fill:#14002d,stroke:#a855f7,color:#c084fc
    style CUR  fill:#14002d,stroke:#a855f7,color:#c084fc

    style SRC  fill:#111005,stroke:#cc8800
    style LOOP fill:#1a0505,stroke:#ff3c3c
    style OUT  fill:#051a08,stroke:#00cc66
    style WEB  fill:#1a1a00,stroke:#ccaa00
    style MCP  fill:#0d0019,stroke:#a855f7
```

---

## Quick Start

**Prerequisites:** [Ollama](https://ollama.ai) installed and running locally.

```bash
# 1. Pull the models
ollama pull llama3.1:8b
ollama pull mistral:7b

# 2. Clone and install
git clone https://github.com/0xDanielSec/duel-framework.git
cd duel-framework
pip install -r requirements.txt

# 3. Run your first battle (CLI)
python main.py --technique T1078.004 --rounds 5 --verbose

# 4. Or open the full web UI
python server.py
# → http://localhost:8000

# 5. Or connect via MCP (Claude Desktop / Cursor)
python mcp_server.py
```

---

## Web Interfaces

Start with `python server.py` → `http://localhost:8000`

| Route | Page | What it does |
|---|---|---|
| `/` | **War Room** | Select technique, configure rounds/logs/models, run battle live, watch telemetry and KQL update each round with real-time scoreboard |
| `/heatmap` | **Heatmap** | MITRE ATT&CK coverage matrix — colour-coded by evasion rate, shows which techniques are tested and which are gaps |
| `/tournament` | **Tournament** | Run multiple Defender models against the same Attacker; auto-ranks by detection rate in a bracket table |
| `/campaign` | **Campaign** | Run multi-technique kill chains (e.g. Cloud Takeover: T1078 → T1528 → T1098 → T1114) with attacker context carried between stages |
| `/export` | **Sentinel Export** | Browse all surviving KQL rules, filter by severity, download as a production ARM template ready for deployment |
| `/autonomous` | **Autonomous** | Objective-based autonomous red team — LLM selects and chains techniques toward a goal (persistence, exfiltration, credential-access, full-compromise) |
| `/mcp` | **MCP** | Tool reference, connect instructions for Claude Desktop/Cursor, live MCP server log viewer |

---

## MCP Server

DUEL exposes all capabilities as an [MCP](https://modelcontextprotocol.io) server. Any MCP-compatible agent — Claude Desktop, Cursor, or custom — can run battles, generate KQL, plan campaigns, and export Sentinel rules through natural language.

```bash
pip install mcp
python mcp_server.py   # starts on stdio transport
```

### Connect to Claude Desktop

Edit `claude_desktop_config.json`:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "duel": {
      "command": "python",
      "args": ["C:/path/to/duel-framework/mcp_server.py"]
    }
  }
}
```

### Connect to Cursor

Add to `.cursor/mcp.json` in your project root, or via Settings → MCP:

```json
{
  "mcpServers": {
    "duel": {
      "command": "python",
      "args": ["C:/path/to/duel-framework/mcp_server.py"]
    }
  }
}
```

### Available Tools

| Tool | Description |
|---|---|
| `run_battle(technique_id, rounds, logs_per_round)` | Run a full adversarial duel, return structured results |
| `get_coverage()` | Return heatmap data: evasion rates per technique and tactic |
| `generate_kql(technique_id)` | Return the highest-detection-rate KQL rule for a technique |
| `plan_campaign(objective)` | Plan a kill chain from a named campaign or free-text objective |
| `get_attacker_memory(technique_id)` | Return evasion patterns and dangerous fields the Attacker has learned |
| `export_sentinel(severity)` | Return an ARM template with KQL rules filtered by severity |
| `get_battle_analysis(technique_id)` | Return full battle analysis: mutation patterns, detection gaps, KQL evolution |
| `list_techniques()` | Return all 38 techniques with metadata and battle-tested status |

### Example Prompts

```
List all DUEL techniques grouped by MITRE tactic and flag which haven't been tested.

Run a battle for T1078.004 with 5 rounds and explain the evasion strategy the Attacker used.

Get the best KQL rule for password spraying (T1110.003) and explain each clause.

Plan a cloud account takeover kill chain and show me the MCP call sequence to test it.

What fields has the DUEL attacker learned are dangerous for T1556.006?

Export all High severity Sentinel rules and show the az deployment command.

Run battles for T1110.003, T1528, and T1606.002, then compare their evasion rates.
```

---

## Techniques

### MITRE ATT&CK — 28 Techniques

| ID | Name | Primary Tactic | Sentinel Table |
|---|---|---|---|
| T1018 | Remote System Discovery | Discovery | AzureActivity |
| T1040 | Network Sniffing | Credential Access | AzureActivity |
| T1069.003 | Permission Groups Discovery: Cloud Groups | Discovery | AuditLogs |
| T1078.001 | Valid Accounts: Default Accounts | Defense Evasion | SigninLogs |
| T1078.004 | Valid Accounts: Cloud Accounts | Defense Evasion | SigninLogs |
| T1087.004 | Account Discovery: Cloud Account | Discovery | AuditLogs |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence | AuditLogs |
| T1110.003 | Brute Force: Password Spraying | Credential Access | SigninLogs |
| T1114.002 | Email Collection: Remote Email Collection | Collection | OfficeActivity |
| T1133 | External Remote Services | Initial Access | SigninLogs |
| T1136.003 | Create Account: Cloud Account | Persistence | AuditLogs |
| T1190 | Exploit Public-Facing Application | Initial Access | AzureActivity |
| T1199 | Trusted Relationship | Initial Access | AuditLogs |
| T1485 | Data Destruction | Impact | AzureActivity |
| T1486 | Data Encrypted for Impact | Impact | AzureActivity |
| T1526 | Cloud Service Discovery | Discovery | AuditLogs |
| T1528 | Steal Application Access Token | Credential Access | SigninLogs |
| T1530 | Data from Cloud Storage | Collection | AzureActivity |
| T1537 | Transfer Data to Cloud Account | Exfiltration | AzureActivity |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Defense Evasion | AuditLogs |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | Credential Access | SigninLogs |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | AuditLogs |
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access | OfficeActivity |
| T1566.002 | Phishing: Spearphishing Link | Initial Access | OfficeActivity |
| T1567.002 | Exfiltration Over Web Service: To Cloud Storage | Exfiltration | AzureActivity |
| T1606.002 | Forge Web Credentials: SAML Tokens | Credential Access | AuditLogs |
| T1621 | Multi-Factor Authentication Request Generation | Credential Access | SigninLogs |
| T1648 | Serverless Execution | Execution | AzureActivity |

### OWASP LLM Top 10 2025 — 10 Techniques

| ID | Name | Attack Vector |
|---|---|---|
| LLM01 | Prompt Injection | Malicious prompt payloads hijacking LLM behaviour |
| LLM02 | Insecure Output Handling | Unvalidated LLM output used downstream |
| LLM03 | Training Data Poisoning | Corrupted training/fine-tuning data |
| LLM04 | Model Denial of Service | Resource exhaustion via adversarial inputs |
| LLM05 | Supply Chain Vulnerabilities | Compromised models, datasets, or plugins |
| LLM06 | Sensitive Information Disclosure | LLM leaking PII, credentials, or system prompts |
| LLM07 | Insecure Plugin Design | Unsafe tool/plugin interfaces |
| LLM08 | Excessive Agency | LLM with overly broad permissions performing unintended actions |
| LLM09 | Overreliance | Trust in LLM output without verification |
| LLM10 | Model Theft | Extraction of model weights or behaviour via query |

> **Adding new techniques:** Drop a JSON file following the existing schema into `techniques/` (MITRE) or `techniques/llm/` (OWASP LLM). No code changes required.

---

## How it Works

### Attacker Agent (`agents/attacker.py`)

The Attacker uses `llama3.1:8b` at temperature 0.85. On round 1 it reads the technique JSON — IOCs, evasion variants, platform details — and generates `N` synthetic log entries conforming to the target Sentinel table schema. Each log is stamped with a `_duel_id` UUID for tracing.

From round 2 onwards the Attacker is shown the Defender's KQL rule and the logs that were detected. It explicitly reasons about which fields triggered detection and mutates: rotating IP addresses, changing user agents, splitting spray patterns, adding noise fields, or mimicking legitimate baseline behaviour. It also loads its **persistent memory** (`AttackerMemory`) — stable evasion patterns and dangerous field values accumulated across all previous battles against this technique.

### Defender Agent (`agents/defender.py`)

The Defender uses `mistral:7b` at temperature 0.4 for deterministic KQL output. It is constrained to use only tables present in the attack logs and forbidden from using constructs the KQL engine does not support. From round 2 it sees the evaded logs and explicitly hardens the rule: broadening IP ranges, adding field-level anomaly detection, or shifting to behavioural rather than value-based matching. Optional **Feodo Tracker** threat intel can enrich rules with live C2 IP blocklists.

### KQL Detection Engine (`engine/detection.py`)

A pandas-backed KQL interpreter. Attack logs are loaded into per-table DataFrames matching real Sentinel schemas. The engine executes a full KQL pipeline stage by stage, returning the set of `_duel_id` values that matched.

**Supported operators:**

| Operator | Notes |
|---|---|
| `where` | `==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `has`, `has_any`, `startswith`, `endswith`, `in`, `!in`, `in~`, `matches regex`, `isempty`, `isnotempty`, `isnull`, `isnotnull`, `and`/`or`/`not` |
| `project` / `project-away` | Column selection and removal |
| `summarize` | `count()`, `dcount()`, `make_list()`, `make_set()`, `arg_max()`, `arg_min()` with and without `by` |
| `extend` | Column assignment |
| `top N by` | Sort + head |
| `limit` / `take` | Row cap |
| `order by` / `sort by` | Ascending/descending |
| `distinct` | Deduplication |
| `let` | Scalar numbers, strings, `dynamic([...])` lists — substituted before execution |
| `join` | `inner`, `leftouter`, `rightouter`, `fullouter`, `leftanti`, `rightanti`; `$left.col == $right.col` syntax |
| `make-series count() on T step Xh by col` | Maps to pandas resample; units s/m/h/d |
| `mv-expand` | Explodes list-valued columns into rows |
| `parse col with * "lit" name:type *` | Regex-based named field extraction |

### Scoring

Each round: `detected_count` points to the Defender, `evaded_count` points to the Attacker. Detection and evasion rates are tracked per round and cumulatively. After all rounds the `BattleAnalyst` derives mutation patterns, identifies stable vs rotating field values, detects defender blind spots, and writes `battle_analysis.md`.

---

## CLI Reference

### `main.py` — single technique battle

```bash
python main.py [OPTIONS]

Options:
  --technique TEXT        MITRE or OWASP LLM technique ID  [default: T1078.004]
  --rounds INT            Number of adversarial rounds      [default: 5]
  --attacker-model TEXT   Ollama model for Attacker         [default: llama3.1:8b]
  --defender-model TEXT   Ollama model for Defender         [default: mistral:7b]
  --logs INT              Attack logs per round             [default: 10]
  --verbose               Print telemetry and KQL each round
```

```bash
python main.py --technique T1110.003 --rounds 10 --logs 15 --verbose
python main.py --technique LLM01 --attacker-model llama3.1:8b
```

### `tournament.py` — multi-model Defender ranking

```bash
python tournament.py [OPTIONS]

Options:
  --technique TEXT        MITRE technique ID                [default: T1078.004]
  --rounds INT            Rounds per Defender               [default: 3]
  --attacker-model TEXT   Ollama model for Attacker         [default: llama3.1:8b]
  --defenders TEXT        Comma-separated Defender models   [required]
  --logs INT              Attack logs per round             [default: 10]
```

```bash
python tournament.py --technique T1078.004 --rounds 5 \
    --defenders "mistral:7b,llama3.1:8b,qwen2.5:7b"
```

### `campaign.py` — multi-technique kill chain

```bash
python campaign.py [OPTIONS]

Options:
  --campaign TEXT         Campaign name (cloud-takeover, identity-attack) [required]
  --rounds INT            Rounds per stage                  [default: 3]
  --logs INT              Attack logs per round             [default: 10]
  --attacker-model TEXT                                     [default: llama3.1:8b]
  --defender-model TEXT                                     [default: mistral:7b]
  --verbose
```

```bash
python campaign.py --campaign cloud-takeover --rounds 5 --verbose
python campaign.py --campaign identity-attack --rounds 3 --logs 12
```

**Campaigns:**
- `cloud-takeover` — T1078.004 → T1528 → T1098.001 → T1114.002
- `identity-attack` — T1110.003 → T1556.006 → T1136.003 → T1069.003

### `autonomous.py` — LLM-driven red team

```bash
python autonomous.py [OPTIONS]

Options:
  --objective TEXT        Attack objective [required]
                          choices: persistence | exfiltration |
                                   credential-access | full-compromise
  --max-techniques INT    Max techniques to chain           [default: 4]
  --auto                  Fully autonomous — no prompts between stages
  --attacker-model TEXT                                     [default: llama3.1:8b]
  --defender-model TEXT                                     [default: mistral:7b]
  --logs INT                                                [default: 10]
  --verbose
```

```bash
python autonomous.py --objective full-compromise --max-techniques 6 --auto
python autonomous.py --objective exfiltration --verbose
```

### `run_all.py` — batch coverage runner

```bash
python run_all.py [OPTIONS]

Options:
  --list                  Print coverage status and exit
  --force                 Re-run techniques that already have battle logs
  --rounds INT                                              [default: 5]
  --logs INT                                                [default: 10]
  --attacker-model TEXT
  --defender-model TEXT
  --verbose
```

```bash
python run_all.py --list              # show coverage gaps
python run_all.py                     # run only missing techniques
python run_all.py --force --rounds 3  # re-run everything
```

### `server.py` — web UI

```bash
python server.py        # http://localhost:8000
```

### `mcp_server.py` — MCP server

```bash
python mcp_server.py    # stdio transport — connect via Claude Desktop or Cursor
```

---

## Output Artifacts

Every battle writes to the `output/` directory:

| File | Generated by | Contents |
|---|---|---|
| `round_NN_battle_log.json` | `BattleScorer` | Per-round: attack logs, KQL rule, detected/evaded sets, scores |
| `full_battle_log_<T>.json` | `BattleScorer` | All rounds combined for technique T, used by MCP tools and web UI |
| `final_report.md` | `BattleScorer` | Surviving KQL rules in code blocks, winner summary |
| `battle_analysis.md` | `BattleAnalyst` | Field mutation analysis, detection gaps, hardening recommendations |
| `duel_report_<T>_<date>.pdf` | `ReportGenerator` | Full PDF with charts, mutation tables, surviving rules |
| `attacker_memory.json` | `MemoryStore` | Persistent evasion patterns across all battles (never reset) |
| `sentinel_export.json` | `SentinelExporter` | ARM template for direct Sentinel deployment |
| `sentinel_export.md` | `SentinelExporter` | Human-readable rule summary |
| `tournament_<T>.json` | `TournamentScorer` | Per-model scores and rankings |
| `tournament_report.md` | `TournamentScorer` | Tournament bracket results |
| `campaign_<name>.md` | `campaign.py` | Kill chain execution summary |
| `autonomous_report.md` | `autonomous.py` | Autonomous red team session report |
| `coverage_summary.json` | `run_all.py` | Aggregated results from a full coverage run |
| `mcp_server.log` | `mcp_server.py` | MCP tool call log |
| `duel.log` | All scripts | Unified debug log |
| `threat_intel_cache.json` | `ThreatIntel` | Cached Feodo Tracker feed |

---

## Project Structure

```
duel-framework/
├── main.py                  # CLI — single technique battle
├── server.py                # FastAPI web server (6 dashboards)
├── mcp_server.py            # MCP server — 8 tools for Claude/Cursor
├── campaign.py              # Multi-technique kill chain runner
├── autonomous.py            # LLM-driven autonomous red team
├── tournament.py            # Multi-model Defender tournament
├── run_all.py               # Batch coverage runner
├── requirements.txt
│
├── agents/
│   ├── attacker.py          # Attacker agent — telemetry generation + mutation
│   └── defender.py          # Defender agent — KQL generation + hardening
│
├── engine/
│   ├── detection.py         # KQL executor over pandas DataFrames
│   ├── scoring.py           # BattleScorer + BattleAnalyst
│   ├── attacker_memory.py   # Persistent evasion memory (MemoryStore)
│   ├── sentinel_export.py   # ARM template builder (SentinelExporter)
│   ├── report_generator.py  # PDF report generation
│   ├── llm_detection.py     # OWASP LLM policy-based detection
│   ├── autonomous_attacker.py # Autonomous technique sequencer
│   ├── threat_intel.py      # Feodo Tracker integration
│   ├── tournament_scorer.py # Multi-model ranking
│   ├── groq_client.py       # Ollama + Groq client wrapper
│   └── test_detection.py    # KQL executor unit tests
│
├── techniques/
│   ├── T1018.json           # 28 MITRE ATT&CK technique definitions
│   ├── T1040.json
│   ├── ...
│   └── llm/
│       ├── LLM01.json       # 10 OWASP LLM Top 10 2025 definitions
│       └── ...
│
├── static/
│   ├── index.html           # War Room
│   ├── heatmap.html         # ATT&CK Coverage Heatmap
│   ├── tournament.html      # Tournament bracket
│   ├── campaign.html        # Kill chain visualiser
│   ├── export.html          # Sentinel rule export
│   ├── autonomous.html      # Autonomous red team feed
│   └── mcp.html             # MCP integration guide
│
├── scripts/
│   └── weekly_battle.py     # GitHub Actions battle runner
│
├── .github/
│   └── workflows/
│       └── weekly-duel.yml  # Weekly automated battles (Mondays 08:00 UTC)
│
└── output/                  # Generated at runtime (gitignored)
    ├── full_battle_log_*.json
    ├── attacker_memory.json
    ├── sentinel_export.json
    └── ...
```

---

## Contributing

**New techniques** — add a JSON file to `techniques/` or `techniques/llm/` following the existing schema (`technique_id`, `name`, `tactic`, `sentinel_tables`, `iocs`, `evasion_variants`, `detection_kql_hints`). No code changes required. Include a sample `battle_analysis.md` from a 5-round run in your PR.

**Detection engine** — the KQL executor in `engine/detection.py` has unit tests in `engine/test_detection.py`. Run them with:
```bash
python -m pytest engine/test_detection.py -v
```
PRs extending the engine must include a new test case.

**Model benchmarking** — tested against `llama3.1:8b` (Attacker) and `mistral:7b` (Defender). If you benchmark other Ollama models and find better pairings, open an issue with the evasion/detection rates.

All contributions must follow the hard rules in `CLAUDE.md`: English only, zero external API calls, no simplification of KQL realism.

---

## Ethical Use

DUEL generates **entirely synthetic telemetry** against **in-process pandas DataFrames**. It does not connect to any Azure tenant, Microsoft 365 environment, or live Sentinel workspace. No real credentials, logs, or systems are involved. The framework is intended for security research, red/blue team training, and detection engineering education.

---

## License

MIT License — see [LICENSE](LICENSE).

---

*DUEL is an independent research project. It is not affiliated with or endorsed by Microsoft, Anthropic, or the MITRE Corporation. MITRE ATT&CK® is a registered trademark of The MITRE Corporation.*
