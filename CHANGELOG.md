# Changelog

All notable changes to DUEL are documented in this file.

## [1.0.1] — Errata (2026-09-05)

A research-integrity audit of the published paper's scaling-law experiment found four issues,
now documented in `docs/ERRATA.md` (attached as `docs/ERRATA.pdf`). The paper's PDF itself
(v1) is unchanged — this release adds the errata as a companion document.

1. **Meta-Resilience weight was never applied.** Declared at 10% in §3.2, but never computed
   for the published Table 1 — those scores used a renormalised 4-component form. DABS now
   records `weight_profile`, `weights_nominal`, and `weights_effective` explicitly instead of
   silently renormalizing.
2. **Two parameter counts were wrong.** qwen2.5:7b (7.0B → 7.61B) and qwen2.5:14b (14.0B →
   14.7B), corrected against official model cards. Refit R² moves from 0.0557 to 0.0530 —
   conclusion unchanged.
3. **The weekly automated battle badge never reflected a real result.** 21 runs
   (2026-04-25–2026-08-31) used decommissioned Groq model IDs and silently recorded zero
   rounds every time. Unrelated to the paper's numbers; the badge is now paused pending a
   verified fix.
4. **Live threat-intelligence enrichment was active in the original runs and is not
   seed-controlled**, so the paper's seed=42 reproducibility claim did not hold as stated.
   Benchmarks now default to `--threat-intel off` and record the mode used in every result.

Also: a pre-existing binary-corruption bug was found and fixed — `docs/paper.pdf` was being
silently mangled by Windows line-ending normalization on checkout (broken PDF `xref` table).
`.gitattributes` now marks PDFs and other binary formats correctly; both `paper.pdf` and the
new `ERRATA.pdf` were regenerated and verified byte-identical to their git blobs.

**For Zenodo:** attach `docs/ERRATA.pdf` as an additional file on the new version; the v1
paper PDF is not replaced.

## [1.0.0] — Current stable release

Full production-ready release. All modules stable and integrated. MCP Server, 38 techniques,
persistent memory, autonomous red team, PDF reports, and GitHub Actions automation are all
live and tested.

## [0.15.0] — MCP Server (Claude Desktop + Cursor integration)

- Added `mcp_server.py` exposing 8 DUEL capabilities as MCP tools
- Tools: run_battle, get_heatmap, list_techniques, get_memory, run_tournament,
  run_campaign, run_autonomous, export_sentinel
- Compatible with Claude Desktop, Cursor, and any MCP-enabled agent

## [0.14.0] — OWASP LLM Top 10 module

- Added full OWASP LLM Top 10 2025 attack simulation (LLM01–LLM10)
- Prompt Attacker generates real injection payloads for each LLM risk category
- LLM Guardian generates detection policies instead of KQL rules
- War Room UI dynamically swaps labels between MITRE and LLM modes

## [0.13.0] — 28 MITRE techniques (Microsoft Cloud coverage)

- Expanded technique library from initial set to 28 MITRE ATT&CK cloud/identity techniques
- Coverage spans all major Sentinel tables: `SigninLogs`, `AuditLogs`, `AzureActivity`,
  `OfficeActivity`
- Tactics covered: Initial Access, Credential Access, Persistence, Discovery,
  Collection, Exfiltration, Impact, Defense Evasion

## [0.12.0] — KQL engine extended

- Added `join` operator with `kind=` inner / leftouter / rightouter / fullouter /
  leftanti / rightanti and `$left.col == $right.col` syntax
- Added `let` bindings: scalar numbers, strings, and `dynamic([...])` lists
- Added `make-series count() on T step Xh by col` mapped to pandas resample
- Added `arg_max()` / `arg_min()` aggregations in `summarize`
- Added `mv-expand` for list-valued column explosion
- Added `parse col with * "lit" name:type *` regex-based field extraction

## [0.11.0] — GitHub Actions weekly automation

- Added `.github/workflows/weekly_battle.yml`
- Runs a full battle across all 38 techniques every Monday at 03:00 UTC
- Commits surviving KQL rules and updated heatmap back to the repository
- Sends battle summary as a GitHub Actions job summary

## [0.10.0] — PDF report auto-generation

- Added `scripts/generate_pdf.py` using ReportLab
- Per-battle PDF includes mutation analysis, field stability charts, and surviving KQL rules
- Auto-generated after every completed battle and linked from the War Room UI

## [0.9.0] — Autonomous Red Team mode

- Added `autonomous.py` with LLM-driven objective-based attack sequencing
- Attacker LLM selects the next technique based on previous round outcomes
- No human prompts required — full autonomous campaign from a single goal description
- Added `/autonomous` dashboard page to the War Room UI

## [0.8.0] — Threat intel integration (Feodo Tracker)

- Added Feodo Tracker C2 IP feed integration in `server.py`
- Defender optionally enriches KQL rules with live C2 IP blocklists
- Threat Intel badge in War Room header shows live IOC count and source status
- Added `/api/threatintel` endpoint and TI modal popup

## [0.7.0] — Persistent attacker memory

- Attacker now writes `output/attacker_memory.json` after every battle
- Memory stores: stable evasion patterns, dangerous field values, successful mutation strategies
- Each subsequent battle loads prior memory so the attacker starts with accumulated intel
- Memory panel added to War Room UI with drag-to-resize and expand/collapse controls

## [0.6.0] — Sentinel export (ARM template)

- Added ARM template export for surviving KQL rules
- One-click download from the `/export` dashboard
- Template is valid for direct deployment to Microsoft Sentinel Scheduled Alert Rules
- Added `GET /api/export/arm` endpoint in `server.py`

## [0.5.0] — Campaign mode (kill chain chaining)

- Added `campaign.py` for multi-stage kill chain execution
- Attacker context carries forward between techniques in a defined kill chain
- Supports custom kill chain definitions via JSON config
- Added `/campaign` dashboard page to the War Room UI

## [0.4.0] — Tournament mode (multi-model ranking)

- Added `tournament.py` for ranking multiple Defender models head-to-head
- Runs the same Attacker against N Defender models and produces a ranked leaderboard
- Supports any Ollama model as Defender
- Added `/tournament` dashboard page to the War Room UI

## [0.3.0] — MITRE coverage heatmap

- Added heatmap visualization at `/heatmap`
- Displays evasion rates per MITRE ATT&CK technique and tactic
- Colour-coded matrix: green (detected) → red (evaded)
- Reads live data from `output/` battle logs

## [0.2.0] — Web UI war room with FastAPI WebSockets

- Added `server.py` (FastAPI + WebSockets) replacing the CLI-only interface
- War Room dashboard with live round-by-round telemetry and KQL updates
- Real-time scoreboard, battle feed, status pills, and particle explosion on battle end
- CRT scanline overlay, panel glow animations, and KQL syntax highlighting

## [0.1.0] — Initial adversarial loop

- Core adversarial loop: Attacker (llama3.1) vs Defender (mistral)
- `main.py` orchestrates multi-round battles via CLI
- `engine/detection.py` implements a pandas-backed KQL executor
- Attacker generates synthetic Microsoft Sentinel telemetry per MITRE technique
- Defender generates KQL detection rules; engine scores each round
- Structured JSON battle logs written to `output/`
- Initial MITRE ATT&CK technique set targeting cloud/identity scenarios
