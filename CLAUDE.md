# DUEL — Claude Code Briefing

## Project Identity
DUEL (Dual Unsupervised Evasion Loop) is an adversarial security research 
framework. Two LLM agents battle across multiple rounds. The Attacker 
generates synthetic telemetry mimicking real Microsoft Sentinel schemas. 
The Defender generates KQL detection rules. A local detection engine scores 
each round.

## Hard Rules
- All code, comments, commits, and output files must be in English
- Zero calls to Anthropic API or any paid LLM API — Ollama only
- Never simplify the KQL rules to make detection easier — realism matters
- Attacker must always reason about previous round detections before mutating
- Defender must always reference evaded samples before hardening rules

## Stack
- Python 3.11+
- Ollama (llama3.1 for Attacker, mistral for Defender)
- kql-python + pandas for local detection engine
- Rich for CLI output
- MITRE ATT&CK as source of truth for techniques

## Output Standards
- Every round produces a structured JSON log in /output
- Final report is markdown with surviving KQL rules in code blocks
- Battle logs must include: technique, round, attacker_strategy, 
  defender_reasoning, detection_result, evasion_rate

## KQL Engine — Supported Operators

`engine/detection.py` implements a pandas-backed KQL executor.
Tests live in `engine/test_detection.py` (`python -m pytest engine/test_detection.py -v`).

| Operator | Notes |
|---|---|
| `where` | `==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `has`, `startswith`, `endswith`, `in`, `in~`, `!in`, `has_any`, `matches regex`, `isempty`, `isnotempty`, `isnull`, `isnotnull`, `and`/`or`/`not` |
| `project` / `project-away` | Column selection / removal |
| `summarize` | `count()`, `dcount()`, `make_list()`, `make_set()`, `arg_max()`, `arg_min()` — with or without `by` grouping |
| `extend` | Simple column assignment |
| `top N by col` | Sort + head |
| `limit` / `take` | Row cap |
| `order by` / `sort by` | Ascending/descending |
| `distinct` | Deduplication |
| `let` | Scalar numbers, strings, and `dynamic([...])` lists; variables substituted before execution |
| `join` | `kind=` inner / leftouter / rightouter / fullouter / leftanti / rightanti; `$left.col == $right.col` syntax; subquery failure is graceful |
| `make-series count() on T step Xh by col` | Maps to pandas resample; units s/m/h/d |
| `mv-expand col` | Explodes list-valued column into individual rows |
| `parse col with * "lit" name:type *` | Regex-based named field extraction; types string / int / real |

`union` is not supported (silently skipped). Unknown operators pass the DataFrame through unchanged.

## What NOT to do
- Do not add external API calls
- Do not hallucinate Sentinel table schemas — use only real documented schemas
- Do not break the adversarial loop structure in main.py
