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

## What NOT to do
- Do not add external API calls
- Do not hallucinate Sentinel table schemas — use only real documented schemas
- Do not break the adversarial loop structure in main.py
