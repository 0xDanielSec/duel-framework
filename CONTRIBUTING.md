# Contributing to DUEL

## Adding New MITRE Techniques

Techniques live in `techniques/mitre/`. Each file is a JSON object with the following schema:

```json
{
  "id": "T1234.001",
  "name": "Technique Name: Sub-technique",
  "tactic": "Credential Access",
  "sentinel_table": "SigninLogs",
  "schema_fields": {
    "TimeGenerated": "datetime",
    "UserPrincipalName": "string",
    "IPAddress": "string",
    "ResultType": "int",
    "AppDisplayName": "string"
  },
  "attacker_hint": "Generate sign-in logs with repeated ResultType 50126 from rotating IPs targeting the same UPN.",
  "defender_hint": "Detect N distinct IPs for a single UPN within a short window, filtering noise by AppDisplayName.",
  "mitre_url": "https://attack.mitre.org/techniques/T1234/001/"
}
```

**Rules:**
- `sentinel_table` must be a real documented Microsoft Sentinel schema (`SigninLogs`,
  `AuditLogs`, `AzureActivity`, `OfficeActivity`, `SecurityEvent`, etc.)
- `schema_fields` must reflect the actual published schema — do not invent field names
- `attacker_hint` and `defender_hint` must be specific enough to produce distinct telemetry
- File name must match the `id` field: `T1234.001.json`

After adding the file, register the technique in `static/index.html` under the correct
`<optgroup>` tactic and in the technique selector map inside `server.py`.

## Adding New OWASP LLM Techniques

OWASP LLM techniques live in `techniques/owasp/`. Schema:

```json
{
  "id": "LLM11",
  "name": "New Risk Name",
  "category": "OWASP LLM Top 10",
  "attacker_hint": "Generate realistic attack payloads that exploit this risk category.",
  "defender_hint": "Define a detection policy that identifies the attack pattern.",
  "owasp_url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
}
```

OWASP techniques use text payloads instead of Sentinel telemetry. The Attacker produces
injection strings or abuse scenarios; the Defender produces a natural-language detection
policy rather than KQL. The engine scores based on keyword and semantic matching instead
of log field matching.

## Extending the KQL Detection Engine

The engine is in `engine/detection.py`. Supported operators and their pandas mappings are
documented in `CLAUDE.md`.

To add a new operator:
1. Add a handler method `_op_<name>(self, df, clause)` that takes a DataFrame and returns
   a DataFrame.
2. Register it in the `_dispatch` table at the top of `KQLEngine`.
3. Write tests in `engine/test_detection.py` covering: basic case, edge case (empty
   DataFrame, missing column), and interaction with existing operators.
4. Run `python -m pytest engine/test_detection.py -v` — all tests must pass before opening
   a PR.

Do not add operators that require external network calls or subprocess execution.

## Adding New Ollama Model Support

Attacker and Defender models are specified per battle via `--attacker-model` and
`--defender-model` CLI flags (or the model dropdowns in the War Room UI).

Any model available in the local Ollama registry is automatically supported. To add a new
model to the War Room dropdown:

1. Add an `<option>` to the model `<select>` elements in `static/index.html`.
2. Add the model name to the allowed list in `server.py` if input validation is present.
3. Pull the model locally before running: `ollama pull <model>`.

No code changes are required in the engine or agents — they use the model name passed at
runtime.

## PR Guidelines

- **Language:** All code, comments, commit messages, and documentation must be in English.
- **No external API calls:** Zero calls to Anthropic, OpenAI, or any paid LLM API.
  Ollama only.
- **Tests:** New KQL operators require tests in `engine/test_detection.py`. New techniques
  do not require tests but must be validated with at least one real battle run.
- **Battle analysis sample:** Every PR that changes agent prompts, the KQL engine, or
  technique definitions must include a `battle_analysis.md` file in the PR description
  with the following structure:

```markdown
## Battle Analysis Sample

**Technique:** T1234.001  
**Rounds:** 5  
**Attacker model:** llama3.1:8b  
**Defender model:** mistral:7b  

| Round | Attacker evasion rate | KQL rule change |
|-------|-----------------------|-----------------|
| 1     | 30%                   | Initial rule    |
| 2     | 60%                   | Added IP filter |
| ...   | ...                   | ...             |

**Outcome:** Attacker/Defender won. Evasion rate changed from X% to Y%.
**Key mutation:** [describe the mutation that changed the outcome]
```

## Code Style

- Python 3.11+, standard library where possible.
- No type: ignore suppressions without an explanatory comment.
- Functions longer than 40 lines should be split.
- No print statements in library code — use the `rich` console or return values.
- No comments that restate what the code does. Only write a comment when the *why* is
  non-obvious: a hidden constraint, a workaround for a documented bug, a subtle invariant.
- Imports: stdlib → third-party → local, separated by blank lines.
- All JSON output files must be valid JSON (run `python -m json.tool` to verify).
