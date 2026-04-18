"""
Attacker LLM agent — generates synthetic attack telemetry based on MITRE
ATT&CK techniques, mutating each round to evade the Defender's KQL rules.
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
import random

import ollama

logger = logging.getLogger(__name__)

ATTACKER_SYSTEM = """\
You are an elite red-team operator simulating adversarial activity for a \
security research framework called DUEL. You generate REALISTIC synthetic \
telemetry logs that mimic genuine Microsoft Azure / Microsoft 365 attack \
activity tied to a specific MITRE ATT&CK technique.

CRITICAL RULES:
1. Output ONLY a valid JSON array — no prose, no markdown, no code fences.
2. Each element is a log entry dict with fields matching the specified \
   Microsoft Sentinel table schema.
3. Every entry MUST include a "table" field (e.g. "SigninLogs") and a \
   "_duel_id" field with a unique UUID string.
4. Make logs realistic: real-looking UPNs, IPs, UserAgents, timestamps, etc.
5. If previous detections are provided, MUTATE your approach to evade them. \
   Analyze exactly which field values triggered detection and change them \
   while preserving the core attack pattern.
6. Never repeat identical log values across rounds.
"""

ATTACKER_PROMPT_TEMPLATE = """\
MITRE Technique: {technique_id} — {technique_name}
Description: {description}
Target Sentinel tables: {tables}

ROUND {round_num} of {total_rounds}

{prev_context}

Generate exactly {num_logs} synthetic attack log entries for this technique. \
Use the SigninLogs schema with these fields:
  TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, \
  CountryOrRegion, City, ResultType, ResultDescription, \
  AuthenticationRequirement, ConditionalAccessStatus, UserAgent, \
  ClientAppUsed, RiskLevelDuringSignIn, RiskState, CorrelationId

Evasion guidance for this technique: {evasion_hints}

Output JSON array only.
"""

MUTATION_PROMPT_TEMPLATE = """\
MITRE Technique: {technique_id} — {technique_name}
ROUND {round_num} of {total_rounds}

The Defender's KQL rule last round was:
```kql
{last_kql}
```

It DETECTED {detected_count} of your {total_logs} logs ({detection_rate:.0%} detection rate).

Detected log samples (study these — they got caught):
{detected_samples}

Evaded log samples (these worked — preserve the evasion patterns):
{evaded_samples}

Now generate {num_logs} NEW attack logs that specifically evade the above KQL \
rule. Reason about which field values, patterns, or thresholds the rule targets \
and craft telemetry that avoids them while still representing the same \
MITRE technique: {technique_id}.

Allowed tables: SigninLogs, SecurityEvent, AuditLogs
Required fields per entry: table, _duel_id, plus all schema fields for that table.

Evasion vectors to consider:
{evasion_hints}

Output JSON array only.
"""


class AttackerAgent:
    def __init__(self, model: str = "llama3.1:8b", num_logs: int = 10):
        self.model = model
        self.num_logs = num_logs
        self.round_history: list[dict] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_logs(
        self,
        technique: dict,
        round_num: int,
        total_rounds: int,
        last_kql: str | None = None,
        detected_logs: list[dict] | None = None,
        evaded_logs: list[dict] | None = None,
    ) -> list[dict]:
        """
        Generate synthetic attack telemetry for one round.
        Mutates strategy based on previous detection results.
        """
        if round_num == 1 or last_kql is None:
            prompt = self._build_initial_prompt(technique, round_num, total_rounds)
        else:
            prompt = self._build_mutation_prompt(
                technique, round_num, total_rounds,
                last_kql, detected_logs or [], evaded_logs or [],
            )

        raw = self._call_ollama(prompt)
        logs = self._parse_logs(raw)

        # Stamp each log with a unique _duel_id and normalise known schema fields
        for log in logs:
            if not log.get("_duel_id"):
                log["_duel_id"] = str(uuid.uuid4())
            log.setdefault("table", "SigninLogs")
            if not log.get("TimeGenerated") or log["TimeGenerated"] in ("", "now", "ISO8601"):
                log["TimeGenerated"] = _random_timestamp()
            # ResultType must be an integer (Azure AD error code; 0 = success).
            # LLMs frequently emit strings like "Success" or "0" — normalise them.
            rt = log.get("ResultType")
            if isinstance(rt, str):
                log["ResultType"] = _RESULT_TYPE_MAP.get(rt.lower(), 0)

        logger.info("Attacker generated %d logs for round %d", len(logs), round_num)
        self.round_history.append({
            "round": round_num,
            "prompt": prompt,
            "raw_response": raw,
            "logs": logs,
        })
        return logs

    # ------------------------------------------------------------------
    # Prompt builders
    # ------------------------------------------------------------------

    def _build_initial_prompt(self, technique: dict, round_num: int, total_rounds: int) -> str:
        prev_context = (
            "This is the FIRST round. Generate a representative initial attack pattern."
        )
        return ATTACKER_PROMPT_TEMPLATE.format(
            technique_id=technique["technique_id"],
            technique_name=technique["name"],
            description=technique["description"],
            tables=", ".join(technique.get("sentinel_tables", ["SigninLogs"])),
            round_num=round_num,
            total_rounds=total_rounds,
            prev_context=prev_context,
            num_logs=self.num_logs,
            evasion_hints="\n".join(f"- {h}" for h in technique.get("evasion_variants", [])),
        )

    def _build_mutation_prompt(
        self,
        technique: dict,
        round_num: int,
        total_rounds: int,
        last_kql: str,
        detected: list[dict],
        evaded: list[dict],
    ) -> str:
        def _sample(logs: list[dict], n: int = 2) -> str:
            samples = logs[:n]
            clean = [{k: v for k, v in s.items() if not k.startswith("_duel")} for s in samples]
            return json.dumps(clean, indent=2, default=str) if clean else "None"

        return MUTATION_PROMPT_TEMPLATE.format(
            technique_id=technique["technique_id"],
            technique_name=technique["name"],
            round_num=round_num,
            total_rounds=total_rounds,
            last_kql=last_kql,
            detected_count=len(detected),
            total_logs=len(detected) + len(evaded),
            detection_rate=len(detected) / max(len(detected) + len(evaded), 1),
            detected_samples=_sample(detected),
            evaded_samples=_sample(evaded),
            num_logs=self.num_logs,
            evasion_hints="\n".join(f"- {h}" for h in technique.get("evasion_variants", [])),
        )

    # ------------------------------------------------------------------
    # Ollama call
    # ------------------------------------------------------------------

    def _call_ollama(self, prompt: str) -> str:
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": ATTACKER_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.85, "num_predict": 4096},
            )
            return response["message"]["content"]
        except Exception as exc:
            logger.error("Ollama call failed: %s", exc)
            raise

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_logs(self, raw: str) -> list[dict]:
        """Extract JSON array from LLM response, handling markdown fences."""
        text = raw.strip()

        # Strip markdown code fences
        if "```" in text:
            import re
            m = re.search(r"```(?:json)?\s*(\[.+?\])\s*```", text, re.DOTALL)
            if m:
                text = m.group(1)
            else:
                text = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()

        # Find first [ ... ] block
        start = text.find("[")
        if start == -1:
            logger.warning("No JSON array found in attacker response")
            return _fallback_logs(self.num_logs)

        # Find matching ]
        depth, end = 0, -1
        for i, ch in enumerate(text[start:], start):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    end = i
                    break

        if end == -1:
            logger.warning("Unclosed JSON array in attacker response")
            return _fallback_logs(self.num_logs)

        try:
            logs = json.loads(text[start:end + 1])
            if not isinstance(logs, list):
                raise ValueError("Expected list")
            return logs
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("JSON parse error: %s", exc)
            return _fallback_logs(self.num_logs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# LLMs emit ResultType as strings; map them to the Azure AD integer error codes.
_RESULT_TYPE_MAP: dict[str, int] = {
    "success": 0, "successful": 0, "succeeded": 0,
    "0": 0, "ok": 0, "pass": 0, "passed": 0,
    "failure": 50074, "failed": 50074, "fail": 50074,
    "error": 50074, "invalid": 50074,
}


def _random_timestamp(offset_hours: int = 0) -> str:
    base = datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 23))
    return base.isoformat()


def _fallback_logs(n: int) -> list[dict]:
    """Emergency fallback: deterministic synthetic logs when LLM parse fails."""
    logs = []
    ips = ["185.220.101.5", "45.142.212.100", "91.108.4.200", "198.96.155.3", "23.129.64.214"]
    users = [
        "admin@contoso.com", "svc-account@contoso.com",
        "j.smith@contoso.com", "support@contoso.com", "finance@contoso.com",
    ]
    for i in range(n):
        logs.append({
            "table": "SigninLogs",
            "_duel_id": str(uuid.uuid4()),
            "TimeGenerated": _random_timestamp(),
            "UserPrincipalName": random.choice(users),
            "AppDisplayName": "Microsoft Azure Portal",
            "IPAddress": random.choice(ips),
            "Location": "RU",
            "CountryOrRegion": "RU",
            "City": "Moscow",
            "ResultType": 0,
            "ResultDescription": "Successfully signed in",
            "AuthenticationRequirement": "singleFactorAuthentication",
            "ConditionalAccessStatus": "notApplied",
            "UserAgent": "python-requests/2.28.0",
            "ClientAppUsed": "Other clients",
            "RiskLevelDuringSignIn": "none",
            "RiskState": "none",
            "CorrelationId": str(uuid.uuid4()),
        })
    return logs
