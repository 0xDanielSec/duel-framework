"""
Defender LLM agent — generates KQL detection rules targeting the Attacker's
synthetic telemetry, hardening each round based on what evaded detection.
"""

import json
import logging
import re

import ollama

logger = logging.getLogger(__name__)

DEFENDER_SYSTEM = """\
You are a senior Microsoft Sentinel detection engineer participating in an \
adversarial AI security framework called DUEL. Your mission is to write KQL \
(Kusto Query Language) detection rules that catch malicious activity in \
Microsoft Sentinel log tables.

CRITICAL RULES:
1. Output ONLY the raw KQL query — no prose, no explanations, no markdown fences.
2. The query MUST start with a table name from the AVAILABLE TABLES list provided \
   in the user prompt. Starting with any other table causes a hard failure.
3. NEVER use join, union, or any cross-table operator. Every rule must query \
   exactly one table — the one that contains the attack telemetry.
4. Use only these operators: where, project, project-away, summarize, extend, \
   top, limit, order by, sort by, distinct, count.
5. Target realistic field values visible in the attack logs provided.
6. If previous evasions are shown, HARDEN your rule to close those gaps. \
   Reason about what field patterns or thresholds the attacker exploited and \
   write conditions that catch them.
7. Prefer broad rules that catch patterns over narrow rules that match exact values.

SigninLogs field reference:
  TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location,
  CountryOrRegion, City, ResultType, ResultDescription,
  AuthenticationRequirement, ConditionalAccessStatus, UserAgent,
  ClientAppUsed, RiskLevelDuringSignIn, RiskState, CorrelationId

SecurityEvent field reference:
  TimeGenerated, EventID, Activity, Account, Computer, SubjectUserName,
  TargetUserName, LogonType, IpAddress, Status

AuditLogs field reference:
  TimeGenerated, OperationName, Result, Category, ActivityDisplayName,
  Identity, CorrelationId
"""

INITIAL_PROMPT_TEMPLATE = """\
MITRE Technique: {technique_id} — {technique_name}
Description: {description}

ROUND {round_num} of {total_rounds} — Write your initial detection rule.

AVAILABLE TABLES (only these contain data — start your query with one of them):
  {available_tables}

Sample attack logs from the Attacker this round:
{attack_samples}

Detection hints from the MITRE knowledge base:
{detection_hints}

Write a single KQL query that detects this attack pattern. \
Your query MUST start with one of the AVAILABLE TABLES above. \
Focus on behavioral indicators rather than exact IP/user matches since \
those will rotate. Output KQL only.
"""

HARDENING_PROMPT_TEMPLATE = """\
MITRE Technique: {technique_id} — {technique_name}
ROUND {round_num} of {total_rounds} — HARDEN your detection rule.

AVAILABLE TABLES (only these contain data — start your query with one of them):
  {available_tables}

Your PREVIOUS KQL rule:
{last_kql}

Performance last round:
- Detected: {detected_count} logs ({detection_rate:.0%} detection rate)
- Evaded:   {evaded_count} logs

Logs that EVADED your rule (study these carefully — find the gaps):
{evaded_samples}

Logs that WERE DETECTED (preserve what worked):
{detected_samples}

New attack logs from this round:
{new_attack_samples}

Analyze WHY the evaded logs slipped through your rule. Identify the specific \
field values, thresholds, or operators that need to change. Then write an \
IMPROVED KQL query that closes those gaps.

Rules:
- Your query MUST start with one of the AVAILABLE TABLES above.
- NEVER use join or union.
- Do not just add exact-match conditions on rotating values (IPs, UPNs).
- Target structural patterns: protocols, timing, auth method, CA status, etc.
- You may use OR conditions to cover multiple evasion variants.

Output KQL only.
"""


class DefenderAgent:
    def __init__(self, model: str = "mistral:7b"):
        self.model = model
        self.round_history: list[dict] = []
        self.last_kql: str | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_rule(
        self,
        technique: dict,
        round_num: int,
        total_rounds: int,
        attack_logs: list[dict],
        detected_logs: list[dict] | None = None,
        evaded_logs: list[dict] | None = None,
    ) -> str:
        """
        Generate a KQL detection rule for this round.
        Returns a KQL string.
        """
        if round_num == 1 or self.last_kql is None:
            prompt = self._build_initial_prompt(technique, round_num, total_rounds, attack_logs)
        else:
            prompt = self._build_hardening_prompt(
                technique, round_num, total_rounds, attack_logs,
                detected_logs or [], evaded_logs or [],
            )

        raw = self._call_ollama(prompt)
        kql = self._clean_kql(raw)

        logger.info("Defender generated KQL (%d chars) for round %d", len(kql), round_num)
        self.last_kql = kql
        self.round_history.append({
            "round": round_num,
            "prompt": prompt,
            "raw_response": raw,
            "kql": kql,
        })
        return kql

    # ------------------------------------------------------------------
    # Prompt builders
    # ------------------------------------------------------------------

    def _build_initial_prompt(
        self, technique: dict, round_num: int, total_rounds: int, attack_logs: list[dict]
    ) -> str:
        return INITIAL_PROMPT_TEMPLATE.format(
            technique_id=technique["technique_id"],
            technique_name=technique["name"],
            description=technique["description"],
            round_num=round_num,
            total_rounds=total_rounds,
            available_tables=", ".join(_tables_in_logs(attack_logs)),
            attack_samples=_format_logs(attack_logs, n=5),
            detection_hints="\n".join(
                f"- {h}" for h in technique.get("detection_kql_hints", [])
            ),
        )

    def _build_hardening_prompt(
        self,
        technique: dict,
        round_num: int,
        total_rounds: int,
        attack_logs: list[dict],
        detected: list[dict],
        evaded: list[dict],
    ) -> str:
        return HARDENING_PROMPT_TEMPLATE.format(
            technique_id=technique["technique_id"],
            technique_name=technique["name"],
            round_num=round_num,
            total_rounds=total_rounds,
            available_tables=", ".join(_tables_in_logs(attack_logs)),
            last_kql=self.last_kql or "(none)",
            detected_count=len(detected),
            evaded_count=len(evaded),
            detection_rate=len(detected) / max(len(detected) + len(evaded), 1),
            evaded_samples=_format_logs(evaded, n=4),
            detected_samples=_format_logs(detected, n=2),
            new_attack_samples=_format_logs(attack_logs, n=4),
        )

    # ------------------------------------------------------------------
    # Ollama call
    # ------------------------------------------------------------------

    def _call_ollama(self, prompt: str) -> str:
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": DEFENDER_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.4, "num_predict": 2048},
            )
            return response["message"]["content"]
        except Exception as exc:
            logger.error("Ollama call failed: %s", exc)
            raise

    # ------------------------------------------------------------------
    # KQL cleanup
    # ------------------------------------------------------------------

    def _clean_kql(self, raw: str) -> str:
        """Strip markdown fences and prose, leaving only the KQL query."""
        text = raw.strip()

        # Extract from code fence if present
        m = re.search(r"```(?:kql|kusto|sql)?\s*(.+?)```", text, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip()

        # Remove leading prose: find the first line that looks like a table name
        tables = {"SigninLogs", "SecurityEvent", "AuditLogs",
                  "AADSignInLogs", "AADNonInteractiveUserSignInLogs"}
        lines = text.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if any(stripped.startswith(t) for t in tables):
                return "\n".join(lines[i:]).strip()

        # Last resort: return everything
        return text

    def get_last_kql(self) -> str | None:
        return self.last_kql


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_logs(logs: list[dict], n: int = 4) -> str:
    """Format logs as compact JSON, removing internal _duel_ fields."""
    samples = logs[:n]
    clean = [{k: v for k, v in s.items() if not k.startswith("_duel")} for s in samples]
    return json.dumps(clean, indent=2, default=str) if clean else "[]"


def _tables_in_logs(logs: list[dict]) -> list[str]:
    """Return the unique table names present in a list of attack logs, in order."""
    seen: list[str] = []
    for log in logs:
        t = log.get("table", "SigninLogs")
        if t not in seen:
            seen.append(t)
    return seen or ["SigninLogs"]
