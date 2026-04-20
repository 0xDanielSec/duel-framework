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
You are a Microsoft Sentinel detection engineer in the DUEL framework. \
Output ONLY a raw KQL query — no prose, no markdown fences.

TABLE NAMES: write them bare — never wrap in backticks or quotes. \
Correct: SigninLogs   Wrong: `SigninLogs`  Wrong: 'SigninLogs'

SUPPORTED: where (==, !=, <, >, <=, >=, has, contains, startswith, endswith, \
in ("a","b"), isempty, isnotempty, and/or/not), project, project-away, \
summarize count() by, extend, top N by, limit N, order by, distinct, count.

FORBIDDEN (silently match nothing — hard failure): \
subqueries in in(), ago/now/bin/datetime, prev/next/last, CountIf/dcountif, \
let, join, union, make_list, make_set, mv-expand.

DETECTION LOGIC — your rule runs against the ATTACK LOGS:
- Every "where" condition must be TRUE for attack rows or those rows are removed.
- Match field values that ARE in the logs (== or in() or has). \
  Do NOT negate a value present in the logs — that removes the attack rows.
- T1078 attacks are SUCCESSFUL logins: ResultType == 0. \
  Never write ResultType != 0.

EXAMPLE:
  SigninLogs
  | where ResultType == 0
  | where AuthenticationRequirement has "Not Required"
  | where AppDisplayName in ("Azure AD Portal", "Azure Portal")

FIELDS — SigninLogs: TimeGenerated, UserPrincipalName, AppDisplayName, \
IPAddress, Location, CountryOrRegion, City, ResultType, ResultDescription, \
AuthenticationRequirement, ConditionalAccessStatus, UserAgent, ClientAppUsed, \
RiskLevelDuringSignIn, RiskState, CorrelationId | \
SecurityEvent: TimeGenerated, EventID, Activity, Account, Computer, \
SubjectUserName, TargetUserName, LogonType, IpAddress, Status | \
AuditLogs: TimeGenerated, OperationName, Result, Category, \
ActivityDisplayName, Identity, CorrelationId
"""

INITIAL_PROMPT_TEMPLATE = """\
MITRE Technique: {technique_id} — {technique_name}
Description: {description}

ROUND {round_num} of {total_rounds} — Write your initial detection rule.

AVAILABLE TABLES — your query MUST start with one of these exactly:
  {available_tables}

Attack log samples ({total_logs} logs total, showing {sample_count}):
{attack_samples}

Distinct field values observed across all {total_logs} attack logs:
{field_value_summary}

Conceptual detection hints (implement as simple where conditions only):
{detection_hints}

INSTRUCTIONS:
  1. Start with one of the AVAILABLE TABLES above — no other table name.
  2. Use ONLY the operators listed in the system prompt.
  3. Do NOT use subqueries, time functions, or any FORBIDDEN construct.
  4. Write 2-4 "where" conditions. Each condition must be TRUE for the attack
     logs — use == or in() or has/contains to MATCH values you see above.
     Do NOT negate (!=) a value that appears in the "Distinct field values".
  5. ResultType == 0 in these logs. Do NOT write ResultType != 0.
  6. Start with "ResultType == 0", then add conditions matching suspicious
     field values you observe (unusual auth method, risky app, risk level, etc.).

Output ONLY the KQL query — no explanation, no markdown, no fences.
"""

HARDENING_PROMPT_TEMPLATE = """\
MITRE Technique: {technique_id} — {technique_name}
ROUND {round_num} of {total_rounds} — HARDEN your detection rule.

AVAILABLE TABLES — your query MUST start with one of these exactly:
  {available_tables}

Your PREVIOUS KQL rule:
{last_kql}

Performance last round:
  Detected: {detected_count} logs ({detection_rate:.0%} rate)
  Evaded:   {evaded_count} logs

Logs that EVADED your rule (find the gap):
{evaded_samples}

Distinct field values in evaded logs:
{evaded_field_summary}

Logs that WERE DETECTED (preserve what worked):
{detected_samples}

New attack logs this round:
{new_attack_samples}

Distinct field values in new attack logs:
{new_field_summary}

INSTRUCTIONS:
  1. Start with one of the AVAILABLE TABLES above — no other table name.
  2. Use ONLY the operators listed in the system prompt — NO subqueries, NO
     time functions, NO CountIf, NO prev/next/last, NO FORBIDDEN constructs.
  3. Identify which field values in the evaded logs your previous conditions
     missed and add or adjust "where" conditions to cover them.
  4. Each condition must be TRUE for attack rows. Do NOT negate (!=) a value
     you see in the field summaries — that removes the attack rows.
  5. Do NOT just match exact IPs or UPNs — those rotate. Target structural
     fields: AuthenticationRequirement, ClientAppUsed, AppDisplayName,
     RiskLevelDuringSignIn, ConditionalAccessStatus, CountryOrRegion.
  6. Use "or" conditions to cover multiple evasion variants in one clause.
  7. Keep ResultType == 0 (do NOT flip to != 0).

Output ONLY the KQL query — no explanation, no markdown, no fences.
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
        samples = attack_logs[:5]
        return INITIAL_PROMPT_TEMPLATE.format(
            technique_id=technique["technique_id"],
            technique_name=technique["name"],
            description=technique["description"],
            round_num=round_num,
            total_rounds=total_rounds,
            available_tables=", ".join(_tables_in_logs(attack_logs)),
            total_logs=len(attack_logs),
            sample_count=len(samples),
            attack_samples=_format_logs(samples),
            field_value_summary=_field_value_summary(attack_logs),
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
            evaded_field_summary=_field_value_summary(evaded) if evaded else "  (none)",
            detected_samples=_format_logs(detected, n=2),
            new_attack_samples=_format_logs(attack_logs, n=4),
            new_field_summary=_field_value_summary(attack_logs),
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
                options={"temperature": 0.4, "num_predict": 1024},
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

        # Remove leading prose: find the first line that looks like a table name.
        # Also normalise a bare backtick/quote prefix on the table token.
        tables = {"SigninLogs", "SecurityEvent", "AuditLogs",
                  "AADSignInLogs", "AADNonInteractiveUserSignInLogs",
                  "OfficeActivity"}
        lines = text.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip().lstrip("`'\"")
            if any(stripped.startswith(t) for t in tables):
                clean_lines = [line.lstrip().lstrip("`'\"")] + lines[i + 1:]
                return "\n".join(clean_lines).strip()

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


def _field_value_summary(logs: list[dict], max_vals: int = 6) -> str:
    """
    Show distinct values per field across all logs so the LLM can write
    where conditions that match what is actually in the data.
    Skips internal _duel_* fields and the 'table' routing field.
    """
    if not logs:
        return "  (no logs)"
    field_vals: dict[str, list[str]] = {}
    for log in logs:
        for k, v in log.items():
            if k.startswith("_duel") or k == "table":
                continue
            sv = str(v)
            if k not in field_vals:
                field_vals[k] = []
            if sv not in field_vals[k]:
                field_vals[k].append(sv)
    lines = []
    for field in sorted(field_vals):
        vals = field_vals[field]
        shown = vals[:max_vals]
        overflow = f" … +{len(vals) - max_vals} more" if len(vals) > max_vals else ""
        lines.append(f"  {field}: {shown}{overflow}")
    return "\n".join(lines)


def _tables_in_logs(logs: list[dict]) -> list[str]:
    """Return the unique table names present in a list of attack logs, in order."""
    seen: list[str] = []
    for log in logs:
        t = log.get("table", "SigninLogs")
        if t not in seen:
            seen.append(t)
    return seen or ["SigninLogs"]
