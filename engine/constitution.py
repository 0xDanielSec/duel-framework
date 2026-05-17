"""
Constitutional Defense Mode — the Defender generates and upholds a security
constitution: a set of named principles that guide KQL construction.

The Attacker may try to make the Defender violate its own principles by
crafting log data with manipulative field values (constitution attack).
"""

import json
import logging
import re

logger = logging.getLogger(__name__)


CONSTITUTION_SYSTEM = """\
You are a Microsoft Sentinel detection architect. Define a security constitution \
— a set of detection principles for a specific MITRE ATT&CK technique.

OUTPUT FORMAT — a single JSON object, no prose, no markdown fences:
{
  "principles": [
    {
      "id": "P1",
      "text": "Always anchor detection to successful authentication (ResultType == 0)",
      "kql_anchor": "ResultType"
    }
  ],
  "version": 1,
  "technique_id": ""
}

RULES:
1. Output ONLY the JSON object. No markdown, no explanation.
2. Write exactly 3-5 principles. Each must be concrete and testable against a KQL rule.
3. kql_anchor: comma-separated field name(s) the principle targets. May be empty string.
4. Principles must be technique-specific — no generic advice.
"""

CORRECTION_SYSTEM = """\
You are a Microsoft Sentinel detection engineer. Fix a KQL rule so it complies \
with a security constitution. Output ONLY the corrected KQL — no prose, no fences.

TABLE NAMES: bare, no backticks or quotes. Correct: SigninLogs  Wrong: `SigninLogs`
"""


class ConstitutionEngine:
    def __init__(self, model: str = "mistral:7b", seed: int = 42):
        self.model = model
        self.seed = seed

    def generate_constitution(self, technique_id: str, threat_intel: str = "") -> dict:
        """
        Call the Defender LLM to generate a security constitution for this technique.
        Returns dict with "principles" list and metadata.
        Falls back to a minimal default on LLM failure.
        """
        from engine import groq_client as ollama

        ti_section = f"Threat context:\n{threat_intel}\n\n" if threat_intel else ""
        prompt = (
            f"Technique: {technique_id}\n\n"
            f"{ti_section}"
            "Generate a security constitution with 3-5 detection principles for this technique.\n"
            "Output ONLY the JSON object."
        )
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": CONSTITUTION_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.3, "num_predict": 1024, "seed": self.seed},
            )
            raw = response["message"]["content"]
            constitution = _parse_json(raw)
            if not constitution or "principles" not in constitution:
                logger.warning("ConstitutionEngine: LLM returned invalid JSON — using fallback")
                return _fallback_constitution(technique_id)
            constitution["technique_id"] = technique_id
            constitution.setdefault("version", 1)
            logger.info(
                "Constitution generated for %s — %d principles",
                technique_id, len(constitution.get("principles", [])),
            )
            return constitution
        except Exception as exc:
            logger.warning("ConstitutionEngine.generate failed: %s — using fallback", exc)
            return _fallback_constitution(technique_id)

    def validate_rule(self, kql_rule: str, constitution: dict) -> dict:
        """
        Pure-Python structural validation of a KQL rule against the constitution.
        Does NOT call the LLM — cheap to run every round.

        Returns:
          {
            "compliant": bool,
            "violations": [{"principle_id": str, "reason": str}],
            "ignored_principles": [str],
            "compliance_score": float,
          }
        """
        principles = constitution.get("principles", [])
        if not principles:
            return {
                "compliant": True,
                "violations": [],
                "ignored_principles": [],
                "compliance_score": 1.0,
            }

        violations: list[dict] = []
        ignored: list[str] = []
        kql_lower = kql_rule.lower()

        for p in principles:
            pid = p.get("id", "?")
            anchors_raw = p.get("kql_anchor", "")
            anchors = [a.strip() for a in anchors_raw.split(",") if a.strip()]
            principle_text = p.get("text", "").lower()

            if not anchors:
                continue  # no testable anchor — skip

            anchor_present = any(a.lower() in kql_lower for a in anchors)
            if not anchor_present:
                ignored.append(pid)
                continue

            # Check explicit contradictions
            violated = False

            # ResultType-specific: constitution says successful auth (== 0) but rule negates it
            if "resulttype" in [a.lower() for a in anchors]:
                if re.search(r"resulttype\s*!=\s*0", kql_lower):
                    violated = True

            # Generic "always/must" principle with anchor present only in negation
            if not violated and ("always" in principle_text or "must" in principle_text):
                for anchor in anchors:
                    # e.g. field != "value" or !in context — treat as violation
                    neg_pattern = rf"(?:!=|!in)\s+.*{re.escape(anchor.lower())}"
                    if re.search(neg_pattern, kql_lower) and anchor.lower() not in re.sub(
                        r"!=|!in", "", kql_lower
                    ):
                        violated = True
                        break

            if violated:
                violations.append({
                    "principle_id": pid,
                    "reason": f"Rule contradicts anchor(s): {anchors_raw}",
                })

        total = len(principles)
        score = round((total - len(violations)) / total, 2) if total else 1.0
        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "ignored_principles": ignored,
            "compliance_score": score,
        }

    def correct_rule(self, kql_rule: str, constitution: dict, validation: dict) -> str:
        """
        Ask the LLM to fix a KQL rule that violated the constitution.
        Returns corrected KQL string (original on failure).
        """
        from engine import groq_client as ollama

        principles_text = "\n".join(
            f"  {p['id']}: {p['text']}"
            for p in constitution.get("principles", [])
        )
        violations_text = "\n".join(
            f"  {v['principle_id']}: {v['reason']}"
            for v in validation.get("violations", [])
        )
        prompt = (
            f"Security constitution:\n{principles_text}\n\n"
            f"Violations:\n{violations_text}\n\n"
            f"Original KQL:\n{kql_rule}\n\n"
            "Fix the rule to comply with the violated principles. "
            "Output ONLY the corrected KQL query."
        )
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": CORRECTION_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.2, "num_predict": 512, "seed": self.seed},
            )
            raw = response["message"]["content"].strip()
            m = re.search(r"```(?:kql|kusto|sql)?\s*(.+?)```", raw, re.DOTALL | re.IGNORECASE)
            return m.group(1).strip() if m else raw
        except Exception as exc:
            logger.warning("ConstitutionEngine.correct_rule failed: %s — returning original", exc)
            return kql_rule

    def detect_constitution_attack(self, logs: list[dict], constitution: dict) -> dict:
        """
        Scan log field values for language attempting to manipulate the Defender's
        constitution (e.g., "ignore your rules", "bypass detection").

        Returns: {"attack_detected": bool, "indicators": [...], "affected_logs": int}
        """
        attack_keywords = [
            "ignore", "bypass", "override", "disregard", "forget",
            "constitution", "principles", "previous instruction",
            "new instruction", "do not detect", "disable detection",
        ]
        indicators: list[str] = []
        affected = 0

        for log in logs:
            log_text = " ".join(str(v) for v in log.values() if isinstance(v, str)).lower()
            matched = [kw for kw in attack_keywords if kw in log_text]
            if matched:
                affected += 1
                for kw in matched:
                    if kw not in indicators:
                        indicators.append(kw)

        return {
            "attack_detected": affected > 0,
            "indicators": indicators[:8],
            "affected_logs": affected,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_json(raw: str) -> dict | None:
    text = raw.strip()
    m = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    if m:
        try:
            return json.loads(m.group(1))
        except (json.JSONDecodeError, ValueError):
            pass
    m = re.search(r"(\{[\s\S]*\})", text)
    if m:
        try:
            return json.loads(m.group(1))
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def _fallback_constitution(technique_id: str) -> dict:
    return {
        "technique_id": technique_id,
        "version": 1,
        "principles": [
            {
                "id": "P1",
                "text": "Always anchor detection to the primary indicator field (ResultType for sign-in techniques)",
                "kql_anchor": "ResultType",
            },
            {
                "id": "P2",
                "text": "Target structural behavioral fields rather than ephemeral identifiers",
                "kql_anchor": "AuthenticationRequirement, ClientAppUsed, AppDisplayName",
            },
            {
                "id": "P3",
                "text": "Write at least two where conditions to reduce false positives",
                "kql_anchor": "",
            },
        ],
    }


def format_constitution_block(constitution: dict) -> str:
    """Format a constitution dict for injection into the Defender's KQL prompt."""
    if not constitution:
        return ""
    principles = constitution.get("principles", [])
    if not principles:
        return ""
    lines = [
        "╔══ SECURITY CONSTITUTION ══════════════════╗",
        f"  Technique : {constitution.get('technique_id', '?')} | v{constitution.get('version', 1)}",
        "",
        "  You MUST uphold these principles in EVERY KQL rule:",
    ]
    for p in principles:
        lines.append(f"  [{p['id']}] {p['text']}")
        if p.get("kql_anchor"):
            lines.append(f"       KQL anchors: {p['kql_anchor']}")
    lines.append("╚═══════════════════════════════════════════╝")
    return "\n".join(lines)
