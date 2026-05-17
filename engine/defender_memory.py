"""
Persistent defender memory — tracks successful KQL rules and field insights
across all battles so the Defender starts each new run with proven detection patterns.
"""

import json
import logging
import re
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).parent.parent / "output"

TRACK_FIELDS = [
    "table", "IPAddress", "CountryOrRegion", "City", "Location",
    "UserAgent", "ClientAppUsed", "AppDisplayName",
    "ResultType", "ResultDescription",
    "AuthenticationRequirement", "ConditionalAccessStatus",
    "RiskLevelDuringSignIn", "RiskState",
    "EventID", "LogonType", "Status",
    "OperationName", "Result", "Category",
]

_KW = {"by", "and", "or", "not", "bin", "count", "true", "false", "asc", "desc"}


class DefenderMemory:
    """
    Reads/writes output/defender_memory.json.
    Accumulates successful KQL rules and field effectiveness across all battles — never resets.
    """

    MEMORY_PATH = OUTPUT_DIR / "defender_memory.json"
    MAX_RULES = 10  # max successful rules per technique

    def __init__(self):
        self._data: dict = self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> dict:
        try:
            if self.MEMORY_PATH.exists():
                with open(self.MEMORY_PATH, encoding="utf-8") as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load defender memory: %s", exc)
        return {}

    def _save(self) -> None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        with open(self.MEMORY_PATH, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, default=str)

    # ------------------------------------------------------------------
    # Technique record accessors
    # ------------------------------------------------------------------

    def _get_technique(self, technique_id: str) -> dict:
        if technique_id not in self._data:
            self._data[technique_id] = {
                "successful_rules": [],
                "failed_patterns": [],
                "best_fields": {},
                "worst_fields": {},
                "total_battles": 0,
                "total_rounds": 0,
            }
        return self._data[technique_id]

    # ------------------------------------------------------------------
    # Core update
    # ------------------------------------------------------------------

    def update_from_battle(self, battle_log: dict) -> None:
        """
        Parse a full_battle_log dict (as produced by BattleScorer) and merge
        successful KQL rules and field effectiveness into persistent memory.
        """
        tid = battle_log.get("technique_id")
        if not tid:
            logger.warning("update_from_battle: missing technique_id")
            return

        tech = self._get_technique(tid)
        tech["total_battles"] += 1

        best_counts:  Counter = Counter(tech.get("best_fields", {}))
        worst_counts: Counter = Counter(tech.get("worst_fields", {}))

        for round_rec in battle_log.get("rounds", []):
            tech["total_rounds"] += 1
            kql            = round_rec.get("kql_rule", "")
            detection_rate = round_rec.get("detection_rate", 0.0)
            kql_valid      = round_rec.get("kql_valid", False)

            if not kql or not kql_valid:
                continue

            rule_fields = _extract_kql_fields(kql)

            if detection_rate > 0:
                # Successful rule — record it and credit its fields
                tech["successful_rules"].append({
                    "round":          round_rec["round"],
                    "detection_rate": detection_rate,
                    "kql":            kql,
                    "timestamp":      round_rec.get("timestamp", ""),
                })
                for field in rule_fields:
                    if field in TRACK_FIELDS:
                        best_counts[field] += 1
            else:
                # Zero-detection round — record failed patterns and penalise fields
                for cond in _extract_conditions_text(kql)[:3]:
                    if cond not in tech["failed_patterns"]:
                        tech["failed_patterns"].append(cond)
                for field in rule_fields:
                    if field in TRACK_FIELDS:
                        worst_counts[field] += 1

        tech["best_fields"]  = dict(best_counts.most_common(20))
        tech["worst_fields"] = dict(worst_counts.most_common(20))

        # Keep top MAX_RULES by detection_rate; break ties by round (prefer later)
        tech["successful_rules"] = sorted(
            tech["successful_rules"],
            key=lambda r: (r["detection_rate"], r["round"]),
            reverse=True,
        )[:self.MAX_RULES]

        tech["failed_patterns"] = tech["failed_patterns"][-20:]

        self._save()
        logger.info(
            "Defender memory updated for %s: %d battles, %d successful rules",
            tid, tech["total_battles"], len(tech["successful_rules"]),
        )

    # ------------------------------------------------------------------
    # Prompt context injection
    # ------------------------------------------------------------------

    def get_context(self, technique_id: str) -> str:
        """
        Return a structured memory block to inject into the Defender's initial prompt.
        Returns empty string if no memory exists for this technique yet.
        """
        tech = self._data.get(technique_id)
        if not tech or tech.get("total_rounds", 0) == 0:
            return ""

        rules = tech.get("successful_rules", [])
        if not rules:
            return ""

        lines = [
            "╔══ PERSISTENT DEFENDER MEMORY ══╗",
            f"  Technique : {technique_id}",
            f"  Battles   : {tech['total_battles']} | Rounds: {tech['total_rounds']}",
            f"  Best rules: {len(rules)} on record",
            "",
            "▶ TOP PERFORMING RULES  (use as starting point — adapt values to current logs):",
        ]
        for rule in rules[:3]:
            rate_pct = f"{rule['detection_rate']:.0%}"
            # Compact one-liner preview
            parts = [l.strip().lstrip("| ") for l in rule["kql"].strip().splitlines()]
            preview = " | ".join(p for p in parts if p)[:200]
            lines.append(f"  [{rate_pct}] {preview}")

        best = tech.get("best_fields", {})
        lines += ["", "▶ HIGH-VALUE FIELDS  (consistently contributed to detection — prioritize):"]
        if best:
            top = sorted(best.items(), key=lambda kv: kv[1], reverse=True)[:6]
            lines.append("    " + " | ".join(f for f, _ in top))
        else:
            lines.append("    (none identified yet)")

        worst = tech.get("worst_fields", {})
        lines += ["", "✖ LOW-VALUE FIELDS  (Attacker rotated away — avoid over-relying on these):"]
        if worst:
            top_w = sorted(worst.items(), key=lambda kv: kv[1], reverse=True)[:4]
            lines.append("    " + " | ".join(f for f, _ in top_w))
        else:
            lines.append("    (none identified yet)")

        failed = tech.get("failed_patterns", [])
        lines += ["", "✖ FAILED PATTERNS  (zero-detection conditions — avoid repeating):"]
        if failed:
            for p in failed[-4:]:
                lines.append(f"    {p}")
        else:
            lines.append("    (none recorded)")

        lines.append("╚═══════════════════════════════╝")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # API surface
    # ------------------------------------------------------------------

    def get_all(self) -> dict:
        """Return summary of full memory store — used by /api/defender_memory."""
        out = {}
        for tid, tech in self._data.items():
            rules = tech.get("successful_rules", [])
            best  = tech.get("best_fields", {})
            worst = tech.get("worst_fields", {})
            out[tid] = {
                "total_battles":          tech.get("total_battles", 0),
                "total_rounds":           tech.get("total_rounds", 0),
                "successful_rules_count": len(rules),
                "best_rules": [
                    {
                        "round":          r["round"],
                        "detection_rate": r["detection_rate"],
                        "kql_preview":    r["kql"].strip()[:300],
                    }
                    for r in rules[:3]
                ],
                "best_fields":    sorted(best.items(),  key=lambda kv: kv[1], reverse=True)[:8],
                "worst_fields":   sorted(worst.items(), key=lambda kv: kv[1], reverse=True)[:6],
                "failed_patterns": tech.get("failed_patterns", [])[-5:],
            }
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_kql_fields(kql: str) -> set[str]:
    """Extract field names referenced in a KQL rule (mirrors scoring.py logic)."""
    fields: set[str] = set()
    patterns = [
        r'\b([A-Za-z_]\w*)\s*(?:==|!=|>=|<=|>|<|contains|has|startswith|endswith|in~?|matches)',
        r'(?:isempty|isnotempty|isnull|isnotnull|dcount|count_if)\(([A-Za-z_]\w*)\)',
        r'\bby\s+([A-Za-z_]\w*)',
        r'\bproject(?:-away)?\s+((?:[A-Za-z_]\w*\s*,\s*)*[A-Za-z_]\w*)',
    ]
    for pat in patterns:
        for m in re.finditer(pat, kql, re.IGNORECASE):
            for name in re.split(r"\s*,\s*", m.group(1)):
                name = name.strip()
                if name and name.lower() not in _KW:
                    fields.add(name)
    return fields


def _extract_conditions_text(kql: str) -> list[str]:
    """Extract individual where-clause condition strings as short text fragments."""
    conditions = []
    for line in kql.splitlines():
        stripped = line.strip()
        if re.match(r"^\|\s*where\b", stripped, re.IGNORECASE):
            cond = re.sub(r"^\|\s*where\s+", "", stripped, count=1, flags=re.IGNORECASE)
            if cond:
                conditions.append(cond[:100])
    return conditions
