"""
Persistent attacker memory — tracks evasion patterns across all battles
so the Attacker starts each new run already applying mutations that worked.
"""

import json
import logging
from collections import Counter, defaultdict
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

_EMPTY = {"", "none", "None", "null", "Null", "NULL", "{}", "[]"}


def _is_empty(v) -> bool:
    return str(v).strip() in _EMPTY


class MemoryStore:
    """
    Reads/writes output/attacker_memory.json.
    Accumulates evasion/detection patterns across all battles — never resets.
    """

    MEMORY_PATH = OUTPUT_DIR / "attacker_memory.json"
    MAX_ENTRIES = 100   # max evaded/detected entries per technique

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
            logger.warning("Failed to load attacker memory: %s", exc)
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
                "successful_evasions": [],
                "failed_mutations": [],
                "stable_signatures": {},
                "dangerous_fields": {},
                "evasion_patterns": [],
                "total_battles": 0,
                "total_rounds": 0,
            }
        return self._data[technique_id]

    # ------------------------------------------------------------------
    # Core update
    # ------------------------------------------------------------------

    def update_from_battle(self, battle_log: dict) -> None:
        """
        Parse a full_battle_log dict (as produced by BattleScorer) and
        merge all evasion/detection patterns into persistent memory.
        """
        tid = battle_log.get("technique_id")
        if not tid:
            logger.warning("update_from_battle: missing technique_id")
            return

        tech = self._get_technique(tid)
        tech["total_battles"] += 1

        for round_rec in battle_log.get("rounds", []):
            tech["total_rounds"] += 1
            evaded_logs   = round_rec.get("evaded_logs", [])
            detected_logs = round_rec.get("detected_logs", [])
            evasion_rate  = round_rec.get("evasion_rate", 0.0)

            # Successful evasions
            for log in evaded_logs:
                entry = {
                    k: str(v) for k, v in log.items()
                    if k in TRACK_FIELDS and not _is_empty(v)
                }
                if entry:
                    tech["successful_evasions"].append(entry)

            # Failed mutations
            for log in detected_logs:
                entry = {
                    k: str(v) for k, v in log.items()
                    if k in TRACK_FIELDS and not _is_empty(v)
                }
                if entry:
                    tech["failed_mutations"].append(entry)

            # Dangerous fields: values that consistently got caught
            for log in detected_logs:
                for field in TRACK_FIELDS:
                    v = log.get(field)
                    if v and not _is_empty(v):
                        sv = str(v)
                        tech["dangerous_fields"].setdefault(field, {})
                        tech["dangerous_fields"][field][sv] = (
                            tech["dangerous_fields"][field].get(sv, 0) + 1
                        )

            # High-level evasion pattern for successful rounds
            if evasion_rate > 0.5 and evaded_logs:
                pattern = self._derive_pattern(evaded_logs)
                if pattern:
                    tech["evasion_patterns"].append(pattern)

        # Stable signatures: fields consistent across all evaded logs
        tech["stable_signatures"] = self._compute_stable(tech["successful_evasions"])

        # Trim to stay bounded
        tech["successful_evasions"] = tech["successful_evasions"][-self.MAX_ENTRIES:]
        tech["failed_mutations"]    = tech["failed_mutations"][-self.MAX_ENTRIES:]
        tech["evasion_patterns"]    = tech["evasion_patterns"][-20:]

        self._save()
        logger.info(
            "Attacker memory updated for %s: %d battles, %d rounds",
            tid, tech["total_battles"], tech["total_rounds"],
        )

    # ------------------------------------------------------------------
    # Prompt context injection
    # ------------------------------------------------------------------

    def get_context(self, technique_id: str) -> str:
        """
        Return a structured memory summary to inject into the Attacker prompt.
        Empty string if no memory exists for this technique yet.
        """
        tech = self._data.get(technique_id)
        if not tech or tech.get("total_rounds", 0) == 0:
            return ""

        lines = [
            "╔══ PERSISTENT ATTACKER MEMORY ══╗",
            f"  Technique : {technique_id}",
            f"  Battles   : {tech['total_battles']} | Rounds: {tech['total_rounds']}",
            f"  Evasions  : {len(tech['successful_evasions'])} on record",
            "",
            "▶ SAFE FIELD VALUES  (consistently evaded detection — reuse these):",
        ]

        stable = tech.get("stable_signatures", {})
        if stable:
            for field, values in stable.items():
                vals_str = " | ".join(str(v) for v in values[:4])
                lines.append(f"    {field}: {vals_str}")
        else:
            lines.append("    (none recorded yet)")

        lines += ["", "✖ DANGEROUS VALUES  (triggered detection — AVOID):"]
        dangerous = tech.get("dangerous_fields", {})
        if dangerous:
            sorted_d = sorted(
                dangerous.items(),
                key=lambda kv: sum(kv[1].values()),
                reverse=True,
            )
            for field, val_counts in sorted_d[:6]:
                top = sorted(val_counts.items(), key=lambda x: x[1], reverse=True)[:3]
                bad_vals = " | ".join(v for v, _ in top)
                lines.append(f"    {field}: {bad_vals}")
        else:
            lines.append("    (none identified yet)")

        lines += ["", "▶ RECOMMENDED STRATEGY  (from past wins):"]
        patterns = tech.get("evasion_patterns", [])
        if patterns:
            for p in patterns[-4:]:
                lines.append(f"    • {p}")
        else:
            lines.append("    • rotate IPAddress and UserAgent each round")

        lines.append("╚════════════════════════════════╝")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # API surface
    # ------------------------------------------------------------------

    def get_all(self) -> dict:
        """Return summary of full memory store — used by /api/memory."""
        out = {}
        for tid, tech in self._data.items():
            # Count occurrences of each stable value from the evasion log
            field_val_counts: dict[str, Counter] = defaultdict(Counter)
            for entry in tech.get("successful_evasions", []):
                for field, val in entry.items():
                    field_val_counts[field][str(val)] += 1

            # stable_signatures: {field: [[value, count], ...]} — same format as dangerous_fields
            stable_with_counts = {
                field: [[v, field_val_counts[field].get(v, 0)] for v in vals]
                for field, vals in tech.get("stable_signatures", {}).items()
            }

            out[tid] = {
                "total_battles":     tech.get("total_battles", 0),
                "total_rounds":      tech.get("total_rounds", 0),
                "evasion_count":     len(tech.get("successful_evasions", [])),
                "stable_signatures": stable_with_counts,
                "dangerous_fields": {
                    field: sorted(vals.items(), key=lambda x: x[1], reverse=True)[:5]
                    for field, vals in tech.get("dangerous_fields", {}).items()
                },
                "evasion_patterns": tech.get("evasion_patterns", [])[-10:],
            }
        return out

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_stable(evasions: list[dict]) -> dict[str, list[str]]:
        """Fields present in ≥60% of evaded logs — top-3 values each."""
        if not evasions:
            return {}
        total = len(evasions)
        field_counts: Counter = Counter()
        field_values: dict[str, Counter] = defaultdict(Counter)

        for entry in evasions:
            for field, val in entry.items():
                field_counts[field] += 1
                field_values[field][str(val)] += 1

        stable = {}
        for field, count in field_counts.items():
            if count / total >= 0.6:
                top = [v for v, _ in field_values[field].most_common(3)]
                stable[field] = top
        return stable

    @staticmethod
    def _derive_pattern(evaded_logs: list[dict]) -> str:
        """Derive a short evasion-pattern description from a successful round."""
        parts = []

        ua_vals = {str(l["UserAgent"]) for l in evaded_logs if l.get("UserAgent")}
        ip_vals = {str(l["IPAddress"]) for l in evaded_logs if l.get("IPAddress")}
        ca_vals = {str(l["ConditionalAccessStatus"]) for l in evaded_logs
                   if l.get("ConditionalAccessStatus")}
        ua_vals -= _EMPTY
        ip_vals -= _EMPTY
        ca_vals -= _EMPTY

        if len(ua_vals) > 1:
            parts.append(f"rotated {len(ua_vals)} UserAgents")
        elif ua_vals:
            parts.append(f"stable UserAgent: {next(iter(ua_vals))!r}")

        if len(ip_vals) > 2:
            parts.append(f"spread across {len(ip_vals)} IPs")
        elif ip_vals:
            parts.append(f"IPs: {', '.join(list(ip_vals)[:2])}")

        if ca_vals:
            parts.append(f"ConditionalAccess={next(iter(ca_vals))!r}")

        return "; ".join(parts)
