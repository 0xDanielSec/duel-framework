"""
DUEL — Historical Analysis Engine
Computes cross-session attacker evolution statistics from all battle logs.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "output"

_FIELD_RE = re.compile(
    r"\b(UserPrincipalName|IPAddress|AppDisplayName|ResultType|EventID|Account|"
    r"Computer|OperationName|Location|CountryOrRegion|RiskLevelDuringSignIn|"
    r"LogonType|RiskState|AuthenticationRequirement|UserAgent|ClientAppUsed|"
    r"ConditionalAccessStatus|TimeGenerated|CorrelationId|City|Category|"
    r"ActivityDisplayName|InitiatedBy|TargetResources|Caller|"
    r"OperationNameValue|Level|OfficeWorkload|Operation|UserId|"
    r"SourceIP|DestinationIP|DeviceAction|ProcessName|CommandLine|"
    r"SubjectUserName|SubjectDomainName|ObjectName|ObjectType)\b"
)


class HistoricalAnalyzer:
    def __init__(self):
        self._battles: list[dict] = []
        self._loaded = False

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _load(self, technique_filter: str | None = None) -> None:
        if self._loaded and not technique_filter:
            return
        pattern = (
            f"full_battle_log_{technique_filter}.json"
            if technique_filter else "full_battle_log_*.json"
        )
        battles = []
        for path in sorted(OUTPUT_DIR.glob(pattern)):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue
            mtime = path.stat().st_mtime
            data["_session_date"] = datetime.fromtimestamp(
                mtime, tz=timezone.utc
            ).isoformat()
            data["_session_file"] = path.stem
            battles.append(data)
        self._battles = sorted(
            battles, key=lambda b: b.get("_session_date", "")
        )
        if not technique_filter:
            self._loaded = True

    def _kql_fields(self, kql: str) -> set[str]:
        return set(_FIELD_RE.findall(kql))

    # ── Public analysis methods ──────────────────────────────────────────────

    def evasion_trend(
        self, technique_filter: str | None = None
    ) -> dict[str, list[dict]]:
        """
        Per technique: list of {session, round, evasion_rate, detection_rate, timestamp}
        in chronological order.
        """
        self._load(technique_filter)
        trends: dict[str, list[dict]] = {}
        for battle in self._battles:
            tid = battle.get("technique_id", "")
            if not tid:
                continue
            for rnd in battle.get("rounds", []):
                ts = rnd.get("timestamp") or battle.get("_session_date", "")
                trends.setdefault(tid, []).append({
                    "session":        battle["_session_file"],
                    "round":          rnd.get("round", 0),
                    "evasion_rate":   round(float(rnd.get("evasion_rate", 0.0)), 4),
                    "detection_rate": round(float(rnd.get("detection_rate", 0.0)), 4),
                    "timestamp":      ts,
                })
        return trends

    def mutation_velocity(
        self, technique_filter: str | None = None
    ) -> dict[str, list[dict]]:
        """
        Per technique: KQL field delta between consecutive rounds.
        velocity = |fields_added| + |fields_removed|.
        """
        self._load(technique_filter)
        result: dict[str, list[dict]] = {}
        for battle in self._battles:
            tid = battle.get("technique_id", "")
            rounds = battle.get("rounds", [])
            if not tid or len(rounds) < 2:
                continue
            prev: set[str] | None = None
            for rnd in rounds:
                fields = self._kql_fields(rnd.get("kql_rule", ""))
                if prev is not None:
                    added   = sorted(fields - prev)
                    removed = sorted(prev - fields)
                    result.setdefault(tid, []).append({
                        "session":        battle["_session_file"],
                        "round":          rnd["round"],
                        "fields_added":   added,
                        "fields_removed": removed,
                        "velocity":       len(added) + len(removed),
                    })
                prev = fields
        return result

    def defender_improvement(
        self, technique_filter: str | None = None
    ) -> list[dict]:
        """
        Per technique per session: detection_rate change from round 1 to last round.
        Positive = Defender improved. Sorted descending by improvement.
        """
        self._load(technique_filter)
        rows: list[dict] = []
        for battle in self._battles:
            tid = battle.get("technique_id", "")
            rounds = [
                r for r in battle.get("rounds", [])
                if r.get("detection_rate") is not None
            ]
            if not tid or len(rounds) < 2:
                continue
            r1   = float(rounds[0]["detection_rate"])
            last = float(rounds[-1]["detection_rate"])
            rows.append({
                "technique_id":     tid,
                "session":          battle["_session_file"],
                "round_1_detection": round(r1, 4),
                "final_detection":   round(last, 4),
                "improvement":       round(last - r1, 4),
                "rounds":            len(rounds),
            })
        return sorted(rows, key=lambda x: x["improvement"], reverse=True)

    def attacker_learning(
        self, technique_filter: str | None = None
    ) -> list[dict]:
        """
        Per technique: evasion rate slope across all rounds.
        Positive improvement = Attacker progressively better at evasion.
        Sorted descending by improvement.
        """
        self._load(technique_filter)
        tech_evasions: dict[str, list[float]] = {}
        for battle in self._battles:
            tid = battle.get("technique_id", "")
            if not tid:
                continue
            for rnd in battle.get("rounds", []):
                tech_evasions.setdefault(tid, []).append(
                    float(rnd.get("evasion_rate", 0.0))
                )

        result = []
        for tid, evasions in tech_evasions.items():
            if len(evasions) < 2:
                continue
            improvement = evasions[-1] - evasions[0]
            result.append({
                "technique_id":  tid,
                "evasion_start": round(evasions[0], 4),
                "evasion_end":   round(evasions[-1], 4),
                "evasion_avg":   round(sum(evasions) / len(evasions), 4),
                "improvement":   round(improvement, 4),
                "total_rounds":  len(evasions),
            })
        return sorted(result, key=lambda x: x["improvement"], reverse=True)

    def field_rotation_map(
        self, technique_filter: str | None = None
    ) -> dict[str, int]:
        """
        Count how many times each Sentinel field is referenced across all KQL rules.
        Higher frequency = more consistently targeted by the Defender.
        """
        self._load(technique_filter)
        counts: dict[str, int] = {}
        for battle in self._battles:
            for rnd in battle.get("rounds", []):
                for field in self._kql_fields(rnd.get("kql_rule", "")):
                    counts[field] = counts.get(field, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def session_comparison(
        self, technique_filter: str | None = None
    ) -> dict[str, list[dict]]:
        """
        Per technique: one entry per battle session with aggregate stats.
        Useful for spotting techniques run multiple times.
        """
        self._load(technique_filter)
        by_tech: dict[str, list[dict]] = {}
        for battle in self._battles:
            tid = battle.get("technique_id", "")
            rounds = battle.get("rounds", [])
            if not tid or not rounds:
                continue
            evasions   = [float(r.get("evasion_rate", 0.0))   for r in rounds]
            detections = [float(r.get("detection_rate", 0.0)) for r in rounds]
            by_tech.setdefault(tid, []).append({
                "session":            battle["_session_file"],
                "session_date":       battle.get("_session_date", ""),
                "total_rounds":       len(rounds),
                "avg_evasion_rate":   round(sum(evasions)   / len(evasions),   4),
                "avg_detection_rate": round(sum(detections) / len(detections), 4),
                "final_evasion":      round(evasions[-1],   4),
                "final_detection":    round(detections[-1], 4),
                "winner":             battle.get("winner", ""),
            })
        return by_tech

    def analyze(self, technique_filter: str | None = None) -> dict:
        """Run all analyses and return a single combined dict."""
        self._load(technique_filter)
        return {
            "evasion_trend":        self.evasion_trend(technique_filter),
            "mutation_velocity":    self.mutation_velocity(technique_filter),
            "defender_improvement": self.defender_improvement(technique_filter),
            "attacker_learning":    self.attacker_learning(technique_filter),
            "field_rotation_map":   self.field_rotation_map(technique_filter),
            "session_comparison":   self.session_comparison(technique_filter),
            "total_battles":        len(self._battles),
            "total_techniques":     len({
                b.get("technique_id", "") for b in self._battles
                if b.get("technique_id")
            }),
        }
