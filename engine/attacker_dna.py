"""
DUEL — Attacker DNA Fingerprinting
Computes a 6-dimension behavioral fingerprint per Ollama model used as Attacker.
"""

import json
import re
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

_SKIP_FIELDS = frozenset({"_duel_id", "table", "TimeGenerated", "CorrelationId", "timestamp"})

_PERSONALITY_COLORS = {
    "Ghost":      "#a78bfa",
    "Berserker":  "#ff3c3c",
    "Strategist": "#ffd700",
    "Chameleon":  "#00ff88",
    "Novice":     "#718096",
}

_DIM_COLORS = {
    "field_preference_score": "#06b6d4",
    "evasion_innovation":     "#a78bfa",
    "reaction_speed":         "#ffd700",
    "risk_tolerance":         "#ff3c3c",
    "persistence":            "#3c8eff",
    "adaptability":           "#00ff88",
}

_DIM_LABELS = {
    "field_preference_score": "FIELD PREF",
    "evasion_innovation":     "INNOVATION",
    "reaction_speed":         "REACTION",
    "risk_tolerance":         "RISK TOLER.",
    "persistence":            "PERSISTENCE",
    "adaptability":           "ADAPTABILITY",
}


class DNAAnalyzer:
    def __init__(self):
        self._battles: list[dict] = []

    # ── Data loading ─────────────────────────────────────────────────────────

    def _load(self) -> None:
        self._battles = []
        for path in sorted(OUTPUT_DIR.glob("full_battle_log_*.json")):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                data["_source_file"] = path.stem
                self._battles.append(data)
            except Exception:
                continue

    def _group_by_model(self) -> dict[str, list[dict]]:
        by_model: dict[str, list[dict]] = {}
        for battle in self._battles:
            model = battle.get("attacker_model", "llama3.1:8b")
            by_model.setdefault(model, []).append(battle)
        return by_model

    # ── Log field helpers ────────────────────────────────────────────────────

    def _log_fields(self, log: dict) -> dict[str, str]:
        return {
            k: str(v)
            for k, v in log.items()
            if k not in _SKIP_FIELDS
            and not k.startswith("_duel")
            and str(v).strip() not in ("", "none", "None", "{}", "null")
        }

    def _kql_fields(self, kql: str) -> set[str]:
        return set(_FIELD_RE.findall(kql))

    # ── Dimension: field_preference_score ────────────────────────────────────

    def _field_preference_score(self, battles: list[dict]) -> float:
        """Diversity of fields used in evaded logs across all rounds.
        Higher = attacker targets more field dimensions per round."""
        counts_per_round: list[int] = []
        for battle in battles:
            for rnd in battle.get("rounds", []):
                fields: set[str] = set()
                for log in rnd.get("evaded_logs", []):
                    fields.update(self._log_fields(log).keys())
                if fields:
                    counts_per_round.append(len(fields))

        if not counts_per_round:
            return 0.0
        avg = sum(counts_per_round) / len(counts_per_round)
        # 3 fields → 0.0 | 15 fields → 1.0
        return min(1.0, max(0.0, (avg - 3) / 12))

    # ── Dimension: evasion_innovation ────────────────────────────────────────

    def _evasion_innovation(self, battles: list[dict]) -> float:
        """Ratio of new field values introduced each round vs total values seen.
        Higher = attacker invents fresh evasion values rather than repeating old ones."""
        changed = 0
        total = 0
        for battle in battles:
            rounds = battle.get("rounds", [])
            if len(rounds) < 2:
                continue
            prev: dict[str, set] = {}
            for rnd in rounds:
                curr: dict[str, set] = {}
                for log in rnd.get("evaded_logs", []):
                    for field, val in self._log_fields(log).items():
                        curr.setdefault(field, set()).add(val)
                for field, vals in curr.items():
                    old = prev.get(field, set())
                    if old:
                        new_vals = vals - old
                        changed += len(new_vals)
                        total += len(vals)
                prev = curr

        if total == 0:
            return 0.5
        return min(1.0, changed / total)

    # ── Dimension: reaction_speed ─────────────────────────────────────────────

    def _reaction_speed(self, battles: list[dict]) -> float:
        """Evasion improvement in the round immediately after being detected.
        Higher = attacker adapts quickly to a Defender win."""
        deltas: list[float] = []
        for battle in battles:
            rounds = battle.get("rounds", [])
            for i in range(len(rounds) - 1):
                det_rate = float(rounds[i].get("detection_rate", 0.0))
                if det_rate > 0.4:  # Defender was winning
                    curr_eva = float(rounds[i].get("evasion_rate", 0.0))
                    next_eva = float(rounds[i + 1].get("evasion_rate", 0.0))
                    deltas.append(next_eva - curr_eva)

        if not deltas:
            return 0.5
        avg = sum(deltas) / len(deltas)
        # avg ∈ [-1, 1] → score ∈ [0, 1] centered at 0.5
        return min(1.0, max(0.0, 0.5 + avg))

    # ── Dimension: risk_tolerance ─────────────────────────────────────────────

    def _risk_tolerance(self, battles: list[dict]) -> float:
        """Rate at which attacker reuses fields the Defender has already targeted.
        Higher = attacker boldly reuses burned fields (risky)."""
        reused = 0
        total_targeted = 0
        for battle in battles:
            rounds = battle.get("rounds", [])
            for i in range(len(rounds) - 1):
                targeted = self._kql_fields(rounds[i].get("kql_rule", ""))
                next_fields: set[str] = set()
                for log in rounds[i + 1].get("evaded_logs", []):
                    next_fields.update(self._log_fields(log).keys())
                for field in targeted:
                    total_targeted += 1
                    if field in next_fields:
                        reused += 1

        if total_targeted == 0:
            return 0.5
        return reused / total_targeted

    # ── Dimension: persistence ────────────────────────────────────────────────

    def _persistence(self, battles: list[dict]) -> float:
        """Field-set overlap between consecutive winning rounds.
        Higher = attacker sticks to a working strategy rather than constantly mutating."""
        similarities: list[float] = []
        for battle in battles:
            rounds = battle.get("rounds", [])
            for i in range(len(rounds) - 1):
                if float(rounds[i].get("evasion_rate", 0.0)) < 0.5:
                    continue  # Only measure while attacker is winning
                curr: set[str] = set()
                nxt: set[str] = set()
                for log in rounds[i].get("evaded_logs", []):
                    curr.update(self._log_fields(log).keys())
                for log in rounds[i + 1].get("evaded_logs", []):
                    nxt.update(self._log_fields(log).keys())
                if curr and nxt:
                    union = len(curr | nxt)
                    jaccard = len(curr & nxt) / union if union else 0.0
                    similarities.append(jaccard)

        if not similarities:
            return 0.5
        return sum(similarities) / len(similarities)

    # ── Dimension: adaptability ───────────────────────────────────────────────

    def _adaptability(self, battles: list[dict]) -> float:
        """Overall evasion improvement slope (first round → last round).
        Higher = attacker learns and improves across the session."""
        improvements: list[float] = []
        for battle in battles:
            rounds = battle.get("rounds", [])
            if len(rounds) < 2:
                continue
            first = float(rounds[0].get("evasion_rate", 0.0))
            last  = float(rounds[-1].get("evasion_rate", 0.0))
            improvements.append(last - first)

        if not improvements:
            return 0.5
        avg = sum(improvements) / len(improvements)
        # avg ∈ [-1, 1] → score ∈ [0, 1]
        return min(1.0, max(0.0, (avg + 1.0) / 2))

    # ── Personality classification ────────────────────────────────────────────

    def _personality(self, dims: dict) -> tuple[str, str]:
        ei = dims["evasion_innovation"]
        rs = dims["reaction_speed"]
        rt = dims["risk_tolerance"]
        pe = dims["persistence"]
        fi = dims["field_preference_score"]
        ad = dims["adaptability"]
        avg = sum(dims.values()) / len(dims)

        if avg < 0.35:
            return "Novice", _PERSONALITY_COLORS["Novice"]
        if ei > 0.6 and ad > 0.6 and rt < 0.4:
            return "Ghost", _PERSONALITY_COLORS["Ghost"]
        if rt > 0.6 and rs > 0.6:
            return "Berserker", _PERSONALITY_COLORS["Berserker"]
        if pe > 0.6 and fi > 0.6:
            return "Strategist", _PERSONALITY_COLORS["Strategist"]
        if ei > 0.6 and ad > 0.6:
            return "Chameleon", _PERSONALITY_COLORS["Chameleon"]

        # Fallback: dominant dimension decides
        top = max(dims, key=dims.get)
        if top in ("evasion_innovation", "adaptability"):
            return "Chameleon", _PERSONALITY_COLORS["Chameleon"]
        if top in ("risk_tolerance", "reaction_speed"):
            return "Berserker", _PERSONALITY_COLORS["Berserker"]
        if top in ("persistence", "field_preference_score"):
            return "Strategist", _PERSONALITY_COLORS["Strategist"]
        return "Novice", _PERSONALITY_COLORS["Novice"]

    # ── Model stats ───────────────────────────────────────────────────────────

    def _model_stats(self, battles: list[dict]) -> dict:
        total_rounds = sum(b.get("total_rounds", 0) for b in battles)
        techniques = {b.get("technique_id", "") for b in battles if b.get("technique_id")}
        all_evasion = [
            float(r.get("evasion_rate", 0.0))
            for b in battles for r in b.get("rounds", [])
        ]
        avg_evasion = sum(all_evasion) / len(all_evasion) if all_evasion else 0.0
        wins = sum(1 for b in battles if b.get("winner") == "Attacker")
        return {
            "total_battles":    len(battles),
            "total_rounds":     total_rounds,
            "total_techniques": len(techniques),
            "techniques":       sorted(techniques),
            "avg_evasion_rate": round(avg_evasion, 4),
            "attacker_wins":    wins,
            "win_rate":         round(wins / len(battles), 4) if battles else 0.0,
        }

    # ── Technique breakdown ───────────────────────────────────────────────────

    def _technique_breakdown(self, battles: list[dict]) -> list[dict]:
        """Top techniques by average evasion rate across all battles."""
        by_tech: dict[str, list[float]] = {}
        battle_counts: dict[str, int] = {}
        for battle in battles:
            tid = battle.get("technique_id", "")
            if not tid:
                continue
            rates = [float(r.get("evasion_rate", 0.0)) for r in battle.get("rounds", [])]
            if rates:
                by_tech.setdefault(tid, []).extend(rates)
                battle_counts[tid] = battle_counts.get(tid, 0) + 1
        rows = [
            {
                "technique_id":    tid,
                "avg_evasion_rate": round(sum(vals) / len(vals), 4),
                "battle_count":    battle_counts.get(tid, 0),
            }
            for tid, vals in by_tech.items()
        ]
        return sorted(rows, key=lambda r: r["avg_evasion_rate"], reverse=True)[:5]

    # ── Battle timeline ───────────────────────────────────────────────────────

    def _battle_timeline(self, battles: list[dict]) -> list[dict]:
        """Last 5 battles in chronological order with date, technique, evasion."""
        entries = []
        for battle in battles:
            tid    = battle.get("technique_id", "")
            rounds = battle.get("rounds", [])
            if not rounds:
                continue
            ts = next((r.get("timestamp", "") for r in rounds if r.get("timestamp")), "")
            date_str = ts[:10] if len(ts) >= 10 else "unknown"
            final_evasion = float(rounds[-1].get("evasion_rate", 0.0))
            entries.append({
                "technique_id":  tid,
                "date":          date_str,
                "timestamp":     ts,
                "final_evasion": round(final_evasion, 4),
                "winner":        battle.get("winner", ""),
            })
        entries.sort(key=lambda e: (e["timestamp"], e["technique_id"]))
        return entries[-5:]

    # ── DNA strand segments ───────────────────────────────────────────────────

    def _dna_strand(self, dims: dict) -> list[dict]:
        return [
            {
                "key":   k,
                "label": _DIM_LABELS[k],
                "score": round(dims[k], 4),
                "color": _DIM_COLORS[k],
            }
            for k in dims
        ]

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self) -> dict:
        self._load()
        by_model = self._group_by_model()
        fingerprints: dict[str, dict] = {}
        for model, battles in by_model.items():
            dims = {
                "field_preference_score": round(self._field_preference_score(battles), 4),
                "evasion_innovation":     round(self._evasion_innovation(battles), 4),
                "reaction_speed":         round(self._reaction_speed(battles), 4),
                "risk_tolerance":         round(self._risk_tolerance(battles), 4),
                "persistence":            round(self._persistence(battles), 4),
                "adaptability":           round(self._adaptability(battles), 4),
            }
            personality, color = self._personality(dims)
            fingerprints[model] = {
                "model":                model,
                "personality":          personality,
                "color":                color,
                "dimensions":           dims,
                "dna_strand":           self._dna_strand(dims),
                "stats":                self._model_stats(battles),
                "technique_breakdown":  self._technique_breakdown(battles),
                "battle_timeline":      self._battle_timeline(battles),
            }
        return fingerprints

    def save(self) -> Path:
        data = self.analyze()
        path = OUTPUT_DIR / "attacker_dna.json"
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path
