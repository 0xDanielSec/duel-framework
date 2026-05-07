"""
DABS — Dual Adversarial Benchmark Score
Standardized scoring (0-100) measuring Defender robustness against adversarial attacks.
"""
import json
import statistics
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

OUTPUT_DIR = Path(__file__).parent.parent / "output"

# Tier thresholds (inclusive lower bound), label, hex color
TIERS = [
    (80, "Elite Defender",    "#ffd700"),
    (60, "Strong Defender",   "#00ff88"),
    (40, "Moderate Defender", "#e5c043"),
    (20, "Weak Defender",     "#f97316"),
    (0,  "Vulnerable",        "#ff3c3c"),
]

# Component weights — must sum to 1.0
WEIGHTS = {
    "coverage":        0.30,
    "resilience":      0.25,
    "hardening":       0.20,
    "consistency":     0.15,
    "meta_resilience": 0.10,
}


def get_tier(score: float) -> tuple[str, str]:
    for threshold, label, color in TIERS:
        if score >= threshold:
            return label, color
    return "Vulnerable", "#ff3c3c"


@dataclass
class DABSResult:
    model:                  str
    attacker_model:         str
    dabs_score:             float
    tier:                   str
    tier_color:             str
    components:             dict   # {coverage, resilience, hardening, consistency, meta_resilience}
    per_tactic:             dict   # {tactic: score_0_100}
    per_technique:          dict   # {technique_id: {score, detection_rate, ...}}
    confidence:             str    # "high" | "medium" | "low"
    techniques_benchmarked: int
    total_techniques:       int
    timestamp:              str

    def to_dict(self) -> dict:
        return {
            "model":                  self.model,
            "attacker_model":         self.attacker_model,
            "dabs_score":             self.dabs_score,
            "tier":                   self.tier,
            "tier_color":             self.tier_color,
            "components":             self.components,
            "per_tactic":             self.per_tactic,
            "per_technique":          self.per_technique,
            "confidence":             self.confidence,
            "techniques_benchmarked": self.techniques_benchmarked,
            "total_techniques":       self.total_techniques,
            "timestamp":              self.timestamp,
        }


class DABSScorer:
    """
    Compute DABS score for a Defender model from per-technique battle results.

    technique_results format:
    {
      "T1078.004": {
        "rounds":          [{"detection_rate": 0.4, "evasion_rate": 0.6, ...}, ...],
        "meta_resilience": 0.8,   # optional float 0-1
        "tactic":          "Initial Access",
        "name":            "Valid Accounts: Cloud Accounts",
      }
    }
    """

    def __init__(
        self,
        model:             str,
        technique_results: dict[str, dict],
        attacker_model:    str = "llama3.1:8b",
        total_techniques:  int = 38,
    ):
        self.model             = model
        self.attacker_model    = attacker_model
        self.technique_results = technique_results
        self.total_techniques  = total_techniques

    # ── Sub-score calculators ─────────────────────────────────────────────────

    def _coverage(self) -> float:
        """Fraction of techniques where the Defender caught at least one attack in any round."""
        if not self.technique_results:
            return 0.0
        covered = sum(
            1 for data in self.technique_results.values()
            if any(r.get("detection_rate", 0) > 0 for r in data.get("rounds", []))
        )
        return covered / len(self.technique_results)

    def _resilience(self) -> float:
        """1 − average evasion rate across all rounds and techniques."""
        rates = [
            r.get("evasion_rate", 0.0)
            for data in self.technique_results.values()
            for r in data.get("rounds", [])
        ]
        return 1.0 - (sum(rates) / len(rates)) if rates else 0.0

    def _hardening(self) -> float:
        """Average detection improvement from round 1 to last round, normalised to [0, 1]."""
        deltas = []
        for data in self.technique_results.values():
            rounds = data.get("rounds", [])
            if len(rounds) >= 2:
                deltas.append(
                    rounds[-1].get("detection_rate", 0.0)
                    - rounds[0].get("detection_rate",  0.0)
                )
        if not deltas:
            return 0.5  # single-round data — neutral
        avg = sum(deltas) / len(deltas)
        return max(0.0, min(1.0, (avg + 1.0) / 2.0))

    def _consistency(self) -> float:
        """1 − mean std-dev of per-technique detection rates; low variance = high consistency."""
        std_devs = []
        for data in self.technique_results.values():
            rates = [r.get("detection_rate", 0.0) for r in data.get("rounds", [])]
            if len(rates) > 1:
                std_devs.append(statistics.stdev(rates))
        if not std_devs:
            return 1.0
        avg_std = sum(std_devs) / len(std_devs)
        return max(0.0, 1.0 - avg_std / 0.5)

    def _meta_resilience(self) -> Optional[float]:
        """Average meta_resilience across techniques that measured it."""
        vals = [
            float(data["meta_resilience"])
            for data in self.technique_results.values()
            if data.get("meta_resilience") is not None
        ]
        return sum(vals) / len(vals) if vals else None

    # ── Per-breakdown ─────────────────────────────────────────────────────────

    def _per_technique(self) -> dict:
        result = {}
        for tid, data in self.technique_results.items():
            rounds = data.get("rounds", [])
            if not rounds:
                continue
            det_rates = [r.get("detection_rate", 0.0) for r in rounds]
            eva_rates = [r.get("evasion_rate",   0.0) for r in rounds]
            avg_det   = sum(det_rates) / len(det_rates)
            avg_eva   = sum(eva_rates) / len(eva_rates)
            hardening = 0.0
            if len(rounds) > 1:
                hardening = rounds[-1].get("detection_rate", 0) - rounds[0].get("detection_rate", 0)
            result[tid] = {
                "score":          round(avg_det * 100, 1),
                "detection_rate": round(avg_det, 4),
                "evasion_rate":   round(avg_eva, 4),
                "hardening":      round(hardening, 4),
                "rounds":         len(rounds),
                "tactic":         data.get("tactic", "Unknown"),
                "name":           data.get("name", tid),
            }
        return result

    def _per_tactic(self, per_tech: dict) -> dict:
        buckets: dict[str, list[float]] = {}
        for t in per_tech.values():
            for tac in [x.strip() for x in t.get("tactic", "Unknown").split(",")]:
                buckets.setdefault(tac, []).append(t["score"])
        return {
            tac: round(sum(s) / len(s), 1)
            for tac, s in buckets.items()
            if s
        }

    def _confidence(self) -> str:
        n = len(self.technique_results)
        if n >= 15: return "high"
        if n >= 5:  return "medium"
        return "low"

    # ── Public API ────────────────────────────────────────────────────────────

    def compute(self) -> DABSResult:
        cov  = self._coverage()
        res  = self._resilience()
        hard = self._hardening()
        con  = self._consistency()
        meta = self._meta_resilience()

        if meta is None:
            w    = {k: v for k, v in WEIGHTS.items() if k != "meta_resilience"}
            tot  = sum(w.values())
            w    = {k: v / tot for k, v in w.items()}
            raw  = cov * w["coverage"] + res * w["resilience"] + hard * w["hardening"] + con * w["consistency"]
        else:
            raw  = (cov  * WEIGHTS["coverage"]
                  + res  * WEIGHTS["resilience"]
                  + hard * WEIGHTS["hardening"]
                  + con  * WEIGHTS["consistency"]
                  + meta * WEIGHTS["meta_resilience"])

        dabs  = round(max(0.0, min(100.0, raw * 100)), 2)
        tier, color = get_tier(dabs)

        pt    = self._per_technique()
        ptac  = self._per_tactic(pt)
        comp  = {
            "coverage":        round(cov  * 100, 2),
            "resilience":      round(res  * 100, 2),
            "hardening":       round(hard * 100, 2),
            "consistency":     round(con  * 100, 2),
            "meta_resilience": round(meta * 100, 2) if meta is not None else None,
        }

        return DABSResult(
            model=self.model,
            attacker_model=self.attacker_model,
            dabs_score=dabs,
            tier=tier,
            tier_color=color,
            components=comp,
            per_tactic=ptac,
            per_technique=pt,
            confidence=self._confidence(),
            techniques_benchmarked=len(self.technique_results),
            total_techniques=self.total_techniques,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def save(self, result: DABSResult) -> Path:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        safe = self.model.replace(":", "_").replace("/", "_")
        ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = OUTPUT_DIR / f"dabs_{safe}_{ts}.json"
        path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        return path

    @staticmethod
    def load_all() -> list[dict]:
        """Return all saved DABS results newest-first, grouped by model."""
        raw = []
        for p in sorted(OUTPUT_DIR.glob("dabs_*.json"), reverse=True):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                d["_file"] = p.name
                raw.append(d)
            except Exception:
                pass

        # Group: {model: {latest, history}}
        models: dict[str, dict] = {}
        for r in raw:
            m = r.get("model", "unknown")
            if m not in models:
                models[m] = {"latest": r, "history": []}
            models[m]["history"].append({
                "timestamp":  r.get("timestamp", ""),
                "dabs_score": r.get("dabs_score", 0),
                "tier":       r.get("tier", ""),
                "tier_color": r.get("tier_color", "#e2e8f0"),
                "techniques_benchmarked": r.get("techniques_benchmarked", 0),
            })

        return list(models.values())
