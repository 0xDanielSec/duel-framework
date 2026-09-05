"""
DABS — Dual Adversarial Benchmark Score
Standardized scoring (0-100) measuring Defender robustness against adversarial attacks.
"""
import json
import statistics
import subprocess
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

# Named, versioned weight profiles. A component missing from a profile is not
# scored under it at all (e.g. swarm_resilience doesn't exist in dabs_v1); a
# component present in the profile but with no data for this run is dropped
# and the remaining weights re-normalised — see compute(). Every profile's
# nominal weights must sum to 1.0.
WEIGHT_PROFILES: dict[str, dict[str, float]] = {
    # Weights exactly as declared in docs/paper.md §3.2. Table 1 (the published
    # 5-model scaling result) was computed under this profile. meta_resilience
    # was never populated for that run, so Table 1 actually used the 4-component
    # renormalised form (effective weights ≈ 33.3/27.8/22.2/16.7) — see
    # docs/ERRATA.md. swarm_resilience did not exist as a concept at v1.
    "dabs_v1": {
        "coverage":        0.30,
        "resilience":      0.25,
        "hardening":       0.20,
        "consistency":     0.15,
        "meta_resilience": 0.10,
    },
    # Current weights — added swarm_resilience, rebalanced the other five to
    # make room for it. This is the default for all new runs.
    "dabs_v2": {
        "coverage":          0.28,
        "resilience":        0.23,
        "hardening":         0.19,
        "consistency":       0.14,
        "meta_resilience":   0.08,
        "swarm_resilience":  0.08,
    },
}
DEFAULT_WEIGHT_PROFILE = "dabs_v2"


def get_pipeline_version() -> str:
    """
    "<short-commit-hash>@<YYYY-MM-DD>" for the currently checked-out code.
    Falls back to "unknown@<date>" outside a git repo (e.g. an installed
    package with no .git directory) rather than raising.
    """
    from datetime import datetime, timezone
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).parent.parent, text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        commit = "unknown"
    dirty = ""
    try:
        status = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=Path(__file__).parent.parent, text=True, stderr=subprocess.DEVNULL,
        )
        if status.strip():
            dirty = "-dirty"
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        pass
    return f"{commit}{dirty}@{date}"


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
    components:             dict   # {coverage, resilience, hardening, consistency, meta_resilience, swarm_resilience}
    per_tactic:             dict   # {tactic: score_0_100}
    per_technique:          dict   # {technique_id: {score, detection_rate, ...}}
    confidence:             str    # "high" | "medium" | "low"
    techniques_benchmarked: int
    total_techniques:       int
    timestamp:              str
    seed:                   int = 42
    excluded_components:    Optional[dict] = None  # {component: reason} — explicit, not silent None
    platform:               str = "ollama"  # "ollama" | "groq" — inference backend used to generate this result
    weight_profile:         str = DEFAULT_WEIGHT_PROFILE
    weights_nominal:        Optional[dict] = None  # profile's declared weights, unconditional
    weights_effective:      Optional[dict] = None  # after dropping missing/excluded components + renormalising
    pipeline_version:       str = "unknown"  # "<short-commit-hash>@<date>" — see DABSScorer docstring

    def to_dict(self) -> dict:
        return {
            "model":                  self.model,
            "attacker_model":         self.attacker_model,
            "platform":               self.platform,
            "pipeline_version":       self.pipeline_version,
            "seed":                   self.seed,
            "dabs_score":             self.dabs_score,
            "tier":                   self.tier,
            "tier_color":             self.tier_color,
            "weight_profile":         self.weight_profile,
            "weights_nominal":        self.weights_nominal or {},
            "weights_effective":      self.weights_effective or {},
            "components":             self.components,
            "excluded_components":    self.excluded_components or {},
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
        seed:              int = 42,
        swarm_results:     Optional[dict] = None,
        exclude_components: Optional[list[str]] = None,
        platform:          str = "ollama",
        weight_profile:    str = DEFAULT_WEIGHT_PROFILE,
        pipeline_version:  str = "unknown",
    ):
        """
        pipeline_version identifies the exact code that produced this score —
        recommended format "<short-commit-hash>@<YYYY-MM-DD>" (see
        get_pipeline_version() below). DABS is an absolute 0-100 score, but
        the underlying prompts/weights/detection logic change over time
        (see docs/ERRATA.md, docs/scaling_v2_results.md) — an absolute DABS
        value is only safely comparable to another value with the SAME
        pipeline_version. Comparing across pipeline_version values should
        use rank ordering and fitted trends (e.g. the scaling-law power fit),
        not raw score differences.
        """
        self.model             = model
        self.attacker_model    = attacker_model
        self.technique_results = technique_results
        self.total_techniques  = total_techniques
        self.seed              = seed
        self.swarm_results     = swarm_results   # optional: {technique_id: swarm_context}
        self.platform          = platform        # "ollama" | "groq" — must reflect the real inference backend
        self.pipeline_version  = pipeline_version
        if weight_profile not in WEIGHT_PROFILES:
            raise ValueError(
                f"Unknown weight_profile {weight_profile!r} — must be one of "
                f"{sorted(WEIGHT_PROFILES)}"
            )
        self.weight_profile = weight_profile
        # Components force-excluded for this experiment (e.g. reproducibility
        # against a baseline that never had them) — recorded explicitly in the
        # output rather than silently dropping to None + renormalising.
        self.exclude_components = set(exclude_components or [])

    # ── Sub-score calculators ─────────────────────────────────────────────────

    @staticmethod
    def _ok_rounds(data: dict) -> list[dict]:
        """
        Rounds that actually completed. A round marked timeout=True carries no
        detection_rate/evasion_rate — it means "we don't know", not "0% detected".
        Every numeric component below must use this instead of raw rounds so a
        timeout is excluded from the math rather than silently scored as a miss.
        """
        return [r for r in data.get("rounds", []) if not r.get("timeout")]

    def _coverage(self) -> float:
        """Fraction of techniques where the Defender caught at least one attack in any round."""
        if not self.technique_results:
            return 0.0
        covered = sum(
            1 for data in self.technique_results.values()
            if any(r.get("detection_rate", 0) > 0 for r in self._ok_rounds(data))
        )
        return covered / len(self.technique_results)

    def _resilience(self) -> float:
        """1 − average evasion rate across all completed rounds and techniques."""
        rates = [
            r.get("evasion_rate", 0.0)
            for data in self.technique_results.values()
            for r in self._ok_rounds(data)
        ]
        return 1.0 - (sum(rates) / len(rates)) if rates else 0.0

    def _hardening(self) -> float:
        """Average detection improvement from first to last COMPLETED round, normalised to [0, 1]."""
        deltas = []
        for data in self.technique_results.values():
            rounds = self._ok_rounds(data)
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
            rates = [r.get("detection_rate", 0.0) for r in self._ok_rounds(data)]
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

    def _swarm_resilience(self) -> Optional[float]:
        """
        Measures Defender robustness against a coordinated swarm attack.
        Computed as 1 - (average best-strategy evasion rate across all techniques
        that have swarm data).  Returns None when no swarm data was supplied.
        """
        if not self.swarm_results:
            return None
        evasion_rates: list[float] = []
        for swarm_ctx in self.swarm_results.values():
            stats = swarm_ctx.get("strategy_stats", {})
            if not stats:
                continue
            best_rate = max(
                s.get("evasion_rate", 0.0) for s in stats.values()
            )
            evasion_rates.append(best_rate)
        if not evasion_rates:
            return None
        avg_best_evasion = sum(evasion_rates) / len(evasion_rates)
        return max(0.0, 1.0 - avg_best_evasion)

    # ── Per-breakdown ─────────────────────────────────────────────────────────

    def _per_technique(self) -> dict:
        result = {}
        for tid, data in self.technique_results.items():
            all_rounds = data.get("rounds", [])
            rounds     = self._ok_rounds(data)
            timeouts   = len(all_rounds) - len(rounds)
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
                "timeouts":       timeouts,
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
        profile = WEIGHT_PROFILES[self.weight_profile]

        cov   = self._coverage()
        res   = self._resilience()
        hard  = self._hardening()
        con   = self._consistency()
        meta  = None if "meta_resilience"  in self.exclude_components else self._meta_resilience()
        swarm = None if "swarm_resilience" in self.exclude_components else self._swarm_resilience()

        excluded: dict[str, str] = {}
        for name in self.exclude_components:
            excluded[name] = "explicitly excluded for this experiment (see CLAUDE.md / run config)"

        # Build active-component map and re-normalise weights so they always sum to 1.
        active: dict[str, float] = {
            "coverage":    cov,
            "resilience":  res,
            "hardening":   hard,
            "consistency": con,
        }

        def _consider(name: str, value: Optional[float], no_data_reason: str) -> None:
            if value is None:
                if name not in excluded:
                    excluded[name] = no_data_reason
                return
            if name not in profile:
                excluded[name] = f"not part of weight_profile {self.weight_profile!r}"
                return
            active[name] = value

        _consider("meta_resilience", meta,  "no meta-resilience data supplied for this run")
        _consider("swarm_resilience", swarm, "no swarm data supplied for this run")

        total_w = sum(profile[k] for k in active)
        raw = sum(v * profile[k] / total_w for k, v in active.items())
        weights_effective = {k: round(profile[k] / total_w, 4) for k in active}

        dabs        = round(max(0.0, min(100.0, raw * 100)), 2)
        tier, color = get_tier(dabs)

        pt   = self._per_technique()
        ptac = self._per_tactic(pt)
        comp = {
            "coverage":         round(cov  * 100, 2),
            "resilience":       round(res  * 100, 2),
            "hardening":        round(hard * 100, 2),
            "consistency":      round(con  * 100, 2),
            "meta_resilience":  round(meta  * 100, 2) if meta  is not None else None,
            "swarm_resilience": round(swarm * 100, 2) if swarm is not None else None,
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
            seed=self.seed,
            excluded_components=excluded,
            platform=self.platform,
            weight_profile=self.weight_profile,
            weights_nominal=dict(profile),
            weights_effective=weights_effective,
            pipeline_version=self.pipeline_version,
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
