"""
Scaling Laws Analyzer — measures how DABS score evolves with model size.
Fits a power law curve: DABS = a * (params_B)^b
"""
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np

OUTPUT_DIR = Path(__file__).parent.parent / "output"

def _entry(
    params_total_b: float,
    source_url: str,
    platform: str = "ollama",
    params_active_b: float | None = None,
    arch: str = "dense",
    arch_confidence: str = "confirmed",
) -> dict:
    """
    params_active_b defaults to params_total_b for dense models — for a dense
    model "active params" is not a meaningful distinct concept, so the two
    are the same number by construction, not an estimate. For a
    mixture-of-experts (arch="moe") model, params_active_b MUST be passed
    explicitly from the same official source as params_total_b.

    "params_b" is kept as a backward-compatible alias for params_total_b —
    every existing caller (ScalingLawsAnalyzer, run_scaling_benchmark.py's
    display table) that reads entry["params_b"] keeps working unchanged and
    the MAIN scaling-law regression uses total params by default. Runs with
    params_active_b as the x-axis instead are a separate sensitivity
    analysis, not the primary fit — see docs/scaling_v2_results.md §4.
    """
    return {
        "params_b":        params_total_b,  # alias, see docstring
        "params_total_b":  params_total_b,
        "params_active_b": params_active_b if params_active_b is not None else params_total_b,
        "arch":            arch,
        # "confirmed": the model card states this architecture outright.
        # "inferred": no explicit statement either way — arch was guessed
        # from indirect signals (e.g. no active-params figure, no MoE naming
        # convention). Must be surfaced in docs/scaling_v2_results.md
        # Limitations wherever "inferred" appears — never silently treated
        # as equal-confidence to a confirmed entry.
        "arch_confidence": arch_confidence,
        "source_url":      source_url,
        "platform":        platform,
    }


# Every entry MUST carry a verifiable source (official model card / provider
# docs) — no estimated parameter counts. A model with no confirmed source
# does not get an entry and therefore cannot enter a benchmark grid.
MODEL_REGISTRY: dict[str, dict] = {
    # ── Original 5 (scaling_v2 reproduction) ────────────────────────────────
    "phi3.5:latest": _entry(3.8,  "https://huggingface.co/microsoft/Phi-3.5-mini-instruct"),
    "phi3.5":        _entry(3.8,  "https://huggingface.co/microsoft/Phi-3.5-mini-instruct"),
    "mistral:7b":    _entry(7.0,  "https://ollama.com/library/mistral:7b"),
    "mistral":       _entry(7.0,  "https://ollama.com/library/mistral:7b"),
    "qwen2.5:7b":    _entry(7.61, "https://huggingface.co/Qwen/Qwen2.5-7B"),
    "llama3.1:8b":   _entry(8.0,  "https://huggingface.co/meta-llama/Llama-3.1-8B"),
    "llama3.1":      _entry(8.0,  "https://huggingface.co/meta-llama/Llama-3.1-8B"),
    "qwen2.5:14b":   _entry(14.7, "https://huggingface.co/Qwen/Qwen2.5-14B"),

    # ── New local (Ollama) low end — hybrid grid, 2026-09-05 ────────────────
    "llama3.2:1b": _entry(1.23, "https://huggingface.co/meta-llama/Llama-3.2-1B"),
    "llama3.2:3b": _entry(3.21, "https://huggingface.co/meta-llama/Llama-3.2-3B"),
    "qwen2.5:3b":  _entry(3.09, "https://huggingface.co/Qwen/Qwen2.5-3B"),
    # gemma2:2b — the HF card header literally reads "Model size: 3B params"
    # (looks like a template artifact shared across the Gemma 2 family page),
    # but the card body states "the 2B model was trained with 2 trillion
    # tokens" for this specific checkpoint, and 2B matches the model's own
    # name/tag. Recorded as 2.0B; flagged here rather than silently trusting
    # either number.
    "gemma2:2b":   _entry(2.0,  "https://huggingface.co/google/gemma-2-2b"),

    # ── Cross-platform control — same model, both platforms ────────────────
    # gpt-oss-20b: MoE, 21B total / 3.6B active (official card). Ollama's
    # own `ollama show gpt-oss:latest` independently reports "parameters
    # 20.9B", consistent with the 21B HF figure.
    "gpt-oss:latest":       _entry(21.0, "https://huggingface.co/openai/gpt-oss-20b",
                                   platform="ollama", params_active_b=3.6, arch="moe"),
    "openai/gpt-oss-20b":   _entry(21.0, "https://huggingface.co/openai/gpt-oss-20b",
                                   platform="groq", params_active_b=3.6, arch="moe"),

    # ── New Groq-only ────────────────────────────────────────────────────────
    "openai/gpt-oss-120b": _entry(117.0, "https://huggingface.co/openai/gpt-oss-120b",
                                  platform="groq", params_active_b=5.1, arch="moe"),
    # Qwen3.8-27B: card states "27B" with no separate active-params figure and
    # no MoE naming pattern (cf. Qwen3's "-A3B" convention for its actual MoE
    # variants) — treated as dense. Flagged as inferred, not confirmed, since
    # the card doesn't say "dense" outright.
    "qwen/qwen3.8-27b":    _entry(27.0, "https://huggingface.co/Qwen/Qwen3.8-27B",
                                  platform="groq", arch_confidence="inferred"),

    # ── Verified but excluded from the current grid (see docs/scaling_v2_results.md) ──
    # allam-2-7b: bilingual Arabic-English specialist; exact "-2-" HF card
    # 401'd, citing the same publisher's public 7B card as the closest source.
    "allam-2-7b": _entry(7.0, "https://huggingface.co/ALLaM-AI/ALLaM-7B-Instruct-preview",
                         platform="groq"),
    # openai/gpt-oss-safeguard-20b: same base as gpt-oss-20b, safety/
    # moderation fine-tune — not a general-purpose Defender candidate.
    "openai/gpt-oss-safeguard-20b": _entry(21.0, "https://huggingface.co/openai/gpt-oss-safeguard-20b",
                                            platform="groq", params_active_b=3.6, arch="moe"),
}


class ScalingLawsAnalyzer:
    """Analyze DABS scores vs model size and fit a power law curve."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or OUTPUT_DIR

    def _resolve_params(self, model_name: str) -> Optional[float]:
        entry = MODEL_REGISTRY.get(model_name)
        if entry is not None:
            return entry["params_b"]
        base = model_name.split(":")[0]
        for key, entry in MODEL_REGISTRY.items():
            if key.split(":")[0] == base:
                return entry["params_b"]
        return None

    def _load_dabs_scores(self) -> list[dict]:
        seen: dict[str, dict] = {}
        for p in sorted(self.output_dir.glob("dabs_*.json"), reverse=True):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            model = d.get("model", "")
            params = self._resolve_params(model)
            if params is None or d.get("dabs_score", 0) <= 0:
                continue
            if model not in seen:
                seen[model] = {
                    "model":                model,
                    "params_b":             params,
                    "dabs_score":           d["dabs_score"],
                    "tier":                 d.get("tier", ""),
                    "tier_color":           d.get("tier_color", "#718096"),
                    "per_tactic":           d.get("per_tactic", {}),
                    "techniques_benchmarked": d.get("techniques_benchmarked", 0),
                    "timestamp":            d.get("timestamp", ""),
                }
        return sorted(seen.values(), key=lambda x: x["params_b"])

    def _fit_power_law(
        self, params: list[float], scores: list[float]
    ) -> tuple[float, float, float]:
        """
        Fit DABS = a * (params_B)^b via log-linearization.
        Returns (a, b, r2).
        """
        if len(params) < 2:
            return (scores[0] if scores else 50.0, 0.5, 0.0)

        log_x = np.log(np.array(params, dtype=float))
        log_y = np.log(np.maximum(0.1, np.array(scores, dtype=float)))
        coeffs = np.polyfit(log_x, log_y, 1)
        b = float(coeffs[0])
        a = float(math.exp(float(coeffs[1])))

        y_hat = np.array([a * (x ** b) for x in params])
        ss_res = float(np.sum((np.array(scores) - y_hat) ** 2))
        mean_y = float(np.mean(scores))
        ss_tot = float(np.sum((np.array(scores) - mean_y) ** 2))
        r2 = 1.0 - ss_res / ss_tot if ss_tot > 1e-10 else 1.0

        return a, b, r2

    def _inflection_point(self, a: float, b: float, pred_70b: float) -> float:
        """
        Model size where 80 % of the predicted 70B score is reached.
        Represents where marginal gains become significantly diminished.
        """
        if b <= 0 or a <= 0:
            return 8.0
        target = max(0.1, min(99.0, 0.8 * pred_70b))
        x = (target / a) ** (1.0 / b)
        return round(float(x), 1)

    def _per_tactic_trends(self, data_points: list[dict]) -> dict[str, dict]:
        buckets: dict[str, list[tuple[float, float]]] = {}
        for dp in data_points:
            for tactic, score in dp.get("per_tactic", {}).items():
                buckets.setdefault(tactic, []).append((dp["params_b"], float(score)))

        result = {}
        for tactic, points in buckets.items():
            pts_sorted = sorted(points, key=lambda x: x[0])
            if len(pts_sorted) < 2:
                result[tactic] = {
                    "data_points":   [{"params_b": x, "score": y} for x, y in pts_sorted],
                    "equation":      f"DABS ≈ {pts_sorted[0][1]:.1f} (single point)",
                    "a": None, "b": None, "r2": None,
                    "predicted_32b": None, "predicted_70b": None,
                }
                continue
            xs = [p[0] for p in pts_sorted]
            ys = [p[1] for p in pts_sorted]
            a, b, r2 = self._fit_power_law(xs, ys)
            result[tactic] = {
                "data_points":   [{"params_b": x, "score": y} for x, y in pts_sorted],
                "a":             round(a, 4),
                "b":             round(b, 4),
                "r2":            round(r2, 4),
                "equation":      f"DABS = {a:.2f} × P^{b:.3f}",
                "predicted_32b": round(min(100.0, a * (32.0 ** b)), 1),
                "predicted_70b": round(min(100.0, a * (70.0 ** b)), 1),
            }
        return result

    def _curve_points(self, a: float, b: float) -> list[dict]:
        points = []
        x = 1.0
        while x <= 100.0:
            points.append({
                "params_b":       round(x, 2),
                "predicted_dabs": round(min(100.0, a * (x ** b)), 2),
            })
            x *= 1.2
        return points

    def analyze(self) -> dict:
        data_points = self._load_dabs_scores()

        if len(data_points) < 2:
            return {
                "status":            "insufficient_data",
                "message": (
                    "Need at least 2 models to fit a scaling law. "
                    "Run scripts/run_scaling_benchmark.py to generate data."
                ),
                "data_points":       data_points,
                "power_law":         None,
                "predictions":       {},
                "inflection_point_b": None,
                "curve_points":      [],
                "per_tactic":        {},
                "models_analyzed":   len(data_points),
                "timestamp":         datetime.now(timezone.utc).isoformat(),
            }

        xs = [dp["params_b"] for dp in data_points]
        ys = [dp["dabs_score"] for dp in data_points]

        a, b, r2 = self._fit_power_law(xs, ys)
        pred_32 = round(min(100.0, a * (32.0 ** b)), 2)
        pred_70 = round(min(100.0, a * (70.0 ** b)), 2)

        result = {
            "status":      "ok",
            "data_points": data_points,
            "power_law": {
                "a":        round(a, 4),
                "b":        round(b, 4),
                "equation": f"DABS = {a:.2f} × P^{b:.3f}",
                "r2":       round(r2, 4),
            },
            "predictions": {
                "32b": pred_32,
                "70b": pred_70,
            },
            "inflection_point_b": self._inflection_point(a, b, pred_70),
            "curve_points":       self._curve_points(a, b),
            "per_tactic":         self._per_tactic_trends(data_points),
            "models_analyzed":    len(data_points),
            "timestamp":          datetime.now(timezone.utc).isoformat(),
        }

        self._save(result)
        return result

    def _save(self, result: dict) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / "scaling_laws.json"
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return path
