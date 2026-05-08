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

MODEL_REGISTRY: dict[str, float] = {
    "phi3.5:latest": 3.8,
    "phi3.5":        3.8,
    "mistral:7b":    7.0,
    "mistral":       7.0,
    "qwen2.5:7b":    7.0,
    "llama3.1:8b":   8.0,
    "llama3.1":      8.0,
    "qwen2.5:14b":   14.0,
}


class ScalingLawsAnalyzer:
    """Analyze DABS scores vs model size and fit a power law curve."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or OUTPUT_DIR

    def _resolve_params(self, model_name: str) -> Optional[float]:
        if model_name in MODEL_REGISTRY:
            return MODEL_REGISTRY[model_name]
        base = model_name.split(":")[0]
        for key, params in MODEL_REGISTRY.items():
            if key.split(":")[0] == base:
                return params
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
