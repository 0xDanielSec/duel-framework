"""
Shared loader for the Scaling Laws v2 grid — read-only.

Reads output/benchmarks/scaling_v2/*.json and output/benchmarks/groq_grid/*.json
(the raw per-model DABS results produced by run_scaling_benchmark.py / run_groq_grid.py),
joins them with engine/scaling_laws.py's MODEL_REGISTRY for params/arch metadata
(the only fields not present in the result JSON itself), and reproduces the same
fit + significance test documented in docs/scaling_v2_results.md §4/§4a:
  - equation/R² via the existing engine.scaling_laws.ScalingLawsAnalyzer._fit_power_law()
    (log-linearized power law, R² measured in linear space)
  - p-value/95% CI for the exponent via scipy.stats.linregress on the same
    log(params)/log(DABS) pairs (engine/scaling_laws.py reports r2 only, no
    inferential statistics — this mirrors the one-off analysis in §4a, not a
    change to that module).

Used by scripts/generate_pages_data.py (GitHub Pages) and server.py
(/api/scaling_v2, /api/dabs_v2). Never writes to engine/ or output/benchmarks/ —
read-only by design, since a scaling benchmark may be running concurrently.

Nothing here is invented or hardcoded: every number traces to a file under
output/benchmarks/ or to engine/scaling_laws.py's MODEL_REGISTRY (imported,
not duplicated).
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from scipy import stats

from engine.scaling_laws import MODEL_REGISTRY, ScalingLawsAnalyzer

ROOT = Path(__file__).resolve().parent.parent
SCALING_V2_DIR = ROOT / "output" / "benchmarks" / "scaling_v2"
GROQ_GRID_DIR = ROOT / "output" / "benchmarks" / "groq_grid"
LEGACY_DABS_DIR = ROOT / "output"  # old output/dabs_*.json schema — pre-v2

# The gpt-oss control pair (§1/§5 of docs/scaling_v2_results.md) is one model
# measured on two platforms, not two grid points. The Ollama leg is kept
# canonical for the fit; the Groq leg is still shown in the model table but
# excluded from the regression to avoid double-weighting one model.
FIT_EXCLUDED_MODELS = {"openai/gpt-oss-20b"}

# "domain" — general-purpose vs. specialized fine-tune. Sourced from the
# MODEL_REGISTRY's own inline notes (docs/scaling_v2_results.md §1), not
# inferred: only the two entries the codebase already documents as
# specialized get a non-default label. Everything else in the current grid
# is a general-purpose chat model per the same source. A model not found
# here (e.g. a future domain-tuned entry not yet in MODEL_REGISTRY) is
# reported as "unclassified", never guessed.
SPECIALIZED_DOMAIN_NOTES = {
    "allam-2-7b": "bilingual Arabic-English specialist (excluded from grid)",
    "openai/gpt-oss-safeguard-20b": "safety/moderation fine-tune (excluded from grid)",
}


def _domain(model: str, registry_match: bool) -> str:
    if not registry_match:
        return "unclassified"
    return SPECIALIZED_DOMAIN_NOTES.get(model, "general-purpose")


def _rel(p: Path) -> str:
    return str(p.relative_to(ROOT)).replace("\\", "/")


def _load_canonical_points() -> list[dict]:
    """One row per model's canonical (seed=42, single-run) grid point."""
    points = []
    for d in (SCALING_V2_DIR, GROQ_GRID_DIR):
        if not d.is_dir():
            continue
        for p in sorted(d.glob("dabs_*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if data.get("run_index") is not None:
                continue  # a §3a variance-experiment repeat, not a grid point
            model = data.get("model", "")
            reg = MODEL_REGISTRY.get(model)
            v1 = data.get("dabs_v1", {}) or {}
            v2 = data.get("dabs_v2", {}) or {}
            points.append({
                "model":               model,
                "platform":            data.get("platform", ""),
                "attacker_model":      data.get("attacker_model"),
                "threat_intel_mode":   data.get("threat_intel_mode"),
                "pipeline_version":    data.get("pipeline_version"),
                "seed":                data.get("seed"),
                "timestamp":           data.get("timestamp"),
                "dabs_v1":             v1.get("dabs_score"),
                "dabs_v2":             v2.get("dabs_score"),
                "weight_profile":      v1.get("weight_profile"),
                "excluded_components": v1.get("excluded_components"),
                "tier":                v1.get("tier"),
                "params_total_b":      reg["params_total_b"] if reg else None,
                "params_active_b":     reg["params_active_b"] if reg else None,
                "arch":                reg["arch"] if reg else None,
                "arch_confidence":     reg["arch_confidence"] if reg else None,
                "source_url":          reg["source_url"] if reg else None,
                "registry_match":      reg is not None,
                "domain":              _domain(model, reg is not None),
                "source_file":         _rel(p),
                "included_in_fit":     reg is not None and model not in FIT_EXCLUDED_MODELS,
            })
    return points


def _load_variance_points() -> dict[str, dict]:
    """
    §3a variance experiment: repeat runs (run_index set), grouped by model AND
    by whether the seed was fixed (seed=42 determinism check) or omitted
    (unseeded variance check) — these are two different experiments and must
    not be pooled into one mean/SD.
    """
    groups: dict[tuple[str, str], list[dict]] = {}
    for p in sorted(SCALING_V2_DIR.glob("dabs_*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("run_index") is None:
            continue
        model = data.get("model", "")
        label = "seed42" if data.get("seed") == 42 else "unseeded"
        groups.setdefault((model, label), []).append({
            "run_index": data["run_index"],
            "seed":      data.get("seed"),
            "dabs_v1":   (data.get("dabs_v1", {}) or {}).get("dabs_score"),
            "source_file": _rel(p),
        })

    result: dict[str, dict] = {}
    for (model, label), runs in groups.items():
        vals = [r["dabs_v1"] for r in runs if r["dabs_v1"] is not None]
        if len(vals) < 2:
            continue
        arr = np.array(vals, dtype=float)
        result.setdefault(model, {})[label] = {
            "runs": sorted(runs, key=lambda r: r["run_index"]),
            "n":    len(vals),
            "mean": round(float(arr.mean()), 2),
            "sd":   round(float(arr.std(ddof=1)), 2),
        }
    return result


def _legacy_files() -> list[str]:
    """output/dabs_*.json — the pre-v2, top-level dabs_score schema. If any
    exist, they are legacy and not comparable to the nested dabs_v1/dabs_v2
    schema everything else in this module reads."""
    if not LEGACY_DABS_DIR.is_dir():
        return []
    return [_rel(p) for p in sorted(LEGACY_DABS_DIR.glob("dabs_*.json"))]


def _fit(points: list[dict], key: str, param_key: str) -> dict:
    pts = [p for p in points
           if p["included_in_fit"] and p.get(key) is not None and p.get(param_key) is not None]
    if len(pts) < 3:
        return {"status": "insufficient_data", "n": len(pts)}

    xs = [p[param_key] for p in pts]
    ys = [p[key] for p in pts]
    names = [p["model"] for p in pts]

    a, b, r2_linear = ScalingLawsAnalyzer()._fit_power_law(xs, ys)

    log_x = np.log(xs)
    log_y = np.log(ys)
    reg = stats.linregress(log_x, log_y)
    n = len(xs)
    tval = float(stats.t.ppf(0.975, n - 2))
    ci_lo = reg.slope - tval * reg.stderr
    ci_hi = reg.slope + tval * reg.stderr

    return {
        "status":       "ok",
        "n":            n,
        "a":            round(a, 4),
        "b":            round(b, 4),
        "equation":     f"DABS = {a:.2f} × P^{b:+.3f}",
        "r2_linear":    round(r2_linear, 4),
        "r2_log":       round(reg.rvalue ** 2, 4),
        "p_value":      round(float(reg.pvalue), 4),
        "ci95_lo":      round(float(ci_lo), 4),
        "ci95_hi":      round(float(ci_hi), 4),
        "significant_at_0.05": bool(reg.pvalue < 0.05),
        "points": [{"model": nm, "params_b": x, "dabs": y} for nm, x, y in zip(names, xs, ys)],
    }


def load_scaling_v2() -> dict:
    points = _load_canonical_points()
    variance = _load_variance_points()
    legacy = _legacy_files()

    fit_v1        = _fit(points, "dabs_v1", "params_total_b")
    fit_v2        = _fit(points, "dabs_v2", "params_total_b")
    fit_v1_active = _fit(points, "dabs_v1", "params_active_b")

    # Sensitivity check mirroring §4a: drop the single highest-leverage point
    # (largest params_total_b in the fitted set) and refit.
    fit_v1_no_outlier = None
    fittable = [p for p in points if p["included_in_fit"] and p.get("dabs_v1") is not None
                and p.get("params_total_b") is not None]
    if len(fittable) >= 4:
        largest = max(fittable, key=lambda p: p["params_total_b"])
        reduced = [p for p in points if p is not largest]
        fit_v1_no_outlier = _fit(reduced, "dabs_v1", "params_total_b")
        fit_v1_no_outlier["excluded_model"] = largest["model"]

    return {
        "status": fit_v1.get("status", "insufficient_data"),
        "sources": [
            "output/benchmarks/scaling_v2/*.json",
            "output/benchmarks/groq_grid/*.json",
            "engine/scaling_laws.py::MODEL_REGISTRY (params_total_b/params_active_b/arch — "
            "not present in the result JSON itself, read not duplicated)",
        ],
        "points":   points,
        "variance": variance,
        "legacy_files": legacy,
        "fit": {
            "dabs_v1":                    fit_v1,
            "dabs_v2":                    fit_v2,
            "dabs_v1_active_params":      fit_v1_active,
            "dabs_v1_no_highest_leverage": fit_v1_no_outlier,
        },
    }


if __name__ == "__main__":
    print(json.dumps(load_scaling_v2(), indent=2))
