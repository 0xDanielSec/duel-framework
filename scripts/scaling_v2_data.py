"""
Shared loader for the Scaling Laws v2 grid — read-only.

Reads output/benchmarks/scaling_v2/*.json and output/benchmarks/groq_grid/*.json
(the raw per-model DABS results produced by run_scaling_benchmark.py / run_groq_grid.py),
joins them with engine/scaling_laws.py's MODEL_REGISTRY for params/arch metadata
(the only fields not present in the result JSON itself). This module does NOT
refit anything itself:
  - equation/R² come from the existing engine.scaling_laws.ScalingLawsAnalyzer
    ._fit_power_law() (log-linearized power law, R² measured in linear space) —
    imported, not reimplemented.
  - p-value/95% CI for the exponent are read from
    output/benchmarks/scaling_v2/fit_stats_result.json, the one-off significance
    analysis that already produced docs/scaling_v2_results.md §4a (leverage/
    Cook's distance included there, not surfaced here). If that file's own
    model set no longer matches what this loader actually found (e.g. a new
    model landed and the file wasn't regenerated), the significance block is
    marked "stale" instead of silently showing a mismatched p-value/CI.

Used by scripts/generate_pages_data.py (GitHub Pages) and server.py
(/api/scaling_v2, /api/dabs_v2). Never writes to engine/ or output/benchmarks/ —
read-only by design, since a scaling benchmark may be running concurrently.

Nothing here is invented or hardcoded: every number traces to a file under
output/benchmarks/, to engine/scaling_laws.py's MODEL_REGISTRY, or to `git log`
against the commit history (used only to reconstruct pipeline_version for the
3 grid points saved before that field existed — see _reconstruct_pipeline_version).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import numpy as np  # only for the §3a variance mean/SD below — no fit/stats recomputation

from engine.scaling_laws import MODEL_REGISTRY, ScalingLawsAnalyzer

ROOT = Path(__file__).resolve().parent.parent
SCALING_V2_DIR = ROOT / "output" / "benchmarks" / "scaling_v2"
GROQ_GRID_DIR = ROOT / "output" / "benchmarks" / "groq_grid"
LEGACY_DABS_DIR = ROOT / "output"  # old output/dabs_*.json schema — pre-v2
FIT_STATS_FILE = SCALING_V2_DIR / "fit_stats_result.json"  # one-off §4a analysis artifact

# The gpt-oss control pair (§1/§5 of docs/scaling_v2_results.md) is one model
# measured on two platforms, not two grid points. The Ollama leg is kept
# canonical for the fit; the Groq leg is still shown in the model table but
# excluded from the regression to avoid double-weighting one model.
FIT_EXCLUDED_MODELS = {"openai/gpt-oss-20b"}

# "domain" — general vs. security-domain fine-tune. Read directly from
# MODEL_REGISTRY[model]["domain"] (engine/scaling_laws.py), the field added
# alongside foundation-sec-8b:instruct-q8_0 (docs/scaling_v2_results.md §7) —
# every registry entry sets it explicitly ("general" or "security"), so this
# is no longer inferred or hardcoded here. A model not found in the registry
# at all is reported as "unclassified", never guessed.
#
# Previously this module kept its own separate SPECIALIZED_DOMAIN_NOTES dict
# (allam-2-7b, gpt-oss-safeguard-20b) predating MODEL_REGISTRY's own `domain`
# field — that duplicated, and had drifted from, the registry's own data
# (it had no entry for foundation-sec-8b at all, so every point silently
# read back "general-purpose"). Removed in favor of the single source of
# truth now that one exists.
def _domain(reg: dict | None) -> str:
    if reg is None:
        return "unclassified"
    return reg.get("domain", "unclassified")


def _rel(p: Path) -> str:
    return str(p.relative_to(ROOT)).replace("\\", "/")


def _reconstruct_pipeline_version(timestamp: str | None) -> tuple[str | None, bool]:
    """
    3 of the 12 canonical grid points (phi3.5:latest, mistral:7b, qwen2.5:7b)
    were saved before engine/dabs_scorer.py::get_pipeline_version() existed,
    so pipeline_version is null in their JSON. Reconstruct it from the main
    branch's commit history as of the run's own timestamp — the commit that
    was HEAD when the run started, which is the best available approximation
    of what get_pipeline_version() would have recorded had it existed then.
    Returns (value, was_reconstructed). Never fabricates a value: if git log
    finds nothing (e.g. run predates the repo, or git is unavailable), returns
    (None, False) rather than guessing.
    """
    if not timestamp:
        return None, False
    try:
        result = subprocess.run(
            ["git", "log", "main", "--before", timestamp, "-1", "--format=%h"],
            cwd=ROOT, capture_output=True, text=True, timeout=10,
        )
        commit_hash = result.stdout.strip()
    except Exception:
        return None, False
    if not commit_hash:
        return None, False
    return f"{commit_hash} (reconstructed)", True


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
            pipeline_version = data.get("pipeline_version")
            pipeline_version_reconstructed = False
            if pipeline_version is None:
                pipeline_version, pipeline_version_reconstructed = \
                    _reconstruct_pipeline_version(data.get("timestamp"))
            points.append({
                "model":               model,
                "platform":            data.get("platform", ""),
                "attacker_model":      data.get("attacker_model"),
                "threat_intel_mode":   data.get("threat_intel_mode"),
                "pipeline_version":    pipeline_version,
                "pipeline_version_reconstructed": pipeline_version_reconstructed,
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
                "domain":              _domain(reg),
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


def _load_fit_stats() -> dict | None:
    if not FIT_STATS_FILE.is_file():
        return None
    try:
        return json.loads(FIT_STATS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def _significance_from_file(stats_key: str | None, current_names: set[str]) -> dict:
    """
    Reads the p-value/95% CI for one fit variant from fit_stats_result.json
    (§4a/§7's one-off scipy.stats.linregress analysis — not recomputed here).
    stats_key is "full" (n=12, all fit points), "no120b" (the highest-
    leverage-point-removed sensitivity check), or "full_n13" (n=12 + the
    foundation-sec-8b:instruct-q8_0 point, §7) — the only three variants that
    file covers; dabs_v2 and active-params fits get "unavailable", same as
    docs/scaling_v2_results.md §4a says explicitly for those variants.
    """
    if stats_key is None:
        return {"status": "unavailable"}
    all_stats = _load_fit_stats()
    if not all_stats or stats_key not in all_stats:
        return {"status": "unavailable"}
    entry = all_stats[stats_key]
    if set(entry.get("names", [])) != current_names:
        return {
            "status": "stale",
            "reason": (
                f"{_rel(FIT_STATS_FILE)} was computed for a different model set "
                f"(n={entry.get('n')}) than the current grid (n={len(current_names)}) — "
                f"re-run the §4a significance analysis and regenerate that file."
            ),
        }
    return {
        "status":       "ok",
        "p_value":      round(float(entry["p"]), 4),
        "stderr":       round(float(entry["stderr"]), 4),
        "ci95_lo":      round(float(entry["ci_lo"]), 4),
        "ci95_hi":      round(float(entry["ci_hi"]), 4),
        "r2_log":       round(float(entry["r2"]), 4),
        "significant_at_0.05": bool(entry["p"] < 0.05),
        "source": _rel(FIT_STATS_FILE),
    }


def _fit(points: list[dict], key: str, param_key: str, stats_key: str | None = None) -> dict:
    pts = [p for p in points
           if p["included_in_fit"] and p.get(key) is not None and p.get(param_key) is not None]
    if len(pts) < 3:
        return {"status": "insufficient_data", "n": len(pts)}

    xs = [p[param_key] for p in pts]
    ys = [p[key] for p in pts]
    names = [p["model"] for p in pts]

    a, b, r2_linear = ScalingLawsAnalyzer()._fit_power_law(xs, ys)
    significance = _significance_from_file(stats_key, set(names))

    result = {
        "status":       "ok",
        "n":            len(xs),
        "a":            round(a, 4),
        "b":            round(b, 4),
        "equation":     f"DABS = {a:.2f} × P^{b:+.3f}",
        "r2_linear":    round(r2_linear, 4),
        "significance": significance,
        "points": [{"model": nm, "params_b": x, "dabs": y} for nm, x, y in zip(names, xs, ys)],
    }
    # Flatten the common ok-path fields up a level too, for callers that don't
    # want to reach into `significance` — absent (None) when not "ok"/stale.
    if significance.get("status") == "ok":
        result.update({
            "p_value": significance["p_value"],
            "ci95_lo": significance["ci95_lo"],
            "ci95_hi": significance["ci95_hi"],
            "r2_log":  significance["r2_log"],
            "significant_at_0.05": significance["significant_at_0.05"],
        })
    return result


def load_scaling_v2() -> dict:
    points = _load_canonical_points()
    variance = _load_variance_points()
    legacy = _legacy_files()

    fit_v1        = _fit(points, "dabs_v1", "params_total_b", stats_key="full_n13")
    fit_v2        = _fit(points, "dabs_v2", "params_total_b")  # no §4a significance computed for dabs_v2
    fit_v1_active = _fit(points, "dabs_v1", "params_active_b")  # none for active-params either

    # Sensitivity check mirroring §4a: drop the single highest-leverage point
    # (largest params_total_b in the fitted set) and refit.
    fit_v1_no_outlier = None
    fittable = [p for p in points if p["included_in_fit"] and p.get("dabs_v1") is not None
                and p.get("params_total_b") is not None]
    if len(fittable) >= 4:
        largest = max(fittable, key=lambda p: p["params_total_b"])
        reduced = [p for p in points if p is not largest]
        fit_v1_no_outlier = _fit(reduced, "dabs_v1", "params_total_b", stats_key="no120b")
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
