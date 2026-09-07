"""
Statistical analysis for docs/scaling_v2_results.md §4/§3a follow-up.
Uses scipy.stats.linregress on the log-log data (same log-linearization
_fit_power_law already uses in engine/scaling_laws.py) to get p-value and
95% CI for the exponent b, then Cook's distance / leverage per point,
refit without gpt-oss-120b, and a scatter plot.
"""
import numpy as np
from scipy import stats
import json

# n=12 grid, from docs/scaling_v2_results.md §3 table, dabs_v1 column
# (model, params_total_b, dabs_v1)
DATA = [
    ("llama3.2:1b",       1.23,  36.52),
    ("gemma2:2b",         2.0,   61.03),
    ("qwen2.5:3b",        3.09,  49.53),
    ("llama3.2:3b",       3.21,  63.76),
    ("phi3.5:latest",     3.8,   47.50),
    ("mistral:7b",        7.0,   52.63),
    ("qwen2.5:7b",        7.61,  62.42),
    ("llama3.1:8b",       8.0,   55.26),
    ("qwen2.5:14b",       14.7,  59.96),
    ("gpt-oss:latest",    21.0,  51.16),
    ("qwen/qwen3.8-27b",  27.0,  69.00),
    ("openai/gpt-oss-120b", 117.0, 65.30),
]

def fit_and_stats(data, label):
    names = [d[0] for d in data]
    x = np.array([d[1] for d in data], dtype=float)
    y = np.array([d[2] for d in data], dtype=float)
    log_x = np.log(x)
    log_y = np.log(np.maximum(0.1, y))

    res = stats.linregress(log_x, log_y)
    b = res.slope
    a = float(np.exp(res.intercept))
    r2 = res.rvalue ** 2
    n = len(x)
    dof = n - 2
    # 95% CI for slope
    tcrit = stats.t.ppf(0.975, dof)
    ci_lo = b - tcrit * res.stderr
    ci_hi = b + tcrit * res.stderr

    # Leverage (hat values) and Cook's distance for simple linear regression
    # in log-log space (log_y ~ intercept + b*log_x)
    X = np.column_stack([np.ones(n), log_x])
    H = X @ np.linalg.inv(X.T @ X) @ X.T
    hii = np.diag(H)
    y_hat_log = res.intercept + b * log_x
    resid = log_y - y_hat_log
    mse = np.sum(resid ** 2) / dof
    p = 2  # params in log-log regression
    cooks_d = (resid ** 2 / (p * mse)) * (hii / (1 - hii) ** 2)

    print(f"\n=== {label} (n={n}) ===")
    print(f"Fit: DABS = {a:.2f} x P^{b:+.4f}")
    print(f"R^2 = {r2:.4f}")
    print(f"slope p-value (H0: b=0) = {res.pvalue:.4f}")
    print(f"slope std err = {res.stderr:.4f}")
    print(f"95% CI for exponent b: [{ci_lo:+.4f}, {ci_hi:+.4f}]")
    print(f"{'model':<24}{'params_B':>10}{'leverage':>10}{'cooks_d':>10}")
    for nm, xi, hi, cd in zip(names, x, hii, cooks_d):
        flag = "  <-- high leverage" if hi > 2*p/n else ("  <-- high Cook's D" if cd > 4/n else "")
        print(f"{nm:<24}{xi:>10.2f}{hi:>10.3f}{cd:>10.3f}{flag}")

    return {"a": a, "b": b, "r2": r2, "p": res.pvalue, "stderr": res.stderr,
            "ci_lo": ci_lo, "ci_hi": ci_hi, "n": n,
            "names": names, "x": x.tolist(), "y": y.tolist(),
            "hii": hii.tolist(), "cooks_d": cooks_d.tolist()}

full = fit_and_stats(DATA, "Full grid n=12 (dabs_v1)")

data_no_120b = [d for d in DATA if d[0] != "openai/gpt-oss-120b"]
no120b = fit_and_stats(data_no_120b, "Grid without gpt-oss-120b, n=11 (dabs_v1)")

# ---- §3a comparison: unseeded SD vs neighboring-model DABS gaps in the grid ----
sorted_grid = sorted(DATA, key=lambda d: d[1])
gaps = []
for i in range(len(sorted_grid) - 1):
    gaps.append(abs(sorted_grid[i+1][2] - sorted_grid[i][2]))
print("\n=== Neighboring-model DABS gaps in n=12 grid (sorted by params) ===")
for i in range(len(sorted_grid) - 1):
    m1, m2 = sorted_grid[i][0], sorted_grid[i+1][0]
    print(f"{m1:<22} -> {m2:<22} gap = {gaps[i]:.2f}")
print(f"\nmin gap = {min(gaps):.2f}, median gap = {np.median(gaps):.2f}, mean gap = {np.mean(gaps):.2f}")
print("mistral:7b unseeded SD (n=3) = 5.07; llama3.1:8b unseeded SD (n=3) = 1.95")

json.dump({"full": {k: v for k, v in full.items() if k not in ("hii", "cooks_d")},
           "no120b": {k: v for k, v in no120b.items() if k not in ("hii", "cooks_d")},
           "gaps": gaps},
          open("fit_stats_result.json", "w"), indent=2, default=str)
