# Errata

Corrections to `docs/paper.md` ("Scaling Laws Do Not Predict Adversarial Robustness in
LLM-Based Security Detection Systems"). This is a separate document — the paper itself is
not edited. All three items below will be folded into the v2 revision.

Dated 2026-09-05.

---

## 1. Meta-Resilience was never computed for Table 1

Section 3.2 declares DABS as five weighted components, including:

> **Meta-Resilience** | 10% | Resistance to adversarial reasoning injection via log fields

Table 1 (§4.1), however, only reports four components — Coverage, Resilience, Hardening,
Consistency — with no Meta-Resilience column. The codebase confirms why: no call site that
produced the five-model scaling result ever populated `meta_resilience` in a technique
result, so the component was always absent for that experiment.

The actual DABS scores in Table 1 were therefore computed on the renormalized 4-component
form, with effective weights:

| Component | Nominal (paper) | Effective (Table 1, meta absent) |
|---|---|---|
| Coverage | 30% | 33.3% |
| Resilience | 25% | 27.8% |
| Hardening | 20% | 22.2% |
| Consistency | 15% | 16.7% |
| Meta-Resilience | 10% | — (never populated) |

This renormalization was never disclosed in the paper. The codebase now names this exact
weighting `dabs_v1` (`engine/dabs_scorer.py::WEIGHT_PROFILES`) so it can be reproduced
precisely, and every DABS result now records `weight_profile`, `weights_nominal`, and
`weights_effective` explicitly instead of silently renormalizing.

**Conclusion unaffected.** Table 1's numbers do not change — this corrects what the paper
says about how they were computed, not the numbers themselves.

---

## 2. Two model parameter counts were wrong

Table 1 (§3.3) listed `qwen2.5:7b` at 7.0B and `qwen2.5:14b` at 14.0B — rounded, unsourced
figures. Verified against the official Hugging Face model cards:

| Model | Paper value | Corrected value | Source |
|---|---|---|---|
| qwen2.5:7b | 7.0B | **7.61B** | https://huggingface.co/Qwen/Qwen2.5-7B |
| qwen2.5:14b | 14.0B | **14.7B** | https://huggingface.co/Qwen/Qwen2.5-14B |

The other three model's figures (phi3.5:latest 3.8B, mistral:7b 7.0B, llama3.1:8b 8.0B) were
re-verified against their own official cards and are unchanged.

Refitting the same power law (`DABS = a × P^b`, log-linear regression, same 5 DABS scores
from Table 1) with the corrected parameter counts:

| Fit | Equation | R² |
|---|---|---|
| Published | DABS = 65.36 × P^−0.087 | 0.0557 |
| Corrected | DABS = 64.67 × P^−0.080 | 0.0530 |

**Conclusion unaffected.** The corrected R² (0.0530) is within rounding distance of the
published value (0.0557) — parameter count explains essentially none of the variance either
way.

---

## 3. The weekly automated battle badge never reflected a real result

`.github/workflows/weekly-duel.yml` ran every Monday from 2026-04-25 through 2026-08-31 (21
runs) using Groq model IDs (`llama-3.1-70b-versatile` as Attacker, `mixtral-8x7b-32768` as
Defender) that were decommissioned on Groq's side. Every Defender call failed; every
technique recorded zero rounds; the workflow's own guard only checked "did any technique
avoid raising an exception," which a zero-round battle satisfies, so it committed a
`0.0% / 0-0` badge to `README.md` every single week without ever raising an error.

This automation is entirely separate from the scaling-law experiment — its output was never
read by `docs/paper.md` — so it does not affect any number in the paper. It is listed here
because it was discovered during this audit and is a factual correction about a claim the
README made ("Last Weekly Battle") that was never true.

Fixed: the badge is paused (`README.md`), `scripts/weekly_battle.py` now refuses to run
against a known-decommissioned model ID and fails the job (instead of committing) on any
technique error or an all-zero result, and raw weekly output is now saved to
`output/benchmarks/weekly/` (versioned in git) instead of only a gitignored path.

---

## 4. The original runs used live threat-intelligence enrichment, not seed-controlled

Live threat-intelligence enrichment (URLhaus/Feodo, added 2026-04-25) was active during the
original 5-model runs and is not seed-controlled; the paper's reproducibility claim (seed=42)
therefore did not hold. Benchmarks now run with `--threat-intel off` by default; the mode is
recorded in every output JSON.

Dated 2026-09-05.
