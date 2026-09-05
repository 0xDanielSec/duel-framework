# Scaling Laws v2 — Results

**Status: DRAFT SKELETON — no results filled in yet.** Every value below is a placeholder.
This document is populated only from real, executed runs — see `output/benchmarks/` for the
raw JSON backing every number that eventually goes here. Nothing in this file is invented.

Companion to `docs/paper.md` §4.1 and `docs/ERRATA.md`. Goal: replace the n=5, 3.8B–14B
scaling-law measurement with n≥12 spanning the widest available parameter range, using Groq
for models that don't run locally, without biasing the result toward confirming or refuting
the original R²=0.055 finding.

---

## 1. Model grid

**Approved 2026-09-05.** Original design had the Attacker also running on Groq for
Groq-Defender entries; cancelled — this account's Groq catalog has no model near
llama3.1:8b's size (smallest general-purpose option is 7B and bilingual-specialized). The
Attacker is now **llama3.1:8b on local Ollama for every entry, including Groq Defenders** —
`engine/groq_client.py` gained a per-agent `platform` override so one process can run a local
Attacker and a cloud Defender at once (`feat/groq-grid`, not merged).

| Model | Platform | Params total (B) | Params active (B) | Arch | Source (model card) | Role |
|---|---|---|---|---|---|---|
| phi3.5:latest | ollama | 3.8 | 3.8 | dense | huggingface.co/microsoft/Phi-3.5-mini-instruct | original 5 |
| mistral:7b | ollama | 7.0 | 7.0 | dense | ollama.com/library/mistral:7b | original 5 |
| qwen2.5:7b | ollama | 7.61 | 7.61 | dense | huggingface.co/Qwen/Qwen2.5-7B | original 5 |
| llama3.1:8b | ollama | 8.0 | 8.0 | dense | huggingface.co/meta-llama/Llama-3.1-8B | original 5 (+ fixed Attacker for every entry below) |
| qwen2.5:14b | ollama | 14.7 | 14.7 | dense | huggingface.co/Qwen/Qwen2.5-14B | original 5 |
| llama3.2:1b | ollama | 1.23 | 1.23 | dense | huggingface.co/meta-llama/Llama-3.2-1B | new local |
| gemma2:2b | ollama | 2.0 | 2.0 | dense | huggingface.co/google/gemma-2-2b | new local — card header inconsistency, see note below |
| qwen2.5:3b | ollama | 3.09 | 3.09 | dense | huggingface.co/Qwen/Qwen2.5-3B | new local |
| llama3.2:3b | ollama | 3.21 | 3.21 | dense | huggingface.co/meta-llama/Llama-3.2-3B | new local |
| gpt-oss:latest | **ollama** | 21.0 | 3.6 | moe | huggingface.co/openai/gpt-oss-20b | **cross-platform control (Ollama leg)** |
| openai/gpt-oss-20b | **groq** | 21.0 | 3.6 | moe | huggingface.co/openai/gpt-oss-20b | **cross-platform control (Groq leg)** — same model as the row above |
| qwen/qwen3.8-27b | groq | 27.0 | 27.0 | dense (**inferred**) | huggingface.co/Qwen/Qwen3.8-27B | new Groq |
| openai/gpt-oss-120b | groq | 117.0 | 5.1 | moe | huggingface.co/openai/gpt-oss-120b | new Groq |

`n = 12` distinct models (5 original + 4 new local + 3 new Groq), across **8 battles** — the
gpt-oss control pair measures the same model on both platforms and is not a 13th grid point.

**Excluded, recorded for the record:** `allam-2-7b` (7B, huggingface.co/ALLaM-AI/ALLaM-7B-Instruct-preview
— the exact "-2-" card 401'd; specialized Arabic-English bilingual model, not general-purpose) and
`openai/gpt-oss-safeguard-20b` (21B/3.6B active MoE, huggingface.co/openai/gpt-oss-safeguard-20b — safety/
moderation fine-tune, not a general Defender candidate; a possible future experiment on its own, not this
one).

**Reasoning effort.** gpt-oss is a reasoning model; `reasoning_effort` is fixed to `"medium"`
identically on both platforms (Ollama's `think=` param, Groq's `reasoning_effort=` field — same
low/medium/high scale, different parameter name, translated in `engine/groq_client.py::chat()`)
and recorded in every saved result JSON. Chosen because "low" would underuse the reasoning
capability that is the point of testing this model, and "high" would multiply per-round
latency/token cost across the grid without a clear benefit; "medium" is also the shared
middle point on the scale both providers expose, minimizing how much this one arbitrary
choice itself becomes a variable. Left unfixed, a different reasoning depth per platform would
be its own confound in the cross-platform control — indistinguishable from a genuine platform
effect.

---

## 2. Reproduction of the original 5 models

Same seed (42), same 5 techniques (T1078.004, T1110.003, T1528, T1621, T1556.006), same 3
rounds, same attacker (llama3.1:8b), run against the current codebase on local Ollama.
Scored under both weight profiles (`docs/ERRATA.md` item 1) so formula drift and LLM-output
drift are never conflated.

| Model | Paper (dabs_v1 implicit) | Reproduced v1 | Δ (LLM-output drift) | Direction | Reproduced v2 | Δ (v1→v2, formula drift only) |
|---|---|---|---|---|---|---|
| phi3.5:latest | 59.63 | 47.50 | **−12.13** | reproduced LOWER | 47.64 | +0.14 |
| mistral:7b | 66.27 | 52.63 | **−13.64** | reproduced LOWER | 52.78 | +0.15 |
| qwen2.5:7b | 54.81 | TBD | TBD | TBD | TBD | TBD |
| llama3.1:8b | 41.53 | TBD | TBD | TBD | TBD | TBD |
| qwen2.5:14b | 55.97 | TBD | TBD | TBD | TBD | TBD |

> ### ⚠ STOP RULE TRIGGERED — both models completed so far exceed the ~5-point threshold
>
> `phi3.5:latest` (−12.13) and `mistral:7b` (−13.64) both reproduce **well below** the
> published Table 1 values — more than double the ~5-point limit set as the go/no-go
> criterion before proceeding to the ≥12-model grid. Per instruction, execution is **not**
> being interrupted — all 5 original models run to completion so the full pattern is visible
> — but the ≥12-model grid does **not** proceed until this table is reviewed.
>
> **Process note, stated plainly:** `phi3.5:latest` finished first and was reported in this
> conversation as "clean" without checking it against the stop rule — an oversight, not a
> judgment call. It should have been flagged the moment it completed. `mistral:7b` was
> caught, `phi3.5:latest` was not, until asked. Both deltas point the same direction (v1
> drift, not weight-profile drift — Δ(v1→v2) is negligible for both, ~+0.15), which is
> itself informative: whatever changed since the paper, it isn't the scoring formula.
>
> Candidate causes, not yet distinguished from each other: `--threat-intel off` removing an
> enrichment the original runs likely had (`docs/ERRATA.md` item 4 — this would make
> reproduced scores *diverge* from the paper by construction, in either direction depending
> on whether that enrichment helped or hurt); genuine Attacker/Defender model output drift
> between whatever Ollama build ran the original experiment and the current one; or a
> substantive behavioral change elsewhere in the prompt/scoring pipeline since the paper was
> written that has not yet been identified. Not diagnosed further until the table is
> complete.

Raw per-model JSON: `output/benchmarks/scaling_v2/dabs_<model>_<timestamp>.json` (each contains
both `dabs_v1` and `dabs_v2` in full, including per-component and per-technique breakdowns).

---

## 3. Full grid (n ≥ 12) — DABS vs parameters

<!-- One row per model in the Section 1 grid. dabs_v2 is the primary column going forward;
     dabs_v1 is carried alongside for continuity with the paper's original comparison. -->

| Model | Platform | Params (B) | DABS (dabs_v1) | DABS (dabs_v2) | Tier | Confidence | Notes |
|---|---|---|---|---|---|---|---|
| TBD | | | | | | | |

---

## 4. Scaling law fits

| Fit | Equation | R² | n | Notes |
|---|---|---|---|---|
| v1 published (paper) | DABS = 65.36 × P^−0.087 | 0.0557 | 5 | Original Table 1, params as originally (mis)stated |
| v1 corrected (this audit) | DABS = 64.67 × P^−0.080 | 0.0530 | 5 | Same 5 DABS scores, corrected params (7.61B, 14.7B) — see ERRATA.md item 2 |
| v2 reproduced, n=5 | TBD | TBD | 5 | Current pipeline, dabs_v2 weights, same 5 models |
| v2 full grid, n≥12 | TBD | TBD | ≥12 | Current pipeline, dabs_v2 weights, full grid |
| v2 full grid, Groq-only subset | TBD | TBD | TBD | Isolates platform effect — Ollama models excluded |

---

## 5. Groq vs. Ollama — platform cross-check

Per mission rule 3: at least one model run on both platforms (llama3.1:8b) to check whether
quantization/sampling differences between Groq's hosted inference and local Ollama move the
DABS score.

| Model | Platform | DABS (dabs_v2) | Components (coverage/resilience/hardening/consistency) | Notes |
|---|---|---|---|---|
| llama3.1:8b | ollama | TBD | TBD | Reproduction run, Section 2 |
| llama3.1:8b | groq | TBD | TBD | Same seed/techniques/rounds |

**Δ:** TBD. If this exceeds ~5 DABS points, it is reported as a limitation (below), not
smoothed over — platform is a confound, not a modeling choice.

---

## 6. Limitations

<!-- Written honestly once results exist. Known items to address even if the numbers turn out
     clean: -->

- **The original 5-model paper results almost certainly ran with live threat-intel
  enrichment, undisclosed.** `engine/threat_intel.py` (URLhaus/Feodo/OTX, live fetch,
  1h cache) was added 2026-04-25 — before the scaling-laws feature (2026-05-08) and
  before the paper's May 2026 publication. Prior to this audit, `DefenderAgent.__init__`
  had no toggle at all: it unconditionally called `ThreatIntelFeed()` on every
  instantiation. `docs/paper.md` never mentions threat intel, URLhaus, Feodo, IOC, or
  blocklist anywhere (§3.2/§3.3 methodology is silent on it). This means the original
  Defender wasn't a bare LLM — it was an LLM plus whatever IOC snapshot URLhaus/Feodo/OTX
  happened to return at benchmark time, which is not controlled by `seed=42` despite the
  paper's reproducibility claim (§3.3). This reproduction run (Section 2) uses
  `--threat-intel off` specifically to remove this confound going forward; it cannot be
  removed retroactively from the original Table 1 numbers.
- **qwen/qwen3.8-27b's architecture (dense) is inferred, not confirmed.** The model card
  states "27B" with no separate active-parameter figure and no MoE naming pattern (cf.
  Qwen3's own "-A3B" convention for its actual MoE variants), so it is treated as dense —
  `arch_confidence: "inferred"` in `engine/scaling_laws.py::MODEL_REGISTRY`, surfaced in
  `scripts/run_groq_grid.py`'s printed grid. If it turns out to be MoE, its `params_active_b`
  in this document would be wrong and any params_active-based fit (§4) involving it would
  need correcting.
- **No Groq-side Attacker equivalent to llama3.1:8b exists on this account.** The Groq
  catalog for this API key has 6 general-purpose chat models total, none near 8B (smallest
  is a 7B bilingual Arabic-English specialist). The original "Attacker also on Groq" design
  was cancelled; the Attacker is llama3.1:8b on local Ollama for every grid entry, including
  Groq Defenders (§1). This means the Groq-Defender legs are not a full "everything on Groq"
  measurement — only the Defender varies by platform, which is what the cross-platform
  control (gpt-oss, §1/§5) is actually built to isolate.
- **Groq's own docs list additional Production models (Llama 3.1 8B, Llama 3.3 70B) that
  this account's API key cannot see** (`GET /openai/v1/models` returns 12 models total, none
  of them Llama) — likely an Enterprise-tier gate, unconfirmed. If a higher account tier
  becomes available, the grid should be revisited; the current 12-model grid reflects what
  this specific key can actually run, not the full Groq catalog.
- TBD — parameter range actually achieved vs. the "1B to 70B+" target.
- TBD — technique subset is still 5 of 38; full-campaign DABS needs ≥15 techniques for
  medium confidence (per `docs/paper.md` §6.2, unchanged here).
- TBD — Groq quantization/serving details are not publicly documented per-model the way a
  local Ollama quantization tag is; this limits how precisely the Ollama-vs-Groq comparison
  in Section 5 can attribute a delta to quantization specifically vs. other serving
  differences (sampling implementation, system prompt handling, etc).
- TBD — any model that failed (rate limit, decommissioned, unavailable) during the run, with
  no invented substitute value. List every failure here even if the final grid still reaches
  n≥12 without it.
- TBD — anything else surfaced during execution.

---

## Summary (to be written last)

<!-- The 10-line summary requested in the mission: old R² (n=5) vs new (n≥12), whether the
     paper's conclusion holds, changes, and what goes into v2. Written only after every table
     above is filled from real runs. -->
