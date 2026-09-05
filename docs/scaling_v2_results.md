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
>
> **Update:** phi3.5 (0.7966) and mistral (0.7943) reproduce at a consistent ~0.795 ratio of
> the paper value — not random per-model noise, a systematic multiplicative factor. Updated
> stop rule (still in effect): a model whose ratio falls **outside ~0.7–0.9**, or whose
> direction inverts (reproduces *higher* than paper), triggers a full stop — the ~0.795
> pattern itself is now the expected baseline, not a violation. See §2a for the code-level
> diagnosis of candidate causes.

### 2a. Diagnosis — what changed since the paper, at the code level

`226aed4` (2026-05-08, "feat: scaling laws...") is the commit that introduced the scaling-law
feature and is taken as the pipeline state that produced Table 1 (same day as the paper draft
commit `eada793`; DOI added the next day in `d6af684`). `git diff 226aed4 HEAD` for the files
the mission asked about:

**The single largest finding: `seed` did not exist in the code when the paper was written.**
`agents/attacker.py` and `agents/defender.py` had no `seed` parameter and no `"seed"` key in
any `ollama.chat()` `options={}` dict at `226aed4`. It was added two days later, in
`e30fdb0` (2026-05-10, "feat: reproducible seed support — all experiments reproducible with
--seed 42") — **after** the paper draft and the Zenodo DOI commit. Every LLM call in the
original scaling-law run was unseeded. The paper's §3.3 claim "All experiments use seed=42"
was not true of the run that produced Table 1 — the capability didn't exist yet. This is not
a "the pipeline drifted" finding, it's a "the original run was never deterministic in the
first place" finding, and on its own could fully explain why a seeded re-run lands on a
different, but internally consistent, operating point.

| # | File | Change since `226aed4` | Affects score? | Note |
|---|---|---|---|---|
| 1 | `agents/attacker.py`, `agents/defender.py` | `seed=42` added to every `options={}` (previously no `seed` key existed at all) | **YES** | See above — the leading candidate cause |
| 2 | `agents/defender.py` | `DefenderMemory` — injects accumulated per-technique context into the round-1 prompt | No, *in this reproduction* | Added 2026-05-17 (`0e8a6a5`), 9 days after the paper. `output/defender_memory.json` does not exist in this environment; `get_context()` returns `""` for every technique (tested directly). `run_scaling_benchmark.py`'s `_battle()` never calls `save_full_battle_log()` either, so this reproduction never reads *or* writes memory. Latent risk for a future run in an environment where that file has accumulated data — not a factor here. |
| 3 | `agents/defender.py` | `ConstitutionEngine` / `constitutional_mode` | No | Added 2026-05-17 (`2fa6d30`); defaults `False`, not enabled by this reproduction — dead code path for our runs |
| 4 | `agents/attacker.py`, `agents/defender.py` | `temperature`, `num_predict` | No | Byte-identical: 0.9/4096 (attacker payload call), 0.85/4096 (attacker main call), 0.3/2048 (defender LLM-mode call), 0.4/1024 (defender KQL call) |
| 5 | `agents/attacker.py`, `agents/defender.py` | System prompt text (`DEFENDER_SYSTEM`, `ATTACKER_SYSTEM`, etc.) | No | Unchanged; the Defender's `INITIAL_PROMPT_TEMPLATE` gained `{defender_memory}`/`{constitution}` interpolation slots, both empty per #2/#3 |
| 6 | `engine/scoring.py` | `compliance_result`, `constitution`, `constitution_attacks` fields on `BattleScorer`/saved log | No | Constitutional-mode only, inert here |
| 7 | `engine/scoring.py` | `seed` field added to `BattleScorer` and the saved battle-log dict | No (metadata only) | Doesn't touch `record_round()`'s detection-rate/evasion-rate math |
| 8 | `engine/dabs_scorer.py` | `WEIGHTS` 30/25/20/15/10 → 28/23/19/14/8/8, `swarm_resilience` added | **YES, but already controlled for** | Exactly `docs/ERRATA.md` item 1 — isolated by scoring every reproduction under `weight_profile="dabs_v1"` (paper weights) for the comparison in §2; not a residual confound in the Δ column above |
| 9 | `engine/dabs_scorer.py` | `_coverage`/`_resilience`/`_hardening`/`_consistency` formulas | No | Byte-identical — only the weighting/renormalisation logic around them changed |
| 10 | `engine/detection.py` | — | No | Zero diff. KQL detection engine is byte-identical to `226aed4` |
| 11 | *(not a code diff — a deliberate choice for this reproduction)* | `--threat-intel off` | **Suspected, unresolved** | The feature existed before the paper (2026-04-25) and ran live/unconditionally then (`docs/ERRATA.md` item 4). Turning it off for this reproduction is correct methodology going forward but is a real difference from how the original ran. Isolation test below. |

`prompts/` does not exist anywhere in this repo's history — system/template prompts live
inline in `agents/attacker.py` and `agents/defender.py`, covered above.

### GPU queue — prepared, not run yet (executes on `feat/groq-grid`, after the concurrent
### 5-model reproduction on `main` finishes; nothing shares GPU with it)

**1. Seed isolation + first DABS variance estimate.** mistral:7b, unseeded, 3 independent
runs, everything else identical (`--threat-intel off`, both weight profiles):

```
python scripts/run_scaling_benchmark.py \
  --models mistral:7b \
  --seed none \
  --repeat 3 \
  --threat-intel off
```

Dual purpose: (a) if the mean lands back near 66.27, `seed=42` not existing in the original
code (ERRATA item 5) explains the ~0.795 ratio; (b) the standard deviation across the 3 runs
is the project's first empirical estimate of DABS variance, to be reported as an error bar in
every table going forward, not just this one. `agents/attacker.py`/`agents/defender.py` now
support `seed=None` (omits the `seed` key from Ollama options entirely, not a sentinel value)
and `run_scaling_benchmark.py` supports `--repeat N` with automatic mean/stdev — both
implemented and unit-/integration-tested on `feat/groq-grid` (mocked, no real Ollama calls
yet), not merged to main.

**2.** The 4 new local models + `gpt-oss:latest` (the cross-platform control, Ollama leg).

**3.** The 3 new Groq models.

**4. Threat-intel snapshot test — only if time allows; low expected information value.**

```
python scripts/run_scaling_benchmark.py \
  --models mistral:7b \
  --threat-intel snapshot \
  --threat-intel-snapshot output/benchmarks/threat_intel_snapshot_2026-09-05.json
```

`output/benchmarks/threat_intel_snapshot_2026-09-05.json` was generated today from live
`ThreatIntelFeed` (no code changes — used as-is). **The v1 (original paper) threat-intel
enrichment is irreconstructable**: URLhaus's `/v1/urls/recent/` endpoint now returns
`401 Unauthorized` (it previously required no auth — an external API change, not a local bug,
discovered this session) and Feodo Tracker returned `503` at fetch time; a local SSL
certificate issue was also found and fixed along the way (`SSL_CERT_FILE` wasn't pointed at
`certifi`'s bundle) but is a separate problem from the 401/503s. Today's snapshot has **zero
real IOCs** — only the static baseline user-agent list, so this test can only show whether
merely *activating* the threat-intel code path (prompt scaffolding, `_build_ti_block()`) moves
the score with no real matches — not what the original run's actual enrichment did, which
cannot be recovered.

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

**`pipeline_version` and comparability.** Every result JSON now records `pipeline_version`
(`<short-commit-hash>[-dirty]@<date>`, `engine/dabs_scorer.py::get_pipeline_version()`, added
on `feat/groq-grid`, not yet in main). DABS is an absolute 0-100 score, but the prompts,
weights, and scoring logic it depends on change over time — exactly what §2/§2a document.
**An absolute DABS value is only safely comparable to another value carrying the same
`pipeline_version`.** Comparing across pipeline versions (e.g. this reproduction vs. the
paper's original run, which predates `pipeline_version` existing at all and is identified
only as "the code at `226aed4`") should use rank ordering and fitted trends — which model
beats which, and the shape/exponent of the power-law fit — not raw score differences. The
~0.795 ratio pattern (§2) is itself an example: the *ordering* of phi3.5 vs. mistral is
preserved (mistral still scores higher), even though neither absolute value matches its
paper counterpart.

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
