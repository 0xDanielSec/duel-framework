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

| Model | Paper (dabs_v1 implicit) | Reproduced v1 | Δ (LLM-output drift) | Ratio (repro/paper) | Direction | Reproduced v2 | Δ (v1→v2, formula drift only) |
|---|---|---|---|---|---|---|---|
| phi3.5:latest | 59.63 | 47.50 | −12.13 | 0.7966 | LOWER | 47.64 | +0.14 |
| mistral:7b | 66.27 | 52.63 | −13.64 | 0.7942 | LOWER | 52.78 | +0.15 |
| qwen2.5:7b | 54.81 | 62.42 | **+7.61** | **1.1388** | **HIGHER** | 62.57 | +0.15 |
| llama3.1:8b | 41.53 | 55.26 | **+13.73** | **1.3306** | **HIGHER** | 55.31 | +0.05 |
| qwen2.5:14b | 55.97 | — | — | — | **PENDING — hardware limitation, see §2b** | — | — |

> ### ⚠ STOP RULE TRIGGERED, TWICE, AND MISSED TWICE — this is the second time in this audit
>
> `phi3.5:latest` (ratio 0.7966) and `mistral:7b` (0.7942) reproduce lower than the paper, in
> the ~0.7–0.9 band. `qwen2.5:7b` (1.1388) and `llama3.1:8b` (1.3306) reproduce **higher** —
> both outside the band **and** inverted in direction, exactly the stop-rule trigger condition
> stated explicitly in the instruction that updated this rule. Neither was flagged when it
> finished; this was only caught while writing up the qwen2.5:14b hardware-failure report,
> after all four models had already completed.
>
> **Process note, stated plainly, again:** the same failure as `phi3.5:latest` earlier in this
> session — a completed model was reported without being checked against the stop rule it was
> completing *for*. Twice now. The check needed to run automatically the moment each model's
> JSON is saved, not be reconstructed from memory after the fact.
>
> **Implemented, not just noted:** `scripts/run_scaling_benchmark.py::_check_stop_rule()` now
> runs inside `_save_both_profiles()`, right after every model's dabs_v1 is computed — before
> this conversation moves on to anything else. It prints `paper | reproduced_v1 | ratio |
> status`, with a highlighted `[PARE]` line when the ratio falls outside `STOP_RULE_BAND`
> (0.7-0.9), and embeds the same report dict in the saved JSON (`"stop_rule"` key) so it
> travels with the artifact, not only the console log. `PAPER_DABS_V1` holds the five
> published reference values so no model can finish without the check running against it.
>
> **What the mixed-direction pattern actually means.** Two models lower, two higher is *not*
> consistent with a single systematic multiplicative bias (which would push every model the
> same way — e.g. threat-intel enrichment uniformly helping or a scoring change uniformly
> shifting scores). It *is* consistent with **ERRATA item 5** taken at face value: the
> original runs had no seed at all, so each model's Table 1 number is one unrepeated random
> draw with no reason to land systematically high or low relative to a seeded re-run — some
> draws were lucky, some weren't, independent per model. This makes the queued mistral:7b
> unseeded x3 test (§2b, GPU queue item 1) more informative than originally framed: it isn't
> only testing "does removing the seed move the mean back toward 66.27" — the *spread* across
> 3 unseeded runs, if wide, would itself explain why different models could land on opposite
> sides of their paper value by chance alone.
>
> Candidate causes, still not distinguished from each other, now weighted by the above:
> unseeded original runs (ERRATA item 5 — favored by the mixed-direction evidence);
> `--threat-intel off` removing an enrichment the original runs likely had (`docs/ERRATA.md`
> item 4 — would need to explain why it helped 2 models and hurt 2 others, which is possible
> but not the simplest reading); genuine Attacker/Defender model output drift between whatever
> Ollama build ran the original experiment and the current one; or a substantive behavioral
> change elsewhere in the prompt/scoring pipeline since the paper was written that has not yet
> been identified. Not diagnosed further until the table is
> complete.
>
> **Update (superseded by the table above once qwen2.5:7b/llama3.1:8b finished):** with only
> phi3.5 and mistral in hand, this note originally read the ~0.795 ratio as "a consistent,
> systematic multiplicative factor, not random noise." That reading does not survive the other
> two models reproducing *higher* than paper instead — see the mixed-direction analysis above,
> which now favors the opposite interpretation (unseeded original runs, not a uniform
> systematic bias). Left here rather than deleted, as a record of a conclusion this audit
> drew too early from n=2 and had to revise at n=4. See §2a for the code-level diagnosis of
> candidate causes.

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

### 2b. Local hardware & runtime setup

Recorded because it materially affected this reproduction: **16 GB total physical RAM**
(`Win32_OperatingSystem.TotalVisibleMemorySize` = 16,721,960 KB). The `qwen2.5:14b` leg
(model file 9.0 GB) was OOM-killed by the OS three times in a row before completing — Attacker
(llama3.1:8b, 7.3 GB resident) and Defender models are large enough relative to total RAM that
this machine cannot always hold both, or even one large model plus normal desktop load,
without contention. Mitigations applied, in order:

1. `engine/groq_client.py::chat()` now passes `keep_alive=0` to the local Ollama client on
   every call — the Attacker and Defender models are never simultaneously resident past the
   call that needs them (reload cost ~10-30s, noise against multi-minute rounds). This alone
   did not fix the qwen2.5:14b failures — the model didn't fit even without any other model
   loaded.
2. `OLLAMA_MAX_LOADED_MODELS=1` set as a user environment variable, Ollama app restarted to
   pick it up (confirmed unset beforehand).
3. Background applications (Chrome, Discord, Spotify, Notion) closed; Windows pagefile
   increase to 16 GB requested (not independently confirmed applied — `Win32_ComputerSystem
   .AutomaticManagedPagefile` still reported `True`, i.e. system-managed, at relaunch time;
   may require a reboot to take effect as configured). Free RAM went from a stable ~8.3 GB
   (across all three failed attempts) to ~10.6 GB after closing applications alone.

**`num_ctx`:** not set explicitly anywhere in `agents/attacker.py` or `agents/defender.py` —
grepped, confirmed absent. Every `ollama.chat()` call relies on the Ollama server's own
runtime default rather than a value this project chose. `ollama show qwen2.5:14b` reports the
model's maximum supported context length as 32768; this is the architecture's ceiling, not
necessarily the context actually allocated at inference time without an explicit `num_ctx`.
The exact effective default for the installed Ollama version (0.33.3) was not independently
verified here — if `num_ctx` ever needs to be pinned for cross-run comparability, it isn't
today, for any model in this reproduction, not just qwen2.5:14b.

**Outcome: qwen2.5:14b marked PENDING — hardware limitation, not run.** A 4th attempt, with
all three mitigations above applied (keep_alive=0, `OLLAMA_MAX_LOADED_MODELS=1`, background
apps closed, free RAM ~9-11 GB throughout — a real improvement over the ~8.3 GB of the first
three attempts), progressed further than any prior attempt: 4 of 5 techniques completed in
full, and the 5th (`T1556.006`) reached round 2 of 3 before being OOM-killed by the OS again.
No partial or corrupted JSON was written (`_save_both_profiles()` only runs after all
techniques finish) — confirmed nothing exists for this model in
`output/benchmarks/scaling_v2/`. Per instruction, this was the last attempt — no 5th retry.
**The reproduction stands at 4 of 5 models** (phi3.5:latest, mistral:7b, qwen2.5:7b,
llama3.1:8b); qwen2.5:14b's Table 1 row (55.97) has no reproduced counterpart in this audit.
Revisiting it is a matter of hardware (more RAM, a machine with a GPU that has enough VRAM to
avoid system-RAM contention entirely, or the pagefile increase actually taking effect after a
reboot), not of code or methodology — nothing here suggests the model itself is unreproducible
in principle.

### 2c. Per-technique checkpointing + `--resume`

Implemented so qwen2.5:14b (and any future model) needs only its missing techniques re-run,
not the whole 5-technique set from scratch. `scripts/run_scaling_benchmark.py` now writes
`output/benchmarks/scaling_v2/_checkpoints/<model>.json` after every technique completes
(`partial: true`, the list of completed technique IDs, and their full results). `--resume`
loads it, skips the already-completed techniques, and runs only what's missing.

**Why resuming is legitimate here, not just convenient:** the seed is applied per round inside
`_battle()` (no cross-technique RNG state to break), `DefenderMemory`/`AttackerMemory` are
inert in every benchmark run (§2a — no accumulated file in this environment, and the
benchmark script never calls `save_full_battle_log()` which is the only thing that would write
to them), and each technique gets a fresh `AttackerAgent`/`DefenderAgent` instance with no
state carried from the previous technique. There is nothing a resumed technique could inherit
from the techniques run in an earlier process.

**A real bug was caught and fixed while building this**, worth recording as a concrete
argument for the automated stop-rule check (§2/next section) generalized to code review too:
the first implementation finalized and saved a result — and deleted the checkpoint — as soon
as `technique_results` was non-empty, regardless of whether *all* requested techniques had
completed. A technique that errored (not just one still pending a `--resume`) would silently
produce a "complete" DABS score computed from whatever subset happened to succeed, with the
checkpoint destroyed and no way to tell afterward that a technique was ever missing. Caught by
a mocked test (simulate one technique raising, assert the checkpoint survives and the run
reports `incomplete` instead of finalizing) before this ever ran for real. Fixed: finalization
now requires `technique_results` to cover every requested technique (minus any that
permanently don't exist on disk, e.g. an LLM-only ID requested without the LLM technique
files present) before saving a final score or clearing the checkpoint.

**Ollama restart between techniques**, `--resume` only: `_restart_ollama()` kills and
relaunches the local Ollama app before each remaining technique. This mitigates the qwen2.5:14b
OOM symptom without a confirmed root cause — the per-20s memory samples taken around the
actual failure (§2b) fluctuated between ~9-11 GB free without a sustained downward trend, which
does not clearly support a slow leak/KV-cache-growth theory; a transient allocation spike at a
model reload (forced on every call by `keep_alive=0`, §2b item 1) is at least as consistent
with the evidence. Restarting the daemon is cheap insurance against either explanation, not a
diagnosis of which one is correct. Windows-only, best-effort — a failure to restart is logged
and does not abort the run.

---

## 3. Full grid (n ≥ 12) — DABS vs parameters

<!-- One row per model in the Section 1 grid. dabs_v2 is the primary column going forward;
     dabs_v1 is carried alongside for continuity with the paper's original comparison. -->

| Model | Platform | Params (B) | DABS (dabs_v1) | DABS (dabs_v2) | Tier | Confidence | Notes |
|---|---|---|---|---|---|---|---|
| TBD | | | | | | | |

---

## 3a. Variance experiment (now the central result of v2, per instruction)

Queue: (a) mistral:7b seed=42 x2 — determinism check. (b) mistral:7b unseeded x3. (c)
llama3.1:8b unseeded x3 — the model that diverged in the opposite direction from mistral/phi3.5.
All three use `--threat-intel off`, both weight profiles, otherwise identical to §2.

| Model | Seed | n | Raw dabs_v1 values | Mean | SD | Range |
|---|---|---|---|---|---|---|
| mistral:7b | 42 (fixed) | 2 | [52.63, 52.63] | 52.63 | **0.00** | 0.00 |
| mistral:7b | none | 3 | [47.90, 57.85, 51.14] | 52.30 | **5.07** | 9.95 |
| llama3.1:8b | none | 3 | TBD | TBD | TBD | TBD |

**(a) Determinism holds.** `seed=42` produces byte-for-byte identical DABS across 2
independent processes (`stdev=0.00`, every one of the 15 rounds matched exactly, not just the
final aggregate) — see the raw per-round log,
`output/benchmarks/logs/variance_2a_mistral_seed42_x2.log`. The v2 pipeline's own
reproducibility claim (same seed → same DABS) is **not** in question. This isolates the
open question to a single cause: whatever moved mistral/phi3.5/qwen2.5:7b/llama3.1:8b away
from Table 1, it is not "the seed doesn't actually pin anything."

**(b) Unseeded variance is real, large, and crosses the ~5-point line — but does not by
itself reach the paper's value.** SD=5.07 across 3 runs is at the ~5-point threshold set as
the "Table 1 didn't distinguish models reliably" criterion — a single unseeded run, as the
original was, is not a reliable point estimate for this model. However: none of the 3 draws
(max 57.85) came within 8 points of the paper's 66.27. Modeling the unseeded distribution as
approximately normal (mean 52.30, sd 5.07), landing on 66.27 is a ~2.7σ draw — possible, but
not the most parsimonious reading of 3 data points. **Conclusion: unseeded variance (ERRATA
item 5) is a real, evidenced contributor, but is not sufficient on its own to explain the
mistral/phi3.5 gap from Table 1 — something else (genuine pipeline/environment drift, or an
enrichment effect, or a combination) most likely still contributes.** Not further decomposed
without more data than 3 runs provides.

**(c) llama3.1:8b, the inverted-direction case — TBD, running.**

Raw per-model JSON for every repeat: `output/benchmarks/scaling_v2/dabs_<model>_run<N>_<timestamp>.json`.

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
