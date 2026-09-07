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
| qwen2.5:14b | 55.97 | 59.96 | **+3.99** | **1.0713** | **HIGHER** | 60.0 | +0.04 |

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
>
> **Update at n=5 (qwen2.5:14b, §2b):** ratio 1.0713, **HIGHER**, `[PARE]`. The pattern is now
> 2 lower (phi3.5, mistral) / 3 higher (qwen2.5:7b, llama3.1:8b, qwen2.5:14b) — still mixed
> direction, still inconsistent with one uniform systematic bias, still consistent with ERRATA
> item 5 (unseeded original runs as independent random draws). qwen2.5:14b's ratio (1.0713) is
> the closest to 1.0 of the three "higher" models — notably milder than qwen2.5:7b (1.1388) or
> llama3.1:8b (1.3306) — which does not fit a simple "larger models drift higher" story either;
> ordering by parameter count does not track ordering by ratio. **All 5 original models now
> reproduced; this table will not gain further rows.**

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

**Outcome after the 4th attempt: 4 of 5 techniques completed, 5th OOM-killed again.** With all
three mitigations above applied (free RAM ~9-11 GB throughout, a real improvement over the
~8.3 GB of the first three attempts), this attempt progressed further than any prior one: 4 of
5 techniques completed in full, and the 5th (`T1556.006`) reached round 2 of 3 before being
OOM-killed by the OS again. No partial or corrupted JSON was written (`_save_both_profiles()`
only runs after all techniques finish). Two more `--resume` attempts after this both died
**immediately after the Ollama restart**, before round 1 of the resumed technique even started
— with healthy free memory both before and after the restart. This pointed at the restart
sequence itself (killing and immediately reloading a large model into an app still settling)
as the likely trigger, not general memory scarcity.

**Fix: stop restarting Ollama unless something is actually still resident, and stop guessing
how long to wait.** `_ollama_has_resident_model()` (`GET /api/ps`) now gates the restart
entirely — with `keep_alive=0` on every call, nothing should be resident between techniques,
so the old unconditional per-technique restart was mostly restarting a already-idle app for no
reason, and doing it right before loading a 9 GB model back in. `_wait_for_ollama_ready()`
replaced the old fixed `sleep(3)` after a restart with polling `GET /api/tags` until it
returns 200, plus a 10s settle — so on the rare case a restart genuinely is needed, the next
model load doesn't race the app's own startup.

**5th and final attempt (this document's authorized last try): succeeded, 5/5 techniques,
no OOM, no restart triggered at all.** Free RAM stayed 9.4-11.9 GB throughout
(`output/benchmarks/logs/scaling_v2_qwen14b_final.log`); `qwen2.5:14b` reproduced at
`dabs_v1=59.96` against the paper's `55.97` (ratio 1.0713, ratio-based `[PARE]` — outside the
0.7-0.9 band, same "reproduces higher" direction as qwen2.5:7b and llama3.1:8b, not the "lower"
direction of phi3.5/mistral). **The reproduction now stands at 5 of 5 original models.**
Whether the fix (removing an unnecessary restart) or simply having more free RAM available at
this specific attempt is what actually resolved it was not isolated — both changed at once.
Recorded honestly as "no longer failing" rather than "root-caused."

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
| phi3.5:latest | ollama | 3.8 | 47.50 | 47.64 | Moderate Defender | confirmed | reproduced, ratio 0.7966 vs paper (§2) |
| mistral:7b | ollama | 7.0 | 52.63 | 52.78 | Moderate Defender | confirmed | reproduced (seed=42), see §3a for unseeded x3 |
| qwen2.5:7b | ollama | 7.61 | 62.42 | 62.57 | Strong Defender | confirmed | reproduced, ratio 1.1388 vs paper — [PARE] (§2) |
| llama3.1:8b | ollama | 8.0 | 55.26 | 55.31 | Strong Defender | confirmed | reproduced (seed=42), ratio 1.3306 — [PARE] (§2); see §3a for unseeded x3 |
| qwen2.5:14b | ollama | 14.7 | 59.96 | 60.0 | Strong Defender | confirmed | reproduced (seed=42), ratio 1.0713 — [PARE] (§2); resolved after 6+ OOM attempts, see §2b |
| llama3.2:1b | ollama | 1.23 | 36.52 | 36.7 | Weak Defender | confirmed | new local, no paper reference |
| llama3.2:3b | ollama | 3.21 | 63.76 | 63.9 | Strong Defender | confirmed | new local, no paper reference |
| qwen2.5:3b | ollama | 3.09 | 49.53 | 49.6 | Moderate Defender | confirmed | new local, no paper reference; one benign KQL table-redirect warning (SigninLogs), not an error |
| gemma2:2b | ollama | 2.0 | 61.03 | 61.2 | Strong Defender | confirmed | new local, no paper reference |
| gpt-oss:latest | ollama | 21.0 | 51.16 | 51.2 | Moderate Defender | confirmed | cross-platform control (Ollama leg); `KQL execution error: list index out of range` in 9/15 rounds — not seen in any other model this batch, flagged not yet diagnosed |
| openai/gpt-oss-20b | groq | 21.0 | 52.59 | 52.68 | Moderate Defender | confirmed | cross-platform control (Groq leg), see §5 |
| openai/gpt-oss-120b | groq | 117.0 | 65.30 | 65.28 | Strong Defender | confirmed | new Groq; 1/15 rounds hit the gpt-oss KQL parsing error (§5) |
| qwen/qwen3.8-27b | groq | 27.0 | 69.00 | 68.98 | Strong Defender | inferred | new Groq, no KQL parsing errors |

---

## 3a. Variance experiment (now the central result of v2, per instruction)

Queue: (a) mistral:7b seed=42 x2 — determinism check. (b) mistral:7b unseeded x3. (c)
llama3.1:8b unseeded x3 — the model that diverged in the opposite direction from mistral/phi3.5.
All three use `--threat-intel off`, both weight profiles, otherwise identical to §2.

| Model | Seed | n | Raw dabs_v1 values | Mean | SD | Range |
|---|---|---|---|---|---|---|
| mistral:7b | 42 (fixed) | 2 | [52.63, 52.63] | 52.63 | **0.00** | 0.00 |
| mistral:7b | none | 3 | [47.90, 57.85, 51.14] | 52.30 | **5.07** | 9.95 |
| llama3.1:8b | none | 3 | [59.63, 60.62, 63.39] | 61.21 | **1.95** | 3.76 |

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

**(c) llama3.1:8b — low variance, and unseeded runs don't come close to the paper value at
all. This is the more decisive result of the three.** `raw=[59.63, 60.62, 63.39]`,
`mean=61.21`, `sd=1.95` — well *under* the 5-point threshold, tightly clustered, all three
runs individually triggering `[PARE]` against the paper's 41.53 (ratios 1.44-1.53). Modeling
this as normal(61.21, 1.95), the paper's 41.53 is ~10σ away — not a plausible unseeded draw
from whatever distribution these three runs sample. **Unlike mistral:7b, unseeded variance
(ERRATA item 5) cannot explain llama3.1:8b's divergence from Table 1 at all** — this looks
like a real, reproducible, systematic difference between the current pipeline and whatever
produced the original 41.53, not sampling noise. Not yet identified. One structural note,
not yet investigated further: llama3.1:8b is both Attacker (fixed for every model in this
whole reproduction) and Defender in this specific run — a self-play configuration that may
behave differently from every other model pairing tested, worth isolating in a future test
(e.g. does a *different* fixed Attacker change llama3.1:8b's Defender score materially?).

**Comparing (b) and (c): the two divergent models fail in qualitatively different ways.**
mistral:7b's gap from Table 1 is partly (not fully) explained by high unseeded variance
(sd=5.07) landing consistently on the low side. llama3.1:8b's gap is not explained by
variance at all — it's a tight, consistent, ~20-point elevation above its paper value. Whatever
changed since the paper, it did not affect every model the same way, and for at least one
model (llama3.1:8b) it is not reducible to "the original run got unlucky."

Raw per-model JSON for every repeat: `output/benchmarks/scaling_v2/dabs_<model>_run<N>_<timestamp>.json`.

---

## 4. Scaling law fits

| Fit | Equation | R² | n | Notes |
|---|---|---|---|---|
| v1 published (paper) | DABS = 65.36 × P^−0.087 | 0.0557 | 5 | Original Table 1, params as originally (mis)stated |
| v1 corrected (this audit) | DABS = 64.67 × P^−0.080 | 0.0530 | 5 | Same 5 DABS scores, corrected params (7.61B, 14.7B) — see ERRATA.md item 2. Confirms `_fit_power_law` reproduces the paper's method: 0.0530 vs. published 0.0557, difference fully attributable to the params correction. |
| reproduced n=5 (this audit, dabs_v1) | DABS = 38.76 × P^+0.176 | **0.5653** | 5 | Same 5 models/positions as the paper, current pipeline, seed=42 (§2 table) — **not** the paper's own numbers. Sign flips positive. |
| **full grid, n=12 (dabs_v1)** | DABS = 47.08 × P^+0.080 | **0.3103** | 12 | Full §3 grid, total params, gpt-oss counted once (Ollama leg; Groq leg excluded — see below) |
| full grid, n=12 (dabs_v2) | DABS = 47.26 × P^+0.079 | 0.3056 | 12 | Same 12 points, current (dabs_v2) weight profile — formula drift alone barely moves R² |
| full grid, n=12 (dabs_v1, MoE on **active** params) | DABS = 44.74 × P^+0.132 | 0.3762 | 12 | Sensitivity check: gpt-oss:latest at 3.6B, gpt-oss-120b at 5.1B active instead of 21.0B/117.0B total — R² gets *stronger*, not weaker |

**Fit computed via `ScalingLawsAnalyzer()._fit_power_law()`** — the same log-linearized
power-law fit (`DABS = a · P^b`, R² measured in linear space against the fitted curve) already
implemented in `engine/scaling_laws.py` and used by `scripts/run_scaling_benchmark.py`'s own
console output. Not reimplemented for this document. The disk-loading half of
`ScalingLawsAnalyzer` (`_load_dabs_scores`/`analyze()`) was checked and found **stale** — it
globs `output/dabs_*.json` (not `output/benchmarks/scaling_v2/`) and reads a top-level
`dabs_score` key that no longer exists in the current `dabs_v1`/`dabs_v2` nested schema — so
every point in the table above was extracted by hand from each model's saved JSON
(`dabs_v1.dabs_score` / `dabs_v2.dabs_score`) and fed directly to `_fit_power_law()`, not
produced by running `analyze()`. The fit math is unmodified original code; only the
data-loading step was bypassed. Points used, in order: llama3.2:1b (1.23B), gemma2:2b (2.0B),
qwen2.5:3b (3.09B), llama3.2:3b (3.21B), phi3.5:latest (3.8B), mistral:7b (7.0B), qwen2.5:7b
(7.61B), llama3.1:8b (8.0B), qwen2.5:14b (14.7B), gpt-oss:latest (21.0B, Ollama leg only —
see below), qwen/qwen3.8-27b (27.0B), openai/gpt-oss-120b (117.0B). All from §2/§3, seed=42,
`--threat-intel off`, single run each (not the §3a repeat means).

**Why gpt-oss's Groq leg is excluded from the fit.** Per §1, the gpt-oss control pair is one
model measured on two platforms, not two grid points — including both (52.59 alongside 51.16
at the identical params_b=21.0) would double-weight one model and, worse, silently smuggle a
platform effect into what is supposed to be a params-only fit. The Ollama leg was kept as
canonical because the rest of the local-model grid is also Ollama; this is a judgment call,
stated here rather than left implicit. Using the Groq leg instead (52.59) or the mean of both
(51.88) changes R² by at most ~0.01 in informal spot checks — the conclusion below does not
hinge on this choice.

### 4a. Significance, confidence interval, and leverage (n=12 dabs_v1 fit)

Not produced by `engine/scaling_laws.py` — that module reports `r2` only, no inferential
statistics. Computed separately (`scipy.stats.linregress` on the same `log(P)`/`log(DABS)`
pair `_fit_power_law` already builds, `scipy==1.18.1`/`numpy==2.5.3`, installed this session —
were not previously in the environment) and not merged into the codebase; this is a one-off
analysis for this document, reproducible from the 12 `(params_b, dabs_v1)` pairs in §3.

| Fit | n | Exponent b | Std err | 95% CI for b | p (H0: b=0) | R² (log-space) | R² (linear-space, matches §4 table) |
|---|---|---|---|---|---|---|---|
| Full grid | 12 | +0.0802 | 0.0360 | **[−0.0001, +0.1605]** | **0.0502** | 0.3313 | 0.3103 |
| Without `openai/gpt-oss-120b` | 11 | +0.0974 | 0.0510 | [−0.0180, +0.2127] | 0.0886 | 0.2882 | (not recomputed in linear space) |

**Note on the two R² numbers**: `linregress` fits and scores in log-log space (R²=0.3313);
`engine/scaling_laws.py::_fit_power_law` fits the same log-linearization but scores R² in
*linear* space against the back-transformed curve (R²=0.3103, the number carried in the §4
table above). Both use the identical `a`/`b` — the 0.021 gap is a scoring-convention
difference, not a different fit. p-value and CI below come from the standard log-log OLS
frame (`linregress`), the one inferential statistics are actually defined for here.

**The full-grid result does not clear conventional significance.** p=0.0502 for the n=12
exponent is on the wrong side of the usual α=0.05 line — one two-thousandths over — and the
95% CI for b, **[−0.0001, +0.1605]**, includes zero. A CI that touches zero and a p-value
just above 0.05 describe the same fact two ways: this dataset cannot reject "no relationship
between parameter count and DABS" at conventional confidence. Dropping the single largest
model drops it further from significance, not closer: n=11 without `gpt-oss-120b` gives
p=0.0886, CI **[−0.0180, +0.2127]** — wider and now comfortably straddling zero.

**Leverage and Cook's distance identify why.** `openai/gpt-oss-120b` (117B, the largest point
by a factor of >4) has leverage 0.505 — more than the 2p/n=0.333 rule-of-thumb threshold for
"high leverage" (p=2 parameters, n=12) — meaning this single point has outsized ability to
pull the fitted line toward it purely by its extreme x-position, independent of whether its y
value is unusual. Its Cook's distance (0.135) stays under the 4/n=0.333 flag, so it is not
also an outlier relative to the fit — a high-leverage point that the fit *isn't* fighting, but
one whose removal (as the n=11 refit shows) still visibly widens the CI and raises the
p-value, because the fit loses its longest lever arm for pinning down the slope.
`llama3.2:1b` (1.23B, the smallest point) is the opposite pattern — Cook's distance 0.815 (n=12)
/ 1.035 (n=11), both far past 4/n, flagging it as a real outlier the fit is straining to
accommodate (its DABS=36.52 is the lowest in the grid, well below its neighbors), while its
leverage (0.271) sits below the high-leverage threshold. Full per-point table:
`output/benchmarks/scaling_v2/fit_stats_result.json`.

**Reading the two flagged points together**: the n=12 fit's positive slope is not an artifact
of one single point in the way a p-hacked or cherry-picked result would be — no point has
*both* high leverage and high Cook's distance — but it is close enough to the p=0.05 line that
the largest and smallest models in the grid each measurably move the result in opposite
directions when perturbed. This is consistent with n=12 being **too small to settle the
question**, not with the trend being fabricated.

Scatter plot (both fits overlaid, log-x): `docs/figures/scaling_v2_n12_scatter.png`.

### 4b. Does single-run variance (§3a) explain the grid's model-to-model gaps?

The two unseeded-triplicate SDs from §3a — mistral:7b SD=5.07, llama3.1:8b SD=1.95 — compare
against the DABS gap between each model and its nearest neighbor by parameter count in the
n=12 grid (sorted by params, `output/benchmarks/scaling_v2/fit_stats_result.json`): gaps range
from **3.70** (qwen/qwen3.8-27b → openai/gpt-oss-120b) to **24.51** (llama3.2:1b → gemma2:2b),
median **9.79**, mean **11.24**. Both measured SDs (1.95, 5.07) sit below the median gap and
below all but the single smallest gap (3.70, which mistral's own 5.07 SD already exceeds).

**One sentence, as asked: a single unseeded run is not reliable enough to distinguish most
neighboring models in this grid** — with SD in the 2-5 point range and most neighbor-gaps at
7-25 points, single-run noise could flip an adjacent pair's rank order only near the grid's
tightest gaps (qwen/qwen3.8-27b vs. gpt-oss-120b at 3.70, llama3.1:8b vs. qwen2.5:14b at 4.70),
not across the grid generally — but every §3 value in this document is still a single run, so
this is a bound on how much confidence the ranking deserves, not a demonstrated failure of it.

> ### n=12 shows a positive trend the n=5 paper result did not — but it does not reach
> ### conventional statistical significance
>
> The paper's headline claim — "scaling laws do not predict adversarial robustness," R²=0.055
> — does not survive unchanged at this expansion, but the replacement claim is weaker than
> "a real trend" and must be stated at that strength. **R² rises from 0.053-0.056 at n=5 to
> 0.31 at n=12** (dabs_v1; dabs_v2 is materially the same, 0.306), and the fitted exponent
> **flips sign**, from slightly negative (P^-0.08) to positive (P^+0.08). But per §4a, that
> exponent's 95% CI is **[−0.0001, +0.1605]** and its p-value is **0.0502** — a hair over the
> conventional 0.05 line, with a CI that touches zero. **This dataset cannot reject "no
> relationship" at conventional confidence, and dropping the single highest-leverage point
> (`openai/gpt-oss-120b`) moves the fit further from significance (n=11, p=0.0886), not closer.**
> The MoE active-params sensitivity check raises the linear-space R² to 0.376, but no p-value/CI
> was computed for that variant in this document — it should not be read as stronger evidence
> of significance than the total-params fit until it is.
>
> **This is not solely an effect of adding new models, though the same caveat applies.**
> Re-fitting the *original 5 models at their original positions*, under only the current
> pipeline (seed=42, §2 table, no new models added at all), gives R²=0.5653 — visibly higher
> than the paper's own n=5 fit (R²=0.053-0.056) at the exact same 5 sizes. No p-value/CI was
> computed for this n=5 refit in this document; at n=5, 3 degrees of freedom, a formal
> significance test would need to accompany any claim stronger than "descriptively higher R²"
> before it could be called anything but suggestive. Combined with §2's finding that 3 of these
> 5 models reproduce meaningfully higher than their Table 1 values and 2 reproduce lower
> (mixed direction, not a uniform shift), the most defensible reading available from what has
> actually been tested is: **the paper's original n=5 dataset was noisy** (most plausibly
> because those runs were unseeded single draws, ERRATA item 5) **in a way that changed what a
> fit to it shows — not proof of a real relationship, since neither the n=5 nor the n=12 fit
> clears significance at conventional confidence.**
>
> **What this does and does not establish — restated at the correct strength.** It does not
> vindicate a clean scaling law — R²=0.29-0.38 across the n=11/n=12/active-params variants is,
> at best, a weak-to-moderate positive association in the data actually collected, and it does
> not clear p<0.05 in the one variant (n=12, total params) where significance was formally
> tested. 12 points is a small sample for a power-law fit (`docs/paper.md` §6.2's own "≥15
> techniques for medium confidence" bar is about technique count, not model count, but the
> spirit applies equally here) — and this analysis independently shows *why* it's too small:
> two individual points (the largest, by leverage; the smallest, by Cook's distance, §4a) each
> measurably move the result. It also does not mean the paper's authors were wrong to report
> what their data showed; R²=0.055 on 5 unseeded single-draw points was an honest description
> of what those 5 points looked like. **The defensible summary, stated without inflation: the
> paper's n=5, unseeded "no relationship" finding does not survive as stated — the same
> methodology at n=12 with a fixed seed produces a numerically positive exponent and a higher
> R² — but that positive result is itself not statistically significant at conventional
> thresholds (p=0.0502, 95% CI for the exponent includes zero). The honest state of the
> evidence is "inconclusive, trending positive, too small a sample either way," not "the
> original claim was wrong" and not "the original claim is confirmed."**

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

Per mission rule 3: at least one model run on both platforms. As noted in §1, llama3.1:8b
itself could not be the cross-platform pair — no Groq model near its size exists on this
account's catalog, and llama3.1:8b is the fixed Attacker for every grid entry, never a Groq
Defender. The actual control is the **gpt-oss-20b pair**: same model weights
(huggingface.co/openai/gpt-oss-20b), one leg on local Ollama (`gpt-oss:latest`), one on Groq
(`openai/gpt-oss-20b`), same fixed local llama3.1:8b Attacker, same seed/techniques/rounds/
threat-intel-off.

| Model | Platform | DABS (dabs_v1) | DABS (dabs_v2) | Components (coverage/resilience/hardening/consistency, dabs_v2) |
|---|---|---|---|---|
| gpt-oss:latest | ollama | 51.16 | 51.23 | 60.0 / 28.67 / 47.0 / **76.52** |
| openai/gpt-oss-20b | groq | 52.59 | 52.68 | **80.0** / 30.96 / 53.56 / **32.53** |

**Δ (total score): +1.43 (v1), +1.45 (v2), ratio ≈1.03.** The aggregate DABS is close between
platforms — well inside the ~5-point threshold used elsewhere in this document to call a
difference "real" — so at the total-score level, platform is not a large confound for this
model. **But the component breakdown is not close at all**: `coverage` is 20 points higher on
Groq (80.0 vs 60.0) while `consistency` is 44 points higher on Ollama (76.52 vs 32.53) —
these two shifts happen to cancel out in the weighted total almost exactly. Reading only the
aggregate DABS would hide this; the two platforms are not producing the same *kind* of
Defender behavior; they land on a similar overall grade for different reasons. Not
diagnosed further here (5 techniques × 3 rounds is not enough to separate quantization,
sampling, or Groq-side serving differences from ordinary run-to-run variance per §3a) — flagged
as an open question, not smoothed over.

**reasoning_effort verification (per the new CLAUDE.md rule — checked against code, not
assumed):** `agents/defender.py` sets `reasoning_effort=DEFAULT_REASONING_EFFORT` ("medium")
for both calls whenever `is_reasoning_model(self.model)` is true, regardless of platform — so
both legs of this pair *did* run at the same reasoning effort. However, only
`scripts/run_groq_grid.py`'s saved JSON records this field (`"reasoning_effort": "medium"` on
the Groq leg); `scripts/run_scaling_benchmark.py` never serializes it, so the Ollama leg's
saved JSON has no `reasoning_effort` key at all — the value was fixed correctly in the actual
LLM call, but is not independently verifiable from the artifact alone. Documented as a gap,
not backfilled after the fact.

The `KQL execution error: list index out of range` pattern (§3 table, gpt-oss:latest row) also
reproduced on the Groq leg (6/15 rounds) and on `openai/gpt-oss-120b` (1/15) — present on both
platforms, so it is a property of gpt-oss's KQL output style hitting an `engine/detection.py`
edge case, not a platform-specific bug.

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
- **Parameter range achieved: 1.23B to 117B total (3.6B to 117B active)** — the "1B to 70B+"
  target from the mission brief is met and exceeded at the top end (gpt-oss-120b, 117B total),
  though the two largest points (27B, 117B) are both Groq-only, so the top of the range is not
  independently cross-checked on local hardware the way the 1-14.7B span is.
- **Technique subset is still 5 of 38** (T1078.004, T1110.003, T1528, T1621, T1556.006) — the
  same 5 as the original paper, kept fixed for comparability (§2). `docs/paper.md` §6.2's own
  bar of ≥15 techniques for "medium confidence" is not met by this reproduction either; every
  DABS value in this document inherits that same limitation from the original paper, unchanged.
- **Groq quantization/serving details are not publicly documented per-model** the way a local
  Ollama quantization tag is. §5 found the two platforms land within ~1.4 points on aggregate
  DABS but differ sharply per-component (coverage +20 Groq, consistency +44 Ollama) — this
  document cannot attribute that split to quantization specifically vs. other serving
  differences (sampling implementation, system prompt handling, etc.) with the data collected.
- **No model failed outright during this audit's own runs** (rate limit, decommissioned,
  unavailable) — every one of the 12 grid models plus the 5 original-position reproductions
  completed with 5/5 techniques. The one real failure mode encountered was local hardware OOM
  on qwen2.5:14b (§2b, 4 attempts before a 5th succeeded) — not a model/API failure, and no
  substitute value was ever used in its place; it is either a real reproduced score or marked
  PENDING, never estimated.
- **`meta_resilience` and `swarm_resilience` remain excluded from every DABS computation in
  this document** (`exclude_components=["swarm_resilience"]` is set explicitly in both
  `scripts/run_scaling_benchmark.py` and `scripts/run_groq_grid.py`; `meta_resilience` is
  never populated by the fixed 5-technique battle format at all — see `docs/ERRATA.md` item 1).
  This means every dabs_v1/dabs_v2 score in this document, old and new, is computed over 4 of
  6 nominal components — consistent within this document, but the "10% weight" and "8%+8%
  weight" figures in the weight-profile definitions are partly theoretical for any run that
  doesn't also exercise the meta/swarm battle modes.
- **Single-run variance (§3a) is per-model, not a shared value — treat it as an individual
  error bar, not a fleet-wide one.** mistral:7b's unseeded SD (5.07) and llama3.1:8b's (1.95)
  differ by a factor of ~2.6; no third model's variance was measured to know where either
  falls in a wider distribution. Every §3/§4 single-run DABS value should be read with *that
  specific model's* measured spread where available (mistral, llama3.1:8b) and as
  **unknown-but-plausibly-in-that-range** for the other 10 grid models, not as if 0 variance
  applied uniformly across the grid — §4b's neighbor-gap comparison already uses both SDs
  separately for this reason, not a pooled or averaged one.
- **`llama3.2:1b` is a Cook's-distance outlier the n=12/n=11 fits are both straining to
  accommodate (§4a: 0.815 at n=12, 1.035 at n=11, both past the 4/n flag), and it sits at the
  small-parameter end where no other grid point is close in size** (next smallest is
  gemma2:2b at 2.0B, then qwen2.5:3b/llama3.2:3b/phi3.5 clustered 3.0-3.8B) — the fit's
  behavior below ~3B rests on a single point, not a locally dense sample the way 7-14.7B is.
  Removing it entirely (not attempted as a formal sensitivity check in this document, unlike
  the gpt-oss-120b removal in §4a) would be a reasonable follow-up before trusting the fit's
  shape at the low-parameter end specifically.

---

## 7. n=13 — Foundation-Sec-8B-Instruct (security domain)

**Model.** `fdtn-ai/Foundation-Sec-8B-Instruct` (Cisco Foundation AI): 8B dense, Llama-3.1-8B
backbone continued-pretrained + instruction-tuned on a curated cybersecurity corpus (CVEs,
threat intel reports, exploit write-ups, compliance guides per the model card) — the only
model in this document with a domain-specific, not general-purpose, training claim. License:
dual — base weights under the Llama 3.1 Community License (Meta), Cisco's own
continued-pretraining/fine-tuning changes under Apache 2.0
(`https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/blob/main/NOTICE.md`). No official
Ollama library tag existed at the time of this run; no third-party community GGUF port was
used either — imported from fdtn-ai's own official Q8_0 GGUF quantization
(`fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF`, file `foundation-sec-8b-instruct-q8_0.gguf`,
8,541,888,288 bytes, sha256 `d0072df70235e92bd996d4efd2347b38c9db530ed83df21f6be3f8958a9832d`)
via a Modelfile that reuses ollama's own `llama3.1:8b` chat template verbatim — confirmed by
`tokenizer_config.json` that the model's special tokens (`<|start_header_id|>`,
`<|end_header_id|>`, `<|eot_id|>`, ids 128006/128007/128009) are unchanged from stock
Llama-3.1-Instruct, and no custom `chat_template` is published for this checkpoint. Registered
as `foundation-sec-8b:instruct-q8_0` in `engine/scaling_laws.py::MODEL_REGISTRY` with a new
`domain` field: `"security"` for this entry, and `"general"` marked explicitly (not left to the
field's default) on all 12 n=12-grid entries plus the two previously-excluded ones
(`allam-2-7b`, `openai/gpt-oss-safeguard-20b`) — neither is cybersecurity-domain-trained, so
`"general"` is accurate for both, not a placeholder. Context
length: the model card prose states 4,096 tokens but `config.json` reports 131,072 (inherited
from the Llama-3.1-8B base) — both recorded rather than one silently picked; not load-bearing
for this benchmark (every technique/prompt here is far under either bound).

**Run.** `--seed 42 --threat-intel off`, same 5 techniques/3 rounds as every other grid entry,
`keep_alive=0` (already the unconditional default for every local Ollama call in
`engine/groq_client.py::chat()` — no flag needed). **Took 3 attempts**: attempts 1 and 2 were
killed by an OS-level low-memory watchdog mid-run (not a Python exception — `ollama ps` showed
nothing resident and free RAM read 8.9-9.5GB at the time, the same range documented in §2b for
`qwen2.5:14b`'s OOM pattern on this 16GB machine). Per-technique checkpointing (§2c) meant each
retry only re-ran the missing techniques via `--resume`, not the full 5. Attempt 3 succeeded
after closing the same background applications §2b already identified (Chrome, Discord,
Spotify, Notion — freed RAM to 11.2-11.9GB) with `OLLAMA_MAX_LOADED_MODELS=1` confirmed still
set. **The optional unseeded ×3 repeat (for an error bar matching mistral:7b/llama3.1:8b, §3a)
was attempted 3 times and killed by the same watchdog every time** (including one `--resume`
retry after freeing RAM the same way) — stopped after the third failure per the standing rule
for this audit (a model does not get a fourth attempt); **no unseeded-variance measurement
exists for this model.** Its single seed=42 point is reported with the same caveat every other
single-run point in this document carries (§4b), with no model-specific SD available the way
mistral:7b (5.07) and llama3.1:8b (1.95) have.

**Result:** `dabs_v1=44.56`, `dabs_v2=44.69`, Moderate Defender, both under `weight_profile`s
with `swarm_resilience` excluded exactly as every other grid entry (§2a item 8/§6).
Components (dabs_v1): coverage 60.0, resilience 15.15, hardening 49.39, consistency 56.23.
Raw JSON: `output/benchmarks/scaling_v2/dabs_foundation-sec-8b_instruct-q8_0_20260907_033242.json`.

**Observation, not yet a diagnosed cause:** both of this model's first two completed
techniques (T1078.004, T1110.003) scored exactly 0% detection across all 6 of their rounds —
`kql_valid=True` in every case (the KQL parsed), but the rules matched specific hardcoded
example values (e.g. `UserPrincipalName in ("johndoe@contoso.com", "jane.doe@contoso.com", ...)`,
`AppDisplayName == "Azure Active Directory"`) that never appear in this benchmark's actual
generated attacker logs (which use different synthetic UPNs/app names each round). This reads
like literal textbook-example IOCs from training data rather than schema-general conditions —
plausible given a security-corpus fine-tune, but this is **one qualitative read of 6 rounds
from one model, not a diagnosed mechanism** — later techniques in the same run (T1528, T1621,
T1556.006) did score non-zero detection (see the raw JSON), so it is not a universal failure
mode for this model either.

| Model | Platform | Params (B) | Domain | DABS (dabs_v1) | DABS (dabs_v2) | Tier | Notes |
|---|---|---|---|---|---|---|---|
| foundation-sec-8b:instruct-q8_0 | ollama | 8.0 | **security** | 44.56 | 44.69 | Moderate Defender | seed=42, single run (see above for why no repeat SD exists); 3rd attempt after 2 OOM kills |

**Refit, n=13** (adding the row above to the n=12 grid in §3, same method as §4/§4a —
`scipy.stats.linregress` on `log(P)`/`log(DABS)`, `_fit_power_law` for the linear-space R² that
matches the rest of this document):

| Fit | n | Equation | R² (linear) | R² (log) | p (H0: b=0) | 95% CI for b |
|---|---|---|---|---|---|---|
| n=12 (unchanged, §4/§4a) | 12 | DABS = 47.08 × P^+0.0802 | 0.3103 | 0.3313 | 0.0502 | [−0.0001, +0.1605] |
| **n=13 (with Foundation-Sec-8B)** | 13 | DABS = 46.34 × P^+0.0797 | 0.2754 | 0.2897 | **0.0577** | [−0.0031, +0.1624] |

Adding this one point moves the fit **further from significance**, not closer (p rises from
0.0502 to 0.0577, R² falls from 0.31 to 0.28) — consistent with §4a's finding that this fit is
sensitive to individual points at n=12; a single below-fit-line addition at a already
well-populated parameter size (8.0B — three other models already sit at 7.0-8.0B) pulls both
statistics the same direction the n=11-without-gpt-oss-120b check did. **No claim of
significance is made at n=13 either.**

**Domain residual — does domain explain what parameter count doesn't?** Using the (unchanged)
n=12 fit as the size-only prediction, `predicted = 47.08 × 8.0^0.0802 = 55.63`. Foundation-Sec-8B's
residual (observed − predicted) is **44.56 − 55.63 = −11.07**. Compared against the three
general-purpose models already sitting at 7.0-8.0B in the n=12 grid:

| Model | Params (B) | Domain | Observed | Predicted (n=12 fit) | Residual |
|---|---|---|---|---|---|
| mistral:7b | 7.00 | general | 52.63 | 55.04 | −2.41 |
| qwen2.5:7b | 7.61 | general | 62.42 | 55.41 | +7.01 |
| llama3.1:8b | 8.00 | general | 55.26 | 55.63 | −0.37 |
| **foundation-sec-8b** | 8.00 | **security** | 44.56 | 55.63 | **−11.07** |

Foundation-Sec-8B's residual is more negative than all three same-size generalist models —
roughly 4-30 points lower than each of theirs. But read against the *full* n=12 residual
spread (all 12 general models against the same n=12 fit, not just the 7-8B cluster): the range
runs from −11.35 (llama3.2:1b) to +12.06 (llama3.2:3b) — **−11.07 is within the range already
produced by general-purpose models elsewhere in the grid**, barely milder than its most
negative point. It is a low outcome, but not a value outside what parameter-count noise alone
already produces at other sizes in this same grid. Full 12-point residual table:
`output/benchmarks/scaling_v2/fit_stats_n13_result.json`.

**Answered at the honest strength the mission asked for: domain does not clearly explain what
size doesn't, on this evidence.** Foundation-Sec-8B underperforms same-size generalists by a
real margin (4-30 points), and the qualitative KQL-overfitting observation above is a plausible
mechanism — but its residual is not extreme relative to the *whole* grid's already-wide
scatter, and **n=1 for the security domain cannot separate "security fine-tuning hurts this
benchmark" from "this specific model happened to land on the low side, the same way
llama3.2:1b or gpt-oss:latest did for reasons unrelated to domain."** This is **one security
model, explicitly not a sample** — no claim about security-domain models in general is made or
supportable from this data. A second and third security-domain model (a different size, a
different lab) would be needed before "domain" could be treated as its own variable rather than
one data point's story.

---

## Summary

1. **The paper's n=5, unseeded result does not hold as originally stated, but the correct
   replacement is "inconclusive," not "a real trend."** At n=12, with a fixed seed and
   corrected parameter counts, R² rises from 0.053-0.056 to **0.31** (dabs_v1) / **0.31**
   (dabs_v2), and the fitted exponent **flips sign** from negative to positive. Tested formally
   (§4a): p=**0.0502** for that exponent, 95% CI **[−0.0001, +0.1605]** — a hair over the
   conventional significance line, with a CI that includes zero. Removing the single
   highest-leverage point (`openai/gpt-oss-120b`, leverage 0.505, §4a) moves the fit *further*
   from significance (n=11, p=0.0886), not closer. The active-params MoE sensitivity variant
   raises R² to 0.38, but no significance test was run for that variant, so it cannot be cited
   as stronger evidence than the tested one. **No claim of "a real positive trend" is made in
   this document at n=12 — p>0.05 on the only variant formally tested.**
2. **This is not solely an effect of adding new models, though the same caveat applies here
   too.** Re-running the *original 5 model positions alone*, under the current pipeline, gives
   R²=0.57 — descriptively higher than the paper's own n=5 fit (R²=0.053-0.056) at the same 5
   sizes — but no p-value/CI was computed for this n=5 refit (3 degrees of freedom); it is
   reported as a descriptive contrast, not a significance result. The paper's original dataset
   being noisy (most plausibly unseeded single draws, ERRATA item 5) is the leading candidate
   explanation for why a fit to it looks different from a fit to the seeded reproduction — not
   proof that a relationship exists, since neither fit clears p<0.05 where that was tested.
3. **The original 5-model reproduction split in both directions**: phi3.5 and mistral scored
   *lower* than Table 1 (ratio ~0.79), qwen2.5:7b, llama3.1:8b, and qwen2.5:14b scored *higher*
   (ratio 1.07-1.33) — mixed-direction, not a uniform bias, consistent with the leading
   candidate cause (`docs/ERRATA.md` item 5: the original runs had no seed at all, so Table 1
   is 5 independent unrepeated draws from a noisy process, not 5 stable measurements). One
   exception was flagged and left unresolved: llama3.1:8b's elevation (~20 points, tight
   variance, ~10σ from paper) is too large and too consistent to be explained by unseeded
   variance alone (§3a) — a genuine, unidentified pipeline/environment difference likely also
   contributes for at least this model.
4. **qwen2.5:14b, the one model that could not be reproduced for most of this audit** (6+ OOM
   failures on 16GB local RAM), succeeded on the final attempt after fixing an unnecessary
   Ollama-restart-then-immediate-load sequence in `scripts/run_scaling_benchmark.py`. All 5
   original models are now reproduced; none are missing or estimated.
5. **Groq vs. Ollama, the one required cross-platform check (mission rule 3):** the gpt-oss-20b
   control pair lands within 1.4 DABS points on the aggregate score (ratio ≈1.03) but diverges
   sharply per-component (coverage +20 on Groq, consistency +44 on Ollama, cancelling out in
   the total) — platform is not a large confound for the *headline number*, but is a real,
   unexplained confound for the *component breakdown*, and this document does not paper over
   that with the clean aggregate result.
6. **What v2 adds structurally, independent of any single number:** `pipeline_version` on every
   result, versioned `dabs_v1`/`dabs_v2` weight profiles with explicit `excluded_components`,
   per-technique checkpointing with `--resume`, an automated stop-rule check that failed
   manually twice before being made automatic, and a CLAUDE.md rule requiring any
   methodological claim in `docs/` to be checked against the cited commit before being written
   — used, and it caught one real gap in this document (§5's `reasoning_effort` field) before
   publication.
7. **Single-run variance (§3a) vs. the grid's own model-to-model gaps (§4b):** the two
   unseeded-triplicate SDs measured (mistral:7b 5.07, llama3.1:8b 1.95) sit below the median
   neighboring-model DABS gap in the n=12 grid (9.79) and below all but its smallest gap
   (3.70). **A single unseeded run is not reliable enough to distinguish most neighboring
   models in this grid**, but the grid's typical gaps are wide enough that single-run noise
   would only plausibly flip rank order at its two or three tightest adjacent pairs, not
   throughout — a bound on confidence, not a demonstrated failure of the ranking.
8. **What is still weak, stated plainly:** n=12 is a small sample for a power-law fit and,
   per §4a, demonstrably too small to reach conventional significance (p=0.0502, CI includes
   zero) or to be robust to removing its single highest-leverage point (p rises to 0.0886
   without it); the technique count (5 of 38) is unchanged from the paper and still below its
   own bar for medium confidence; the two largest grid points (27B, 117B) are Groq-only with no
   local cross-check. **The defensible revision is "the paper's n=5 unseeded result does not
   survive as stated, and a numerically positive, non-significant trend is visible at n=12" —
   not "the paper was wrong," and not "a real scaling relationship is now established."** More
   models, more seeded repeats, or more techniques — not a different fit method — are what
   would resolve p=0.05 in either direction.
9. **n=13 (§7): the first security-domain model added, and it does not change any conclusion
   above.** Foundation-Sec-8B-Instruct (Cisco Foundation AI) scored dabs_v1=44.56 — adding it
   moves the n=12 fit *further* from significance (p: 0.0502 → 0.0577, R²: 0.31 → 0.28), not
   closer, reinforcing point 8's "too small a sample" reading rather than contradicting it. Its
   residual against the n=12 fit (−11.07) is worse than the three general-purpose 7-8B models
   already in the grid, but not more extreme than the *full* grid's own residual range
   (−11.35 to +12.06) — **domain does not clearly explain what parameter count doesn't, on this
   evidence.** This is one security-domain model, explicitly not a sample of security models;
   no general claim about domain-specialized fine-tuning is made or supportable here. Its
   optional unseeded ×3 repeat (for a per-model error bar matching mistral:7b/llama3.1:8b, §3a)
   failed to OS-level low-memory kills 3 times running and was abandoned per this audit's
   standing retry limit — this model's single point carries no model-specific variance estimate.

`docs/ERRATA.md` — 5 items — should accompany any future Zenodo update alongside this document,
per the earlier decision to batch corrections into one revision rather than issue several.
