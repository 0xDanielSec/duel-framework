#!/usr/bin/env python3
"""
Scaling Benchmark — runs DABS for all 5 model sizes, then fits scaling laws.

Runs the same fixed techniques and rounds for every model, so results are
directly comparable. After all models complete, ScalingLawsAnalyzer fits
a power law curve and prints the scaling law table and equation.

Usage:
    python scripts/run_scaling_benchmark.py
    python scripts/run_scaling_benchmark.py --rounds 5
    python scripts/run_scaling_benchmark.py --techniques T1078.004,T1110.003,T1528
    python scripts/run_scaling_benchmark.py --models mistral:7b,qwen2.5:14b
"""
import argparse
import json
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Force line-buffered stdout/stderr even when redirected to a file (the
# default is block-buffered in that case, which left a real run silently
# invisible for 20+ minutes during a hang — see docs/scaling_v2_results.md
# Limitations). PYTHONUNBUFFERED=1 achieves the same thing from the caller's
# side; this makes it true regardless of how the script is invoked.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)

from rich import box
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from agents.attacker import AttackerAgent
from agents.defender import DefenderAgent
from engine.dabs_scorer import DABSResult, DABSScorer, get_pipeline_version, get_tier
from engine.detection import DetectionEngine
from engine.llm_detection import LLMDetectionEngine
from engine.scaling_laws import MODEL_REGISTRY, ScalingLawsAnalyzer
from engine.scoring import BattleScorer

TECHNIQUES_DIR = Path(__file__).parent.parent / "techniques"

DEFAULT_TECHNIQUES    = ["T1078.004", "T1110.003", "T1528", "T1621", "T1556.006"]
DEFAULT_ROUNDS        = 3
DEFAULT_ATTACKER      = "llama3.1:8b"
DEFAULT_ROUND_TIMEOUT = 600  # generous per-round budget (attacker+defender+detection combined)
DEFAULT_MODELS     = [
    "phi3.5:latest",
    "mistral:7b",
    "qwen2.5:7b",
    "llama3.1:8b",
    "qwen2.5:14b",
]

# docs/paper.md Table 1 — dabs_v1 values (paper's own weight profile), for the
# stop-rule check. Not a live/derived value: these are the five published
# numbers, typed once here as the fixed reference for every reproduction run.
PAPER_DABS_V1: dict[str, float] = {
    "phi3.5:latest": 59.63,
    "mistral:7b":    66.27,
    "qwen2.5:7b":    54.81,
    "llama3.1:8b":   41.53,
    "qwen2.5:14b":   55.97,
}
# "Expected" band established from phi3.5/mistral (2026-09-05 reproduction) —
# see docs/scaling_v2_results.md §2. A ratio outside this band, in EITHER
# direction, or exactly on the discovered failure pattern (qwen2.5:7b,
# llama3.1:8b both landed outside it, inverted), is a stop-rule trigger.
# This band is an empirical observation from n=2, not a law — see the same
# section's "missed twice" note for why automating this check, rather than
# remembering to apply it, is the point of this function existing at all.
STOP_RULE_BAND = (0.7, 0.9)

console = Console()

TIER_STYLES = {
    "Elite Defender":    "bold yellow",
    "Strong Defender":   "bold green",
    "Moderate Defender": "bold color(226)",
    "Weak Defender":     "bold dark_orange",
    "Vulnerable":        "bold red",
}


def _load_technique(technique_id: str) -> dict:
    if technique_id.upper().startswith("LLM"):
        path = TECHNIQUES_DIR / "llm" / f"{technique_id.upper()}.json"
    else:
        path = TECHNIQUES_DIR / f"{technique_id}.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _all_technique_count() -> int:
    n = len(list(TECHNIQUES_DIR.glob("*.json")))
    llm_dir = TECHNIQUES_DIR / "llm"
    if llm_dir.exists():
        n += len(list(llm_dir.glob("*.json")))
    return n


def _round_body(
    attacker: AttackerAgent,
    defender: DefenderAgent,
    technique: dict,
    technique_id: str,
    round_num: int,
    rounds: int,
    last_kql: str | None,
    detected_logs: list[dict],
    evaded_logs: list[dict],
) -> tuple[list[dict], str, dict]:
    """The actual attacker+defender+detection work for one round — run inside
    a thread so it can be bounded by round_timeout without killing the process."""
    attack_logs = attacker.generate_logs(
        technique=technique,
        round_num=round_num,
        total_rounds=rounds,
        last_kql=last_kql,
        detected_logs=detected_logs,
        evaded_logs=evaded_logs,
    )
    kql_rule = defender.generate_rule(
        technique=technique,
        round_num=round_num,
        total_rounds=rounds,
        attack_logs=attack_logs,
        detected_logs=detected_logs,
        evaded_logs=evaded_logs,
    )
    engine = (
        LLMDetectionEngine(attack_logs)
        if technique_id.upper().startswith("LLM")
        else DetectionEngine(attack_logs)
    )
    det = engine.run(kql_rule)
    return attack_logs, kql_rule, det


def _battle(
    technique: dict,
    rounds: int,
    attacker_model: str,
    defender_model: str,
    round_timeout: int = DEFAULT_ROUND_TIMEOUT,
    threat_intel_mode: str = "off",
    threat_intel_snapshot_path: str | None = None,
    attacker_platform: str | None = None,
    defender_platform: str | None = None,
    seed: int | None = 42,
) -> dict:
    """
    attacker_platform/defender_platform: None keeps the original auto-detect-
    by-GROQ_API_KEY behaviour (both agents share whatever engine.groq_client
    resolves). Pass explicit "ollama"/"groq" per agent to run them on
    DIFFERENT platforms in the same process — e.g. the Groq grid's fixed
    design: Attacker always "ollama" (llama3.1:8b), Defender "groq" for
    Groq-side grid entries.
    """
    technique_id = technique["technique_id"]
    attacker = AttackerAgent(model=attacker_model, num_logs=10, platform=attacker_platform, seed=seed)
    defender = DefenderAgent(
        model=defender_model,
        threat_intel_mode=threat_intel_mode,
        threat_intel_snapshot_path=threat_intel_snapshot_path,
        platform=defender_platform,
        seed=seed,
    )
    scorer = BattleScorer(
        total_rounds=rounds,
        technique_id=technique_id,
        seed=seed,  # None -> "seed": null in the saved battle log, honestly marking it unseeded
        attacker_model=attacker_model,
    )

    for round_num in range(1, rounds + 1):
        last_kql      = scorer.rounds[-1]["kql_rule"] if scorer.rounds else None
        detected_logs = scorer.get_last_detected_logs()
        evaded_logs   = scorer.get_last_evaded_logs()

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    _round_body, attacker, defender, technique, technique_id,
                    round_num, rounds, last_kql, detected_logs, evaded_logs,
                )
                attack_logs, kql_rule, det = future.result(timeout=round_timeout)
        except FuturesTimeoutError:
            record = scorer.record_timeout(round_num, phase="round")
            console.print(
                f"    [red]{record['timestamp']}[/red] round {round_num}/{rounds} "
                f"[red]TIMEOUT[/red] after {round_timeout}s"
            )
            continue

        record = scorer.record_round(
            round_num=round_num,
            attack_logs=attack_logs,
            kql_rule=kql_rule,
            detected_ids=det["detected_ids"],
            kql_valid=det["kql_valid"],
        )
        console.print(
            f"    [dim]{record['timestamp']}[/dim] round {round_num}/{rounds} done — "
            f"det={record['detection_rate']:.2f} eva={record['evasion_rate']:.2f}"
        )

    return {
        "rounds": scorer.rounds,
        "tactic": technique.get("tactic", technique.get("owasp_category", "Unknown")),
        "name":   technique.get("name", technique_id),
    }


SCALING_V2_DIR = Path(__file__).parent.parent / "output" / "benchmarks" / "scaling_v2"


def _save_both_profiles(
    model: str,
    technique_results: dict[str, dict],
    attacker_model: str,
    total_techs: int,
    platform: str,
    threat_intel_mode: str,
    seed: int | None = 42,
    run_index: int | None = None,
) -> tuple[DABSResult, DABSResult, Path]:
    """
    Score the same technique_results under both dabs_v1 (paper weights) and
    dabs_v2 (current weights) so formula drift and LLM-output drift can be
    told apart, then save one combined JSON to output/benchmarks/scaling_v2/
    (versioned — this is the real artifact for the scaling_v2 comparison).
    """
    pv = get_pipeline_version()
    v1 = DABSScorer(
        model=model, technique_results=technique_results, attacker_model=attacker_model,
        total_techniques=total_techs, exclude_components=["swarm_resilience"],
        platform=platform, weight_profile="dabs_v1", pipeline_version=pv, seed=seed,
    ).compute()
    v2 = DABSScorer(
        model=model, technique_results=technique_results, attacker_model=attacker_model,
        total_techniques=total_techs, exclude_components=["swarm_resilience"],
        platform=platform, weight_profile="dabs_v2", pipeline_version=pv, seed=seed,
    ).compute()

    stop_rule = _check_stop_rule(model, v1.dabs_score)

    SCALING_V2_DIR.mkdir(parents=True, exist_ok=True)
    safe = model.replace(":", "_").replace("/", "_")
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = f"_run{run_index}" if run_index is not None else ""
    path = SCALING_V2_DIR / f"dabs_{safe}{suffix}_{ts}.json"
    path.write_text(json.dumps({
        "model":              model,
        "attacker_model":     attacker_model,
        "platform":           platform,
        "threat_intel_mode":  threat_intel_mode,
        "pipeline_version":   pv,
        "seed":               v1.seed,
        "run_index":          run_index,
        "timestamp":          v2.timestamp,
        "stop_rule":          stop_rule,
        "dabs_v1":            v1.to_dict(),
        "dabs_v2":            v2.to_dict(),
    }, indent=2), encoding="utf-8")

    return v1, v2, path


def _check_stop_rule(model: str, dabs_v1_score: float) -> dict:
    """
    Compare a reproduced dabs_v1 score against docs/paper.md Table 1 and print
    a status line — this is the automated check that replaces a human
    remembering to do it (see docs/scaling_v2_results.md: this exact check
    was missed twice in one day before it was written).

    Returns the report dict that also gets embedded in the saved JSON, so the
    stop-rule status travels with the artifact, not only the console log.
    """
    paper_score = PAPER_DABS_V1.get(model)
    if paper_score is None:
        report = {
            "model": model, "paper": None, "reproduced_v1": round(dabs_v1_score, 2),
            "ratio": None, "status": "no_reference",
        }
        console.print(
            f"  [dim]{model:20s} paper=n/a  reproduced_v1={dabs_v1_score:6.2f}  "
            f"(no PAPER_DABS_V1 reference — not a stop-rule check)[/dim]"
        )
        return report

    ratio = dabs_v1_score / paper_score if paper_score else float("inf")
    lo, hi = STOP_RULE_BAND
    triggered = not (lo <= ratio <= hi)
    status = "STOP_RULE_TRIGGER" if triggered else "ok"
    report = {
        "model": model, "paper": paper_score, "reproduced_v1": round(dabs_v1_score, 2),
        "ratio": round(ratio, 4), "status": status,
    }

    line = (
        f"{model:20s} paper={paper_score:6.2f}  reproduced_v1={dabs_v1_score:6.2f}  "
        f"ratio={ratio:.4f}"
    )
    if triggered:
        console.print(f"  [bold red][PARE][/bold red] {line}  [bold red]OUTSIDE {STOP_RULE_BAND} BAND[/bold red]")
    else:
        console.print(f"  [green]{line}  within {STOP_RULE_BAND} band[/green]")
    return report


CHECKPOINT_DIR = SCALING_V2_DIR / "_checkpoints"


def _checkpoint_path(model: str) -> Path:
    safe = model.replace(":", "_").replace("/", "_")
    return CHECKPOINT_DIR / f"{safe}.json"


def _load_checkpoint(model: str) -> dict | None:
    p = _checkpoint_path(model)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _save_checkpoint(model: str, technique_results: dict[str, dict], seed: int | None, threat_intel_mode: str) -> None:
    """
    Written after each technique completes, so a crash (OOM, timeout, etc.)
    loses at most one technique's work, not the whole model. Legitimate to
    resume from because there is no state carried between techniques: seed is
    applied per round inside _battle(), DefenderMemory is off in every
    benchmark run, and each technique gets fresh AttackerAgent/DefenderAgent
    instances — see docs/scaling_v2_results.md §2c.
    """
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    _checkpoint_path(model).write_text(json.dumps({
        "model": model,
        "seed": seed,
        "threat_intel_mode": threat_intel_mode,
        "completed_techniques": list(technique_results.keys()),
        "technique_results": technique_results,
        "partial": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")


def _clear_checkpoint(model: str) -> None:
    p = _checkpoint_path(model)
    if p.exists():
        p.unlink()


def _restart_ollama() -> None:
    """
    Kill and relaunch the Ollama app so each --resume technique starts
    against a clean daemon. Mitigates (does not diagnose) an OOM observed on
    a 16GB machine partway through a run despite 9-11 GB free throughout --
    the per-20s memory samples around the failure did not show a sustained
    decline, so a slow leak/KV-cache-growth theory is not well supported by
    the evidence in hand; a transient allocation spike right at a model
    reload (keep_alive=0 forces one on every call) is at least as plausible.
    Restarting between techniques is a symptom-level mitigation either way --
    see docs/scaling_v2_results.md §2b/§2c. Windows-only, best-effort: any
    failure here is logged and swallowed rather than aborting the run.
    """
    import subprocess
    import time

    if sys.platform != "win32":
        console.print("  [dim]_restart_ollama: not Windows, skipping[/dim]")
        return
    try:
        subprocess.run(["taskkill", "/F", "/IM", "ollama app.exe"], capture_output=True)
        subprocess.run(["taskkill", "/F", "/IM", "ollama.exe"], capture_output=True)
        time.sleep(1)
        app_path = Path.home() / "AppData" / "Local" / "Programs" / "Ollama" / "ollama app.exe"
        if app_path.exists():
            subprocess.Popen([str(app_path)], creationflags=subprocess.DETACHED_PROCESS)
            time.sleep(3)  # let the daemon come up before the next technique's first call
            console.print("  [dim]Ollama restarted[/dim]")
        else:
            console.print(f"  [yellow]_restart_ollama: {app_path} not found, skipped relaunch[/yellow]")
    except Exception as exc:
        console.print(f"  [yellow]_restart_ollama failed (non-fatal): {exc}[/yellow]")


def _run_model(
    model: str,
    technique_ids: list[str],
    rounds: int,
    attacker_model: str,
    total_techs: int,
    platform: str = "ollama",
    round_timeout: int = DEFAULT_ROUND_TIMEOUT,
    threat_intel_mode: str = "off",
    threat_intel_snapshot_path: str | None = None,
    seed: int | None = 42,
    run_index: int | None = None,
    resume: bool = False,
) -> dict:
    if seed is None:
        console.print("  [yellow]UNSEEDED run — no seed sent to Ollama[/yellow]")
    if run_index is not None:
        console.print(f"  [dim]repeat run {run_index}[/dim]")
    console.print(f"\n[bold cyan]══ Defender: {model} ══[/bold cyan]")

    technique_results: dict[str, dict] = {}
    if resume:
        ckpt = _load_checkpoint(model)
        if ckpt is not None:
            resumed = {k: v for k, v in ckpt.get("technique_results", {}).items() if k in technique_ids}
            technique_results.update(resumed)
            if resumed:
                console.print(
                    f"  [cyan]--resume: {len(resumed)}/{len(technique_ids)} technique(s) "
                    f"already complete ({', '.join(resumed)}) — running the rest[/cyan]"
                )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description:<28}"),
        BarColumn(bar_width=25),
        MofNCompleteColumn(),
        TextColumn("[dim]DABS[/dim] [bold yellow]{task.fields[dabs]:.1f}[/bold yellow]"),
        console=console,
    ) as progress:
        task = progress.add_task(f"[cyan]{model}[/cyan]", total=len(technique_ids), dabs=0.0)
        if technique_results:
            progress.advance(task, len(technique_results))

        skipped_not_found: set[str] = set()

        for tech_id in technique_ids:
            if tech_id in technique_results:
                continue  # resumed from checkpoint, already have this one

            progress.update(task, description=f"[cyan]{tech_id}[/cyan]")
            try:
                technique = _load_technique(tech_id)
            except FileNotFoundError:
                progress.console.print(f"  [yellow]skip {tech_id} — not found[/yellow]")
                skipped_not_found.add(tech_id)
                progress.advance(task)
                continue

            if resume:
                _restart_ollama()

            try:
                result = _battle(
                    technique, rounds, attacker_model, model,
                    round_timeout=round_timeout,
                    threat_intel_mode=threat_intel_mode,
                    threat_intel_snapshot_path=threat_intel_snapshot_path,
                    seed=seed,
                )
                technique_results[tech_id] = result
                _save_checkpoint(model, technique_results, seed, threat_intel_mode)
            except Exception as exc:
                progress.console.print(f"  [red]error {tech_id}: {exc}[/red]")
                progress.advance(task)
                continue

            if technique_results:
                running = DABSScorer(
                    model=model,
                    technique_results=technique_results,
                    attacker_model=attacker_model,
                    total_techniques=len(technique_ids),
                    exclude_components=["swarm_resilience"],
                    seed=seed,
                ).compute().dabs_score
                progress.update(task, dabs=running)

            progress.advance(task)

    if not technique_results:
        console.print(f"[red]No results for {model} — is Ollama running?[/red]")
        return {"dabs_v1": 0.0, "dabs_v2": 0.0}

    required = set(technique_ids) - skipped_not_found
    if set(technique_results) < required:
        missing = sorted(required - set(technique_results))
        console.print(
            f"  [yellow]{model}: incomplete this pass — {len(technique_results)}/{len(required)} "
            f"technique(s) done, missing {missing}. Checkpoint saved "
            f"({_checkpoint_path(model).name}) — rerun with --resume to finish "
            f"instead of a fresh 5-technique run.[/yellow]"
        )
        return {"dabs_v1": None, "dabs_v2": None, "incomplete": True, "missing": missing}

    v1, v2, path = _save_both_profiles(
        model=model,
        technique_results=technique_results,
        attacker_model=attacker_model,
        total_techs=total_techs,
        platform=platform,
        threat_intel_mode=threat_intel_mode,
        seed=seed,
        run_index=run_index,
    )
    _clear_checkpoint(model)  # final result saved — the partial marker is no longer needed

    ts = TIER_STYLES.get(v2.tier, "white")
    console.print(
        f"  DABS(v2) [{ts}]{v2.dabs_score:.1f}[/{ts}]  "
        f"DABS(v1, paper-comparable) [dim]{v1.dabs_score:.1f}[/dim]  "
        f"Tier [{ts}]{v2.tier}[/{ts}]  "
        f"→ [dim]{path.name}[/dim]"
    )
    return {"dabs_v1": v1.dabs_score, "dabs_v2": v2.dabs_score}


def _scaling_table(model_scores: list[tuple[str, float]], title: str = "Scaling Law Results") -> Table:
    tbl = Table(
        title=title,
        style="cyan",
        border_style="dim",
        box=box.SIMPLE_HEAD,
    )
    tbl.add_column("Model",      style="bold white", min_width=20)
    tbl.add_column("Params (B)", justify="right",    min_width=12)
    tbl.add_column("DABS",       justify="right",    min_width=8)
    tbl.add_column("Tier",       min_width=20)

    for model, dabs in model_scores:
        entry = MODEL_REGISTRY.get(model)
        if entry is None:
            base = model.split(":")[0]
            entry = next(
                (v for k, v in MODEL_REGISTRY.items() if k.split(":")[0] == base), None
            )
        params = entry["params_b"] if entry else None
        tier, _ = get_tier(dabs)
        ts = TIER_STYLES.get(tier, "white")
        tbl.add_row(
            model,
            f"{params:.1f}B" if params else "?",
            f"[{ts}]{dabs:.1f}[/{ts}]",
            f"[{ts}]{tier}[/{ts}]",
        )
    return tbl


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DUEL Scaling Benchmark — DABS across model sizes",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--techniques",
        default=",".join(DEFAULT_TECHNIQUES),
        help="Comma-separated technique IDs (fixed for all models)",
    )
    parser.add_argument("--rounds",   type=int, default=DEFAULT_ROUNDS)
    parser.add_argument("--attacker", default=DEFAULT_ATTACKER)
    parser.add_argument(
        "--models",
        default=",".join(DEFAULT_MODELS),
        help="Comma-separated defender models to benchmark in order",
    )
    parser.add_argument(
        "--platform",
        default="ollama",
        choices=["ollama", "groq"],
        help="Inference backend actually used — recorded in every saved result",
    )
    parser.add_argument(
        "--round-timeout",
        type=int,
        default=DEFAULT_ROUND_TIMEOUT,
        help="Seconds before a round (attacker+defender+detection) is abandoned "
             "and recorded as a timeout instead of hanging the whole run",
    )
    parser.add_argument(
        "--threat-intel",
        default="off",
        choices=["live", "snapshot", "off"],
        help="Defender threat-intel enrichment mode. 'off' (default) and "
             "'snapshot' never touch the network — 'live' is a real external "
             "dependency and must never be used in an unattended benchmark run.",
    )
    parser.add_argument(
        "--threat-intel-snapshot",
        default=None,
        help="Path to a versioned threat-intel snapshot JSON — required if "
             "--threat-intel=snapshot (e.g. output/benchmarks/threat_intel_snapshot_2026-09-05.json)",
    )
    parser.add_argument(
        "--seed",
        default="42",
        help="Integer seed, or 'none' to omit the seed entirely (reproduces "
             "pre-2026-05-10 unseeded behaviour -- see docs/ERRATA.md item 5)",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Run each model this many independent times; with >1, prints "
             "mean/stdev across repeats and the mean feeds the scaling-law fit",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume each model from its per-technique checkpoint "
             "(output/benchmarks/scaling_v2/_checkpoints/<model>.json) if one "
             "exists, running only the techniques not yet completed. Also "
             "restarts the local Ollama app before each technique as a "
             "memory-pressure mitigation — see docs/scaling_v2_results.md.",
    )
    args = parser.parse_args()

    seed = None if args.seed.strip().lower() == "none" else int(args.seed)

    if args.threat_intel == "snapshot" and not args.threat_intel_snapshot:
        parser.error("--threat-intel=snapshot requires --threat-intel-snapshot PATH")

    technique_ids = [t.strip() for t in args.techniques.split(",") if t.strip()]
    models        = [m.strip() for m in args.models.split(",") if m.strip()]
    total_techs   = _all_technique_count()

    console.print("\n[bold yellow]DUEL — Scaling Laws Benchmark[/bold yellow]")
    console.print(f"  [dim]Defender models:[/dim] {', '.join(models)}")
    console.print(f"  [dim]Attacker:[/dim]        {args.attacker}")
    console.print(f"  [dim]Techniques:[/dim]      {', '.join(technique_ids)}")
    console.print(f"  [dim]Rounds / tech:[/dim]   {args.rounds}")
    console.print(f"  [dim]Round timeout:[/dim]   {args.round_timeout}s")
    console.print(f"  [dim]Threat intel:[/dim]    {args.threat_intel}")
    console.print(f"  [dim]Seed:[/dim]            {seed if seed is not None else 'NONE (unseeded)'}")
    console.print(f"  [dim]Repeat:[/dim]          {args.repeat}\n")

    model_scores_v1: list[tuple[str, float]] = []
    model_scores_v2: list[tuple[str, float]] = []
    for model in models:
        repeats_v1: list[float] = []
        repeats_v2: list[float] = []
        for run_i in range(1, args.repeat + 1):
            dabs = _run_model(
                model=model,
                technique_ids=technique_ids,
                rounds=args.rounds,
                attacker_model=args.attacker,
                total_techs=total_techs,
                platform=args.platform,
                round_timeout=args.round_timeout,
                threat_intel_mode=args.threat_intel,
                threat_intel_snapshot_path=args.threat_intel_snapshot,
                seed=seed,
                run_index=run_i if args.repeat > 1 else None,
                resume=args.resume,
            )
            if dabs.get("incomplete"):
                console.print(
                    f"  [yellow]{model}: skipping stats/fit for this run — "
                    f"incomplete (missing {dabs.get('missing')}). See --resume above.[/yellow]"
                )
                continue
            repeats_v1.append(dabs["dabs_v1"])
            repeats_v2.append(dabs["dabs_v2"])

        if not repeats_v1:
            continue  # every attempt for this model was incomplete — nothing to score

        if args.repeat > 1:
            mean_v1, mean_v2 = statistics.mean(repeats_v1), statistics.mean(repeats_v2)
            stdev_v1 = statistics.stdev(repeats_v1) if len(repeats_v1) > 1 else 0.0
            stdev_v2 = statistics.stdev(repeats_v2) if len(repeats_v2) > 1 else 0.0
            console.print(
                f"  [bold]{model}[/bold] over {args.repeat} runs -- "
                f"v1: mean={mean_v1:.2f} stdev={stdev_v1:.2f}  "
                f"v2: mean={mean_v2:.2f} stdev={stdev_v2:.2f}  "
                f"raw={[round(x, 2) for x in repeats_v1]}"
            )
            model_scores_v1.append((model, mean_v1))
            model_scores_v2.append((model, mean_v2))
        else:
            model_scores_v1.append((model, repeats_v1[0]))
            model_scores_v2.append((model, repeats_v2[0]))

    def _params_for(model: str) -> float | None:
        entry = MODEL_REGISTRY.get(model)
        if entry is None:
            base = model.split(":")[0]
            entry = next((v for k, v in MODEL_REGISTRY.items() if k.split(":")[0] == base), None)
        return entry["params_b"] if entry else None

    def _fit(model_scores: list[tuple[str, float]]) -> dict:
        pts = [(p, s) for m, s in model_scores if (p := _params_for(m)) is not None]
        if len(pts) < 2:
            return {"status": "insufficient_data"}
        params  = [p for p, _ in pts]
        scores  = [s for _, s in pts]
        a, b, r2 = ScalingLawsAnalyzer()._fit_power_law(params, scores)
        return {
            "status":   "ok",
            "equation": f"DABS = {a:.2f} × P^{b:.3f}",
            "a": a, "b": b, "r2": r2, "n": len(pts),
        }

    fit_v1 = _fit(model_scores_v1)
    fit_v2 = _fit(model_scores_v2)

    console.print()
    console.print(_scaling_table(model_scores_v1, title="Scaling Law — dabs_v1 (paper-comparable weights)"))
    console.print()
    console.print(_scaling_table(model_scores_v2, title="Scaling Law — dabs_v2 (current weights)"))

    for label, fit in (("dabs_v1", fit_v1), ("dabs_v2", fit_v2)):
        console.print(f"\n[bold yellow]{label}:[/bold yellow]", end=" ")
        if fit["status"] == "ok":
            console.print(f"{fit['equation']}   R² = [bold white]{fit['r2']:.4f}[/bold white]  (n={fit['n']})")
        else:
            console.print("[yellow]insufficient data to fit[/yellow]")

    fit_summary_path = SCALING_V2_DIR / f"fit_summary_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    SCALING_V2_DIR.mkdir(parents=True, exist_ok=True)
    fit_summary_path.write_text(json.dumps({
        "platform":        args.platform,
        "attacker_model":  args.attacker,
        "techniques":      technique_ids,
        "rounds":          args.rounds,
        "model_scores_v1": model_scores_v1,
        "model_scores_v2": model_scores_v2,
        "fit_v1":          fit_v1,
        "fit_v2":          fit_v2,
        "timestamp":       datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")
    console.print(f"\n[dim]Fit summary saved to:[/dim] [cyan]{fit_summary_path.relative_to(Path(__file__).parent.parent)}[/cyan]\n")


if __name__ == "__main__":
    main()
