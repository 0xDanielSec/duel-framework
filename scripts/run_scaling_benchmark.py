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
from engine.dabs_scorer import DABSResult, DABSScorer, get_tier
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
    attacker = AttackerAgent(model=attacker_model, num_logs=10, platform=attacker_platform)
    defender = DefenderAgent(
        model=defender_model,
        threat_intel_mode=threat_intel_mode,
        threat_intel_snapshot_path=threat_intel_snapshot_path,
        platform=defender_platform,
    )
    scorer = BattleScorer(
        total_rounds=rounds,
        technique_id=technique_id,
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
) -> tuple[DABSResult, DABSResult, Path]:
    """
    Score the same technique_results under both dabs_v1 (paper weights) and
    dabs_v2 (current weights) so formula drift and LLM-output drift can be
    told apart, then save one combined JSON to output/benchmarks/scaling_v2/
    (versioned — this is the real artifact for the scaling_v2 comparison).
    """
    v1 = DABSScorer(
        model=model, technique_results=technique_results, attacker_model=attacker_model,
        total_techniques=total_techs, exclude_components=["swarm_resilience"],
        platform=platform, weight_profile="dabs_v1",
    ).compute()
    v2 = DABSScorer(
        model=model, technique_results=technique_results, attacker_model=attacker_model,
        total_techniques=total_techs, exclude_components=["swarm_resilience"],
        platform=platform, weight_profile="dabs_v2",
    ).compute()

    SCALING_V2_DIR.mkdir(parents=True, exist_ok=True)
    safe = model.replace(":", "_").replace("/", "_")
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = SCALING_V2_DIR / f"dabs_{safe}_{ts}.json"
    path.write_text(json.dumps({
        "model":              model,
        "attacker_model":     attacker_model,
        "platform":           platform,
        "threat_intel_mode":  threat_intel_mode,
        "seed":               v1.seed,
        "timestamp":          v2.timestamp,
        "dabs_v1":            v1.to_dict(),
        "dabs_v2":            v2.to_dict(),
    }, indent=2), encoding="utf-8")

    return v1, v2, path


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
) -> dict:
    console.print(f"\n[bold cyan]══ Defender: {model} ══[/bold cyan]")

    technique_results: dict[str, dict] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description:<28}"),
        BarColumn(bar_width=25),
        MofNCompleteColumn(),
        TextColumn("[dim]DABS[/dim] [bold yellow]{task.fields[dabs]:.1f}[/bold yellow]"),
        console=console,
    ) as progress:
        task = progress.add_task(f"[cyan]{model}[/cyan]", total=len(technique_ids), dabs=0.0)

        for tech_id in technique_ids:
            progress.update(task, description=f"[cyan]{tech_id}[/cyan]")
            try:
                technique = _load_technique(tech_id)
            except FileNotFoundError:
                progress.console.print(f"  [yellow]skip {tech_id} — not found[/yellow]")
                progress.advance(task)
                continue

            try:
                result = _battle(
                    technique, rounds, attacker_model, model,
                    round_timeout=round_timeout,
                    threat_intel_mode=threat_intel_mode,
                    threat_intel_snapshot_path=threat_intel_snapshot_path,
                )
                technique_results[tech_id] = result
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
                ).compute().dabs_score
                progress.update(task, dabs=running)

            progress.advance(task)

    if not technique_results:
        console.print(f"[red]No results for {model} — is Ollama running?[/red]")
        return {"dabs_v1": 0.0, "dabs_v2": 0.0}

    v1, v2, path = _save_both_profiles(
        model=model,
        technique_results=technique_results,
        attacker_model=attacker_model,
        total_techs=total_techs,
        platform=platform,
        threat_intel_mode=threat_intel_mode,
    )

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
    args = parser.parse_args()

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
    console.print(f"  [dim]Threat intel:[/dim]    {args.threat_intel}\n")

    model_scores_v1: list[tuple[str, float]] = []
    model_scores_v2: list[tuple[str, float]] = []
    for model in models:
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
        )
        model_scores_v1.append((model, dabs["dabs_v1"]))
        model_scores_v2.append((model, dabs["dabs_v2"]))

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
