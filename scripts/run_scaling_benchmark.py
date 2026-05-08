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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich import box
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from agents.attacker import AttackerAgent
from agents.defender import DefenderAgent
from engine.dabs_scorer import DABSScorer, get_tier
from engine.detection import DetectionEngine
from engine.llm_detection import LLMDetectionEngine
from engine.scaling_laws import MODEL_REGISTRY, ScalingLawsAnalyzer
from engine.scoring import BattleScorer

TECHNIQUES_DIR = Path(__file__).parent.parent / "techniques"

DEFAULT_TECHNIQUES = ["T1078.004", "T1110.003", "T1528", "T1621", "T1556.006"]
DEFAULT_ROUNDS     = 3
DEFAULT_ATTACKER   = "llama3.1:8b"
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


def _battle(
    technique: dict,
    rounds: int,
    attacker_model: str,
    defender_model: str,
) -> dict:
    technique_id = technique["technique_id"]
    attacker = AttackerAgent(model=attacker_model, num_logs=10)
    defender = DefenderAgent(model=defender_model)
    scorer = BattleScorer(
        total_rounds=rounds,
        technique_id=technique_id,
        attacker_model=attacker_model,
    )

    for round_num in range(1, rounds + 1):
        last_kql      = scorer.rounds[-1]["kql_rule"] if scorer.rounds else None
        detected_logs = scorer.get_last_detected_logs()
        evaded_logs   = scorer.get_last_evaded_logs()

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
        scorer.record_round(
            round_num=round_num,
            attack_logs=attack_logs,
            kql_rule=kql_rule,
            detected_ids=det["detected_ids"],
            kql_valid=det["kql_valid"],
        )

    return {
        "rounds": scorer.rounds,
        "tactic": technique.get("tactic", technique.get("owasp_category", "Unknown")),
        "name":   technique.get("name", technique_id),
    }


def _run_model(
    model: str,
    technique_ids: list[str],
    rounds: int,
    attacker_model: str,
    total_techs: int,
) -> float:
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
                result = _battle(technique, rounds, attacker_model, model)
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
                ).compute().dabs_score
                progress.update(task, dabs=running)

            progress.advance(task)

    if not technique_results:
        console.print(f"[red]No results for {model} — is Ollama running?[/red]")
        return 0.0

    scorer = DABSScorer(
        model=model,
        technique_results=technique_results,
        attacker_model=attacker_model,
        total_techniques=total_techs,
    )
    final = scorer.compute()
    path  = scorer.save(final)

    ts = TIER_STYLES.get(final.tier, "white")
    console.print(
        f"  DABS [{ts}]{final.dabs_score:.1f}[/{ts}]  "
        f"Tier [{ts}]{final.tier}[/{ts}]  "
        f"→ [dim]{path.name}[/dim]"
    )
    return final.dabs_score


def _scaling_table(model_scores: list[tuple[str, float]]) -> Table:
    tbl = Table(
        title="Scaling Law Results",
        style="cyan",
        border_style="dim",
        box=box.SIMPLE_HEAD,
    )
    tbl.add_column("Model",      style="bold white", min_width=20)
    tbl.add_column("Params (B)", justify="right",    min_width=12)
    tbl.add_column("DABS",       justify="right",    min_width=8)
    tbl.add_column("Tier",       min_width=20)

    for model, dabs in model_scores:
        params = MODEL_REGISTRY.get(model)
        if params is None:
            base = model.split(":")[0]
            params = next(
                (v for k, v in MODEL_REGISTRY.items() if k.split(":")[0] == base), None
            )
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
    args = parser.parse_args()

    technique_ids = [t.strip() for t in args.techniques.split(",") if t.strip()]
    models        = [m.strip() for m in args.models.split(",") if m.strip()]
    total_techs   = _all_technique_count()

    console.print("\n[bold yellow]DUEL — Scaling Laws Benchmark[/bold yellow]")
    console.print(f"  [dim]Defender models:[/dim] {', '.join(models)}")
    console.print(f"  [dim]Attacker:[/dim]        {args.attacker}")
    console.print(f"  [dim]Techniques:[/dim]      {', '.join(technique_ids)}")
    console.print(f"  [dim]Rounds / tech:[/dim]   {args.rounds}\n")

    model_scores: list[tuple[str, float]] = []
    for model in models:
        dabs = _run_model(
            model=model,
            technique_ids=technique_ids,
            rounds=args.rounds,
            attacker_model=args.attacker,
            total_techs=total_techs,
        )
        model_scores.append((model, dabs))

    # Fit scaling laws
    console.print("\n[bold cyan]Fitting power law curve…[/bold cyan]")
    analysis = ScalingLawsAnalyzer().analyze()

    console.print()
    console.print(_scaling_table(model_scores))

    if analysis.get("status") == "ok":
        pl = analysis["power_law"]
        console.print(f"\n[bold yellow]Power Law:[/bold yellow] {pl['equation']}")
        console.print(f"  R²                      = [bold white]{pl['r2']:.4f}[/bold white]")
        console.print(
            f"  Predicted DABS @ 32B    = "
            f"[bold green]{analysis['predictions']['32b']:.1f}[/bold green]"
        )
        console.print(
            f"  Predicted DABS @ 70B    = "
            f"[bold green]{analysis['predictions']['70b']:.1f}[/bold green]"
        )
        console.print(
            f"  Diminishing returns after [bold cyan]"
            f"{analysis['inflection_point_b']:.1f}B[/bold cyan] parameters"
        )
        console.print(
            f"\n[dim]Full analysis saved to:[/dim] "
            f"[cyan]output/scaling_laws.json[/cyan]\n"
        )
    else:
        console.print(f"[yellow]{analysis.get('message', 'Analysis incomplete')}[/yellow]")
        console.print("[dim]Run with more models to enable curve fitting.[/dim]\n")


if __name__ == "__main__":
    main()
