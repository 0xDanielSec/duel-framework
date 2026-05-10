#!/usr/bin/env python3
"""
DUEL Benchmark — DABS (Dual Adversarial Benchmark Score) runner.

Runs standardised battles across MITRE ATT&CK / OWASP LLM techniques and computes
a reproducible DABS score (0-100) measuring Defender robustness.

Usage:
    python benchmark.py                                # quick 10-technique run with mistral:7b
    python benchmark.py --model mistral:7b --techniques all --rounds 3
    python benchmark.py --model phi3:mini --compare
"""
import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich import box
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from agents.attacker import AttackerAgent
from agents.defender import DefenderAgent
from engine.dabs_scorer import DABSScorer, TIERS, get_tier
from engine.detection import DetectionEngine
from engine.llm_detection import LLMDetectionEngine
from engine.scoring import BattleScorer

TECHNIQUES_DIR = Path(__file__).parent / "techniques"

# Representative 10-technique quick subset
BENCHMARK_QUICK = [
    "T1078.004", "T1110.003", "T1098.001", "T1566.001", "T1485",
    "LLM01", "LLM02", "LLM03", "LLM06", "LLM10",
]

console = Console()

TIER_STYLES = {
    "Elite Defender":    "bold yellow",
    "Strong Defender":   "bold green",
    "Moderate Defender": "bold color(226)",
    "Weak Defender":     "bold dark_orange",
    "Vulnerable":        "bold red",
}

TIER_STARS = {
    "Elite Defender":    "★★★★★",
    "Strong Defender":   "★★★★☆",
    "Moderate Defender": "★★★☆☆",
    "Weak Defender":     "★★☆☆☆",
    "Vulnerable":        "★☆☆☆☆",
}


def _load_technique(technique_id: str) -> dict:
    if technique_id.upper().startswith("LLM"):
        path = TECHNIQUES_DIR / "llm" / f"{technique_id.upper()}.json"
    else:
        path = TECHNIQUES_DIR / f"{technique_id}.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _available_techniques() -> list[str]:
    mitre = sorted(p.stem for p in TECHNIQUES_DIR.glob("*.json"))
    llm_dir = TECHNIQUES_DIR / "llm"
    llm = sorted(p.stem for p in llm_dir.glob("*.json")) if llm_dir.exists() else []
    return mitre + llm


def _battle(
    technique: dict,
    rounds: int,
    attacker_model: str,
    defender_model: str,
    logs_per_round: int,
    seed: int = 42,
) -> dict:
    technique_id = technique["technique_id"]
    attacker = AttackerAgent(model=attacker_model, num_logs=logs_per_round, seed=seed)
    defender = DefenderAgent(model=defender_model, seed=seed)
    scorer   = BattleScorer(
        total_rounds=rounds,
        technique_id=technique_id,
        attacker_model=attacker_model,
        seed=seed,
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

        if technique_id.upper().startswith("LLM"):
            engine = LLMDetectionEngine(attack_logs)
        else:
            engine = DetectionEngine(attack_logs)

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


def _leaderboard_table(results: list[dict]) -> Table:
    table = Table(
        title="DABS Leaderboard",
        style="yellow",
        border_style="dim",
        box=box.SIMPLE_HEAD,
    )
    table.add_column("Rank",        style="dim",        width=6)
    table.add_column("Model",       style="bold white", min_width=20)
    table.add_column("DABS",        justify="right",    min_width=8)
    table.add_column("Tier",        min_width=20)
    table.add_column("Coverage",    justify="right",    min_width=10)
    table.add_column("Resilience",  justify="right",    min_width=10)
    table.add_column("Hardening",   justify="right",    min_width=10)
    table.add_column("Consistency", justify="right",    min_width=10)
    table.add_column("Techs",       justify="right",    min_width=6)

    for i, r in enumerate(sorted(results, key=lambda x: x["dabs_score"], reverse=True)):
        s  = TIER_STYLES.get(r["tier"], "white")
        st = TIER_STARS.get(r["tier"], "")
        c  = r.get("components", {})
        table.add_row(
            ["🥇", "🥈", "🥉"].get(i) if i < 3 else f"#{i+1}",
            r["model"],
            f"[{s}]{r['dabs_score']:.1f}[/{s}]",
            f"[{s}]{st} {r['tier']}[/{s}]",
            f"{c.get('coverage', 0):.0f}",
            f"{c.get('resilience', 0):.0f}",
            f"{c.get('hardening', 0):.0f}",
            f"{c.get('consistency', 0):.0f}",
            str(r.get("techniques_benchmarked", "—")),
        )
    return table


def main() -> None:
    all_techniques = _available_techniques()

    parser = argparse.ArgumentParser(
        description="DUEL DABS Benchmark — measure Defender robustness (0-100)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--model",       default="mistral:7b",   help="Defender model to benchmark")
    parser.add_argument("--techniques",  default="quick",        help="'all', 'quick' (10), or comma-separated IDs")
    parser.add_argument("--rounds",      type=int, default=3,    help="Rounds per technique")
    parser.add_argument("--attacker",    default="llama3.1:8b",  help="Attacker model")
    parser.add_argument("--logs",        type=int, default=10,   help="Logs per round")
    parser.add_argument("--compare",     action="store_true",    help="Show leaderboard after benchmark")
    parser.add_argument("--seed",        type=int, default=42,   help="Random seed for reproducibility (default: 42)")
    args = parser.parse_args()

    random.seed(args.seed)
    try:
        import numpy as np
        np.random.seed(args.seed)
    except ImportError:
        pass

    if args.techniques.lower() == "all":
        technique_ids = all_techniques
    elif args.techniques.lower() == "quick":
        technique_ids = [t for t in BENCHMARK_QUICK if t in all_techniques]
    else:
        technique_ids = [t.strip() for t in args.techniques.split(",") if t.strip()]

    console.print(f"\n[bold yellow]DUEL — DABS Benchmark[/bold yellow]")
    console.print(f"  [dim]Defender:[/dim]   [bold white]{args.model}[/bold white]")
    console.print(f"  [dim]Attacker:[/dim]   [bold white]{args.attacker}[/bold white]")
    console.print(f"  [dim]Techniques:[/dim] {len(technique_ids)}  "
                  f"[dim]Rounds:[/dim] {args.rounds}  "
                  f"[dim]Logs/round:[/dim] {args.logs}  "
                  f"[dim]Seed:[/dim] {args.seed}\n")

    technique_results: dict[str, dict] = {}
    running_dabs = 0.0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description:<28}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TextColumn("[dim]DABS[/dim] [bold yellow]{task.fields[dabs]:.1f}[/bold yellow]"),
        console=console,
    ) as progress:
        task = progress.add_task("Starting…", total=len(technique_ids), dabs=0.0)

        for tech_id in technique_ids:
            progress.update(task, description=f"[cyan]{tech_id}[/cyan]")
            try:
                technique = _load_technique(tech_id)
            except FileNotFoundError:
                progress.console.print(f"  [yellow]skip {tech_id} — not found[/yellow]")
                progress.advance(task)
                continue
            except Exception as exc:
                progress.console.print(f"  [red]load error {tech_id}: {exc}[/red]")
                progress.advance(task)
                continue

            try:
                result = _battle(
                    technique=technique,
                    rounds=args.rounds,
                    attacker_model=args.attacker,
                    defender_model=args.model,
                    logs_per_round=args.logs,
                    seed=args.seed,
                )
                technique_results[tech_id] = result
            except Exception as exc:
                progress.console.print(f"  [red]battle error {tech_id}: {exc}[/red]")
                progress.advance(task)
                continue

            if technique_results:
                running_dabs = DABSScorer(
                    model=args.model,
                    technique_results=technique_results,
                    attacker_model=args.attacker,
                    total_techniques=len(technique_ids),
                    seed=args.seed,
                ).compute().dabs_score

            progress.advance(task)
            progress.update(task, dabs=running_dabs)

    if not technique_results:
        console.print("[red]No techniques completed — check Ollama is running.[/red]\n")
        sys.exit(1)

    # ── Final DABS ────────────────────────────────────────────────────────────
    scorer = DABSScorer(
        model=args.model,
        technique_results=technique_results,
        attacker_model=args.attacker,
        total_techniques=len(all_techniques),
        seed=args.seed,
    )
    result = scorer.compute()
    path   = scorer.save(result)

    ts  = TIER_STYLES.get(result.tier, "white")
    st  = TIER_STARS.get(result.tier, "")
    comp = result.components

    console.print(f"\n[bold yellow]╔══ DABS RESULT ════════════════════════════════╗[/bold yellow]")
    console.print(f"  Model:      [bold white]{result.model}[/bold white]")
    console.print(f"  DABS Score: [{ts}]{result.dabs_score:.2f} / 100[/{ts}]")
    console.print(f"  Tier:       [{ts}]{st} {result.tier}[/{ts}]")
    console.print(f"  Confidence: [dim]{result.confidence}[/dim]  "
                  f"({result.techniques_benchmarked}/{result.total_techniques} techniques)")
    console.print(f"[bold yellow]╚══════════════════════════════════════════════╝[/bold yellow]\n")

    # ── Component table ───────────────────────────────────────────────────────
    comp_tbl = Table(title="Score Components", style="yellow", border_style="dim", box=box.SIMPLE)
    comp_tbl.add_column("Component",    style="dim",     min_width=22)
    comp_tbl.add_column("Score",        justify="right", min_width=8)
    comp_tbl.add_column("Weight",       justify="right", min_width=8)
    comp_tbl.add_column("Contribution", justify="right", min_width=12)

    for key, label, weight in [
        ("coverage",        "Detection Coverage (30%)", 0.30),
        ("resilience",      "Resilience         (25%)", 0.25),
        ("hardening",       "Hardening Rate     (20%)", 0.20),
        ("consistency",     "Consistency        (15%)", 0.15),
        ("meta_resilience", "Meta-Resilience    (10%)", 0.10),
    ]:
        val = comp.get(key)
        if val is None:
            comp_tbl.add_row(label, "—", f"{weight:.0%}", "—")
        else:
            comp_tbl.add_row(label, f"{val:.1f}", f"{weight:.0%}", f"{val * weight:.1f}")

    console.print(comp_tbl)

    # ── Per-tactic breakdown ──────────────────────────────────────────────────
    if result.per_tactic:
        tac_tbl = Table(title="Per-Tactic Detection Scores", style="cyan", border_style="dim", box=box.SIMPLE)
        tac_tbl.add_column("Tactic",  style="dim", min_width=35)
        tac_tbl.add_column("Score",   justify="right")
        for tac, score in sorted(result.per_tactic.items(), key=lambda x: x[1], reverse=True):
            color = "green" if score >= 60 else "yellow" if score >= 40 else "red"
            tac_tbl.add_row(tac, f"[{color}]{score:.1f}[/{color}]")
        console.print(tac_tbl)

    # ── Comparison leaderboard ────────────────────────────────────────────────
    if args.compare:
        saved = DABSScorer.load_all()
        all_latest = [m["latest"] for m in saved]
        if all_latest:
            console.print()
            console.print(_leaderboard_table(all_latest))

    console.print(f"\n[dim]Saved to:[/dim] [cyan]{path}[/cyan]\n")


if __name__ == "__main__":
    main()
