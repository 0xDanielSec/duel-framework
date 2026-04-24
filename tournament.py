"""
DUEL Tournament Mode — pits multiple Defender models against the same Attacker.

Each defender sees identical attack telemetry (generated once per round),
ensuring fair, controlled comparison across all models.

Usage:
  python tournament.py --technique T1078.004 --rounds 3 \
      --defenders "mistral:7b,llama3.1:8b"
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from agents.attacker import AttackerAgent
from agents.defender import DefenderAgent
from engine.detection import DetectionEngine
from engine.scoring import BattleScorer
from engine.tournament_scorer import TournamentScorer

console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler("output/duel.log"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("duel.tournament")

TECHNIQUES_DIR = Path(__file__).parent / "techniques"


def _load_technique(technique_id: str) -> dict:
    path = TECHNIQUES_DIR / f"{technique_id}.json"
    if not path.exists():
        console.print(f"[red]Technique file not found: {path}[/red]")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _print_banner(technique_id: str, rounds: int, defenders: list[str]):
    console.print(Panel(
        "[bold yellow]T O U R N A M E N T[/bold yellow]\n"
        "[dim]Dual Unsupervised Evasion Loop — Multi-Defender Edition[/dim]\n"
        f"[cyan]Technique: {technique_id}  |  Rounds: {rounds}  |  "
        f"Defenders: {len(defenders)}[/cyan]",
        box=box.DOUBLE,
        expand=False,
    ))


def run_tournament(
    technique_id: str,
    rounds: int,
    attacker_model: str,
    defenders: list[str],
    logs_per_round: int,
) -> None:
    Path("output").mkdir(exist_ok=True)
    technique = _load_technique(technique_id)

    _print_banner(technique_id, rounds, defenders)
    console.print(f"\n[bold]Technique:[/bold] {technique_id} — {technique['name']}")
    console.print(f"[bold]Attacker model:[/bold] {attacker_model}")
    console.print(f"[bold]Defenders:[/bold] {', '.join(defenders)}")
    console.print(f"[bold]Rounds:[/bold] {rounds}")
    console.print(f"[bold]Logs per round:[/bold] {logs_per_round}\n")

    # ── Phase 1: Pre-generate attack logs once per round ─────────────────────
    # All defenders see the same telemetry — identical conditions.
    console.rule("[bold red]PHASE 1 — Attack Telemetry Generation[/bold red]")
    attacker = AttackerAgent(model=attacker_model, num_logs=logs_per_round)
    all_attack_logs: dict[int, list[dict]] = {}

    for round_num in range(1, rounds + 1):
        console.print(f"[red]⚔  Round {round_num}/{rounds} — Attacker generating telemetry...[/red]")
        try:
            logs = attacker.generate_logs(
                technique=technique,
                round_num=round_num,
                total_rounds=rounds,
                last_kql=None,
                detected_logs=[],
                evaded_logs=[],
            )
            all_attack_logs[round_num] = logs
            console.print(f"  [dim]Generated {len(logs)} logs for round {round_num}[/dim]")
        except Exception as exc:
            console.print(f"[red]Attacker failed on round {round_num}: {exc}[/red]")
            logger.error("Attacker error round %d: %s", round_num, exc, exc_info=True)
            sys.exit(1)

    # ── Phase 2: Run each defender against the pre-generated logs ────────────
    defender_results: dict[str, dict] = {}

    for defender_model in defenders:
        console.rule(f"[bold blue]DEFENDER: {defender_model}[/bold blue]")
        defender = DefenderAgent(model=defender_model)
        scorer = BattleScorer(total_rounds=rounds, technique_id=technique_id)

        for round_num in range(1, rounds + 1):
            attack_logs = all_attack_logs[round_num]

            console.print(
                f"[blue]🛡  Round {round_num}/{rounds} — "
                f"{defender_model} generating KQL...[/blue]"
            )
            try:
                kql_rule = defender.generate_rule(
                    technique=technique,
                    round_num=round_num,
                    total_rounds=rounds,
                    attack_logs=attack_logs,
                    detected_logs=scorer.get_last_detected_logs(),
                    evaded_logs=scorer.get_last_evaded_logs(),
                )
            except Exception as exc:
                logger.error(
                    "Defender %s error round %d: %s", defender_model, round_num, exc, exc_info=True
                )
                kql_rule = "SigninLogs | where ResultType != 0"

            engine = DetectionEngine(attack_logs)
            det_result = engine.run(kql_rule)

            record = scorer.record_round(
                round_num=round_num,
                attack_logs=attack_logs,
                kql_rule=kql_rule,
                detected_ids=det_result["detected_ids"],
                kql_valid=det_result["kql_valid"],
            )

            det_rate = record["detection_rate"]
            col = "green" if det_rate >= 0.5 else "red"
            console.print(
                f"  [{col}]Detection {det_rate:.0%}  "
                f"({record['detected_count']} detected / "
                f"{record['evaded_count']} evaded)[/{col}]"
            )

        defender_results[defender_model] = {
            "rounds": scorer.rounds,
            "attacker_score": scorer.attacker_score,
            "defender_score": scorer.defender_score,
            "surviving_kql": scorer.surviving_kql,
        }
        console.print(
            f"  [bold]Final: Defender {scorer.defender_score} pts  |  "
            f"Attacker {scorer.attacker_score} pts[/bold]"
        )

    # ── Phase 3: Rank and report ─────────────────────────────────────────────
    console.rule("[bold green]TOURNAMENT RESULTS[/bold green]")
    ts = TournamentScorer(technique_id=technique_id, defender_results=defender_results)
    rankings = ts.rank()

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow")
    tbl.add_column("Rank",       justify="center",  style="bold")
    tbl.add_column("Model",      style="cyan")
    tbl.add_column("Avg Det.",   justify="right")
    tbl.add_column("Avg Eva.",   justify="right")
    tbl.add_column("Consistency", justify="right")
    tbl.add_column("KQL Score",  justify="right")
    tbl.add_column("Best Rd.",   justify="center")
    tbl.add_column("Worst Rd.",  justify="center")

    n = len(rankings)
    for entry in rankings:
        rk = entry["rank"]
        col = "green" if rk == 1 else ("red" if rk == n else "white")
        tbl.add_row(
            f"[{col}]#{rk}[/{col}]",
            f"[{col}]{entry['model']}[/{col}]",
            f"[{col}]{entry['avg_detection_rate']:.0%}[/{col}]",
            f"{entry['avg_evasion_rate']:.0%}",
            f"{entry['consistency']:.3f}",
            str(entry["kql_complexity_score"]),
            f"R{entry['best_round']}",
            f"R{entry['worst_round']}",
        )
    console.print(tbl)

    out_path    = ts.save(all_attack_logs)
    report_path = ts.generate_report(rankings)
    console.print(f"\n[dim]Tournament log    → {out_path}[/dim]")
    console.print(f"[dim]Tournament report → {report_path}[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="DUEL Tournament Mode — multiple Defenders vs the same Attacker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tournament.py --technique T1078.004 --rounds 3 --defenders "mistral:7b,llama3.1:8b"
  python tournament.py --technique T1078.004 --rounds 5 --logs 10 \\
      --defenders "mistral:7b,llama3.1:8b,qwen2.5:7b"
        """,
    )
    parser.add_argument("--technique",      default="T1078.004",
                        help="MITRE technique ID (default: T1078.004)")
    parser.add_argument("--rounds",         type=int, default=3,
                        help="Number of adversarial rounds (default: 3)")
    parser.add_argument("--attacker-model", default="llama3.1:8b",
                        help="Ollama model for the Attacker (default: llama3.1:8b)")
    parser.add_argument("--defenders",      required=True,
                        help='Comma-separated Ollama model names, e.g. "mistral:7b,llama3.1:8b"')
    parser.add_argument("--logs",           type=int, default=10,
                        help="Attack logs generated per round (default: 10)")
    args = parser.parse_args()

    defenders = [m.strip() for m in args.defenders.split(",") if m.strip()]
    if not defenders:
        console.print("[red]No defender models specified.[/red]")
        sys.exit(1)

    run_tournament(
        technique_id=args.technique,
        rounds=args.rounds,
        attacker_model=args.attacker_model,
        defenders=defenders,
        logs_per_round=args.logs,
    )


if __name__ == "__main__":
    main()
