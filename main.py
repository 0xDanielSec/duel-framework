"""
DUEL — Dual Unsupervised Evasion Loop
Adversarial LLM framework: Attacker vs Defender over Microsoft Sentinel schemas.
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

console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler("output/duel.log"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("duel.main")

TECHNIQUES_DIR = Path(__file__).parent / "techniques"


def load_technique(technique_id: str) -> dict:
    path = TECHNIQUES_DIR / f"{technique_id}.json"
    if not path.exists():
        path = TECHNIQUES_DIR / "llm" / f"{technique_id}.json"
    if not path.exists():
        console.print(f"[red]Technique file not found: {technique_id}[/red]")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def print_banner():
    console.print(Panel(
        "[bold red]D U E L[/bold red]\n"
        "[dim]Dual Unsupervised Evasion Loop[/dim]\n"
        "[cyan]Attacker vs Defender — MITRE ATT&CK × Microsoft Sentinel[/cyan]",
        box=box.DOUBLE,
        expand=False,
    ))


def print_round_header(round_num: int, total: int):
    console.rule(f"[bold yellow]ROUND {round_num} / {total}[/bold yellow]")


def print_round_result(record: dict):
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Metric", style="cyan")
    t.add_column("Value", justify="right")

    color_det = "green" if record["detection_rate"] >= 0.5 else "red"
    color_eva = "green" if record["evasion_rate"] >= 0.5 else "red"

    t.add_row("Attack logs generated", str(record["attack_log_count"]))
    t.add_row("Detected", f"[{color_det}]{record['detected_count']}[/{color_det}]")
    t.add_row("Evaded", f"[{color_eva}]{record['evaded_count']}[/{color_eva}]")
    t.add_row("Detection rate", f"[{color_det}]{record['detection_rate']:.0%}[/{color_det}]")
    t.add_row("Evasion rate", f"[{color_eva}]{record['evasion_rate']:.0%}[/{color_eva}]")
    t.add_row("KQL valid", "✓" if record["kql_valid"] else "✗")
    t.add_row("Attacker score (cum.)", str(record["attacker_cumulative_score"]))
    t.add_row("Defender score (cum.)", str(record["defender_cumulative_score"]))

    console.print(t)


def print_kql(kql: str):
    console.print(Panel(
        Text(kql, style="bright_cyan"),
        title="[bold]Defender KQL Rule[/bold]",
        border_style="blue",
    ))


def print_attack_sample(logs: list[dict], n: int = 3):
    if not logs:
        return
    samples = logs[:n]
    preview = json.dumps(
        [{k: v for k, v in s.items() if not k.startswith("_duel")} for s in samples],
        indent=2, default=str,
    )
    console.print(Panel(
        Text(preview[:1200] + ("..." if len(preview) > 1200 else ""), style="yellow"),
        title=f"[bold]Attacker Telemetry Sample ({len(logs)} total)[/bold]",
        border_style="red",
    ))


def run_duel(
    technique_id: str,
    rounds: int,
    attacker_model: str,
    defender_model: str,
    logs_per_round: int,
    verbose: bool,
):
    Path("output").mkdir(exist_ok=True)

    technique = load_technique(technique_id)
    attacker = AttackerAgent(model=attacker_model, num_logs=logs_per_round)
    defender = DefenderAgent(model=defender_model)
    scorer = BattleScorer(total_rounds=rounds, technique_id=technique_id)

    print_banner()
    console.print(f"\n[bold]Technique:[/bold] {technique_id} — {technique['name']}")
    console.print(f"[bold]Attacker model:[/bold] {attacker_model}")
    console.print(f"[bold]Defender model:[/bold] {defender_model}")
    console.print(f"[bold]Rounds:[/bold] {rounds}")
    console.print(f"[bold]Logs per round:[/bold] {logs_per_round}\n")

    for round_num in range(1, rounds + 1):
        print_round_header(round_num, rounds)

        # ── Attacker generates telemetry ─────────────────────────────────
        console.print("[red bold]⚔  Attacker generating telemetry...[/red bold]")
        try:
            attack_logs = attacker.generate_logs(
                technique=technique,
                round_num=round_num,
                total_rounds=rounds,
                last_kql=scorer.rounds[-1]["kql_rule"] if scorer.rounds else None,
                detected_logs=scorer.get_last_detected_logs(),
                evaded_logs=scorer.get_last_evaded_logs(),
            )
        except Exception as exc:
            console.print(f"[red]Attacker failed: {exc}[/red]")
            logger.error("Attacker error round %d: %s", round_num, exc, exc_info=True)
            continue

        if verbose:
            print_attack_sample(attack_logs)

        # ── Defender generates KQL rule ──────────────────────────────────
        console.print("[blue bold]🛡  Defender generating KQL rule...[/blue bold]")
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
            console.print(f"[red]Defender failed: {exc}[/red]")
            logger.error("Defender error round %d: %s", round_num, exc, exc_info=True)
            kql_rule = "SigninLogs | where ResultType != 0"

        if verbose:
            print_kql(kql_rule)

        # ── Detection engine executes KQL ────────────────────────────────
        console.print("[green bold]🔍 Running detection engine...[/green bold]")
        engine = DetectionEngine(attack_logs)
        det_result = engine.run(kql_rule)

        # ── Score the round ──────────────────────────────────────────────
        record = scorer.record_round(
            round_num=round_num,
            attack_logs=attack_logs,
            kql_rule=kql_rule,
            detected_ids=det_result["detected_ids"],
            kql_valid=det_result["kql_valid"],
        )

        print_round_result(record)

        if not det_result["kql_valid"]:
            console.print("[yellow]  KQL parse/execution error — Defender scored 0 this round[/yellow]")

    # ── Final results ────────────────────────────────────────────────────
    console.rule("[bold green]BATTLE COMPLETE[/bold green]")

    winner = "Attacker" if scorer.attacker_score > scorer.defender_score else \
             "Defender" if scorer.defender_score > scorer.attacker_score else "Draw"
    color = "red" if winner == "Attacker" else "blue" if winner == "Defender" else "yellow"
    console.print(f"\n[{color} bold]Winner: {winner}[/{color} bold]")
    console.print(f"  Attacker: {scorer.attacker_score} pts")
    console.print(f"  Defender: {scorer.defender_score} pts")
    console.print(f"  Surviving KQL rules: {len(scorer.surviving_kql)}")

    log_path      = scorer.save_full_battle_log()
    report_path   = scorer.generate_report()
    analysis_path = scorer.generate_analysis()

    try:
        from engine.report_generator import ReportGenerator
        pdf_path = ReportGenerator(scorer).generate()
        console.print(f"[dim]PDF report     → {pdf_path}[/dim]")
    except Exception as exc:
        logger.warning("PDF generation skipped: %s", exc)
        pdf_path = None

    console.print(f"\n[dim]Battle log     → {log_path}[/dim]")
    console.print(f"[dim]Final report   → {report_path}[/dim]")
    console.print(f"[dim]Battle analysis → {analysis_path}[/dim]")

    return scorer


def main():
    parser = argparse.ArgumentParser(
        description="DUEL — Dual Unsupervised Evasion Loop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --rounds 10 --logs 15
  python main.py --technique T1078.004 --rounds 5 --verbose
  python main.py --attacker-model llama3.1:8b --defender-model mistral:7b
        """,
    )
    parser.add_argument("--technique", default="T1078.004",
                        help="MITRE technique ID (default: T1078.004)")
    parser.add_argument("--rounds", type=int, default=5,
                        help="Number of adversarial rounds (default: 5)")
    parser.add_argument("--attacker-model", default="llama3.1:8b",
                        help="Ollama model for the Attacker (default: llama3.1:8b)")
    parser.add_argument("--defender-model", default="mistral:7b",
                        help="Ollama model for the Defender (default: mistral:7b)")
    parser.add_argument("--logs", type=int, default=10,
                        help="Attack logs generated per round (default: 10)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print attack telemetry and KQL rules each round")
    args = parser.parse_args()

    run_duel(
        technique_id=args.technique,
        rounds=args.rounds,
        attacker_model=args.attacker_model,
        defender_model=args.defender_model,
        logs_per_round=args.logs,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
