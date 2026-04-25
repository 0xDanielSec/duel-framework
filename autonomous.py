"""
DUEL — Autonomous Red Team CLI

The Attacker agent plans its own kill chain, decides round budgets per technique,
and generates an executive report — all without human input in --auto mode.

Usage:
  python autonomous.py --objective persistence --auto
  python autonomous.py --objective full-compromise --max-techniques 4 --auto --verbose
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
from engine.autonomous_attacker import AutonomousRedTeam
from campaign import build_campaign_context

console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler("output/duel.log"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("duel.autonomous")

TECHNIQUES_DIR = Path(__file__).parent / "techniques"
OUTPUT_DIR     = Path(__file__).parent / "output"


def load_technique(technique_id: str) -> dict:
    path = TECHNIQUES_DIR / f"{technique_id}.json"
    if not path.exists():
        console.print(f"[red]Technique not found: {path}[/red]")
        sys.exit(1)
    return json.loads(path.read_text(encoding="utf-8"))


def print_banner():
    console.print(Panel(
        "[bold magenta]D U E L — AUTONOMOUS RED TEAM[/bold magenta]\n"
        "[dim]The Attacker decides its own strategy[/dim]\n"
        "[cyan]Self-directed kill chain · MITRE ATT&CK × Microsoft Sentinel[/cyan]",
        box=box.DOUBLE,
        expand=False,
    ))


def print_decision(decision: dict, stage: int):
    color = {"exploit": "red", "explore": "blue", "improve": "yellow"}.get(
        decision["priority"], "white"
    )
    console.print(Panel(
        f"[bold]Technique:[/bold]  {decision['technique_id']}\n"
        f"[bold]Priority:[/bold]   [{color}]{decision['priority'].upper()}[/{color}]\n"
        f"[bold]Rounds:[/bold]     {decision['suggested_rounds']}\n\n"
        f"[dim]{decision['reasoning']}[/dim]",
        title=f"[bold magenta]⚡ AUTONOMOUS DECISION — Stage {stage}[/bold magenta]",
        border_style="magenta",
    ))


def run_stage(
    stage_num: int,
    total_stages: int,
    technique: dict,
    rounds: int,
    attacker: AttackerAgent,
    defender_model: str,
    campaign_context: str | None,
    verbose: bool,
) -> BattleScorer:
    tid = technique["technique_id"]
    console.rule(
        f"[bold magenta]STAGE {stage_num}/{total_stages} — {tid}: {technique['name']}[/bold magenta]"
    )

    if campaign_context:
        console.print(Panel(
            Text(campaign_context[:500], style="dim cyan"),
            title="[bold]Kill Chain Context[/bold]",
            border_style="cyan",
        ))

    defender = DefenderAgent(model=defender_model)
    scorer   = BattleScorer(total_rounds=rounds, technique_id=tid)

    for round_num in range(1, rounds + 1):
        console.rule(f"[yellow]Round {round_num}/{rounds}[/yellow]")

        # ── Attacker ──────────────────────────────────────────────────────
        console.print("[red bold]⚔  Attacker generating telemetry...[/red bold]")
        try:
            attack_logs = attacker.generate_logs(
                technique=technique,
                round_num=round_num,
                total_rounds=rounds,
                last_kql=scorer.rounds[-1]["kql_rule"] if scorer.rounds else None,
                detected_logs=scorer.get_last_detected_logs(),
                evaded_logs=scorer.get_last_evaded_logs(),
                campaign_context=campaign_context if round_num == 1 else None,
            )
        except Exception as exc:
            console.print(f"[red]Attacker failed: {exc}[/red]")
            logger.error("Attacker error stage %d round %d: %s", stage_num, round_num, exc)
            continue

        if verbose:
            preview = json.dumps(
                [{k: v for k, v in s.items() if not k.startswith("_duel")}
                 for s in attack_logs[:2]],
                indent=2, default=str,
            )
            console.print(Panel(
                Text(preview[:700], style="yellow"),
                title="Attack Sample", border_style="red",
            ))

        # ── Defender ──────────────────────────────────────────────────────
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
            kql_rule = "SigninLogs | where ResultType != 0"

        if verbose:
            console.print(Panel(
                Text(kql_rule, style="bright_cyan"),
                title="KQL Rule", border_style="blue",
            ))

        # ── Detection ─────────────────────────────────────────────────────
        console.print("[green bold]🔍 Running detection engine...[/green bold]")
        det_result = DetectionEngine(attack_logs).run(kql_rule)

        record = scorer.record_round(
            round_num=round_num,
            attack_logs=attack_logs,
            kql_rule=kql_rule,
            detected_ids=det_result["detected_ids"],
            kql_valid=det_result["kql_valid"],
        )

        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("Metric", style="cyan")
        t.add_column("Value", justify="right")
        t.add_row("Detection rate",   f"{record['detection_rate']:.0%}")
        t.add_row("Evasion rate",     f"{record['evasion_rate']:.0%}")
        t.add_row("Attacker (cum.)",  str(record["attacker_cumulative_score"]))
        t.add_row("Defender (cum.)",  str(record["defender_cumulative_score"]))
        console.print(t)

    # Stage summary
    total_logs   = sum(r["attack_log_count"] for r in scorer.rounds)
    total_evaded = sum(r["evaded_count"]     for r in scorer.rounds)
    evasion_rate = total_evaded / total_logs if total_logs else 0.0
    winner = scorer._determine_winner()
    c = "red" if winner == "Attacker" else "blue" if winner == "Defender" else "yellow"
    console.print(
        f"\n  Stage winner: [{c} bold]{winner}[/{c} bold] | "
        f"Evasion: {evasion_rate:.0%} | Surviving KQL: {len(scorer.surviving_kql)}"
    )

    scorer.save_full_battle_log()
    return scorer


def run_autonomous(
    objective: str,
    max_techniques: int,
    attacker_model: str,
    defender_model: str,
    logs_per_round: int,
    auto: bool,
    verbose: bool,
):
    OUTPUT_DIR.mkdir(exist_ok=True)
    print_banner()

    console.print(f"\n[bold]Objective:[/bold]       [magenta]{objective}[/magenta]")
    console.print(f"[bold]Max techniques:[/bold]  {max_techniques}")
    console.print(f"[bold]Attacker model:[/bold]  {attacker_model}")
    console.print(f"[bold]Defender model:[/bold]  {defender_model}")
    console.print(f"[bold]Logs per round:[/bold]  {logs_per_round}")
    console.print(f"[bold]Mode:[/bold]            {'FULLY AUTONOMOUS' if auto else 'SUPERVISED'}\n")

    red_team = AutonomousRedTeam(model=attacker_model)

    # ── Plan campaign ──────────────────────────────────────────────────────
    console.print("[magenta bold]🧠 AUTONOMOUS REASONING — Planning kill chain...[/magenta bold]")
    plan = red_team.plan_campaign(objective=objective, max_techniques=max_techniques)

    plan_table = Table(box=box.ROUNDED, title="Autonomous Campaign Plan")
    plan_table.add_column("Stage",     style="cyan",    justify="center")
    plan_table.add_column("Technique", style="magenta")
    plan_table.add_column("Rounds",    justify="center")
    plan_table.add_column("Reasoning", style="dim")
    for i, s in enumerate(plan, 1):
        r = s["reasoning"]
        plan_table.add_row(str(i), s["technique_id"], str(s["rounds"]),
                           r[:90] + ("…" if len(r) > 90 else ""))
    console.print(plan_table)

    if not auto:
        console.print("\n[yellow]Press Enter to execute, or Ctrl+C to abort.[/yellow]")
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            console.print("[red]Aborted.[/red]")
            return

    # ── Execute campaign ───────────────────────────────────────────────────
    attacker     = AttackerAgent(model=attacker_model, num_logs=logs_per_round)
    stage_scorers: list[BattleScorer] = []
    stage_techs:   list[dict]         = []
    campaign_context: str | None      = None

    for idx, stage_plan in enumerate(plan):
        stage_num    = idx + 1
        technique_id = stage_plan["technique_id"]
        rounds       = stage_plan["rounds"]

        print_decision(
            {"technique_id": technique_id, "reasoning": stage_plan["reasoning"],
             "suggested_rounds": rounds, "priority": stage_plan.get("priority", "explore")},
            stage_num,
        )

        technique = load_technique(technique_id)
        stage_techs.append(technique)

        scorer = run_stage(
            stage_num=stage_num,
            total_stages=len(plan),
            technique=technique,
            rounds=rounds,
            attacker=attacker,
            defender_model=defender_model,
            campaign_context=campaign_context,
            verbose=verbose,
        )
        stage_scorers.append(scorer)

        if idx + 1 < len(plan):
            campaign_context = build_campaign_context(technique, scorer, stage_num)
            console.print("\n[magenta bold]🧠 Re-evaluating strategy based on results...[/magenta bold]")

    # ── Final summary ──────────────────────────────────────────────────────
    console.rule("[bold magenta]AUTONOMOUS CAMPAIGN COMPLETE[/bold magenta]")

    stage_results = []
    for i, (tech, scorer) in enumerate(zip(stage_techs, stage_scorers), 1):
        total_logs   = sum(r["attack_log_count"] for r in scorer.rounds)
        total_evaded = sum(r["evaded_count"]     for r in scorer.rounds)
        evasion_rate = total_evaded / total_logs if total_logs else 0.0
        stage_results.append({
            "stage":              i,
            "technique_id":       tech["technique_id"],
            "technique_name":     tech["name"],
            "winner":             scorer._determine_winner(),
            "evasion_rate":       round(evasion_rate, 4),
            "attacker_score":     scorer.attacker_score,
            "defender_score":     scorer.defender_score,
            "surviving_kql_count": len(scorer.surviving_kql),
            "surviving_kql":      scorer.surviving_kql,
        })

    summary = Table(box=box.ROUNDED, title="Autonomous Campaign Results")
    summary.add_column("Stage",          justify="center", style="cyan")
    summary.add_column("Technique",      style="magenta")
    summary.add_column("Winner",         justify="center")
    summary.add_column("Evasion %",      justify="right")
    summary.add_column("Surviving KQL",  justify="right")
    for s in stage_results:
        c = "red" if s["winner"] == "Attacker" else "blue" if s["winner"] == "Defender" else "yellow"
        summary.add_row(str(s["stage"]), s["technique_id"],
                        f"[{c}]{s['winner']}[/{c}]",
                        f"{s['evasion_rate']:.0%}", str(s["surviving_kql_count"]))
    console.print(summary)

    attacker_wins = sum(1 for s in stage_results if s["winner"] == "Attacker")
    rate = attacker_wins / len(stage_results) if stage_results else 0.0
    c = "red" if rate >= 0.5 else "blue"
    console.print(f"\n[{c} bold]Overall success rate: {rate:.0%}[/{c} bold]")

    report_path = red_team.generate_report(
        objective=objective, plan=plan, stage_results=stage_results,
    )
    console.print(f"\n[dim]Autonomous report → {report_path}[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="DUEL — Autonomous Red Team Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Objectives:
  persistence         T1078.004 → T1528 → T1098.001
  exfiltration        T1078.004 → T1528 → T1114.002
  credential-access   T1110.003 → T1556.006 → T1078.004
  full-compromise     T1078.004 → T1528 → T1098.001 → T1114.002

Examples:
  python autonomous.py --objective persistence --auto
  python autonomous.py --objective full-compromise --max-techniques 4 --auto
        """,
    )
    parser.add_argument(
        "--objective", required=True,
        choices=["persistence", "exfiltration", "credential-access", "full-compromise"],
        help="High-level attack objective",
    )
    parser.add_argument("--max-techniques", type=int, default=4,
                        help="Max techniques to chain (default: 4)")
    parser.add_argument("--auto",    action="store_true",
                        help="Fully autonomous — no prompts between stages")
    parser.add_argument("--attacker-model", default="llama3.1:8b")
    parser.add_argument("--defender-model", default="mistral:7b")
    parser.add_argument("--logs",    type=int, default=10,
                        help="Attack logs per round (default: 10)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print telemetry and KQL each round")
    args = parser.parse_args()

    run_autonomous(
        objective=args.objective,
        max_techniques=args.max_techniques,
        attacker_model=args.attacker_model,
        defender_model=args.defender_model,
        logs_per_round=args.logs,
        auto=args.auto,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
