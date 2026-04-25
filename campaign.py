"""
DUEL — Campaign Mode
Chains multiple MITRE ATT&CK techniques into a kill chain.
The Attacker carries context between stages, simulating a real attack scenario.

Usage:
  python campaign.py --campaign cloud-takeover --rounds 3
  python campaign.py --campaign identity-attack --rounds 2 --logs 8 --verbose
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
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
logger = logging.getLogger("duel.campaign")

TECHNIQUES_DIR = Path(__file__).parent / "techniques"
OUTPUT_DIR = Path(__file__).parent / "output"

CAMPAIGNS: dict[str, dict] = {
    "cloud-takeover": {
        "name": "Cloud Takeover",
        "description": (
            "Full cloud account takeover simulating Initial Access through Collection. "
            "The attacker gains entry via valid credentials, steals tokens for persistence, "
            "adds backdoor credentials, then exfiltrates email data."
        ),
        "techniques": ["T1078.004", "T1528", "T1098.001", "T1114.002"],
        "narrative": [
            "Gain initial access using valid cloud credentials",
            "Steal OAuth application access tokens to maintain persistence",
            "Add credentials to cloud accounts for backdoor access",
            "Collect sensitive emails from compromised mailboxes",
        ],
    },
    "identity-attack": {
        "name": "Identity Attack",
        "description": (
            "Full identity-based attack chain targeting authentication and authorization. "
            "The attacker sprays passwords, bypasses MFA, creates backdoor accounts, "
            "then maps group memberships for privilege escalation."
        ),
        "techniques": ["T1110.003", "T1556.006", "T1136.003", "T1069.003"],
        "narrative": [
            "Password spray to compromise initial account",
            "Bypass MFA to eliminate authentication controls",
            "Create new cloud accounts for persistent backdoor",
            "Enumerate group memberships for privilege escalation paths",
        ],
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_technique(technique_id: str) -> dict:
    path = TECHNIQUES_DIR / f"{technique_id}.json"
    if not path.exists():
        console.print(f"[red]Technique file not found: {path}[/red]")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_campaign_context(prev_technique: dict, scorer: BattleScorer, stage_num: int) -> str:
    """Build attacker carry-forward context from the completed previous stage."""
    total_logs = sum(r["attack_log_count"] for r in scorer.rounds)
    total_evaded = sum(r["evaded_count"] for r in scorer.rounds)
    evasion_rate = total_evaded / total_logs if total_logs else 0.0
    winner = scorer._determine_winner()
    outcome = "established a foothold" if winner == "Attacker" else "been partially detected"

    last_evaded = scorer.get_last_evaded_logs()
    evaded_summary = ""
    if last_evaded:
        sample = last_evaded[0]
        clean = {k: v for k, v in sample.items() if not k.startswith("_duel")}
        evaded_summary = (
            f"\nSample evaded telemetry from previous stage: "
            f"{json.dumps(clean, default=str)[:400]}"
        )

    return (
        f"CAMPAIGN CONTEXT — Advancing from Stage {stage_num}: "
        f"{prev_technique['technique_id']} — {prev_technique['name']}.\n"
        f"Previous stage outcome: {winner} | Evasion rate: {evasion_rate:.0%} | "
        f"Evaded {total_evaded}/{total_logs} logs.\n"
        f"The attacker has {outcome} in stage {stage_num}.\n"
        f"Use the compromised access and defender blind spots from stage {stage_num} "
        f"to craft more targeted telemetry for the next kill chain phase."
        f"{evaded_summary}"
    )


# ---------------------------------------------------------------------------
# Stage runner
# ---------------------------------------------------------------------------

def run_campaign_stage(
    stage_num: int,
    total_stages: int,
    technique: dict,
    rounds: int,
    logs_per_round: int,
    attacker: AttackerAgent,
    defender_model: str,
    campaign_context: str | None,
    verbose: bool,
) -> BattleScorer:
    """Run one technique stage. Returns the completed BattleScorer."""
    technique_id = technique["technique_id"]
    console.rule(
        f"[bold cyan]STAGE {stage_num}/{total_stages} — "
        f"{technique_id}: {technique['name']}[/bold cyan]"
    )

    if campaign_context:
        console.print(Panel(
            Text(campaign_context[:600], style="cyan"),
            title="[bold]Campaign Context (Attacker Intel)[/bold]",
            border_style="cyan",
        ))

    defender = DefenderAgent(model=defender_model)
    scorer = BattleScorer(total_rounds=rounds, technique_id=technique_id)

    for round_num in range(1, rounds + 1):
        console.rule(f"[yellow]Round {round_num}/{rounds}[/yellow]")

        # Attacker phase
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
            samples = attack_logs[:2]
            preview = json.dumps(
                [{k: v for k, v in s.items() if not k.startswith("_duel")} for s in samples],
                indent=2, default=str,
            )
            console.print(Panel(
                Text(preview[:800], style="yellow"),
                title="Attack Sample",
                border_style="red",
            ))

        # Defender phase
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
            logger.error("Defender error stage %d round %d: %s", stage_num, round_num, exc)
            kql_rule = "SigninLogs | where ResultType != 0"

        if verbose:
            console.print(Panel(
                Text(kql_rule, style="bright_cyan"),
                title="KQL Rule",
                border_style="blue",
            ))

        # Detection phase
        console.print("[green bold]🔍 Running detection engine...[/green bold]")
        engine = DetectionEngine(attack_logs)
        det_result = engine.run(kql_rule)

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
        t.add_row("Detection rate", f"{record['detection_rate']:.0%}")
        t.add_row("Evasion rate", f"{record['evasion_rate']:.0%}")
        t.add_row("Attacker score (cum.)", str(record["attacker_cumulative_score"]))
        t.add_row("Defender score (cum.)", str(record["defender_cumulative_score"]))
        console.print(t)

    # Stage summary
    total_logs = sum(r["attack_log_count"] for r in scorer.rounds)
    total_evaded = sum(r["evaded_count"] for r in scorer.rounds)
    evasion_rate = total_evaded / total_logs if total_logs else 0.0
    winner = scorer._determine_winner()
    color = "red" if winner == "Attacker" else "blue" if winner == "Defender" else "yellow"
    console.print(
        f"\n  Stage winner: [{color} bold]{winner}[/{color} bold] | "
        f"Evasion: {evasion_rate:.0%} | "
        f"Surviving KQL rules: {len(scorer.surviving_kql)}"
    )

    scorer.save_full_battle_log()
    return scorer


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def generate_campaign_report(
    campaign_name: str,
    campaign_def: dict,
    techniques: list[dict],
    stage_scorers: list[BattleScorer],
) -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)

    attacker_wins = sum(1 for s in stage_scorers if s._determine_winner() == "Attacker")
    total_stages = len(stage_scorers)
    success_rate = attacker_wins / total_stages if total_stages else 0.0

    lines = [
        f"# DUEL Campaign Report — {campaign_def['name']}",
        f"",
        f"**Campaign:** `{campaign_name}`  ",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Description:** {campaign_def['description']}",
        f"",
        f"## Kill Chain Timeline",
        f"",
    ]

    for i, (technique, scorer) in enumerate(zip(techniques, stage_scorers), 1):
        winner = scorer._determine_winner()
        total_logs = sum(r["attack_log_count"] for r in scorer.rounds)
        total_evaded = sum(r["evaded_count"] for r in scorer.rounds)
        evasion_rate = total_evaded / total_logs if total_logs else 0.0
        icon = "🔴" if winner == "Attacker" else "🟢" if winner == "Defender" else "🟡"
        narrative = (
            campaign_def["narrative"][i - 1]
            if i <= len(campaign_def["narrative"])
            else ""
        )

        lines += [
            f"### Stage {i}: {technique['technique_id']} — {technique['name']}",
            f"",
            f"*{narrative}*",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Result | {icon} **{winner}** |",
            f"| Rounds played | {len(scorer.rounds)} |",
            f"| Evasion rate | {evasion_rate:.1%} |",
            f"| Attacker score | {scorer.attacker_score} pts |",
            f"| Defender score | {scorer.defender_score} pts |",
            f"| Surviving KQL rules | {len(scorer.surviving_kql)} |",
            f"",
        ]

        if scorer.surviving_kql:
            best = max(scorer.surviving_kql, key=lambda r: r["detection_rate"])
            lines += [
                f"**Best detection rule (round {best['round']}, "
                f"{best['detection_rate']:.0%} detection rate):**",
                f"",
                f"```kql",
                best["kql"].strip(),
                f"```",
                f"",
            ]

    # Campaign summary
    lines += [
        f"## Campaign Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total stages | {total_stages} |",
        f"| Attacker wins | {attacker_wins} |",
        f"| Defender wins | {total_stages - attacker_wins} |",
        f"| Overall success rate (Attacker) | **{success_rate:.1%}** |",
        f"",
    ]

    # Priority order
    lines += [
        f"## Detection Priority Order",
        f"",
        f"Techniques ranked by evasion rate — highest evasion = hardest to detect "
        f"= should be addressed first.",
        f"",
        f"| Priority | Technique | Name | Evasion Rate | Winner |",
        f"|----------|-----------|------|-------------|--------|",
    ]

    ranked = sorted(
        zip(techniques, stage_scorers),
        key=lambda x: (
            sum(r["evaded_count"] for r in x[1].rounds)
            / max(sum(r["attack_log_count"] for r in x[1].rounds), 1)
        ),
        reverse=True,
    )

    for priority, (tech, scorer) in enumerate(ranked, 1):
        total_logs = sum(r["attack_log_count"] for r in scorer.rounds)
        total_evaded = sum(r["evaded_count"] for r in scorer.rounds)
        evasion_rate = total_evaded / total_logs if total_logs else 0.0
        winner = scorer._determine_winner()
        icon = "🔴" if winner == "Attacker" else "🟢"
        lines.append(
            f"| {priority} | `{tech['technique_id']}` | {tech['name']} "
            f"| {evasion_rate:.1%} | {icon} {winner} |"
        )

    lines += [
        f"",
        f"---",
        f"*Generated by DUEL — Dual Unsupervised Evasion Loop*",
    ]

    report_path = OUTPUT_DIR / f"campaign_{campaign_name}.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return report_path


# ---------------------------------------------------------------------------
# Main campaign runner
# ---------------------------------------------------------------------------

def run_campaign(
    campaign_name: str,
    rounds: int,
    logs_per_round: int,
    attacker_model: str,
    defender_model: str,
    verbose: bool,
) -> list[BattleScorer]:
    OUTPUT_DIR.mkdir(exist_ok=True)

    if campaign_name not in CAMPAIGNS:
        console.print(
            f"[red]Unknown campaign: {campaign_name}. "
            f"Available: {', '.join(CAMPAIGNS)}[/red]"
        )
        sys.exit(1)

    campaign_def = CAMPAIGNS[campaign_name]
    technique_ids = campaign_def["techniques"]
    techniques = [load_technique(t) for t in technique_ids]

    console.print(Panel(
        f"[bold red]D U E L — CAMPAIGN MODE[/bold red]\n"
        f"[cyan]{campaign_def['name']}[/cyan]\n"
        f"[dim]{campaign_def['description'][:120]}[/dim]",
        box=box.DOUBLE,
        expand=False,
    ))

    chain_str = " → ".join(technique_ids)
    console.print(f"\n[bold]Kill chain:[/bold] {chain_str}")
    console.print(f"[bold]Rounds per stage:[/bold] {rounds}")
    console.print(f"[bold]Logs per round:[/bold] {logs_per_round}")
    console.print(f"[bold]Attacker model:[/bold] {attacker_model}")
    console.print(f"[bold]Defender model:[/bold] {defender_model}\n")

    # Single attacker carries context across all stages
    attacker = AttackerAgent(model=attacker_model, num_logs=logs_per_round)

    stage_scorers: list[BattleScorer] = []
    campaign_context: str | None = None

    for stage_num, technique in enumerate(techniques, 1):
        scorer = run_campaign_stage(
            stage_num=stage_num,
            total_stages=len(techniques),
            technique=technique,
            rounds=rounds,
            logs_per_round=logs_per_round,
            attacker=attacker,
            defender_model=defender_model,
            campaign_context=campaign_context,
            verbose=verbose,
        )
        stage_scorers.append(scorer)

        if stage_num < len(techniques):
            campaign_context = build_campaign_context(technique, scorer, stage_num)

    # Final summary
    console.rule("[bold green]CAMPAIGN COMPLETE[/bold green]")
    attacker_wins = sum(1 for s in stage_scorers if s._determine_winner() == "Attacker")
    total_stages = len(stage_scorers)
    success_rate = attacker_wins / total_stages if total_stages else 0.0

    color = "red" if attacker_wins > total_stages / 2 else "blue"
    console.print(
        f"\n[{color} bold]Campaign success rate (Attacker): {success_rate:.0%}[/{color} bold]"
    )

    summary_table = Table(
        box=box.ROUNDED,
        title="Kill Chain Results",
        show_header=True,
    )
    summary_table.add_column("Stage", style="cyan", justify="center")
    summary_table.add_column("Technique", style="dim")
    summary_table.add_column("Winner", justify="center")
    summary_table.add_column("Evasion %", justify="right")
    summary_table.add_column("KQL rules", justify="right")

    for i, (technique, scorer) in enumerate(zip(techniques, stage_scorers), 1):
        winner = scorer._determine_winner()
        wcolor = "red" if winner == "Attacker" else "blue" if winner == "Defender" else "yellow"
        total_logs = sum(r["attack_log_count"] for r in scorer.rounds)
        total_evaded = sum(r["evaded_count"] for r in scorer.rounds)
        evasion_rate = total_evaded / total_logs if total_logs else 0.0
        summary_table.add_row(
            str(i),
            technique["technique_id"],
            f"[{wcolor}]{winner}[/{wcolor}]",
            f"{evasion_rate:.0%}",
            str(len(scorer.surviving_kql)),
        )

    console.print(summary_table)

    report_path = generate_campaign_report(
        campaign_name, campaign_def, techniques, stage_scorers
    )
    console.print(f"\n[dim]Campaign report → {report_path}[/dim]")

    return stage_scorers


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DUEL — Campaign Mode: multi-technique kill chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available campaigns:
  cloud-takeover:   T1078.004 → T1528 → T1098.001 → T1114.002
                    (Valid Accounts → Token Theft → Credential Add → Email Collection)
  identity-attack:  T1110.003 → T1556.006 → T1136.003 → T1069.003
                    (Password Spray → MFA Bypass → Account Creation → Group Discovery)

Examples:
  python campaign.py --campaign cloud-takeover --rounds 3
  python campaign.py --campaign identity-attack --rounds 2 --logs 8 --verbose
        """,
    )
    parser.add_argument(
        "--campaign", required=True, choices=list(CAMPAIGNS.keys()),
        help="Campaign name",
    )
    parser.add_argument(
        "--rounds", type=int, default=3,
        help="Adversarial rounds per technique stage (default: 3)",
    )
    parser.add_argument(
        "--logs", type=int, default=10,
        help="Attack logs generated per round (default: 10)",
    )
    parser.add_argument(
        "--attacker-model", default="llama3.1:8b",
        help="Ollama model for the Attacker (default: llama3.1:8b)",
    )
    parser.add_argument(
        "--defender-model", default="mistral:7b",
        help="Ollama model for the Defender (default: mistral:7b)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print attack telemetry and KQL rules each round",
    )
    args = parser.parse_args()

    run_campaign(
        campaign_name=args.campaign,
        rounds=args.rounds,
        logs_per_round=args.logs,
        attacker_model=args.attacker_model,
        defender_model=args.defender_model,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
