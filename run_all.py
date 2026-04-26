"""
run_all.py — Run DUEL battles for every technique that lacks a battle log.

Usage:
  python run_all.py                          # skip already-covered techniques
  python run_all.py --force                  # re-run everything
  python run_all.py --rounds 3 --logs 8      # override battle parameters
  python run_all.py --only-missing           # (default) explicit alias for skip mode
  python run_all.py --list                   # print coverage status and exit
"""

import argparse
import json
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

TECHNIQUES_DIR = Path(__file__).parent / "techniques"
OUTPUT_DIR     = Path(__file__).parent / "output"


def discover_techniques() -> list[str]:
    mitre = sorted(p.stem for p in TECHNIQUES_DIR.glob("*.json"))
    llm_dir = TECHNIQUES_DIR / "llm"
    llm = sorted(p.stem for p in llm_dir.glob("*.json")) if llm_dir.exists() else []
    return mitre + llm


def covered_techniques() -> set[str]:
    return {p.stem.replace("full_battle_log_", "") for p in OUTPUT_DIR.glob("full_battle_log_*.json")}


def print_coverage(all_ids: list[str], covered: set[str]) -> None:
    t = Table(title="DUEL Coverage", box=box.ROUNDED, show_lines=False)
    t.add_column("Technique", style="cyan", no_wrap=True)
    t.add_column("Status", justify="center")

    for tid in all_ids:
        if tid in covered:
            t.add_row(tid, "[green]covered[/green]")
        else:
            t.add_row(tid, "[red]missing[/red]")

    console.print(t)
    console.print(
        f"\n[bold]{len(covered)}/{len(all_ids)}[/bold] techniques covered, "
        f"[yellow]{len(all_ids) - len(covered)}[/yellow] remaining.\n"
    )


def run_all(
    rounds: int,
    attacker_model: str,
    defender_model: str,
    logs_per_round: int,
    force: bool,
    verbose: bool,
) -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)

    from main import run_duel  # import here so Rich banner fires per-battle

    all_ids = discover_techniques()
    covered = covered_techniques()

    targets = all_ids if force else [t for t in all_ids if t not in covered]

    print_coverage(all_ids, covered)

    if not targets:
        console.print("[bold green]All techniques already covered. Use --force to re-run.[/bold green]")
        return

    console.print(f"[bold]Running {len(targets)} battle(s)...[/bold]\n")

    results: list[dict] = []
    failed:  list[str]  = []

    for idx, tid in enumerate(targets, 1):
        console.rule(f"[bold magenta]{idx}/{len(targets)} — {tid}[/bold magenta]")
        t0 = time.time()
        try:
            scorer = run_duel(
                technique_id=tid,
                rounds=rounds,
                attacker_model=attacker_model,
                defender_model=defender_model,
                logs_per_round=logs_per_round,
                verbose=verbose,
            )
            elapsed = time.time() - t0
            results.append({
                "technique_id":    tid,
                "winner":          "Attacker" if scorer.attacker_score > scorer.defender_score
                                   else "Defender" if scorer.defender_score > scorer.attacker_score
                                   else "Draw",
                "attacker_score":  scorer.attacker_score,
                "defender_score":  scorer.defender_score,
                "surviving_rules": len(scorer.surviving_kql),
                "elapsed_s":       round(elapsed, 1),
            })
        except Exception as exc:
            console.print(f"[red bold]FAILED {tid}: {exc}[/red bold]")
            failed.append(tid)

    _print_summary(results, failed)

    if failed:
        console.print(f"\n[red bold]{len(failed)} technique(s) failed:[/red bold] {', '.join(failed)}")
        sys.exit(1)


def _print_summary(results: list[dict], failed: list[str]) -> None:
    if not results:
        return

    console.rule("[bold green]COVERAGE RUN COMPLETE[/bold green]")

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Technique",     style="cyan")
    t.add_column("Winner",        justify="center")
    t.add_column("Atk",           justify="right")
    t.add_column("Def",           justify="right")
    t.add_column("Surviving KQL", justify="right")
    t.add_column("Time (s)",      justify="right", style="dim")

    for r in results:
        color = "red" if r["winner"] == "Attacker" else "blue" if r["winner"] == "Defender" else "yellow"
        t.add_row(
            r["technique_id"],
            f"[{color}]{r['winner']}[/{color}]",
            str(r["attacker_score"]),
            str(r["defender_score"]),
            str(r["surviving_rules"]),
            str(r["elapsed_s"]),
        )

    console.print(t)

    atk_wins = sum(1 for r in results if r["winner"] == "Attacker")
    def_wins = sum(1 for r in results if r["winner"] == "Defender")
    draws    = sum(1 for r in results if r["winner"] == "Draw")
    total_t  = sum(r["elapsed_s"] for r in results)

    console.print(
        f"\nAttacker won [red]{atk_wins}[/red] | "
        f"Defender won [blue]{def_wins}[/blue] | "
        f"Draws [yellow]{draws}[/yellow]  —  "
        f"Total time: {total_t:.0f}s"
    )

    summary_path = OUTPUT_DIR / "coverage_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({"battles": results, "failed": failed}, f, indent=2)
    console.print(f"[dim]Coverage summary → {summary_path}[/dim]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run DUEL battles for all (or uncovered) techniques.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--force",          action="store_true",
                        help="Re-run techniques that already have battle logs")
    parser.add_argument("--only-missing",   action="store_true",
                        help="(Default) Run only techniques without existing logs")
    parser.add_argument("--list",           action="store_true",
                        help="Print coverage status and exit")
    parser.add_argument("--rounds",         type=int, default=5,
                        help="Adversarial rounds per technique (default: 5)")
    parser.add_argument("--logs",           type=int, default=10,
                        help="Attack logs per round (default: 10)")
    parser.add_argument("--attacker-model", default="llama3.1:8b")
    parser.add_argument("--defender-model", default="mistral:7b")
    parser.add_argument("--verbose",        action="store_true")

    args = parser.parse_args()

    all_ids = discover_techniques()
    covered = covered_techniques()

    if args.list:
        print_coverage(all_ids, covered)
        return

    run_all(
        rounds=args.rounds,
        attacker_model=args.attacker_model,
        defender_model=args.defender_model,
        logs_per_round=args.logs,
        force=args.force,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
