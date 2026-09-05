#!/usr/bin/env python3
"""
Groq scaling grid runner — extends the 5-model local reproduction
(scripts/run_scaling_benchmark.py) to the >=12-model grid from
scripts/list_groq_models.py, using the SAME fixed techniques/rounds/seed/
scorer so results are directly comparable.

Design (per mission "Parte B" decisions, do not change without discussion):
  - One process = one platform. Like run_scaling_benchmark.py, the actual
    inference backend is selected by engine/groq_client.py based on whether
    GROQ_API_KEY is set in THIS process's environment — there is no mixed-
    platform single run. To cover both platforms, run this script twice:
    once with GROQ_API_KEY unset (--platform ollama) and once with it set
    (--platform groq).
  - On a Groq run, the Attacker ALSO runs on Groq (nearest available
    equivalent to llama3.1:8b there) — fully cloud, no mixed attacker/
    defender platform within one battle. The exact Groq attacker model id
    must be passed explicitly via --attacker (never guessed/hardcoded here).
  - Cross-platform control: llama3.1:8b as Defender, run once per platform
    with the matching-platform Attacker each time. This isolates the
    Attacker+Defender platform confound in one pair of runs, per mission
    rule 3.
  - threat-intel defaults to "off" (see docs/ERRATA.md item 4) and every
    saved JSON records platform/attacker_model/defender_model/
    threat_intel_mode/weight_profile/seed explicitly.

Grid input: a JSON file shaped like scripts/list_groq_models.py's snapshot
output, filtered/curated by a human (every entry needs params_b AND
source_url from an official model card — see grid schema below). This
script does not invent or infer parameter counts; a grid entry missing
params_b or source_url is rejected.

Grid entry schema (one dict per model):
{
  "groq_id":        "llama-3.3-70b-versatile",
  "family":         "Llama 3.3",
  "params_b":       70.0,
  "source_url":     "https://huggingface.co/meta-llama/Llama-3.3-70B-Instruct",
  "context_window": 131072,
  "role":           "defender"   # "defender" | "attacker" | "both"
}

Usage:
    # Validate a grid file and print what would run — no network calls at all.
    python scripts/run_groq_grid.py --grid path/to/grid.json --platform groq \\
        --attacker llama-3.3-70b-versatile --dry-run

    # Real run (requires GROQ_API_KEY in env for --platform groq):
    python scripts/run_groq_grid.py --grid path/to/grid.json --platform groq \\
        --attacker llama-3.3-70b-versatile

Output: output/benchmarks/groq_grid/dabs_<model>_<timestamp>.json — same
dabs_v1/dabs_v2 combined schema as output/benchmarks/scaling_v2/, in a
separate directory so a real run here can never collide with the ongoing
5-model reproduction's output files.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.table import Table

# Same fixed experimental design as scripts/run_scaling_benchmark.py so
# results are directly comparable — do not diverge without updating both.
from scripts.run_scaling_benchmark import (  # noqa: E402
    DEFAULT_ROUNDS,
    DEFAULT_ROUND_TIMEOUT,
    DEFAULT_TECHNIQUES,
    _all_technique_count,
    _battle,
    _load_technique,
)
from engine.dabs_scorer import DABSScorer  # noqa: E402

GRID_OUTPUT_DIR = Path(__file__).parent.parent / "output" / "benchmarks" / "groq_grid"
REQUIRED_GRID_FIELDS = ("groq_id", "family", "params_b", "source_url", "role")

console = Console()


def load_grid(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("candidates", data) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected a list of grid entries (or {{'candidates': [...]}})")

    validated = []
    for i, entry in enumerate(entries):
        missing = [f for f in REQUIRED_GRID_FIELDS if not entry.get(f)]
        if missing:
            raise ValueError(
                f"{path}: entry {i} ({entry.get('groq_id', '?')!r}) missing required "
                f"field(s) {missing} — every grid model needs params_b AND source_url "
                f"from an official model card. Not entering the grid without one."
            )
        if entry["role"] not in ("defender", "attacker", "both"):
            raise ValueError(f"{path}: entry {i} has invalid role {entry['role']!r}")
        validated.append(entry)
    return validated


def print_grid(entries: list[dict], platform: str) -> None:
    tbl = Table(title=f"Groq Grid — platform={platform}", style="cyan")
    tbl.add_column("groq_id", style="bold white")
    tbl.add_column("family")
    tbl.add_column("params_b", justify="right")
    tbl.add_column("role")
    tbl.add_column("source_url", overflow="fold")
    for e in sorted(entries, key=lambda x: x["params_b"]):
        tbl.add_row(e["groq_id"], e["family"], f"{e['params_b']:.1f}", e["role"], e["source_url"])
    console.print(tbl)


def run_defender(
    defender_model: str,
    attacker_model: str,
    platform: str,
    round_timeout: int,
    threat_intel_mode: str,
) -> Path:
    technique_ids = DEFAULT_TECHNIQUES
    total_techs   = _all_technique_count()
    technique_results: dict[str, dict] = {}

    for tech_id in technique_ids:
        technique = _load_technique(tech_id)
        technique_results[tech_id] = _battle(
            technique, DEFAULT_ROUNDS, attacker_model, defender_model,
            round_timeout=round_timeout,
            threat_intel_mode=threat_intel_mode,
        )

    v1 = DABSScorer(
        model=defender_model, technique_results=technique_results, attacker_model=attacker_model,
        total_techniques=total_techs, exclude_components=["swarm_resilience"],
        platform=platform, weight_profile="dabs_v1",
    ).compute()
    v2 = DABSScorer(
        model=defender_model, technique_results=technique_results, attacker_model=attacker_model,
        total_techniques=total_techs, exclude_components=["swarm_resilience"],
        platform=platform, weight_profile="dabs_v2",
    ).compute()

    GRID_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    safe = defender_model.replace(":", "_").replace("/", "_")
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = GRID_OUTPUT_DIR / f"dabs_{safe}_{ts}.json"
    path.write_text(json.dumps({
        "model":             defender_model,
        "attacker_model":    attacker_model,
        "platform":          platform,
        "threat_intel_mode": threat_intel_mode,
        "seed":              v1.seed,
        "timestamp":         v2.timestamp,
        "dabs_v1":           v1.to_dict(),
        "dabs_v2":           v2.to_dict(),
    }, indent=2), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="DUEL Groq Grid Runner")
    parser.add_argument("--grid", required=True, help="Path to a curated grid JSON file")
    parser.add_argument("--platform", required=True, choices=["ollama", "groq"])
    parser.add_argument(
        "--attacker", required=True,
        help="Attacker model id for THIS platform (never guessed — pass explicitly)",
    )
    parser.add_argument("--round-timeout", type=int, default=DEFAULT_ROUND_TIMEOUT)
    parser.add_argument("--threat-intel", default="off", choices=["live", "snapshot", "off"])
    parser.add_argument("--dry-run", action="store_true", help="Validate and print the grid; make zero network calls")
    args = parser.parse_args()

    entries = load_grid(args.grid)
    defenders = [e for e in entries if e["role"] in ("defender", "both")]

    print_grid(entries, args.platform)
    console.print(f"\n[dim]Attacker for this run:[/dim] {args.attacker}  [dim](platform={args.platform})[/dim]")
    console.print(f"[dim]Defenders to run:[/dim] {len(defenders)}")
    console.print(f"[dim]Techniques:[/dim] {', '.join(DEFAULT_TECHNIQUES)}  [dim]Rounds:[/dim] {DEFAULT_ROUNDS}")
    console.print(f"[dim]Threat intel:[/dim] {args.threat_intel}  [dim]Round timeout:[/dim] {args.round_timeout}s")

    if args.dry_run:
        console.print("\n[bold yellow]--dry-run: no network calls made, no output written.[/bold yellow]")
        return

    if args.platform == "groq" and not os.environ.get("GROQ_API_KEY", "").strip():
        console.print("[red]--platform groq requires GROQ_API_KEY in the environment.[/red]")
        sys.exit(1)
    if args.platform == "ollama" and os.environ.get("GROQ_API_KEY", "").strip():
        console.print(
            "[red]GROQ_API_KEY is set but --platform ollama was requested — "
            "engine/groq_client.py would route calls to Groq regardless. "
            "Unset GROQ_API_KEY for an ollama run.[/red]"
        )
        sys.exit(1)

    for e in defenders:
        console.print(f"\n[bold cyan]== Defender: {e['groq_id']} ({e['params_b']}B) ==[/bold cyan]")
        path = run_defender(
            defender_model=e["groq_id"],
            attacker_model=args.attacker,
            platform=args.platform,
            round_timeout=args.round_timeout,
            threat_intel_mode=args.threat_intel,
        )
        console.print(f"  saved -> {path.relative_to(Path(__file__).parent.parent)}")


if __name__ == "__main__":
    main()
