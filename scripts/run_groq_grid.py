#!/usr/bin/env python3
"""
Hybrid scaling grid runner — extends the 5-model local reproduction
(scripts/run_scaling_benchmark.py) to a mixed Ollama+Groq grid, using the
SAME fixed techniques/rounds/seed/scorer so results are directly comparable.

Design decisions (2026-09-05, superseding the original "Attacker on Groq too"
plan — do not change without discussion):
  - The Attacker is ALWAYS llama3.1:8b on local Ollama, for every Defender in
    the grid, Groq-platform Defenders included. There is no Groq-side
    Attacker in this design; consistency of the Attacker was judged more
    valuable than matching Attacker platform to Defender platform. This is
    possible in a single process because engine/groq_client.py now supports
    an explicit per-agent `platform` override instead of one auto-detected
    singleton backend for the whole process — see AttackerAgent(platform=)/
    DefenderAgent(platform=).
  - Each grid entry carries its OWN "platform" (ollama|groq) rather than one
    global --platform flag for the whole run — the grid is mixed by design.
  - Cross-platform control: the SAME model (gpt-oss-20b) has two grid
    entries, one per platform ("gpt-oss:latest" on ollama, "openai/gpt-oss-
    20b" on groq) — both use the local llama3.1:8b Attacker, isolating the
    Defender-platform effect alone (no Attacker-platform confound).
  - Groq runs are meant to happen AFTER the concurrent local reproduction
    finishes, so they don't compete for the same Ollama/GPU resource (the
    Attacker is local even for Groq-Defender entries).
  - threat-intel defaults to "off" (see docs/ERRATA.md item 4) and every
    saved JSON records platform/attacker_model/defender_model/
    threat_intel_mode/weight_profile/seed explicitly.

Grid input: a curated JSON file (human-approved — this script does not build
or approve a grid on its own). Every entry needs params_b AND source_url
already verified in engine/scaling_laws.py::MODEL_REGISTRY; this script
resolves params from there rather than trusting the grid file's own
params/source fields (which may be stale) — a model not in MODEL_REGISTRY is
rejected.

Grid entry schema (one dict per model):
{
  "model_id":  "openai/gpt-oss-20b",   # exact id passed to DefenderAgent(model=...)
  "platform":  "groq",                  # "ollama" | "groq" — THIS entry's Defender platform
  "role":      "defender"               # "defender" | "control" (control = also run on the other platform)
}

Usage:
    # Validate a grid file and print what would run — no network calls at all.
    python scripts/run_groq_grid.py --grid path/to/grid.json --dry-run

    # Real run (requires GROQ_API_KEY for any "groq"-platform entry):
    python scripts/run_groq_grid.py --grid path/to/grid.json

Output: output/benchmarks/groq_grid/dabs_<model>_<platform>_<timestamp>.json
— same dabs_v1/dabs_v2 combined schema as output/benchmarks/scaling_v2/, in
a separate directory so a real run here can never collide with the
concurrent 5-model reproduction's output files.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")  # no-op if the file doesn't exist

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
from engine.scaling_laws import MODEL_REGISTRY  # noqa: E402

ATTACKER_MODEL = "llama3.1:8b"
ATTACKER_PLATFORM = "ollama"  # fixed — see module docstring

GRID_OUTPUT_DIR = Path(__file__).parent.parent / "output" / "benchmarks" / "groq_grid"
REQUIRED_GRID_FIELDS = ("model_id", "platform", "role")

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
            raise ValueError(f"{path}: entry {i} missing required field(s) {missing}")
        if entry["platform"] not in ("ollama", "groq"):
            raise ValueError(f"{path}: entry {i} has invalid platform {entry['platform']!r}")
        if entry["role"] not in ("defender", "control"):
            raise ValueError(f"{path}: entry {i} has invalid role {entry['role']!r}")

        registry_entry = MODEL_REGISTRY.get(entry["model_id"])
        if registry_entry is None:
            raise ValueError(
                f"{path}: entry {i} ({entry['model_id']!r}) is not in "
                f"engine/scaling_laws.py::MODEL_REGISTRY — every grid model needs a "
                f"verified params_b + source_url there first. Not entering the grid "
                f"without one."
            )
        entry = {**entry, **registry_entry}  # params_b/params_total_b/params_active_b/arch/source_url
        validated.append(entry)
    return validated


def print_grid(entries: list[dict]) -> None:
    tbl = Table(title="Hybrid Scaling Grid", style="cyan")
    tbl.add_column("model_id", style="bold white")
    tbl.add_column("platform")
    tbl.add_column("role")
    tbl.add_column("total_B", justify="right")
    tbl.add_column("active_B", justify="right")
    tbl.add_column("arch")
    tbl.add_column("source_url", overflow="fold")
    for e in sorted(entries, key=lambda x: x["params_total_b"]):
        tbl.add_row(
            e["model_id"], e["platform"], e["role"],
            f"{e['params_total_b']:.2f}", f"{e['params_active_b']:.2f}", e["arch"],
            e["source_url"],
        )
    console.print(tbl)
    console.print(f"\n[dim]Attacker (fixed, all entries):[/dim] {ATTACKER_MODEL} [dim](platform={ATTACKER_PLATFORM})[/dim]")


def run_defender(
    defender_model: str,
    defender_platform: str,
    round_timeout: int,
    threat_intel_mode: str,
) -> Path:
    technique_ids = DEFAULT_TECHNIQUES
    total_techs   = _all_technique_count()
    technique_results: dict[str, dict] = {}

    for tech_id in technique_ids:
        technique = _load_technique(tech_id)
        technique_results[tech_id] = _battle(
            technique, DEFAULT_ROUNDS, ATTACKER_MODEL, defender_model,
            round_timeout=round_timeout,
            threat_intel_mode=threat_intel_mode,
            attacker_platform=ATTACKER_PLATFORM,
            defender_platform=defender_platform,
        )

    v1 = DABSScorer(
        model=defender_model, technique_results=technique_results, attacker_model=ATTACKER_MODEL,
        total_techniques=total_techs, exclude_components=["swarm_resilience"],
        platform=defender_platform, weight_profile="dabs_v1",
    ).compute()
    v2 = DABSScorer(
        model=defender_model, technique_results=technique_results, attacker_model=ATTACKER_MODEL,
        total_techniques=total_techs, exclude_components=["swarm_resilience"],
        platform=defender_platform, weight_profile="dabs_v2",
    ).compute()

    GRID_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    safe = f"{defender_model}_{defender_platform}".replace(":", "_").replace("/", "_")
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = GRID_OUTPUT_DIR / f"dabs_{safe}_{ts}.json"
    path.write_text(json.dumps({
        "model":             defender_model,
        "attacker_model":    ATTACKER_MODEL,
        "platform":          defender_platform,       # Defender's platform (Attacker is always ollama)
        "attacker_platform": ATTACKER_PLATFORM,
        "threat_intel_mode": threat_intel_mode,
        "seed":              v1.seed,
        "timestamp":         v2.timestamp,
        "dabs_v1":           v1.to_dict(),
        "dabs_v2":           v2.to_dict(),
    }, indent=2), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="DUEL Hybrid Scaling Grid Runner")
    parser.add_argument("--grid", required=True, help="Path to a curated grid JSON file")
    parser.add_argument(
        "--only-platform", choices=["ollama", "groq"], default=None,
        help="Run only entries matching this platform (e.g. run local models "
             "now, Groq models later once the concurrent reproduction is done)",
    )
    parser.add_argument("--round-timeout", type=int, default=DEFAULT_ROUND_TIMEOUT)
    parser.add_argument("--threat-intel", default="off", choices=["live", "snapshot", "off"])
    parser.add_argument("--dry-run", action="store_true", help="Validate and print the grid; make zero network/Ollama calls")
    args = parser.parse_args()

    entries = load_grid(args.grid)
    if args.only_platform:
        entries = [e for e in entries if e["platform"] == args.only_platform]

    print_grid(entries)
    console.print(f"[dim]Entries to run:[/dim] {len(entries)}")
    console.print(f"[dim]Techniques:[/dim] {', '.join(DEFAULT_TECHNIQUES)}  [dim]Rounds:[/dim] {DEFAULT_ROUNDS}")
    console.print(f"[dim]Threat intel:[/dim] {args.threat_intel}  [dim]Round timeout:[/dim] {args.round_timeout}s")

    if args.dry_run:
        console.print("\n[bold yellow]--dry-run: no network/Ollama calls made, no output written.[/bold yellow]")
        return

    if any(e["platform"] == "groq" for e in entries) and not os.environ.get("GROQ_API_KEY", "").strip():
        console.print("[red]Grid includes a 'groq' entry but GROQ_API_KEY is not set (env or .env).[/red]")
        sys.exit(1)

    for e in entries:
        console.print(f"\n[bold cyan]== Defender: {e['model_id']} ({e['platform']}, {e['params_total_b']}B total) ==[/bold cyan]")
        path = run_defender(
            defender_model=e["model_id"],
            defender_platform=e["platform"],
            round_timeout=args.round_timeout,
            threat_intel_mode=args.threat_intel,
        )
        console.print(f"  saved -> {path.relative_to(Path(__file__).parent.parent)}")


if __name__ == "__main__":
    main()
