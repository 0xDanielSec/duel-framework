#!/usr/bin/env python3
"""
Export DUEL battle data as a HuggingFace-compatible adversarial dataset.

Usage:
    python scripts/export_dataset.py
    python scripts/export_dataset.py --repo-id 0xDanielSec/duel-adversarial-logs

Set HF_TOKEN env variable to auto-upload to HuggingFace Hub after generation.
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from engine.dataset_generator import DatasetGenerator, DATASET_DIR

console = Console()


def _show_summary(stats: dict) -> None:
    table = Table(title="Dataset Summary", style="cyan", border_style="dim")
    table.add_column("Split",   style="bold white", min_width=18)
    table.add_column("Records", justify="right", style="green")

    table.add_row("Train (70%)",      str(stats["train"]))
    table.add_row("Validation (15%)", str(stats["validation"]))
    table.add_row("Test (15%)",       str(stats["test"]))
    table.add_row("[bold]Total[/bold]", f"[bold]{stats['total']}[/bold]")

    console.print()
    console.print(table)
    console.print(f"\n[dim]Techniques covered:[/dim] {len(stats['techniques'])}")
    if stats["label_dist"]:
        dist = "  ".join(f"{k}: {v}" for k, v in stats["label_dist"].items())
        console.print(f"[dim]Labels:[/dim] {dist}")
    console.print(f"[dim]Avg evasion rate:[/dim] {stats['avg_evasion_rate']:.1%}")
    console.print(f"\n[dim]Files written to:[/dim] [cyan]{DATASET_DIR}[/cyan]")

    for fname in ("train.jsonl", "validation.jsonl", "test.jsonl",
                  "train.parquet", "validation.parquet", "test.parquet",
                  "dataset_card.md", "README.md"):
        p = DATASET_DIR / fname
        size = f"{p.stat().st_size / 1024:.1f} KB" if p.exists() else "—"
        console.print(f"  [dim]{fname:<25}[/dim] {size}")


def _upload_to_hub(repo_id: str, token: str) -> None:
    console.print(f"\n[bold green]HF_TOKEN found — uploading to HuggingFace Hub[/bold green]")
    console.print(f"[dim]Repo:[/dim] {repo_id}")
    try:
        from huggingface_hub import HfApi
        api = HfApi(token=token)
        api.create_repo(repo_id=repo_id, repo_type="dataset", exist_ok=True, private=False)
        api.upload_folder(
            folder_path=str(DATASET_DIR),
            repo_id=repo_id,
            repo_type="dataset",
        )
        console.print(
            f"[bold green]Uploaded:[/bold green] "
            f"https://huggingface.co/datasets/{repo_id}"
        )
    except Exception as exc:
        console.print(f"[bold red]Upload failed:[/bold red] {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export DUEL adversarial dataset")
    parser.add_argument(
        "--repo-id",
        default="0xDanielSec/duel-adversarial-logs",
        help="HuggingFace repo ID for upload (default: 0xDanielSec/duel-adversarial-logs)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for train/val/test split (default: 42)",
    )
    args = parser.parse_args()

    console.print("\n[bold cyan]DUEL — Adversarial Dataset Export[/bold cyan]")
    console.print("[dim]Scanning output/ for battle logs...[/dim]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Generating dataset...", total=None)
        gen = DatasetGenerator(seed=args.seed)
        stats = gen.generate()
        progress.update(task, description="Done.", completed=1, total=1)

    _show_summary(stats)

    if stats["total"] == 0:
        console.print(
            "\n[yellow]No battle logs found.[/yellow] "
            "Run a battle first: [bold]python main.py[/bold]"
        )

    hf_token = os.environ.get("HF_TOKEN", "")
    if hf_token:
        _upload_to_hub(args.repo_id, hf_token)
    else:
        console.print(
            "\n[dim]Tip: set [bold]HF_TOKEN[/bold] env var to auto-upload to HuggingFace Hub.[/dim]"
        )
    console.print()


if __name__ == "__main__":
    main()
