"""
DUEL Replay Engine — re-runs stored attack telemetry against a new Defender model.
The Attacker is skipped entirely; stored logs from a previous battle are replayed.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich import box
from rich.table import Table

from agents.defender import DefenderAgent
from engine.detection import DetectionEngine
from engine.scoring import BattleScorer

console = Console()
logger  = logging.getLogger(__name__)

OUTPUT_DIR     = Path(__file__).parent.parent / "output"
TECHNIQUES_DIR = Path(__file__).parent.parent / "techniques"


class ReplayEngine:
    """
    Loads a full_battle_log_*.json and replays stored attack logs against
    a new Defender model. The Attacker phase is skipped entirely — only
    the Defender and detection engine run.
    """

    def __init__(self, log_path: str | Path):
        self.log_path      = Path(log_path)
        self.battle_data:  dict       = {}
        self.technique_id: str        = ""
        self.original_seed: int       = 42
        self.original_date: str       = ""
        self.rounds_data:  list[dict] = []
        self.total_rounds: int        = 0

    # ── Public API ────────────────────────────────────────────────────────

    def load_battle(self) -> dict:
        """Load and validate the battle log JSON. Populates instance attributes."""
        if not self.log_path.exists():
            raise FileNotFoundError(f"Battle log not found: {self.log_path}")

        with open(self.log_path, encoding="utf-8") as f:
            data = json.load(f)

        if "technique_id" not in data or "rounds" not in data:
            raise ValueError(
                f"Invalid battle log (missing technique_id or rounds): {self.log_path}"
            )

        self.battle_data   = data
        self.technique_id  = data["technique_id"]
        self.original_seed = data.get("seed", 42)
        self.rounds_data   = data.get("rounds", [])
        self.total_rounds  = len(self.rounds_data)

        first_ts = self.rounds_data[0].get("timestamp", "") if self.rounds_data else ""
        self.original_date = first_ts[:10] if first_ts else "unknown"

        return data

    def load_technique(self) -> dict:
        """Load full technique metadata from the techniques directory."""
        tid = self.technique_id
        if tid.upper().startswith("LLM"):
            path = TECHNIQUES_DIR / "llm" / f"{tid.upper()}.json"
        else:
            path = TECHNIQUES_DIR / f"{tid}.json"

        if path.exists():
            with open(path, encoding="utf-8") as f:
                return json.load(f)

        # Minimal fallback if technique file is missing
        return {
            "technique_id":       tid,
            "name":               tid,
            "description":        "",
            "sentinel_tables":    ["SigninLogs"],
            "detection_kql_hints": [],
            "evasion_variants":   [],
        }

    def replay(self, defender_model: str, seed: int = 42) -> BattleScorer:
        """
        Run the Defender against stored attack logs from each original round.
        Prints a Rich UI with REPLAY MODE banner and per-round tables.
        Returns a completed BattleScorer.
        """
        if not self.battle_data:
            self.load_battle()

        technique = self.load_technique()
        is_llm    = self.technique_id.upper().startswith("LLM")

        console.print(Panel(
            f"[bold cyan]R E P L A Y   M O D E[/bold cyan]\n"
            f"[dim]Re-running stored telemetry — Attacker skipped[/dim]\n"
            f"[yellow]Technique:[/yellow] {self.technique_id}  "
            f"| [yellow]Original:[/yellow] {self.original_date}  "
            f"| [yellow]Rounds:[/yellow] {self.total_rounds}",
            box=box.DOUBLE,
            border_style="cyan",
            expand=False,
        ))
        console.print(f"[bold]Defender model:[/bold] {defender_model}")
        console.print(f"[bold]Seed:[/bold]           {seed}")
        console.print(f"[bold]Source log:[/bold]     {self.log_path.name}\n")

        defender = DefenderAgent(model=defender_model, seed=seed)
        scorer   = BattleScorer(
            total_rounds=self.total_rounds,
            technique_id=self.technique_id,
            seed=seed,
        )

        for i, round_data in enumerate(self.rounds_data, 1):
            # Reconstruct full attack log list from the original round record
            attack_logs = (
                round_data.get("detected_logs", [])
                + round_data.get("evaded_logs", [])
            )
            original_round = round_data.get("round", i)

            console.rule(f"[bold cyan]REPLAY ROUND {i}/{self.total_rounds}[/bold cyan]")
            console.print(
                f"  [dim]Original round {original_round}: "
                f"{len(attack_logs)} stored attack logs[/dim]"
            )

            # ── Defender generates KQL rule ──────────────────────────────
            console.print("[blue bold]🛡  Defender generating KQL rule...[/blue bold]")
            try:
                kql_rule = defender.generate_rule(
                    technique=technique,
                    round_num=i,
                    total_rounds=self.total_rounds,
                    attack_logs=attack_logs,
                    detected_logs=scorer.get_last_detected_logs(),
                    evaded_logs=scorer.get_last_evaded_logs(),
                )
            except Exception as exc:
                logger.error("Defender error replay round %d: %s", i, exc)
                kql_rule = "SigninLogs | where ResultType != 0"
                console.print(f"[red]Defender fallback: {exc}[/red]")

            # ── Detection engine ─────────────────────────────────────────
            console.print("[green bold]🔍 Running detection engine...[/green bold]")
            if is_llm:
                from engine.llm_detection import LLMDetectionEngine
                engine: DetectionEngine = LLMDetectionEngine(attack_logs)
            else:
                engine = DetectionEngine(attack_logs)
            det_result = engine.run(kql_rule)

            record = scorer.record_round(
                round_num=i,
                attack_logs=attack_logs,
                kql_rule=kql_rule,
                detected_ids=det_result["detected_ids"],
                kql_valid=det_result["kql_valid"],
            )

            # ── Round summary table ──────────────────────────────────────
            t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
            t.add_column("Metric", style="cyan")
            t.add_column("Value", justify="right")
            cd = "green" if record["detection_rate"] >= 0.5 else "red"
            ce = "green" if record["evasion_rate"]   >= 0.5 else "red"
            t.add_row("Stored logs replayed",      str(record["attack_log_count"]))
            t.add_row("Detected",  f"[{cd}]{record['detected_count']}[/{cd}]")
            t.add_row("Evaded",    f"[{ce}]{record['evaded_count']}[/{ce}]")
            t.add_row("Detection rate", f"[{cd}]{record['detection_rate']:.0%}[/{cd}]")
            t.add_row("Evasion rate",   f"[{ce}]{record['evasion_rate']:.0%}[/{ce}]")
            t.add_row("KQL valid", "✓" if record["kql_valid"] else "✗")
            console.print(t)

        return scorer

    def save_replay_log(self, scorer: BattleScorer, defender_model: str) -> Path:
        """Save replay results to a uniquely named file in /output."""
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        safe_model = defender_model.replace(":", "_").replace("/", "_")
        ts_str     = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename   = (
            f"full_battle_log_{self.technique_id}"
            f"_replay_{safe_model}_{ts_str}.json"
        )
        battle = {
            "technique_id":         self.technique_id,
            "attacker_model":       self.battle_data.get("attacker_model", "llama3.1:8b"),
            "defender_model":       defender_model,
            "seed":                 scorer.seed,
            "replay":               True,
            "original_log":         self.log_path.name,
            "original_date":        self.original_date,
            "original_seed":        self.original_seed,
            "total_rounds":         scorer.total_rounds,
            "final_attacker_score": scorer.attacker_score,
            "final_defender_score": scorer.defender_score,
            "winner":               scorer._determine_winner(),
            "rounds":               scorer.rounds,
            "surviving_kql_rules":  scorer.surviving_kql,
        }
        path = OUTPUT_DIR / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(battle, f, indent=2, default=str)
        return path
