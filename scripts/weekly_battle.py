#!/usr/bin/env python3
"""
Weekly automated DUEL battle runner.

Runs all 8 supported MITRE techniques with 3 rounds each, then:
  - Saves a timestamped JSON summary to output/weekly_<date>.json
  - Updates the <!-- weekly-badge-start --> section in README.md

Stats are read from the saved output/full_battle_log_*.json files after
all battles complete — not from the in-memory scorer — so results are
accurate even if individual battles error mid-run.

Invoked by .github/workflows/weekly-duel.yml.
"""

import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from main import run_duel  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(_PROJECT_ROOT / "output" / "weekly.log"),
    ],
)
logger = logging.getLogger("duel.weekly")

TECHNIQUES = [
    "T1078.004",
    "T1110.003",
    "T1528",
    "T1556.006",
    "T1098.001",
    "T1136.003",
    "T1069.003",
    "T1114.002",
]

ATTACKER_MODEL = "llama-3.1-70b-versatile"
DEFENDER_MODEL = "mixtral-8x7b-32768"
ROUNDS = 3
LOGS_PER_ROUND = 10


def run_all() -> dict[str, str | None]:
    """
    Run battles for all techniques.
    Returns {technique_id: error_message_or_None}.
    Results are saved to output/full_battle_log_<tid>.json by run_duel().
    """
    errors: dict[str, str | None] = {}
    for tid in TECHNIQUES:
        logger.info("── Running %s ──────────────────────────────────", tid)
        try:
            run_duel(
                technique_id=tid,
                rounds=ROUNDS,
                attacker_model=ATTACKER_MODEL,
                defender_model=DEFENDER_MODEL,
                logs_per_round=LOGS_PER_ROUND,
                verbose=False,
            )
            errors[tid] = None
            logger.info("%s done — log saved to output/", tid)
        except Exception as exc:
            logger.error("Battle failed for %s: %s", tid, exc, exc_info=True)
            errors[tid] = str(exc)
    return errors


def read_battle_results(run_errors: dict[str, str | None]) -> list[dict]:
    """
    Read output/full_battle_log_<tid>.json for each technique and return
    structured results. Techniques that errored during run_all() are marked
    as errors without attempting to read potentially stale log files.
    """
    out = _PROJECT_ROOT / "output"
    results = []
    for tid in TECHNIQUES:
        # Battle errored before saving a log
        if run_errors.get(tid) is not None:
            results.append({
                "technique":       tid,
                "winner":          "error",
                "attacker_score":  0,
                "defender_score":  0,
                "avg_evasion_pct": 0.0,
                "rounds_played":   0,
                "error":           run_errors[tid],
            })
            continue

        log_path = out / f"full_battle_log_{tid}.json"
        if not log_path.exists():
            logger.warning("No battle log for %s at %s", tid, log_path)
            results.append({
                "technique":       tid,
                "winner":          "error",
                "attacker_score":  0,
                "defender_score":  0,
                "avg_evasion_pct": 0.0,
                "rounds_played":   0,
                "error":           "log file not found",
            })
            continue

        try:
            data = json.loads(log_path.read_text(encoding="utf-8"))
            rounds = data.get("rounds", [])
            avg_evasion = (
                sum(r["evasion_rate"] for r in rounds) / len(rounds)
                if rounds else 0.0
            )
            results.append({
                "technique":       tid,
                "winner":          data.get("winner", "Draw"),
                "attacker_score":  data.get("final_attacker_score", 0),
                "defender_score":  data.get("final_defender_score", 0),
                "avg_evasion_pct": round(avg_evasion * 100, 1),
                "rounds_played":   len(rounds),
                "error":           None,
            })
            logger.info(
                "%s — winner=%s evasion=%.1f%% attacker=%d defender=%d",
                tid,
                data.get("winner"),
                avg_evasion * 100,
                data.get("final_attacker_score", 0),
                data.get("final_defender_score", 0),
            )
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            logger.error("Failed to read log for %s: %s", tid, exc)
            results.append({
                "technique":       tid,
                "winner":          "error",
                "attacker_score":  0,
                "defender_score":  0,
                "avg_evasion_pct": 0.0,
                "rounds_played":   0,
                "error":           str(exc),
            })
    return results


def save_summary(results: list[dict], date_str: str) -> Path:
    out = _PROJECT_ROOT / "output"
    out.mkdir(exist_ok=True)
    path = out / f"weekly_{date_str}.json"
    payload = {
        "date":       date_str,
        "techniques": len(results),
        "results":    results,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.info("Weekly summary → %s", path)
    return path


def update_readme(results: list[dict], date_str: str) -> None:
    readme = _PROJECT_ROOT / "README.md"
    if not readme.exists():
        logger.warning("README.md not found — skipping badge update")
        return

    ok = [r for r in results if r["error"] is None]
    avg_evasion = (
        sum(r["avg_evasion_pct"] for r in ok) / len(ok) if ok else 0.0
    )
    attacker_wins = sum(1 for r in ok if r["winner"] == "Attacker")
    defender_wins = sum(1 for r in ok if r["winner"] == "Defender")

    badge_body = (
        f"**Last Weekly Battle:** {date_str} &nbsp;|&nbsp; "
        f"Techniques: {len(results)} &nbsp;|&nbsp; "
        f"Avg Evasion: {avg_evasion:.1f}% &nbsp;|&nbsp; "
        f"Attacker {attacker_wins} – Defender {defender_wins}"
    )
    section = (
        "<!-- weekly-badge-start -->\n"
        f"{badge_body}\n"
        "<!-- weekly-badge-end -->"
    )

    text = readme.read_text(encoding="utf-8")
    if "<!-- weekly-badge-start -->" in text:
        text = re.sub(
            r"<!-- weekly-badge-start -->.*?<!-- weekly-badge-end -->",
            section,
            text,
            flags=re.DOTALL,
        )
    else:
        text = text.replace("\n---\n", f"\n---\n\n{section}\n", 1)

    readme.write_text(text, encoding="utf-8")
    logger.info(
        "README.md badge updated — avg evasion %.1f%%, attacker %d – defender %d",
        avg_evasion, attacker_wins, defender_wins,
    )


if __name__ == "__main__":
    (_PROJECT_ROOT / "output").mkdir(exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    logger.info("Weekly DUEL starting — %s — %d techniques", date_str, len(TECHNIQUES))
    run_errors = run_all()
    results = read_battle_results(run_errors)
    save_summary(results, date_str)
    update_readme(results, date_str)

    ok_count = sum(1 for r in results if r["error"] is None)
    logger.info(
        "Weekly DUEL complete — %d/%d techniques succeeded",
        ok_count, len(TECHNIQUES),
    )
    sys.exit(0 if ok_count > 0 else 1)
