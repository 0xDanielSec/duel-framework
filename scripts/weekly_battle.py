#!/usr/bin/env python3
"""
Weekly automated DUEL battle runner.

Runs all 8 supported MITRE techniques with 3 rounds each, then:
  - Saves a timestamped JSON summary to output/weekly_<date>.json
  - Updates the <!-- weekly-badge --> section in README.md

Invoked by .github/workflows/weekly-duel.yml.
"""

import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is importable when run as a script
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

# Groq model names — groq_client maps Ollama names to these automatically,
# but we pass them directly so the log output is unambiguous.
ATTACKER_MODEL = "llama-3.1-70b-versatile"
DEFENDER_MODEL = "mixtral-8x7b-32768"
ROUNDS = 3
LOGS_PER_ROUND = 10


def run_all() -> list[dict]:
    results: list[dict] = []
    for tid in TECHNIQUES:
        logger.info("── Running %s ──────────────────────────────────", tid)
        try:
            scorer = run_duel(
                technique_id=tid,
                rounds=ROUNDS,
                attacker_model=ATTACKER_MODEL,
                defender_model=DEFENDER_MODEL,
                logs_per_round=LOGS_PER_ROUND,
                verbose=False,
            )
            avg_evasion = (
                sum(r["evasion_rate"] for r in scorer.rounds) / len(scorer.rounds)
                if scorer.rounds else 0.0
            )
            winner = (
                "Attacker" if scorer.attacker_score > scorer.defender_score
                else "Defender" if scorer.defender_score > scorer.attacker_score
                else "Draw"
            )
            results.append({
                "technique":       tid,
                "winner":          winner,
                "attacker_score":  scorer.attacker_score,
                "defender_score":  scorer.defender_score,
                "avg_evasion_pct": round(avg_evasion * 100, 1),
                "rounds_played":   len(scorer.rounds),
                "error":           None,
            })
            logger.info(
                "%s done — winner=%s evasion=%.1f%%",
                tid, winner, avg_evasion * 100,
            )
        except Exception as exc:
            logger.error("Battle failed for %s: %s", tid, exc, exc_info=True)
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
        # Insert after the first horizontal rule
        text = text.replace("\n---\n", f"\n---\n\n{section}\n", 1)

    readme.write_text(text, encoding="utf-8")
    logger.info("README.md badge updated (avg evasion %.1f%%)", avg_evasion)


if __name__ == "__main__":
    (_PROJECT_ROOT / "output").mkdir(exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    logger.info("Weekly DUEL starting — %s — %d techniques", date_str, len(TECHNIQUES))
    results = run_all()
    save_summary(results, date_str)
    update_readme(results, date_str)

    ok_count = sum(1 for r in results if r["error"] is None)
    logger.info(
        "Weekly DUEL complete — %d/%d techniques succeeded",
        ok_count, len(TECHNIQUES),
    )
    sys.exit(0 if ok_count > 0 else 1)
