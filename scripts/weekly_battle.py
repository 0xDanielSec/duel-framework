#!/usr/bin/env python3
"""
Weekly automated DUEL battle runner.

Runs all 8 supported MITRE techniques with 3 rounds each, then:
  - Saves a timestamped JSON summary to output/weekly_<date>.json and, since
    that path is gitignored, a versioned copy to output/benchmarks/weekly/
    (tracked in git) that includes platform/attacker_model/defender_model
  - Updates the <!-- weekly-badge-start --> section in README.md — but ONLY
    if is_run_healthy() passes; otherwise the script exits non-zero, the
    badge is left untouched, and the workflow's commit step never runs

Stats are read from the saved output/full_battle_log_*.json files after
all battles complete — not from the in-memory scorer — so results are
accurate even if individual battles error mid-run.

Invoked by .github/workflows/weekly-duel.yml.
"""

import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
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
PLATFORM = "groq"
ROUNDS = 3
LOGS_PER_ROUND = 10
TECHNIQUE_TIMEOUT_SECS = 300  # 5 min per technique; 8 × 5 = 40 min worst case

# Model IDs Groq has decommissioned. Every run from 2026-04-25 through 2026-08-31
# used DEFENDER_MODEL="mixtral-8x7b-32768" from this set — every Defender call
# failed, every technique recorded zero rounds, and the workflow still committed
# a "0.0% / 0-0" badge every week because no exception ever reached run_all().
# Fail fast instead: if either configured model is on this list, refuse to run
# rather than silently producing another all-zero week.
_KNOWN_DECOMMISSIONED_GROQ_MODELS = {
    "mixtral-8x7b-32768",
}

if ATTACKER_MODEL in _KNOWN_DECOMMISSIONED_GROQ_MODELS or DEFENDER_MODEL in _KNOWN_DECOMMISSIONED_GROQ_MODELS:
    raise SystemExit(
        f"weekly_battle.py: ATTACKER_MODEL={ATTACKER_MODEL!r} / "
        f"DEFENDER_MODEL={DEFENDER_MODEL!r} — one of these is a known-decommissioned "
        "Groq model ID. Pull the current model list from "
        "https://api.groq.com/openai/v1/models and update these constants before "
        "running. See CHANGELOG.md 'Weekly battle badge paused'."
    )


def run_all() -> dict[str, str | None]:
    """
    Run battles for all techniques.
    Returns {technique_id: error_message_or_None}.
    Results are saved to output/full_battle_log_<tid>.json by run_duel().

    Each technique is wrapped in a ThreadPoolExecutor with TECHNIQUE_TIMEOUT_SECS
    so a single hung API call cannot block the entire workflow. The main thread
    stops waiting after the timeout; any dangling thread is cleaned up on exit.
    """
    errors: dict[str, str | None] = {}
    for tid in TECHNIQUES:
        logger.info("── Running %s ──────────────────────────────────", tid)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    run_duel,
                    technique_id=tid,
                    rounds=ROUNDS,
                    attacker_model=ATTACKER_MODEL,
                    defender_model=DEFENDER_MODEL,
                    logs_per_round=LOGS_PER_ROUND,
                    verbose=False,
                )
                future.result(timeout=TECHNIQUE_TIMEOUT_SECS)
            errors[tid] = None
            logger.info("%s done — log saved to output/", tid)
        except FuturesTimeoutError:
            logger.error(
                "Battle timed out after %ds for %s — moving to next technique",
                TECHNIQUE_TIMEOUT_SECS, tid,
            )
            errors[tid] = f"timed out after {TECHNIQUE_TIMEOUT_SECS}s"
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
    payload = {
        "date":           date_str,
        "platform":       PLATFORM,
        "attacker_model": ATTACKER_MODEL,
        "defender_model": DEFENDER_MODEL,
        "techniques":     len(results),
        "results":        results,
    }

    out = _PROJECT_ROOT / "output"
    out.mkdir(exist_ok=True)
    path = out / f"weekly_{date_str}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.info("Weekly summary → %s", path)

    # Versioned copy — output/benchmarks/ is NOT gitignored, so this is the
    # raw artifact that actually gets committed by the CI workflow.
    versioned_dir = _PROJECT_ROOT / "output" / "benchmarks" / "weekly"
    versioned_dir.mkdir(parents=True, exist_ok=True)
    versioned_path = versioned_dir / f"weekly_{date_str}.json"
    versioned_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.info("Versioned weekly summary → %s", versioned_path)

    return path


def is_run_healthy(results: list[dict]) -> tuple[bool, str]:
    """
    Guard against committing a badge that doesn't reflect a real result.

    Returns (healthy, reason). A run is unhealthy if any technique errored
    (API failure, timeout, missing log) or if every technique that "succeeded"
    still recorded zero rounds/score/evasion — the exact failure signature that
    let 21 weeks of decommissioned-model runs commit a fake 0.0%/0-0 badge.
    """
    errored = [r for r in results if r["error"] is not None]
    if errored:
        return False, f"{len(errored)}/{len(results)} technique(s) errored: " + \
            ", ".join(f"{r['technique']}={r['error']}" for r in errored)

    if not results:
        return False, "no results at all"

    all_zero = all(
        r["rounds_played"] == 0
        and r["avg_evasion_pct"] == 0.0
        and r["attacker_score"] == 0
        and r["defender_score"] == 0
        for r in results
    )
    if all_zero:
        return False, "every technique recorded zero rounds — battles ran but produced no data"

    return True, "ok"


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
        f"Attacker: `{ATTACKER_MODEL}` ({PLATFORM}) &nbsp;|&nbsp; "
        f"Defender: `{DEFENDER_MODEL}` ({PLATFORM}) &nbsp;|&nbsp; "
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

    logger.info("Weekly DUEL starting — %s — %d techniques — platform=%s", date_str, len(TECHNIQUES), PLATFORM)
    run_errors = run_all()
    results = read_battle_results(run_errors)
    save_summary(results, date_str)

    healthy, reason = is_run_healthy(results)
    if not healthy:
        logger.error("Run NOT healthy — refusing to update README badge: %s", reason)
        logger.error("Raw results saved to output/ and output/benchmarks/weekly/ for inspection.")
        sys.exit(1)

    update_readme(results, date_str)

    ok_count = sum(1 for r in results if r["error"] is None)
    logger.info(
        "Weekly DUEL complete — %d/%d techniques succeeded",
        ok_count, len(TECHNIQUES),
    )
    sys.exit(0)
