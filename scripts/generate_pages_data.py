#!/usr/bin/env python3
"""
Generate docs/data.json for the GitHub Pages benchmark site.

Two independent sections, each sourced from its own real artifacts — nothing
in either section is invented or carried over from a previous, possibly
invalid, run:

  1. "weekly" — the MITRE/OWASP heatmap + surviving KQL rules, from
     output/full_battle_log_*.json. If every log found has all-zero rounds
     (docs/ERRATA.md item 3's exact failure signature — decommissioned Groq
     models, every Defender call failed, badge committed anyway) this script
     REFUSES to publish those numbers: it writes a "paused" notice in place
     of the heatmap/stats instead, and exits 1 so automation notices, mirroring
     scripts/weekly_battle.py::is_run_healthy()'s guard. If no logs exist at
     all (this environment today), the section is the same paused notice,
     without failing the run — there is simply nothing yet to show.

  2. "scaling_v2" — the n=12 scaling-law grid, from
     scripts/scaling_v2_data.py::load_scaling_v2(), which reads
     output/benchmarks/scaling_v2/ and output/benchmarks/groq_grid/ directly.

Called automatically by .github/workflows/weekly-duel.yml after battles
complete; safe to run locally at any time.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "output"
TECHNIQUES_DIR = ROOT / "techniques"
DOCS_DIR = ROOT / "docs"

sys.path.insert(0, str(ROOT))

WEEKLY_PAUSED_NOTICE = (
    "Weekly automated battle: paused (2026-09-05) — see docs/ERRATA.md item 3. "
    "The previously published numbers on this page (8 techniques, 0.0% evasion, "
    "8 draws) were an artifact of decommissioned Groq model IDs where every "
    "Defender call failed and every technique recorded zero rounds; they have "
    "been removed, not republished. This section will resume once a healthy "
    "weekly run produces real per-technique battle logs."
)


# ── Technique metadata (unchanged) ──────────────────────────────────────────

def load_technique_metadata() -> dict[str, dict]:
    meta: dict[str, dict] = {}
    for p in TECHNIQUES_DIR.glob("*.json"):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            tid = d.get("technique_id") or d.get("id", p.stem)
            meta[tid] = d
        except Exception:
            pass
    llm_dir = TECHNIQUES_DIR / "llm"
    if llm_dir.is_dir():
        for p in llm_dir.glob("*.json"):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                tid = d.get("technique_id") or d.get("id", p.stem)
                meta[tid] = d
            except Exception:
                pass
    return meta


# ── Weekly battle heatmap ────────────────────────────────────────────────────

def load_battle_logs() -> dict[str, dict]:
    logs: dict[str, dict] = {}
    for p in OUTPUT_DIR.glob("full_battle_log_*.json"):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            tid = d.get("technique_id", p.stem.replace("full_battle_log_", ""))
            logs[tid] = d
        except Exception:
            pass
    return logs


def battle_log_is_all_zero(log: dict) -> bool:
    """
    Mirrors scripts/weekly_battle.py::is_run_healthy()'s guard, applied per
    log file here: a technique "succeeded" but recorded zero rounds and zero
    score on both sides — battles ran but produced no data.
    """
    return (
        log.get("total_rounds", 0) == 0
        and log.get("final_attacker_score", 0) == 0
        and log.get("final_defender_score", 0) == 0
    )


def evasion_rate_pct(log: dict) -> float:
    a = log.get("final_attacker_score", 0)
    d = log.get("final_defender_score", 0)
    total = a + d
    return round((a / total) * 100, 1) if total > 0 else 0.0


def best_kql(log: dict) -> tuple[str | None, float]:
    best_rate = -1.0
    best_rule = None
    for r in log.get("rounds", []):
        rate = r.get("detection_rate", 0.0)
        rule = r.get("kql_rule", "") or ""
        rule = rule.strip()
        if rule and rate > best_rate:
            best_rate = rate
            best_rule = rule
    return best_rule, round(best_rate * 100, 1) if best_rate >= 0 else 0.0


def primary_tactic(meta: dict) -> str:
    tactic = meta.get("tactic", "Unknown")
    if isinstance(tactic, list):
        tactic = tactic[0] if tactic else "Unknown"
    return tactic.split(",")[0].strip()


def sentinel_table(meta: dict) -> str:
    tables = meta.get("sentinel_tables")
    if tables:
        return tables[0]
    return meta.get("sentinel_table", "")


def build_entry(tid: str, meta: dict, log: dict | None, mitre: bool) -> dict:
    base = {"id": tid, "name": meta.get("name", tid)}
    if mitre:
        base["tactic"] = primary_tactic(meta)
        base["sentinel_table"] = sentinel_table(meta)
    else:
        base["risk_level"] = meta.get("risk_level", "")

    if log:
        kql, det = best_kql(log)
        return {**base,
                "tested": True,
                "rounds": log.get("total_rounds", 0),
                "evasion_rate": evasion_rate_pct(log),
                "winner": log.get("winner", ""),
                "best_detection_rate": det,
                "best_kql": kql}
    return {**base,
            "tested": False,
            "rounds": 0,
            "evasion_rate": None,
            "winner": None,
            "best_detection_rate": None,
            "best_kql": None}


def top_kql_rules(mitre: list[dict], llm: list[dict]) -> list[dict]:
    rules = []
    for t in mitre + llm:
        if t.get("best_kql") and t.get("best_detection_rate") is not None:
            rules.append({
                "technique_id": t["id"],
                "technique_name": t["name"],
                "detection_rate": t["best_detection_rate"],
                "kql": t["best_kql"],
            })
    rules.sort(key=lambda x: x["detection_rate"], reverse=True)
    return rules[:10]


def build_weekly_section(metadata: dict) -> tuple[dict, bool]:
    """Returns (section, guard_failed)."""
    logs = load_battle_logs()

    bad = {tid: log for tid, log in logs.items() if battle_log_is_all_zero(log)}
    good = {tid: log for tid, log in logs.items() if tid not in bad}

    if bad:
        print(
            f"REFUSING to publish {len(bad)} all-zero-round battle log(s): "
            f"{', '.join(sorted(bad))} — same failure signature as "
            f"docs/ERRATA.md item 3.",
            file=sys.stderr,
        )

    if not logs or bad:
        # No real per-technique data available (nothing has run yet), or what
        # ran is the corrupted zero-round signature — either way, no numbers
        # get published, only the notice. Still build MITRE/OWASP id/name
        # listings (no chart, no stats) so the page has technique metadata to
        # show once real data exists — but never renders it as a heatmap.
        return {
            "status": "paused",
            "notice": WEEKLY_PAUSED_NOTICE,
            "summary": None,
            "mitre_techniques": [],
            "llm_techniques": [],
            "top_kql_rules": [],
        }, bool(bad)

    mitre_ids = sorted(
        [k for k in metadata if not k.startswith("LLM")],
        key=lambda x: (primary_tactic(metadata[x]), x),
    )
    llm_ids = sorted([k for k in metadata if k.startswith("LLM")])

    mitre = [build_entry(tid, metadata[tid], good.get(tid), mitre=True) for tid in mitre_ids]
    llm = [build_entry(tid, metadata[tid], good.get(tid), mitre=False) for tid in llm_ids]

    tested = [t for t in mitre + llm if t["tested"]]
    evasion_vals = [t["evasion_rate"] for t in tested if t["evasion_rate"] is not None]
    winners = [t["winner"] for t in tested if t.get("winner")]

    summary = {
        "techniques_tested": len(tested),
        "techniques_total": len(mitre) + len(llm),
        "avg_evasion_rate": round(sum(evasion_vals) / len(evasion_vals), 1) if evasion_vals else 0.0,
        "total_rounds": sum(t["rounds"] for t in tested),
        "total_battles": len(tested),
        "attacker_wins": winners.count("Attacker"),
        "defender_wins": winners.count("Defender"),
        "draws": winners.count("Draw"),
    }

    return {
        "status": "ok",
        "notice": None,
        "summary": summary,
        "mitre_techniques": mitre,
        "llm_techniques": llm,
        "top_kql_rules": top_kql_rules(mitre, llm),
    }, False


# ── Scaling v2 section ───────────────────────────────────────────────────────

def build_scaling_v2_section() -> dict:
    from scripts.scaling_v2_data import load_scaling_v2
    return load_scaling_v2()


# ── Entry point ──────────────────────────────────────────────────────────────

def generate() -> None:
    DOCS_DIR.mkdir(exist_ok=True)

    metadata = load_technique_metadata()
    weekly, guard_failed = build_weekly_section(metadata)
    scaling_v2 = build_scaling_v2_section()

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "weekly": weekly,
        "scaling_v2": scaling_v2,
    }

    out = DOCS_DIR / "data.json"
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    tested_n = weekly["summary"]["techniques_tested"] if weekly["summary"] else 0
    print(f"Generated {out}  (weekly: {weekly['status']}, {tested_n} techniques tested; "
          f"scaling_v2: {scaling_v2['status']}, {len(scaling_v2['points'])} model points)")

    if guard_failed:
        print("Exiting 1 — a battle log with all-zero rounds was found (see stderr above).",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    generate()
