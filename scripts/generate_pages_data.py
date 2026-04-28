#!/usr/bin/env python3
"""
Generate docs/data.json for the GitHub Pages benchmark site.

Reads:  output/full_battle_log_*.json   (battle results)
        techniques/*.json                (MITRE technique metadata)
        techniques/llm/*.json            (OWASP LLM technique metadata)

Writes: docs/data.json

Called automatically by .github/workflows/weekly-duel.yml after battles complete.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "output"
TECHNIQUES_DIR = ROOT / "techniques"
DOCS_DIR = ROOT / "docs"


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


def build_mitre_entry(tid: str, meta: dict, log: dict | None) -> dict:
    tactic = primary_tactic(meta)
    base = {
        "id": tid,
        "name": meta.get("name", tid),
        "tactic": tactic,
        "sentinel_table": sentinel_table(meta),
    }
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


def build_llm_entry(tid: str, meta: dict, log: dict | None) -> dict:
    base = {
        "id": tid,
        "name": meta.get("name", tid),
        "risk_level": meta.get("risk_level", ""),
    }
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


def generate() -> None:
    DOCS_DIR.mkdir(exist_ok=True)

    metadata = load_technique_metadata()
    logs = load_battle_logs()

    mitre_ids = sorted(
        [k for k in metadata if not k.startswith("LLM")],
        key=lambda x: (primary_tactic(metadata[x]), x),
    )
    llm_ids = sorted(
        [k for k in metadata if k.startswith("LLM")],
    )

    mitre = [build_mitre_entry(tid, metadata[tid], logs.get(tid)) for tid in mitre_ids]
    llm   = [build_llm_entry(tid, metadata[tid], logs.get(tid)) for tid in llm_ids]

    tested = [t for t in mitre + llm if t["tested"]]
    evasion_vals = [t["evasion_rate"] for t in tested if t["evasion_rate"] is not None]
    winners = [t["winner"] for t in tested if t.get("winner")]

    summary = {
        "techniques_tested": len(tested),
        "techniques_total":  len(mitre) + len(llm),
        "avg_evasion_rate":  round(sum(evasion_vals) / len(evasion_vals), 1) if evasion_vals else 0.0,
        "total_rounds":      sum(t["rounds"] for t in tested),
        "total_battles":     len(tested),
        "attacker_wins":     winners.count("Attacker"),
        "defender_wins":     winners.count("Defender"),
        "draws":             winners.count("Draw"),
    }

    data = {
        "generated_at":   datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "summary":        summary,
        "mitre_techniques": mitre,
        "llm_techniques": llm,
        "top_kql_rules":  top_kql_rules(mitre, llm),
    }

    out = DOCS_DIR / "data.json"
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Generated {out}  ({len(tested)}/{len(mitre) + len(llm)} techniques tested)")


if __name__ == "__main__":
    generate()
