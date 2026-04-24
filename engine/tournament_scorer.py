"""
Tournament scoring — aggregates Defender results and produces rankings + report.
"""

import json
import re
import statistics
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "output"

_KQL_OPERATOR_RE = re.compile(
    r'\b(has_any|has|contains|startswith|endswith|matches\s+regex|'
    r'!in\s*\(|in\s*\(|isempty|isnotempty|isnull|isnotnull|and|or|not)\b',
    re.IGNORECASE,
)
_KQL_WHERE_RE = re.compile(r'\|\s*where\b', re.IGNORECASE)
_KQL_COMPARE_RE = re.compile(r'(==|!=|>=|<=|>(?!=)|<(?!=))')


def kql_complexity(rules: list[str]) -> int:
    """Score KQL rules by complexity: where clauses, operators, comparisons, length."""
    if not rules:
        return 0
    total = 0
    for kql in rules:
        wheres = len(_KQL_WHERE_RE.findall(kql))
        operators = len(_KQL_OPERATOR_RE.findall(kql))
        comparisons = len(_KQL_COMPARE_RE.findall(kql))
        length_bonus = len(kql) // 100
        total += wheres * 2 + operators + comparisons + length_bonus
    return total // max(len(rules), 1)


class TournamentScorer:
    def __init__(self, technique_id: str, defender_results: dict[str, dict]):
        self.technique_id = technique_id
        # {model: {rounds: [...], attacker_score: int, defender_score: int}}
        self.defender_results = defender_results

    def rank(self) -> list[dict]:
        entries = []
        for model, data in self.defender_results.items():
            rounds = data["rounds"]
            if not rounds:
                continue
            det_rates = [r["detection_rate"] for r in rounds]
            eva_rates = [r["evasion_rate"] for r in rounds]
            kql_rules = [r["kql_rule"] for r in rounds if r.get("kql_valid")]

            avg_det = sum(det_rates) / len(det_rates)
            avg_eva = sum(eva_rates) / len(eva_rates)
            std_dev = statistics.stdev(det_rates) if len(det_rates) > 1 else 0.0
            consistency = round(1.0 - std_dev, 4)
            kql_score = kql_complexity(kql_rules)

            best_round = max(range(len(rounds)), key=lambda i: rounds[i]["detection_rate"]) + 1
            worst_round = min(range(len(rounds)), key=lambda i: rounds[i]["detection_rate"]) + 1

            entries.append({
                "model": model,
                "avg_detection_rate": round(avg_det, 4),
                "avg_evasion_rate": round(avg_eva, 4),
                "consistency": consistency,
                "kql_complexity_score": kql_score,
                "best_round": best_round,
                "worst_round": worst_round,
                "attacker_score": data.get("attacker_score", 0),
                "defender_score": data.get("defender_score", 0),
                "per_round": [
                    {
                        "round": r["round"],
                        "detection_rate": r["detection_rate"],
                        "evasion_rate": r["evasion_rate"],
                        "kql_valid": r["kql_valid"],
                    }
                    for r in rounds
                ],
            })

        # Primary: avg_detection_rate ↓, Secondary: consistency ↓, Tertiary: kql_score ↓
        entries.sort(
            key=lambda e: (e["avg_detection_rate"], e["consistency"], e["kql_complexity_score"]),
            reverse=True,
        )
        for i, e in enumerate(entries):
            e["rank"] = i + 1
        return entries

    def save(self, all_attack_logs: dict) -> Path:
        OUTPUT_DIR.mkdir(exist_ok=True)
        path = OUTPUT_DIR / f"tournament_{self.technique_id}.json"
        payload = {
            "technique_id": self.technique_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "defenders": list(self.defender_results.keys()),
            "rankings": self.rank(),
            "attack_logs_per_round": {str(k): len(v) for k, v in all_attack_logs.items()},
        }
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    def generate_report(self, rankings: list[dict]) -> Path:
        OUTPUT_DIR.mkdir(exist_ok=True)
        path = OUTPUT_DIR / "tournament_report.md"
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            "# DUEL Tournament Report",
            "",
            f"**Technique:** `{self.technique_id}`  ",
            f"**Generated:** {ts}  ",
            f"**Defenders evaluated:** {len(rankings)}",
            "",
            "---",
            "",
            "## Leaderboard",
            "",
            "| Rank | Model | Avg Detection | Avg Evasion | Consistency | KQL Score | Best Round | Worst Round |",
            "|------|-------|:------------:|:-----------:|:-----------:|:---------:|:----------:|:-----------:|",
        ]
        for e in rankings:
            medal = {1: "🥇", 2: "🥈", 3: "🥉"}.get(e["rank"], f"#{e['rank']}")
            lines.append(
                f"| {medal} | `{e['model']}` | "
                f"{e['avg_detection_rate']:.0%} | "
                f"{e['avg_evasion_rate']:.0%} | "
                f"{e['consistency']:.3f} | "
                f"{e['kql_complexity_score']} | "
                f"R{e['best_round']} | "
                f"R{e['worst_round']} |"
            )

        lines += ["", "---", "", "## Per-Model Round Breakdown", ""]
        for e in rankings:
            lines += [
                f"### `{e['model']}` — Rank #{e['rank']}",
                "",
                "| Round | Detection | Evasion | KQL Valid |",
                "|:-----:|:---------:|:-------:|:---------:|",
            ]
            for r in e["per_round"]:
                valid = "✓" if r["kql_valid"] else "✗"
                lines.append(
                    f"| {r['round']} | {r['detection_rate']:.0%} | "
                    f"{r['evasion_rate']:.0%} | {valid} |"
                )
            lines.append("")

        lines += [
            "---",
            "",
            "## Methodology",
            "",
            "- **Avg Detection Rate** — mean detection rate across all rounds (higher = better defender)",
            "- **Consistency** — `1 − σ(detection_rates)`, range 0–1; higher = more stable performance",
            "- **KQL Complexity Score** — weighted count of `where` clauses, logical operators, "
            "comparison operators, and rule length; higher = more sophisticated rule",
            "- **Ranking** — primary: avg detection rate; tie-break: consistency; "
            "second tie-break: KQL complexity",
        ]

        path.write_text("\n".join(lines), encoding="utf-8")
        return path
