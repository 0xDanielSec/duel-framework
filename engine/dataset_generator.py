"""
Adversarial Dataset Generator — exports DUEL battle data as a structured
HuggingFace-compatible dataset with train/validation/test splits.
"""
import json
import uuid
import random
from pathlib import Path
from typing import Optional

import pandas as pd

OUTPUT_DIR = Path(__file__).parent.parent / "output"
TECHNIQUES_DIR = Path(__file__).parent.parent / "techniques"
DATASET_DIR = OUTPUT_DIR / "dataset"

MODEL_DEFENDER = "mistral:7b"


class DatasetGenerator:
    def __init__(self, seed: int = 42):
        self._seed = seed
        self._technique_meta: dict[str, dict] = {}
        self._load_technique_meta()

    # ── Metadata ──────────────────────────────────────────────────────────────

    def _load_technique_meta(self) -> None:
        for path in TECHNIQUES_DIR.glob("*.json"):
            try:
                with open(path, encoding="utf-8") as f:
                    meta = json.load(f)
                self._technique_meta[meta["technique_id"]] = meta
            except Exception:
                pass
        llm_dir = TECHNIQUES_DIR / "llm"
        if llm_dir.exists():
            for path in llm_dir.glob("*.json"):
                try:
                    with open(path, encoding="utf-8") as f:
                        meta = json.load(f)
                    self._technique_meta[meta["technique_id"]] = meta
                except Exception:
                    pass

    # ── Strategy derivation (mirrors server.py logic) ─────────────────────────

    @staticmethod
    def _attacker_strategy(round_num: int, prev: Optional[dict]) -> str:
        if round_num == 1 or prev is None:
            return "Initial attack — generating baseline telemetry that matches the target technique schema."
        det = prev.get("detected_count", 0)
        evd = prev.get("evaded_count", 0)
        return (
            f"Round {round_num} mutation — {det} log(s) caught last round, {evd} evaded. "
            "Rotating known indicators to slip past the detection rule."
        )

    @staticmethod
    def _defender_reasoning(round_num: int, prev: Optional[dict]) -> str:
        if round_num == 1 or prev is None:
            return "Initial rule — scanning attack logs for detectable patterns and suspicious field values."
        evd = prev.get("evaded_count", 0)
        det = prev.get("detected_count", 0)
        return (
            f"Round {round_num} hardening — {evd} log(s) evaded last round, {det} caught. "
            "Analysing evaded samples to close the remaining detection gaps."
        )

    # ── Record building ───────────────────────────────────────────────────────

    def _build_records(self) -> list[dict]:
        records: list[dict] = []
        for log_path in sorted(OUTPUT_DIR.glob("full_battle_log_*.json")):
            try:
                with open(log_path, encoding="utf-8") as f:
                    battle = json.load(f)
            except Exception:
                continue

            technique_id = battle.get(
                "technique_id", log_path.stem.replace("full_battle_log_", "")
            )
            meta = self._technique_meta.get(technique_id, {})
            attacker_model = battle.get("attacker_model", "llama3.1:8b")

            rounds: list[dict] = battle.get("rounds", [])
            for i, rnd in enumerate(rounds):
                round_num = rnd.get("round", i + 1)
                prev = rounds[i - 1] if i > 0 else None
                kql = rnd.get("kql_rule", "")
                evasion_rate = rnd.get("evasion_rate", 0.0)
                a_strat = self._attacker_strategy(round_num, prev)
                d_reason = self._defender_reasoning(round_num, prev)

                for label, key in (("evaded", "evaded_logs"), ("detected", "detected_logs")):
                    for entry in rnd.get(key, []):
                        clean = {k: v for k, v in entry.items() if k != "_duel_id"}
                        records.append({
                            "id":                 str(uuid.uuid4()),
                            "technique_id":       technique_id,
                            "technique_name":     meta.get("name", technique_id),
                            "tactic":             meta.get("tactic", "Unknown"),
                            "round":              round_num,
                            "log":                clean,
                            "label":              label,
                            "kql_rule":           kql,
                            "attacker_strategy":  a_strat,
                            "defender_reasoning": d_reason,
                            "evasion_rate":       evasion_rate,
                            "mutation_round":     round_num,
                            "model_attacker":     attacker_model,
                            "model_defender":     MODEL_DEFENDER,
                        })
        return records

    # ── Splitting ─────────────────────────────────────────────────────────────

    def _split(self, records: list[dict]) -> tuple[list, list, list]:
        shuffled = records[:]
        random.Random(self._seed).shuffle(shuffled)
        n = len(shuffled)
        t = int(n * 0.70)
        v = t + int(n * 0.15)
        return shuffled[:t], shuffled[t:v], shuffled[v:]

    # ── I/O ───────────────────────────────────────────────────────────────────

    @staticmethod
    def _write_jsonl(records: list[dict], path: Path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=True) + "\n")

    @staticmethod
    def _write_parquet(records: list[dict], path: Path) -> None:
        try:
            import pyarrow  # noqa: F401
        except ImportError:
            return  # pyarrow not installed — skip Parquet output

        flat = []
        for rec in records:
            row = {k: v for k, v in rec.items() if k != "log"}
            row["log"] = json.dumps(rec["log"], ensure_ascii=True)
            flat.append(row)
        df = pd.DataFrame(flat) if flat else pd.DataFrame()
        df.to_parquet(path, index=False)

    # ── Statistics ────────────────────────────────────────────────────────────

    @staticmethod
    def _compute_stats(records: list, train: list, val: list, test: list) -> dict:
        empty_bins: dict[str, int] = {"0-25%": 0, "25-50%": 0, "50-75%": 0, "75-100%": 0}
        if not records:
            return {
                "total": 0, "train": 0, "validation": 0, "test": 0,
                "techniques": [], "label_dist": {},
                "avg_evasion_rate": 0.0, "evasion_rate_bins": empty_bins,
            }

        techniques = sorted({r["technique_id"] for r in records})
        label_dist: dict[str, int] = {}
        for r in records:
            label_dist[r["label"]] = label_dist.get(r["label"], 0) + 1

        avg_ev = sum(r["evasion_rate"] for r in records) / len(records)
        bins = dict(empty_bins)
        for r in records:
            rate = r["evasion_rate"]
            if   rate < 0.25: bins["0-25%"]   += 1
            elif rate < 0.50: bins["25-50%"]  += 1
            elif rate < 0.75: bins["50-75%"]  += 1
            else:              bins["75-100%"] += 1

        return {
            "total":             len(records),
            "train":             len(train),
            "validation":        len(val),
            "test":              len(test),
            "techniques":        techniques,
            "label_dist":        label_dist,
            "avg_evasion_rate":  round(avg_ev, 4),
            "evasion_rate_bins": bins,
        }

    # ── Dataset card ──────────────────────────────────────────────────────────

    def _write_dataset_card(self, stats: dict, path: Path) -> None:
        total = stats["total"]
        size_cat = "n<1K" if total < 1000 else ("1K<n<10K" if total < 10000 else "10K<n<100K")
        techniques_str = (
            ", ".join(f"`{t}`" for t in stats["techniques"]) if stats["techniques"] else "None yet"
        )
        label_rows = "\n".join(f"| `{k}` | {v} |" for k, v in stats["label_dist"].items()) \
            or "| No data | 0 |"
        bin_rows = "\n".join(f"| {k} | {v} |" for k, v in stats["evasion_rate_bins"].items())
        avg_pct = f"{stats['avg_evasion_rate']:.1%}"

        lines = [
            "---",
            "language:",
            "  - en",
            "license: mit",
            "task_categories:",
            "  - text-classification",
            "  - token-classification",
            "tags:",
            "  - security",
            "  - cybersecurity",
            "  - mitre-attack",
            "  - microsoft-sentinel",
            "  - kql",
            "  - adversarial",
            "  - red-team",
            "  - detection-engineering",
            "  - synthetic",
            f"size_categories:",
            f"  - {size_cat}",
            "---",
            "",
            "# DUEL Adversarial Security Dataset",
            "",
            "## Dataset Description",
            "",
            "This dataset contains synthetic adversarial telemetry generated by the **DUEL** framework",
            "(Dual Unified Evasion Loop) — an adversarial LLM security research framework where an",
            "Attacker agent and a Defender agent battle across MITRE ATT&CK and OWASP LLM Top 10",
            "techniques against real Microsoft Sentinel schemas.",
            "",
            "Every record is a single synthetic log entry from one round of the adversarial loop,",
            "labelled as `evaded` (the Defender's KQL rule missed it) or `detected` (caught by the rule).",
            "The accompanying `kql_rule` field contains the Defender's detection rule for that round.",
            "",
            "This dataset is intended for:",
            "- Training and evaluating ML-based intrusion detection models",
            "- Benchmarking KQL detection rule quality",
            "- Studying adversarial mutation strategies in cloud security",
            "- Red/blue team simulation and detection engineering research",
            "",
            "## How It Was Generated",
            "",
            "```",
            "Attacker (llama3.1:8b)                Defender (mistral:7b)",
            "  | generates synthetic telemetry       | writes KQL detection rule",
            "  | mutates each round based on         | hardens rule each round based",
            "    what got detected                     on what evaded",
            "        <-> Detection Engine (pandas KQL executor) <->",
            "              scores every round -> labels: evaded / detected",
            "```",
            "",
            "Each battle runs multiple rounds per technique. The Attacker carries **persistent memory**",
            "across battles — evasion patterns accumulate and feed future mutation strategies.",
            "",
            "## Dataset Statistics",
            "",
            "| Split | Records |",
            "|-------|---------|",
            f"| Train (70%) | {stats['train']} |",
            f"| Validation (15%) | {stats['validation']} |",
            f"| Test (15%) | {stats['test']} |",
            f"| **Total** | **{total}** |",
            "",
            f"**Techniques covered:** {len(stats['techniques'])}",
            "",
            techniques_str,
            "",
            "### Label Distribution",
            "",
            "| Label | Count |",
            "|-------|-------|",
            label_rows,
            "",
            f"**Average evasion rate:** {avg_pct}",
            "",
            "### Evasion Rate Distribution",
            "",
            "| Evasion Rate Bin | Records |",
            "|-----------------|---------|",
            bin_rows,
            "",
            "## Field Descriptions",
            "",
            "| Field | Type | Description |",
            "|-------|------|-------------|",
            "| `id` | string | UUID for this record |",
            "| `technique_id` | string | MITRE ATT&CK or OWASP LLM technique ID (e.g., `T1078.004`, `LLM01`) |",
            "| `technique_name` | string | Human-readable technique name |",
            "| `tactic` | string | ATT&CK tactic (e.g., `Initial Access`, `Persistence`) |",
            "| `round` | int | Battle round number (1-indexed) |",
            "| `log` | object | Synthetic telemetry entry (Microsoft Sentinel schema) |",
            "| `label` | string | `evaded` or `detected` — outcome against the Defender's KQL rule |",
            "| `kql_rule` | string | KQL detection rule used by the Defender in this round |",
            "| `attacker_strategy` | string | Description of the Attacker's mutation strategy for this round |",
            "| `defender_reasoning` | string | Description of the Defender's hardening approach for this round |",
            "| `evasion_rate` | float | Fraction of logs that evaded detection this round (0.0-1.0) |",
            "| `mutation_round` | int | Same as `round` — the mutation iteration number |",
            "| `model_attacker` | string | Ollama model used for the Attacker (e.g., `llama3.1:8b`) |",
            "| `model_defender` | string | Ollama model used for the Defender (e.g., `mistral:7b`) |",
            "",
            "## Sentinel Table Schemas",
            "",
            "The `log` field conforms to real Microsoft Sentinel table schemas:",
            "- `SigninLogs` — Azure AD sign-in events",
            "- `AuditLogs` — Azure AD audit events",
            "- `AzureActivity` — Azure resource management operations",
            "- `OfficeActivity` — Microsoft 365 activity events",
            "- Custom OWASP LLM schemas for AI/LLM attack simulation",
            "",
            "## Citation",
            "",
            "```bibtex",
            "@software{duel_framework_2026,",
            "  author    = {Daniel Gomez},",
            "  title     = {DUEL: Dual Unified Evasion Loop -- Adversarial LLM Security Research Framework},",
            "  year      = {2026},",
            "  url       = {https://github.com/0xDanielSec/duel-framework},",
            "  note      = {Adversarial telemetry dataset generated by LLM agents battling across",
            "               MITRE ATT&CK and OWASP LLM Top 10 techniques}",
            "}",
            "```",
            "",
            "## Framework",
            "",
            "Generated by **[DUEL](https://github.com/0xDanielSec/duel-framework)** — an open-source",
            "adversarial LLM security research framework. Zero external API calls — fully local via Ollama.",
            "",
            "## License",
            "",
            "MIT — see [LICENSE](https://github.com/0xDanielSec/duel-framework/blob/main/LICENSE).",
            "",
            "*All telemetry is entirely synthetic. No real Azure tenants, Microsoft 365 environments,",
            "or live Sentinel workspaces are involved.*",
        ]
        path.write_text("\n".join(lines), encoding="utf-8")

    # ── Public API ────────────────────────────────────────────────────────────

    def generate(self) -> dict:
        """Build, split, and export the full dataset. Returns statistics dict."""
        DATASET_DIR.mkdir(parents=True, exist_ok=True)

        records = self._build_records()
        train, val, test = self._split(records)
        stats = self._compute_stats(records, train, val, test)

        self._write_jsonl(train, DATASET_DIR / "train.jsonl")
        self._write_jsonl(val,   DATASET_DIR / "validation.jsonl")
        self._write_jsonl(test,  DATASET_DIR / "test.jsonl")

        self._write_parquet(train, DATASET_DIR / "train.parquet")
        self._write_parquet(val,   DATASET_DIR / "validation.parquet")
        self._write_parquet(test,  DATASET_DIR / "test.parquet")

        self._write_dataset_card(stats, DATASET_DIR / "dataset_card.md")
        self._write_dataset_card(stats, DATASET_DIR / "README.md")

        return stats
