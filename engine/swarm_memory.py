"""
SwarmMemory — aggregated memory across all parallel attacker strategies.
Extends MemoryStore to track per-strategy evasion patterns and compute
consensus / divergent patterns across the attacker swarm.
Never resets — accumulates forever across all swarm battles.
"""

import logging
from collections import defaultdict

from engine.attacker_memory import MemoryStore, TRACK_FIELDS, OUTPUT_DIR

logger = logging.getLogger(__name__)

STRATEGY_NAMES = ["aggressive", "stealth", "adaptive", "random", "memory-guided"]


class SwarmMemory(MemoryStore):
    """
    Persistent JSON store at output/swarm_memory.json.
    Adds per-strategy round tracking on top of the base MemoryStore.
    """

    MEMORY_PATH = OUTPUT_DIR / "swarm_memory.json"

    # ------------------------------------------------------------------
    # Swarm-specific update
    # ------------------------------------------------------------------

    def update_from_swarm_round(
        self,
        technique_id: str,
        round_num: int,
        per_attacker_results: list[dict],
    ) -> None:
        """
        Ingest one round of parallel-attacker results.

        per_attacker_results elements:
          { strategy, evaded_logs, detected_logs, evasion_rate,
            evaded_count, total_logs }
        """
        tech = self._get_technique(technique_id)
        tech.setdefault("strategy_stats", {})
        tech.setdefault("consensus_patterns", {})
        tech.setdefault("divergent_patterns", {})
        tech.setdefault("best_strategy", None)

        tech["total_rounds"] = tech.get("total_rounds", 0) + 1

        for result in per_attacker_results:
            strategy = result["strategy"]
            stats = tech["strategy_stats"].setdefault(strategy, {
                "total_rounds":     0,
                "total_evaded":     0,
                "total_logs":       0,
                "evasion_patterns": [],
            })
            stats["total_rounds"] += 1
            stats["total_evaded"] += result.get("evaded_count", 0)
            stats["total_logs"]   += result.get("total_logs",   0)

            evaded = result.get("evaded_logs", [])
            if evaded and result.get("evasion_rate", 0) > 0.5:
                pattern = self._derive_pattern(evaded)
                if pattern:
                    stats["evasion_patterns"].append(
                        {"round": round_num, "pattern": pattern}
                    )
                    stats["evasion_patterns"] = stats["evasion_patterns"][-20:]

        self._recompute_consensus(technique_id, per_attacker_results)
        self._update_best_strategy(technique_id)
        self._save()

    # ------------------------------------------------------------------
    # Consensus / divergent analysis
    # ------------------------------------------------------------------

    def _recompute_consensus(
        self,
        technique_id: str,
        per_attacker_results: list[dict],
    ) -> None:
        """
        Consensus  — field values present in evaded logs of ALL active strategies.
        Divergent  — fields where some strategies evaded but others did not.
        """
        tech = self._get_technique(technique_id)

        strategy_field_values: dict[str, dict[str, set]] = {}
        for result in per_attacker_results:
            strategy = result["strategy"]
            field_vals: dict[str, set] = defaultdict(set)
            for log in result.get("evaded_logs", []):
                for field in TRACK_FIELDS:
                    v = log.get(field)
                    if v is not None and str(v).strip() not in ("", "none", "None", "{}"):
                        field_vals[field].add(str(v))
            strategy_field_values[strategy] = dict(field_vals)

        if not strategy_field_values:
            return

        all_fields: set[str] = set()
        for fv in strategy_field_values.values():
            all_fields.update(fv.keys())

        new_consensus: dict[str, list[str]] = {}
        new_divergent: dict[str, dict] = {}

        for field in all_fields:
            all_sets = [fv.get(field, set()) for fv in strategy_field_values.values()]
            non_empty = [s for s in all_sets if s]
            if not non_empty:
                continue

            common = non_empty[0].intersection(*non_empty[1:]) if len(non_empty) > 1 else non_empty[0]
            if common:
                new_consensus[field] = sorted(common)[:5]

            evaded_strategies   = [s for s, fv in strategy_field_values.items() if fv.get(field)]
            detected_strategies = [s for s, fv in strategy_field_values.items() if not fv.get(field)]
            if evaded_strategies and detected_strategies:
                new_divergent[field] = {
                    "evaded_strategies":   evaded_strategies,
                    "detected_strategies": detected_strategies,
                }

        stored = tech.get("consensus_patterns", {})
        for field, values in new_consensus.items():
            existing = set(stored.get(field, []))
            existing.update(values)
            stored[field] = sorted(existing)[:10]
        tech["consensus_patterns"] = stored
        tech["divergent_patterns"] = new_divergent

    def _update_best_strategy(self, technique_id: str) -> None:
        tech = self._get_technique(technique_id)
        stats = tech.get("strategy_stats", {})
        if not stats:
            return
        best = max(
            stats.items(),
            key=lambda kv: kv[1]["total_evaded"] / max(kv[1]["total_logs"], 1),
        )
        tech["best_strategy"] = best[0]

    # ------------------------------------------------------------------
    # Context / reporting
    # ------------------------------------------------------------------

    def get_swarm_context(self, technique_id: str) -> dict:
        """Return swarm analysis for the battle report and Web UI."""
        tech = self._data.get(technique_id, {})
        raw_stats = tech.get("strategy_stats", {})
        strategy_stats = {
            strategy: {
                "total_rounds": s.get("total_rounds", 0),
                "total_evaded": s.get("total_evaded", 0),
                "total_logs":   s.get("total_logs", 0),
                "evasion_rate": round(
                    s["total_evaded"] / max(s["total_logs"], 1), 3
                ),
            }
            for strategy, s in raw_stats.items()
        }
        return {
            "technique_id":       technique_id,
            "consensus_patterns": tech.get("consensus_patterns", {}),
            "divergent_patterns": tech.get("divergent_patterns", {}),
            "best_strategy":      tech.get("best_strategy"),
            "strategy_stats":     strategy_stats,
            "total_rounds":       tech.get("total_rounds", 0),
        }

    def get_all(self) -> dict:
        """Return all swarm memory — used by /api/swarm_memory."""
        return {tid: self.get_swarm_context(tid) for tid in self._data}
