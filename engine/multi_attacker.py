"""
MultiAttackerSwarm — parallel attacker agents with distinct strategies.

Each StrategyAttacker generates logs independently; their logs are pooled for
the Defender, then split back after detection to feed individual mutation loops.
After every round the swarm aggregates evasion patterns into SwarmMemory.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from engine import groq_client as ollama
from agents.attacker import AttackerAgent, _fallback_logs, ATTACKER_SYSTEM
from engine.swarm_memory import SwarmMemory, STRATEGY_NAMES

logger = logging.getLogger(__name__)

MAX_ATTACKERS = 5

# Strategy-specific addenda appended to ATTACKER_SYSTEM before every LLM call.
STRATEGY_ADDENDA: dict[str, str] = {
    "aggressive": (
        "\n\nSTRATEGY: AGGRESSIVE — High risk tolerance. Try the most obvious attack "
        "signatures first. Use known-bad IP ranges (Tor exit nodes, VPS hosting), "
        "distinctive scripted User-Agents, and atypical sign-in times. Speed over stealth."
    ),
    "stealth": (
        "\n\nSTRATEGY: STEALTH — Mimic legitimate user traffic as closely as possible. "
        "Use common browsers (Chrome, Firefox, Edge), realistic home-country locations, "
        "normal business hours, and ResultType=0 (successful logins). Blend in."
    ),
    "adaptive": (
        "\n\nSTRATEGY: ADAPTIVE — Study the last KQL rule carefully. Identify every "
        "field it conditions on and rotate those exact fields first. If the rule "
        "checked CountryOrRegion, use new countries. If it checked UserAgent, switch "
        "to obscure but real browser strings. Directly target the Defender's blind spots."
    ),
    "random": (
        "\n\nSTRATEGY: RANDOM — Completely random field rotation every round. "
        "Vary every possible field value unpredictably across the allowed schema. "
        "Generate maximum field diversity to stress-test any pattern-matching rule."
    ),
    "memory-guided": (
        "\n\nSTRATEGY: MEMORY-GUIDED — Use ONLY the successful evasion patterns from "
        "the persistent attacker memory shown above. Reproduce and refine proven "
        "field-value combinations. Do not introduce novel mutations — exploit what works."
    ),
}


class StrategyAttacker(AttackerAgent):
    """AttackerAgent variant that prepends a strategy directive to ATTACKER_SYSTEM."""

    def __init__(
        self,
        strategy: str,
        model: str = "llama3.1:8b",
        num_logs: int = 10,
        seed: int = 42,
    ):
        super().__init__(model=model, num_logs=num_logs, seed=seed)
        self.strategy = strategy
        self._system  = ATTACKER_SYSTEM + STRATEGY_ADDENDA.get(strategy, "")

    def _call_ollama(self, prompt: str) -> str:
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": self._system},
                    {"role": "user",   "content": prompt},
                ],
                options={"temperature": 0.85, "num_predict": 4096, "seed": self.seed},
            )
            return response["message"]["content"]
        except Exception as exc:
            logger.error("Ollama call failed (strategy=%s): %s", self.strategy, exc)
            raise


class MultiAttackerSwarm:
    """
    Orchestrates N parallel StrategyAttacker agents.

    Each round:
      1. All attackers generate logs simultaneously (ThreadPoolExecutor).
      2. Logs are pooled and deduplicated by _duel_id.
      3. The Defender generates ONE KQL rule against the combined pool.
      4. The detection engine runs against all pooled logs.
      5. Results are split back to individual attackers for next-round mutation.
      6. Swarm memory is updated with per-strategy evasion patterns.

    After the battle, aggregate_memory() / get_swarm_context() return the
    ranked swarm memory: patterns sorted by how many different strategies used them.
    """

    def __init__(
        self,
        num_attackers: int = 3,
        model: str = "llama3.1:8b",
        num_logs: int = 10,
        seed: int = 42,
    ):
        self.num_attackers = min(max(1, num_attackers), MAX_ATTACKERS)
        self.model         = model
        self.num_logs      = num_logs
        self.seed          = seed
        self.swarm_memory  = SwarmMemory()

        strategies = STRATEGY_NAMES[: self.num_attackers]
        self.attackers: list[StrategyAttacker] = [
            StrategyAttacker(
                strategy=strategy,
                model=model,
                num_logs=num_logs,
                seed=seed + i,
            )
            for i, strategy in enumerate(strategies)
        ]

        # Per-attacker mutation state (updated after each round)
        self._last_evaded:   list[list[dict]] = [[] for _ in self.attackers]
        self._last_detected: list[list[dict]] = [[] for _ in self.attackers]

    @property
    def strategies(self) -> list[str]:
        return [a.strategy for a in self.attackers]

    # ------------------------------------------------------------------
    # Round execution
    # ------------------------------------------------------------------

    def generate_round(
        self,
        technique: dict,
        round_num: int,
        total_rounds: int,
        last_kql: str | None,
    ) -> tuple[list[dict], list[list[dict]]]:
        """
        Run all attackers in parallel.

        Returns:
          pooled_logs       — deduplicated union; each log has _swarm_strategy set.
          per_attacker_logs — list of log lists, one per attacker (same objects as
                              in pooled_logs, so _duel_ids are consistent).
        """
        raw_results: list[list[dict] | None] = [None] * self.num_attackers

        with ThreadPoolExecutor(max_workers=self.num_attackers) as executor:
            futures = {
                executor.submit(
                    self._run_one, i, technique, round_num, total_rounds, last_kql
                ): i
                for i in range(self.num_attackers)
            }
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    raw_results[idx] = future.result()
                except Exception as exc:
                    logger.error(
                        "Attacker %d (strategy=%s) failed: %s",
                        idx, self.attackers[idx].strategy, exc,
                    )
                    raw_results[idx] = _fallback_logs(self.num_logs)

        seen_ids: set[str] = set()
        pooled: list[dict] = []
        per_attacker_logs: list[list[dict]] = []

        for i, logs in enumerate(raw_results):
            if logs is None:
                logs = _fallback_logs(self.num_logs)
            deduplicated: list[dict] = []
            for log in logs:
                if log["_duel_id"] not in seen_ids:
                    seen_ids.add(log["_duel_id"])
                    log["_swarm_strategy"] = self.attackers[i].strategy
                    pooled.append(log)
                    deduplicated.append(log)
            per_attacker_logs.append(deduplicated)

        return pooled, per_attacker_logs

    def record_round_results(
        self,
        technique_id: str,
        round_num: int,
        per_attacker_logs: list[list[dict]],
        detected_ids: set[str],
    ) -> list[dict]:
        """
        Distribute detection results back to individual attackers and update
        the swarm memory.

        Returns per-attacker stats list:
          [{ strategy, total_logs, evaded_count, detected_count,
             evasion_rate, evaded_logs, detected_logs }, ...]
        """
        per_attacker_stats: list[dict] = []

        for i, (attacker, logs) in enumerate(zip(self.attackers, per_attacker_logs)):
            evaded_logs   = [l for l in logs if l["_duel_id"] not in detected_ids]
            detected_logs = [l for l in logs if l["_duel_id"] in detected_ids]
            total         = len(logs)
            evasion_rate  = len(evaded_logs) / total if total else 0.0

            self._last_evaded[i]   = evaded_logs
            self._last_detected[i] = detected_logs

            per_attacker_stats.append({
                "strategy":       attacker.strategy,
                "total_logs":     total,
                "evaded_count":   len(evaded_logs),
                "detected_count": len(detected_logs),
                "evasion_rate":   round(evasion_rate, 4),
                "evaded_logs":    evaded_logs,
                "detected_logs":  detected_logs,
            })

        self.swarm_memory.update_from_swarm_round(
            technique_id, round_num, per_attacker_stats
        )

        return per_attacker_stats

    def swarm_consensus_score(self, per_attacker_stats: list[dict]) -> float:
        """
        Fraction of strategies where evasion_rate > 0.5 this round.
        1.0 = every attacker evaded the Defender (maximum swarm consensus).
        """
        if not per_attacker_stats:
            return 0.0
        successful = sum(1 for s in per_attacker_stats if s["evasion_rate"] > 0.5)
        return round(successful / len(per_attacker_stats), 4)

    def get_swarm_context(self, technique_id: str) -> dict:
        """Return swarm analysis for reporting and UI."""
        return self.swarm_memory.get_swarm_context(technique_id)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_one(
        self,
        idx: int,
        technique: dict,
        round_num: int,
        total_rounds: int,
        last_kql: str | None,
    ) -> list[dict]:
        return self.attackers[idx].generate_logs(
            technique=technique,
            round_num=round_num,
            total_rounds=total_rounds,
            last_kql=last_kql,
            detected_logs=self._last_detected[idx],
            evaded_logs=self._last_evaded[idx],
        )
