"""
Autonomous Red Team — DUEL's self-directing Attacker intelligence layer.

Reads historical battle data and attacker memory to decide which technique
to attack next, plan multi-stage campaigns, and generate post-run reports.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from engine import groq_client as ollama
from engine.attacker_memory import MemoryStore

logger = logging.getLogger(__name__)

OUTPUT_DIR    = Path(__file__).parent.parent / "output"
TECHNIQUES_DIR = Path(__file__).parent.parent / "techniques"

# Objective → ordered kill chain (techniques must exist in /techniques)
_OBJECTIVE_CHAINS: dict[str, list[str]] = {
    "persistence":       ["T1078.004", "T1528", "T1098.001"],
    "exfiltration":      ["T1078.004", "T1528", "T1114.002"],
    "credential-access": ["T1110.003", "T1556.006", "T1078.004"],
    "full-compromise":   ["T1078.004", "T1528", "T1098.001", "T1114.002"],
}

_OBJECTIVE_CONTEXT: dict[str, str] = {
    "persistence":
        "Establish durable cloud access — gain initial entry via valid credentials, "
        "steal OAuth tokens to survive password resets, and backdoor account credentials.",
    "exfiltration":
        "Extract sensitive data — compromise cloud accounts, steal authentication tokens "
        "for persistence, then collect and exfiltrate email and file data.",
    "credential-access":
        "Undermine authentication — spray credentials at scale, bypass MFA controls, "
        "then pivot through the compromised cloud identity.",
    "full-compromise":
        "End-to-end cloud environment takeover — initial access, persistent token theft, "
        "credential backdooring, and bulk email exfiltration across the full kill chain.",
}

_AUTONOMOUS_SYSTEM = """\
You are an autonomous red-team AI orchestrator inside DUEL (Dual Unsupervised Evasion Loop).
Your role is to reason strategically about which MITRE ATT&CK technique to attack next,
based on historical battle data, persistent attacker memory, and a high-level objective.

Think like an APT operator optimising a kill chain:
  EXPLOIT  — technique has high historical evasion; repeat to maximise damage
  EXPLORE  — technique never tested; map unknown defensive coverage
  IMPROVE  — technique was partially detected; refine to close remaining gaps

Always respond with valid JSON exactly as instructed. Be concise and specific in reasoning.
"""

_DECISION_PROMPT = """\
AUTONOMOUS NEXT-TECHNIQUE DECISION

Objective     : {objective}
Context       : {obj_context}

Available techniques:
{available_techniques}

Session battle history:
{battle_history}

Persistent memory (cross-session):
{memory_summary}

Choose ONE technique to attack next. Respond with ONLY this JSON object — no prose:
{{
  "technique_id"    : "<one of the available technique IDs above>",
  "reasoning"       : "<2-3 sentences: why this technique, what strategic value>",
  "suggested_rounds": <integer 2-5>,
  "priority"        : "<exploit|explore|improve>"
}}
"""

_PLAN_PROMPT = """\
AUTONOMOUS CAMPAIGN PLANNING

Objective     : {objective}
Context       : {obj_context}
Max stages    : {max_techniques}

Proposed kill chain (in order):
{chain}

Persistent memory:
{memory_summary}

For each stage determine the optimal round count:
  - High historical evasion → fewer rounds (gaps already known)
  - Fresh technique or strong Defender → more rounds

Respond with ONLY this JSON array — no prose:
[
  {{
    "technique_id": "<technique ID from the chain>",
    "reasoning"   : "<one sentence: why this stage matters in the kill chain>",
    "rounds"      : <integer 2-5>
  }},
  ...
]
"""


class AutonomousRedTeam:
    """
    Self-directing red team agent. Reads historical battle data and attacker
    memory to autonomously decide technique sequence and round budgets.
    """

    def __init__(self, model: str = "llama3.1:8b"):
        self.model = model
        self.memory = MemoryStore()
        self._decisions: list[dict] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def decide_next_technique(
        self,
        battle_history: list[dict],
        excluded: list[str] | None = None,
        objective: str = "full-compromise",
    ) -> dict:
        """
        Ask the LLM which technique to attack next.

        Returns: {technique_id, reasoning, suggested_rounds, priority, timestamp}
        """
        excluded = excluded or []
        available = self._load_techniques(excluded)
        if not available:
            raise RuntimeError("No available techniques — all excluded.")

        prompt = _DECISION_PROMPT.format(
            objective=objective,
            obj_context=_OBJECTIVE_CONTEXT.get(objective, "Maximise attack coverage."),
            available_techniques=json.dumps(
                [{"technique_id": tid,
                  "name": t["name"],
                  "tactic": t.get("tactic", "unknown"),
                  "description": t.get("description", "")[:180]}
                 for tid, t in available.items()],
                indent=2,
            ),
            battle_history=self._fmt_history(battle_history),
            memory_summary=self._fmt_memory(list(available.keys())),
        )

        raw = self._llm(prompt)
        decision = self._parse_decision(raw, available)
        decision["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._decisions.append(decision)
        logger.info(
            "Autonomous decision: %s (%s) — %d rounds",
            decision["technique_id"], decision["priority"], decision["suggested_rounds"],
        )
        return decision

    def plan_campaign(self, objective: str, max_techniques: int = 4) -> list[dict]:
        """
        Plan a full kill-chain for the given objective.

        Returns: [{technique_id, reasoning, rounds}, ...]
        """
        available = self._load_techniques([])
        base_chain = _OBJECTIVE_CHAINS.get(objective, _OBJECTIVE_CHAINS["full-compromise"])
        chain = [t for t in base_chain if t in available][:max_techniques]
        if not chain:
            chain = list(available.keys())[:max_techniques]

        prompt = _PLAN_PROMPT.format(
            objective=objective,
            obj_context=_OBJECTIVE_CONTEXT.get(objective, "Maximise attack coverage."),
            max_techniques=max_techniques,
            chain=json.dumps(
                [{"technique_id": tid,
                  "name": available[tid]["name"],
                  "tactic": available[tid].get("tactic", "unknown")}
                 for tid in chain],
                indent=2,
            ),
            memory_summary=self._fmt_memory(chain),
        )

        raw = self._llm(prompt)
        plan = self._parse_plan(raw, available, chain)
        logger.info("Campaign plan: %d stages for objective %r", len(plan), objective)
        return plan

    def generate_report(
        self,
        objective: str,
        plan: list[dict],
        stage_results: list[dict],
    ) -> Path:
        """
        Write output/autonomous_report.md after an autonomous run completes.

        stage_results items: {technique_id, technique_name, winner, evasion_rate,
                               attacker_score, defender_score, surviving_kql_count,
                               surviving_kql (optional list)}
        """
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        total = len(stage_results)
        attacker_wins = sum(1 for s in stage_results if s["winner"] == "Attacker")
        success_rate = attacker_wins / total if total else 0.0
        avg_evasion = sum(s["evasion_rate"] for s in stage_results) / total if total else 0.0

        lines = [
            "# DUEL — Autonomous Red Team Report",
            "",
            f"**Objective:** `{objective}`  ",
            f"**Date:** {date}  ",
            f"**Model:** {self.model}",
            "",
            "## Autonomous Decision Log",
            "",
            f"The agent made {len(self._decisions)} technique-selection decision(s).",
            "",
        ]

        priority_icon = {"exploit": "🔴", "explore": "🔵", "improve": "🟡"}
        for i, dec in enumerate(self._decisions, 1):
            icon = priority_icon.get(dec["priority"], "⚪")
            lines += [
                f"### Decision {i}: `{dec['technique_id']}`",
                "",
                f"**Priority:** {icon} {dec['priority'].upper()}  ",
                f"**Suggested rounds:** {dec['suggested_rounds']}  ",
                "",
                f"> {dec['reasoning']}",
                "",
            ]

        # Kill chain timeline
        chain = " → ".join(s["technique_id"] for s in stage_results)
        lines += [
            "## Kill Chain Executed",
            "",
            f"```",
            chain or "(no stages completed)",
            "```",
            "",
        ]

        for stage in stage_results:
            icon = "🔴" if stage["winner"] == "Attacker" else "🟢" if stage["winner"] == "Defender" else "🟡"
            lines += [
                f"### {stage['technique_id']} — {stage.get('technique_name', '')}",
                "",
                "| Metric | Value |",
                "|--------|-------|",
                f"| Result | {icon} **{stage['winner']}** |",
                f"| Evasion rate | {stage['evasion_rate']:.1%} |",
                f"| Attacker score | {stage['attacker_score']} pts |",
                f"| Defender score | {stage['defender_score']} pts |",
                f"| Surviving KQL rules | {stage['surviving_kql_count']} |",
                "",
            ]

        lines += [
            "## Overall Success",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Stages completed | {total} |",
            f"| Attacker wins | {attacker_wins} |",
            f"| Defender wins | {total - attacker_wins} |",
            f"| **Overall success rate** | **{success_rate:.1%}** |",
            f"| Average evasion rate | {avg_evasion:.1%} |",
            "",
            "## Blue Team Priorities",
            "",
            "Techniques ranked by evasion rate — address highest evasion first.",
            "",
            "| Priority | Technique | Name | Evasion Rate | Winner |",
            "|----------|-----------|------|--------------|--------|",
        ]

        ranked = sorted(stage_results, key=lambda s: s["evasion_rate"], reverse=True)
        for i, s in enumerate(ranked, 1):
            icon = "🔴" if s["winner"] == "Attacker" else "🟢"
            lines.append(
                f"| {i} | `{s['technique_id']}` | {s.get('technique_name','')} "
                f"| {s['evasion_rate']:.1%} | {icon} {s['winner']} |"
            )

        lines += [
            "",
            "## Recommended Detection Rules",
            "",
            "Best surviving rules from each stage.",
            "",
        ]
        for s in stage_results:
            rules = s.get("surviving_kql", [])
            if rules:
                best = max(rules, key=lambda r: r.get("detection_rate", 0))
                lines += [
                    f"### {s['technique_id']} — {best.get('detection_rate', 0):.0%} detection rate",
                    "",
                    "```kql",
                    best.get("kql", "").strip(),
                    "```",
                    "",
                ]

        lines += ["---", "*Generated by DUEL — Autonomous Red Team Mode*"]

        report_path = OUTPUT_DIR / "autonomous_report.md"
        report_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Autonomous report -> %s", report_path)
        return report_path

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load_techniques(self, excluded: list[str]) -> dict[str, dict]:
        result: dict[str, dict] = {}
        for path in sorted(TECHNIQUES_DIR.glob("*.json")):
            try:
                t = json.loads(path.read_text(encoding="utf-8"))
                tid = t.get("technique_id", path.stem)
                if tid not in excluded:
                    result[tid] = t
            except Exception:
                pass
        return result

    def _fmt_history(self, history: list[dict]) -> str:
        if not history:
            return "No battles completed yet — first technique selection."
        return "\n".join(
            f"  - {s['technique_id']}: winner={s['winner']}, evasion={s['evasion_rate']:.0%}"
            for s in history
        )

    def _fmt_memory(self, technique_ids: list[str]) -> str:
        mem = self.memory.get_all()
        if not mem:
            return "No persistent memory — all techniques are fresh targets."
        lines = ["Cross-session memory:"]
        for tid in technique_ids:
            if tid in mem:
                m = mem[tid]
                lines.append(
                    f"  - {tid}: {m['total_battles']} battles, "
                    f"{m['total_rounds']} rounds, "
                    f"{m['evasion_count']} recorded evasions"
                )
        if len(lines) == 1:
            lines.append("  (no memory for these techniques yet)")
        return "\n".join(lines)

    def _llm(self, prompt: str) -> str:
        response = ollama.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": _AUTONOMOUS_SYSTEM},
                {"role": "user",   "content": prompt},
            ],
            options={"temperature": 0.6, "num_predict": 2048},
        )
        return response["message"]["content"]

    def _parse_decision(self, raw: str, available: dict) -> dict:
        for pat in [
            r"```json\s*(\{.+?\})\s*```",
            r"```\s*(\{.+?\})\s*```",
            r"(\{[^{}]*technique_id[^{}]*\})",
        ]:
            m = re.search(pat, raw, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(1))
                    return self._validate_decision(data, available)
                except Exception:
                    pass
        # Fallback: technique with most memory data
        best = max(
            available.keys(),
            key=lambda t: self.memory.get_all().get(t, {}).get("total_rounds", 0),
        )
        return {"technique_id": best, "reasoning": "LLM parse failed — chose most-tested technique.",
                "suggested_rounds": 3, "priority": "explore"}

    def _validate_decision(self, data: dict, available: dict) -> dict:
        tid = data.get("technique_id", "")
        if tid not in available:
            tid = next(iter(available))
        valid_priorities = {"exploit", "explore", "improve"}
        prio = data.get("priority", "explore")
        return {
            "technique_id":     tid,
            "reasoning":        str(data.get("reasoning", data.get("reason", "")))[:600],
            "suggested_rounds": max(2, min(6, int(data.get("suggested_rounds", data.get("rounds", 3))))),
            "priority":         prio if prio in valid_priorities else "explore",
        }

    def _parse_plan(self, raw: str, available: dict, fallback: list[str]) -> list[dict]:
        for pat in [
            r"```json\s*(\[.+?\])\s*```",
            r"```\s*(\[.+?\])\s*```",
            r"(\[[\s\S]+?\])",
        ]:
            m = re.search(pat, raw, re.DOTALL)
            if m:
                try:
                    items = json.loads(m.group(1))
                    if isinstance(items, list):
                        out = []
                        for item in items:
                            tid = item.get("technique_id", "")
                            if tid in available:
                                out.append({
                                    "technique_id": tid,
                                    "reasoning":    str(item.get("reasoning", ""))[:400],
                                    "rounds":       max(2, min(6, int(item.get("rounds", 3)))),
                                })
                        if out:
                            return out
                except Exception:
                    pass
        return [{"technique_id": t, "reasoning": "Planned stage.", "rounds": 3} for t in fallback]
