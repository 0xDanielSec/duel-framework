"""
Battle scoring, round tracking, and final report generation.
"""

import json
import re
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


OUTPUT_DIR = Path(__file__).parent.parent / "output"


class BattleScorer:
    def __init__(self, total_rounds: int, technique_id: str):
        self.total_rounds = total_rounds
        self.technique_id = technique_id
        self.rounds: list[dict] = []
        self.attacker_score = 0
        self.defender_score = 0
        self.surviving_kql: list[dict] = []  # rules that caught ≥1 log at any round

    # ------------------------------------------------------------------
    # Record a completed round
    # ------------------------------------------------------------------

    def record_round(
        self,
        round_num: int,
        attack_logs: list[dict],
        kql_rule: str,
        detected_ids: set[str],
        kql_valid: bool,
    ) -> dict:
        total = len(attack_logs)
        detected = len(detected_ids)
        evaded = total - detected
        detection_rate = detected / total if total else 0.0
        evasion_rate = evaded / total if total else 0.0

        # Score: attacker +1 per evaded log, defender +1 per detected log
        self.attacker_score += evaded
        self.defender_score += detected

        evaded_logs = [l for l in attack_logs if l["_duel_id"] not in detected_ids]
        detected_logs = [l for l in attack_logs if l["_duel_id"] in detected_ids]

        record = {
            "round": round_num,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_log_count": total,
            "detected_count": detected,
            "evaded_count": evaded,
            "detection_rate": round(detection_rate, 4),
            "evasion_rate": round(evasion_rate, 4),
            "kql_valid": kql_valid,
            "kql_rule": kql_rule,
            "evaded_logs": evaded_logs,
            "detected_logs": detected_logs,
            "attacker_cumulative_score": self.attacker_score,
            "defender_cumulative_score": self.defender_score,
        }

        self.rounds.append(record)

        # Track KQL rules that successfully detected at least one log
        if kql_valid and detected > 0:
            self.surviving_kql.append({
                "round": round_num,
                "detection_rate": round(detection_rate, 4),
                "kql": kql_rule,
            })

        self._save_round_log(record)
        return record

    # ------------------------------------------------------------------
    # Convenience getters for agents
    # ------------------------------------------------------------------

    def get_last_evaded_logs(self) -> list[dict]:
        if not self.rounds:
            return []
        return self.rounds[-1]["evaded_logs"]

    def get_last_detected_logs(self) -> list[dict]:
        if not self.rounds:
            return []
        return self.rounds[-1]["detected_logs"]

    def get_round_summary(self) -> dict:
        if not self.rounds:
            return {}
        r = self.rounds[-1]
        return {
            "round": r["round"],
            "detection_rate": r["detection_rate"],
            "evasion_rate": r["evasion_rate"],
            "kql_valid": r["kql_valid"],
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save_round_log(self, record: dict) -> None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        path = OUTPUT_DIR / f"round_{record['round']:02d}_battle_log.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, default=str)

    def save_full_battle_log(self) -> Path:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        battle = {
            "technique_id": self.technique_id,
            "total_rounds": self.total_rounds,
            "final_attacker_score": self.attacker_score,
            "final_defender_score": self.defender_score,
            "winner": self._determine_winner(),
            "rounds": self.rounds,
            "surviving_kql_rules": self.surviving_kql,
        }
        path = OUTPUT_DIR / "full_battle_log.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(battle, f, indent=2, default=str)
        return path

    def generate_report(self) -> Path:
        """Generate the final markdown report with all surviving KQL rules."""
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        winner = self._determine_winner()
        total_logs = sum(r["attack_log_count"] for r in self.rounds)
        total_detected = sum(r["detected_count"] for r in self.rounds)
        overall_detection = total_detected / total_logs if total_logs else 0.0
        overall_evasion = 1.0 - overall_detection

        lines = [
            f"# DUEL Battle Report — {self.technique_id}",
            f"",
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Rounds played:** {len(self.rounds)} / {self.total_rounds}",
            f"**Winner:** {'🔴 Attacker' if winner == 'Attacker' else '🔵 Defender' if winner == 'Defender' else '🟡 Draw'}",
            f"",
            f"## Score Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Attacker total score | {self.attacker_score} |",
            f"| Defender total score | {self.defender_score} |",
            f"| Overall detection rate | {overall_detection:.1%} |",
            f"| Overall evasion rate | {overall_evasion:.1%} |",
            f"| Surviving KQL rules | {len(self.surviving_kql)} |",
            f"",
            f"## Round-by-Round Results",
            f"",
            f"| Round | Attack Logs | Detected | Evaded | Detection % | KQL Valid |",
            f"|-------|------------|----------|--------|-------------|-----------|",
        ]

        for r in self.rounds:
            lines.append(
                f"| {r['round']} | {r['attack_log_count']} | {r['detected_count']} "
                f"| {r['evaded_count']} | {r['detection_rate']:.0%} | {'✓' if r['kql_valid'] else '✗'} |"
            )

        lines += [
            f"",
            f"## Surviving KQL Detection Rules",
            f"",
            f"Rules that successfully detected at least one attack log.",
            f"",
        ]

        if self.surviving_kql:
            for i, rule in enumerate(self.surviving_kql, 1):
                lines += [
                    f"### Rule {i} (Round {rule['round']}, detection rate: {rule['detection_rate']:.0%})",
                    f"",
                    f"```kql",
                    rule["kql"].strip(),
                    f"```",
                    f"",
                ]
        else:
            lines.append("*No rules successfully detected any attack logs.*\n")

        lines += [
            f"## Attacker Evolution",
            f"",
        ]
        for r in self.rounds:
            lines.append(f"**Round {r['round']}** — {r['evaded_count']}/{r['attack_log_count']} logs evaded detection")
            if r["evaded_logs"]:
                sample = r["evaded_logs"][0]
                clean = {k: v for k, v in sample.items() if not k.startswith("_duel")}
                lines.append(f"  - Sample evaded log: `{json.dumps(clean, default=str)[:200]}`")
            lines.append("")

        lines += [
            f"## Defender Evolution",
            f"",
        ]
        for r in self.rounds:
            lines.append(f"**Round {r['round']}** KQL rule:")
            lines.append(f"```kql")
            lines.append(r["kql_rule"].strip())
            lines.append(f"```")
            lines.append("")

        lines.append("---")
        lines.append("*Generated by DUEL — Dual Unsupervised Evasion Loop*")

        report_path = OUTPUT_DIR / "final_report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return report_path

    def generate_analysis(self) -> Path:
        """
        Run post-battle analysis and write output/battle_analysis.md.

        Sections:
          1. Executive summary
          2. Attacker mutation across rounds (stable vs rotating fields)
          3. Why each Defender rule failed (field-level mismatch)
          4. Detection gaps (persistent signatures never targeted by KQL)
          5. Recommendations for a real Sentinel deployment
        """
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        analyst = _BattleAnalyst(self.rounds, self.technique_id)
        content = analyst.build_report()
        path = OUTPUT_DIR / "battle_analysis.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def _determine_winner(self) -> str:
        if self.attacker_score > self.defender_score:
            return "Attacker"
        elif self.defender_score > self.attacker_score:
            return "Defender"
        return "Draw"


# ---------------------------------------------------------------------------
# Post-battle analyst
# ---------------------------------------------------------------------------

class _BattleAnalyst:
    """
    Derives narrative insights from completed battle rounds without calling
    any external model — pure data analysis over the round records.
    """

    # Fields worth tracking for mutation/gap analysis.
    # Excludes unique-per-log identifiers (CorrelationId, SessionId, _duel_id)
    # and timestamp (TimeGenerated) which always differs.
    TRACK_FIELDS = [
        "table", "IPAddress", "CountryOrRegion", "City", "Location",
        "UserAgent", "ClientAppUsed", "AppDisplayName",
        "ResultType", "ResultDescription",
        "AuthenticationRequirement", "ConditionalAccessStatus",
        "RiskLevelDuringSignIn", "RiskState",
        # SecurityEvent
        "EventID", "LogonType", "Status",
        # AuditLogs
        "OperationName", "Result", "Category",
    ]

    # Pre-built KQL snippets keyed by field — used for recommendations.
    FIELD_REMEDIATION = {
        "ConditionalAccessStatus": (
            "High",
            "Logins that bypass Conditional Access",
            'SigninLogs\n| where ConditionalAccessStatus == "notApplied"\n'
            '| where ResultType == 0\n'
            '| project TimeGenerated, UserPrincipalName, IPAddress, '
            'AppDisplayName, CountryOrRegion',
        ),
        "AuthenticationRequirement": (
            "High",
            "Single-factor logins where MFA is expected",
            'SigninLogs\n| where AuthenticationRequirement == "singleFactorAuthentication"\n'
            '| where ConditionalAccessStatus != "success"\n'
            '| summarize count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)\n'
            '| where count_ >= 1',
        ),
        "ClientAppUsed": (
            "Medium",
            "Legacy / non-browser authentication clients",
            'SigninLogs\n'
            '| where ClientAppUsed in ("Other clients", "IMAP4", "POP3", "SMTP", '
            '"MAPI Over HTTP", "Authenticated SMTP")\n'
            '| where ResultType == 0\n'
            '| summarize LoginCount = count(), DistinctApps = dcount(AppDisplayName)\n'
            '  by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)',
        ),
        "CountryOrRegion": (
            "Medium",
            "Logins from atypical countries",
            'SigninLogs\n'
            '| where CountryOrRegion !in ("US", "GB", "CA", "AU", "DE", "FR")\n'
            '| where ResultType == 0\n'
            '| project TimeGenerated, UserPrincipalName, IPAddress, '
            'CountryOrRegion, UserAgent',
        ),
        "RiskLevelDuringSignIn": (
            "Medium",
            "Entra ID risk-scored logins that were allowed through",
            'SigninLogs\n'
            '| where RiskLevelDuringSignIn in ("medium", "high")\n'
            '| where ResultType == 0\n'
            '| project TimeGenerated, UserPrincipalName, IPAddress, '
            'RiskLevelDuringSignIn, RiskState',
        ),
        "ResultType": (
            "Low",
            "Spray pattern — many failures followed by a success",
            'SigninLogs\n'
            '| where ResultType in (50126, 50053, 50055)\n'
            '| summarize FailCount = count(), Users = dcount(UserPrincipalName)\n'
            '  by IPAddress, bin(TimeGenerated, 10m)\n'
            '| where FailCount > 5 and Users > 3',
        ),
        "UserAgent": (
            "Low",
            "Non-browser / scripted user agents on interactive logins",
            'SigninLogs\n'
            '| where UserAgent has_any ("python-requests", "curl", "Go-http-client", '
            '"okhttp", "libwww-perl")\n'
            '| where ResultType == 0',
        ),
    }

    def __init__(self, rounds: list[dict], technique_id: str):
        self.rounds = rounds
        self.technique_id = technique_id
        self._all_evaded: list[dict] = [
            log for r in rounds for log in r["evaded_logs"]
        ]
        self._all_detected: list[dict] = [
            log for r in rounds for log in r["detected_logs"]
        ]
        # Per-round value sets: {round_num: {field: set(values)}}
        self._evaded_values: dict[int, dict[str, set]] = {
            r["round"]: self._value_sets(r["evaded_logs"]) for r in rounds
        }
        # Fields referenced in each round's KQL rule
        self._kql_fields: dict[int, set[str]] = {
            r["round"]: self._extract_kql_fields(r["kql_rule"]) for r in rounds
        }
        self._all_kql_fields: set[str] = set().union(*self._kql_fields.values())

    # ------------------------------------------------------------------
    # Top-level report builder
    # ------------------------------------------------------------------

    def build_report(self) -> str:
        sections = [
            self._header(),
            self._executive_summary(),
            self._attacker_mutation(),
            self._defender_failure_analysis(),
            self._detection_gaps(),
            self._recommendations(),
            "\n---\n*Generated by DUEL — Dual Unsupervised Evasion Loop*",
        ]
        return "\n\n".join(s for s in sections if s)

    # ------------------------------------------------------------------
    # Section 1: Header
    # ------------------------------------------------------------------

    def _header(self) -> str:
        total_logs = sum(r["attack_log_count"] for r in self.rounds)
        total_det  = sum(r["detected_count"]   for r in self.rounds)
        overall_evasion = 1.0 - (total_det / total_logs if total_logs else 0)
        return (
            f"# DUEL Post-Battle Analysis — {self.technique_id}\n\n"
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  \n"
            f"**Rounds:** {len(self.rounds)}  \n"
            f"**Total attack logs:** {total_logs}  \n"
            f"**Overall evasion rate:** {overall_evasion:.0%}  \n"
            f"**Surviving KQL rules:** {sum(1 for r in self.rounds if r['detected_count'] > 0)}"
        )

    # ------------------------------------------------------------------
    # Section 2: Executive summary
    # ------------------------------------------------------------------

    def _executive_summary(self) -> str:
        total_logs  = sum(r["attack_log_count"] for r in self.rounds)
        total_det   = sum(r["detected_count"]   for r in self.rounds)
        total_evad  = total_logs - total_det
        overall_eva = total_evad / total_logs if total_logs else 0

        # Identify the single biggest factor: the field with the widest gap
        gaps = self._gap_fields()
        top_gap = next(iter(gaps), None)

        kql_issues = self._classify_kql_failures()
        dominant_issue = max(kql_issues, key=kql_issues.get) if kql_issues else "unknown"

        issue_text = {
            "wrong_table":     "rules targeted a table that contained no attack logs",
            "no_conditions":   "rules produced no filtering conditions",
            "mismatched_value":"rules checked fields the Attacker had already rotated",
            "untracked_field": "rules never referenced the fields that actually carried the attack signal",
        }.get(dominant_issue, "rules failed to match the Attacker's telemetry pattern")

        lines = [
            "## Executive Summary",
            "",
            f"The Attacker evaded detection on **{total_evad} of {total_logs} logs "
            f"({overall_eva:.0%})** across {len(self.rounds)} rounds. "
            f"The Defender's KQL rules {issue_text}.",
        ]

        if top_gap:
            pct = self._field_presence_pct(top_gap, self._all_evaded)
            lines.append(
                f"\nThe most critical unaddressed signal was **`{top_gap}`** — "
                f"present in {pct:.0%} of all evaded logs and never referenced by "
                f"any Defender rule. This single field, if queried, would have been "
                f"the highest-leverage detection condition."
            )

        lines += [
            "",
            "Sections below detail exactly how the Attacker mutated, why each "
            "Defender rule failed, which detection gaps were left open, and "
            "what rules a real Sentinel deployment should add.",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 3: Attacker mutation
    # ------------------------------------------------------------------

    def _attacker_mutation(self) -> str:
        if len(self.rounds) < 2:
            return ""

        stable, rotating = self._classify_fields()
        lines = ["## 1. Attacker Mutation Across Rounds", ""]

        # Stable signatures
        lines += ["### Stable Attack Signatures", ""]
        lines.append(
            "These fields held the same value across **all rounds** — persistent "
            "IOCs the Attacker did not rotate. They represent the highest-confidence "
            "detection opportunity."
        )
        lines.append("")
        if stable:
            lines.append("| Field | Value(s) | Rounds Present |")
            lines.append("|-------|----------|----------------|")
            for field, values in sorted(stable.items()):
                val_str = ", ".join(f"`{v}`" for v in sorted(values)[:4])
                if len(values) > 4:
                    val_str += f" *(+{len(values)-4} more)*"
                lines.append(f"| `{field}` | {val_str} | all {len(self.rounds)} |")
        else:
            lines.append("*No fields were fully stable — the Attacker rotated everything.*")

        # Rotating fields — show round-by-round deltas
        lines += ["", "### Mutation Vectors", ""]
        lines.append(
            "These fields changed between rounds, showing the Attacker's adaptation "
            "strategy. Fields that changed immediately after the Defender targeted "
            "them are marked **[reactive mutation]**."
        )
        lines.append("")

        for i in range(1, len(self.rounds)):
            prev_r = self.rounds[i - 1]["round"]
            curr_r = self.rounds[i]["round"]
            prev_kql_fields = self._kql_fields.get(prev_r, set())

            deltas = []
            for field in rotating:
                prev_vals = self._evaded_values.get(prev_r, {}).get(field, set())
                curr_vals = self._evaded_values.get(curr_r, {}).get(field, set())
                added   = curr_vals - prev_vals
                removed = prev_vals - curr_vals
                if added or removed:
                    reactive = " **[reactive mutation]**" if field in prev_kql_fields else ""
                    parts = []
                    if removed:
                        parts.append("dropped " + ", ".join(f"`{v}`" for v in sorted(removed)[:3]))
                    if added:
                        parts.append("added "   + ", ".join(f"`{v}`" for v in sorted(added)[:3]))
                    deltas.append(f"- **`{field}`**: {'; '.join(parts)}{reactive}")

            if deltas:
                lines.append(f"**Round {prev_r} → Round {curr_r}:**")
                lines.extend(deltas)
                lines.append("")
            else:
                lines.append(f"**Round {prev_r} → Round {curr_r}:** *(no field changes detected)*")
                lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 4: Why Defender rules failed
    # ------------------------------------------------------------------

    def _defender_failure_analysis(self) -> str:
        lines = ["## 2. Why the Defender's Rules Failed", ""]
        lines.append(
            "For each round: which fields the KQL rule targeted, and why the "
            "evaded logs slipped through."
        )
        lines.append("")

        for r in self.rounds:
            rnum   = r["round"]
            kql    = r["kql_rule"].strip()
            evaded = r["evaded_logs"]
            fields = self._kql_fields[rnum]
            reasons = self._failure_reasons(r)

            lines.append(f"### Round {rnum}")
            lines.append(f"")
            lines.append(f"**KQL rule:**")
            lines.append(f"```kql")
            lines.append(kql)
            lines.append(f"```")
            lines.append(f"")
            lines.append(f"**Fields targeted by rule:** "
                         + (", ".join(f"`{f}`" for f in sorted(fields)) if fields else "*none extracted*"))
            lines.append(f"**Evaded:** {r['evaded_count']}/{r['attack_log_count']} logs  ")
            lines.append(f"**KQL valid:** {'yes' if r['kql_valid'] else 'no — engine error'}")
            lines.append("")

            if not r["kql_valid"]:
                lines.append(
                    "> **Root cause:** The KQL rule caused an execution error in the "
                    "detection engine (likely referenced a table or field that does not "
                    "exist in the attack telemetry). The Defender scored 0 this round."
                )
            elif reasons:
                lines.append("**Why logs evaded:**")
                for reason in reasons:
                    lines.append(f"- {reason}")
            else:
                lines.append("*No specific mismatch identified — all evaded logs passed every condition.*")

            lines.append("")

        return "\n".join(lines)

    def _failure_reasons(self, record: dict) -> list[str]:
        """Diagnose why evaded logs slipped through this round's KQL rule."""
        reasons = []
        kql    = record["kql_rule"]
        evaded = record["evaded_logs"]
        if not evaded:
            return reasons

        fields = self._kql_fields[record["round"]]

        # Check 1: rule has almost no where conditions
        where_count = len(re.findall(r"\|\s*where\b", kql, re.IGNORECASE))
        if where_count == 0:
            reasons.append(
                "The rule contained no `where` filtering operators — it returned "
                "every row in the table, making it useless for detection."
            )
            return reasons

        # Check 2: fields targeted but evaded logs have unexpected values
        conditions = self._extract_simple_conditions(kql)
        for field, op, expected in conditions:
            if field not in evaded[0]:
                reasons.append(
                    f"Rule checked `{field}` but that field does not exist in the "
                    f"attack telemetry — condition always evaluated to false."
                )
                continue
            actual_vals = {str(log.get(field, "")) for log in evaded}
            if op in ("==", "has", "contains") and not any(
                expected.lower() in str(v).lower() for v in actual_vals
            ):
                sample = ", ".join(f"`{v}`" for v in list(actual_vals)[:3])
                reasons.append(
                    f"Rule required `{field} {op} \"{expected}\"` but evaded logs "
                    f"had {sample} — the Attacker had already mutated this field."
                )
            elif op == "!=" and all(str(v) == expected for v in actual_vals):
                reasons.append(
                    f"Rule excluded `{field} == \"{expected}\"` but all evaded logs "
                    f"matched exactly that value, so the condition eliminated them."
                )

        # Check 3: high-signal fields in evaded logs that the rule never mentioned
        high_signal = {"ConditionalAccessStatus", "AuthenticationRequirement",
                       "ClientAppUsed", "RiskLevelDuringSignIn"}
        untouched = high_signal - fields
        if untouched and len(conditions) > 0:
            reasons.append(
                "Rule ignored high-signal fields: "
                + ", ".join(f"`{f}`" for f in sorted(untouched))
                + " — these carried consistent attack patterns but were never queried."
            )

        # Check 4: summarize threshold too high / too low
        threshold_match = re.search(r"count_\s*[><=!]+\s*(\d+)", kql, re.IGNORECASE)
        if threshold_match:
            threshold = int(threshold_match.group(1))
            actual_count = len(evaded)
            if actual_count < threshold:
                reasons.append(
                    f"Rule required at least {threshold} events per group but the "
                    f"Attacker generated only {actual_count} logs — threshold was too "
                    f"high for the attack volume."
                )

        return reasons

    # ------------------------------------------------------------------
    # Section 5: Detection gaps
    # ------------------------------------------------------------------

    def _detection_gaps(self) -> str:
        gaps = self._gap_fields()
        lines = ["## 3. Detection Gaps Exposed", ""]

        if not gaps:
            lines.append(
                "No persistent unaddressed signals found — the Defender's rules "
                "touched every field that appeared consistently across evaded logs. "
                "The evasion was due to threshold or value mismatches, not blind spots."
            )
            return "\n".join(lines)

        lines.append(
            "The following fields appeared in a high percentage of evaded logs "
            "across **all** rounds but were **never referenced** by any Defender "
            "rule. Each is a missed detection opportunity."
        )
        lines.append("")
        lines.append("| Field | Stable Value(s) | % of Evaded Logs | Rounds Never Targeted |")
        lines.append("|-------|-----------------|-----------------|----------------------|")

        for field, (values, pct) in gaps.items():
            val_str = ", ".join(f"`{v}`" for v in sorted(values)[:3])
            if len(values) > 3:
                val_str += f" *(+{len(values)-3} more)*"
            lines.append(
                f"| `{field}` | {val_str} | {pct:.0%} | all {len(self.rounds)} |"
            )

        # Also surface fields the Defender targeted but where value mismatches caused gaps
        mismatch_fields = self._mismatch_fields()
        if mismatch_fields:
            lines += [
                "",
                "### Partial Gaps (field targeted, wrong value)",
                "",
                "These fields were queried by the Defender but with incorrect values — "
                "the Attacker had already rotated them by the time the rule ran:",
                "",
            ]
            for field, rounds_affected in mismatch_fields.items():
                lines.append(f"- **`{field}`** — value mismatch in rounds {rounds_affected}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 6: Recommendations
    # ------------------------------------------------------------------

    def _recommendations(self) -> str:
        gaps = self._gap_fields()
        lines = ["## 4. Recommendations for Real Sentinel Deployment", ""]
        lines.append(
            "Derived from fields that carried a stable, high-confidence attack "
            "signal across every round but were never addressed by any detection "
            "rule. Ordered by confidence: High → Medium → Low."
        )

        added: set[str] = set()
        buckets: dict[str, list[tuple]] = {"High": [], "Medium": [], "Low": []}

        # Priority 1: gap fields that have known remediations
        for field in gaps:
            if field in self.FIELD_REMEDIATION and field not in added:
                conf, title, kql = self.FIELD_REMEDIATION[field]
                buckets[conf].append((field, title, kql, "gap"))
                added.add(field)

        # Priority 2: always recommend the two most structural controls if not covered
        structural = ["ConditionalAccessStatus", "AuthenticationRequirement"]
        for field in structural:
            if field not in added and field in self.FIELD_REMEDIATION:
                conf, title, kql = self.FIELD_REMEDIATION[field]
                buckets[conf].append((field, title, kql, "structural"))
                added.add(field)

        # Priority 3: fill with other remediations for fields seen in evaded logs
        evaded_fields = set(self._all_evaded[0].keys()) if self._all_evaded else set()
        for field, (conf, title, kql) in self.FIELD_REMEDIATION.items():
            if field not in added and field in evaded_fields:
                buckets[conf].append((field, title, kql, "supplemental"))
                added.add(field)

        if not any(buckets.values()):
            lines.append("*No specific recommendations could be derived from the battle data.*")
            return "\n".join(lines)

        rule_num = 0
        for confidence in ("High", "Medium", "Low"):
            for field, title, kql, origin in buckets[confidence]:
                rule_num += 1
                tag = {
                    "gap":          "directly addresses a detected gap",
                    "structural":   "structural control — should be baseline in any deployment",
                    "supplemental": "supplemental — covers additional evasion surface",
                }[origin]
                evaded_pct = self._field_presence_pct(field, self._all_evaded)
                lines += [
                    f"",
                    f"### Rule {rule_num} [{confidence} Confidence]: {title}",
                    f"",
                    f"**Rationale:** `{field}` appeared in {evaded_pct:.0%} of evaded logs; "
                    f"this rule {tag}.",
                    f"",
                    f"```kql",
                    kql.strip(),
                    f"```",
                ]

        lines += [
            "",
            "### Operational Notes",
            "",
            "- **Tune thresholds** against your environment's baseline login volume "
            "before enabling alert rules — start with `count_ >= 1` and raise from there.",
            "- **Enrich with threat intel**: pipe `IPAddress` through "
            "`ThreatIntelligenceIndicator` to score known Tor / hosting-provider ranges.",
            "- **Combine rules**: the highest-signal rule chains "
            "`ConditionalAccessStatus == \"notApplied\"` with "
            "`AuthenticationRequirement == \"singleFactorAuthentication\"` — "
            "both appeared as stable signals throughout this battle.",
            "- **Enable Entra ID Identity Protection**: the `RiskLevelDuringSignIn` "
            "field was populated in attack logs; activating risk-based CA policies "
            "would have blocked many of these logins at the authentication layer.",
        ]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def _value_sets(self, logs: list[dict]) -> dict[str, set]:
        """Return {field: set(values)} for tracked fields across a list of logs."""
        result: dict[str, set] = defaultdict(set)
        for log in logs:
            for field in self.TRACK_FIELDS:
                v = log.get(field)
                if v is not None and str(v).strip() not in ("", "none", "None", "{}"):
                    result[field].add(str(v))
        return dict(result)

    def _classify_fields(self) -> tuple[dict, list]:
        """
        Split TRACK_FIELDS into:
          stable  — identical value set in every round's evaded logs
          rotating — value set changed in at least one round
        """
        if not self._evaded_values:
            return {}, []

        rounds = list(self._evaded_values.values())
        stable, rotating = {}, []

        for field in self.TRACK_FIELDS:
            sets = [r.get(field, set()) for r in rounds]
            sets = [s for s in sets if s]  # ignore rounds where field absent
            if not sets:
                continue
            common = sets[0].intersection(*sets[1:])
            if common and all(s == sets[0] for s in sets):
                stable[field] = common
            else:
                rotating.append(field)

        return stable, rotating

    def _gap_fields(self) -> dict[str, tuple[set, float]]:
        """
        Return fields that:
          1. Appeared in evaded logs across every round (fully persistent signal)
          2. Were never referenced in any KQL rule
          3. Appear in ≥50% of all evaded logs
        Ordered by evaded-log presence percentage descending.
        """
        if not self._evaded_values or not self._all_evaded:
            return {}

        stable, _ = self._classify_fields()
        gaps = {}
        for field, values in stable.items():
            if field in self._all_kql_fields:
                continue
            pct = self._field_presence_pct(field, self._all_evaded)
            if pct >= 0.5:
                gaps[field] = (values, pct)

        return dict(sorted(gaps.items(), key=lambda kv: kv[1][1], reverse=True))

    def _mismatch_fields(self) -> dict[str, list[int]]:
        """
        Fields that the Defender targeted but with wrong values (so evaded logs
        had different values than what the KQL expected).
        Returns {field: [round_nums_affected]}.
        """
        mismatches: dict[str, list[int]] = defaultdict(list)
        for r in self.rounds:
            conditions = self._extract_simple_conditions(r["kql_rule"])
            evaded = r["evaded_logs"]
            if not evaded:
                continue
            for field, op, expected in conditions:
                if op not in ("==", "has", "contains"):
                    continue
                if field not in evaded[0]:
                    continue
                actual_vals = {str(log.get(field, "")) for log in evaded}
                if not any(expected.lower() in v.lower() for v in actual_vals):
                    mismatches[field].append(r["round"])
        return dict(mismatches)

    def _classify_kql_failures(self) -> Counter:
        """
        Bucket each round's failure into one dominant failure category.
        Returns a Counter of failure types across all rounds.
        """
        counts: Counter = Counter()
        for r in self.rounds:
            if r["evaded_count"] == 0:
                continue
            if not r["kql_valid"]:
                counts["wrong_table"] += 1
                continue
            kql = r["kql_rule"]
            fields = self._kql_fields[r["round"]]
            where_count = len(re.findall(r"\|\s*where\b", kql, re.IGNORECASE))
            if where_count == 0:
                counts["no_conditions"] += 1
            elif not fields.intersection(self.TRACK_FIELDS):
                counts["untracked_field"] += 1
            else:
                counts["mismatched_value"] += 1
        return counts

    @staticmethod
    def _field_presence_pct(field: str, logs: list[dict]) -> float:
        """Fraction of logs where `field` has a non-empty value."""
        if not logs:
            return 0.0
        present = sum(
            1 for log in logs
            if str(log.get(field, "")).strip() not in ("", "none", "None", "{}")
        )
        return present / len(logs)

    @staticmethod
    def _extract_kql_fields(kql: str) -> set[str]:
        """
        Extract field names referenced in a KQL rule.
        Covers: where conditions, summarize by, project, dcount().
        """
        fields: set[str] = set()
        patterns = [
            # field operator value
            r'\b([A-Za-z_]\w*)\s*(?:==|!=|>=|<=|>|<|contains|has|startswith|endswith|in~?|matches)',
            # function(field)
            r'(?:isempty|isnotempty|isnull|isnotnull|dcount|count_if)\(([A-Za-z_]\w*)\)',
            # summarize ... by field
            r'\bby\s+([A-Za-z_]\w*)',
            # project field, field
            r'\bproject(?:-away)?\s+((?:[A-Za-z_]\w*\s*,\s*)*[A-Za-z_]\w*)',
        ]
        for pat in patterns:
            for m in re.finditer(pat, kql, re.IGNORECASE):
                # Group 1 might contain comma-separated list (from project)
                for name in re.split(r"\s*,\s*", m.group(1)):
                    name = name.strip()
                    if name and not name.lower() in {"by", "and", "or", "not", "bin",
                                                      "count", "true", "false", "asc", "desc"}:
                        fields.add(name)
        return fields

    @staticmethod
    def _extract_simple_conditions(kql: str) -> list[tuple[str, str, str]]:
        """
        Extract (field, operator, value) triples from KQL where clauses.
        Covers simple binary comparisons and string operators.
        """
        conditions = []
        pattern = re.compile(
            r'\b([A-Za-z_]\w*)\s*'
            r'(==|!=|contains|has|startswith|endswith|>=|<=|>|<)\s*'
            r'["\']?([^"\'|\s\)]+)["\']?',
            re.IGNORECASE,
        )
        for m in pattern.finditer(kql):
            field, op, value = m.group(1), m.group(2), m.group(3)
            if field.lower() not in {"where", "and", "or", "not", "by", "let"}:
                conditions.append((field, op.lower(), value))
        return conditions
