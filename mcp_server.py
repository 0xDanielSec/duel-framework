"""
DUEL — MCP Server
Exposes DUEL's adversarial security research capabilities as MCP tools
so any AI agent supporting the Model Context Protocol can use them.

Run:   python mcp_server.py
Transport: stdio (standard for MCP)
"""

import json
import logging
import sys
from pathlib import Path

# Configure logging BEFORE any other imports so that dependent modules'
# basicConfig calls are silently ignored (force=True overrides any existing setup).
_LOG_DIR = Path(__file__).parent / "output"
_LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler(str(_LOG_DIR / "mcp_server.log"), encoding="utf-8")],
    force=True,
)
_log = logging.getLogger("duel.mcp")

sys.path.insert(0, str(Path(__file__).parent))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from agents.attacker import AttackerAgent  # noqa: E402
from agents.defender import DefenderAgent  # noqa: E402
from campaign import CAMPAIGNS  # noqa: E402
from engine.detection import DetectionEngine  # noqa: E402
from engine.scoring import BattleScorer  # noqa: E402
from engine.sentinel_export import SentinelExporter  # noqa: E402

TECHNIQUES_DIR = Path(__file__).parent / "techniques"
OUTPUT_DIR     = Path(__file__).parent / "output"

mcp = FastMCP(
    "DUEL Security Research Framework",
    instructions=(
        "DUEL is an adversarial LLM security research framework for Microsoft Sentinel. "
        "Two LLM agents battle across rounds: the Attacker generates synthetic telemetry "
        "mimicking real Sentinel schemas, the Defender generates KQL detection rules. "
        "Use these tools to run battles, analyse coverage, generate detection rules, "
        "plan kill chains, and export production-ready Sentinel analytics rules. "
        "Requires Ollama running locally with llama3.1:8b and mistral:7b models pulled."
    ),
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_technique(technique_id: str) -> dict:
    tid = technique_id.upper()
    if tid.startswith("LLM"):
        path = TECHNIQUES_DIR / "llm" / f"{tid}.json"
    else:
        path = TECHNIQUES_DIR / f"{technique_id}.json"
    if not path.exists():
        raise ValueError(f"Technique not found: {technique_id}")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _available_techniques() -> list[str]:
    mitre = sorted(p.stem for p in TECHNIQUES_DIR.glob("*.json"))
    llm_dir = TECHNIQUES_DIR / "llm"
    llm = sorted(p.stem for p in llm_dir.glob("*.json")) if llm_dir.exists() else []
    return mitre + llm


# ---------------------------------------------------------------------------
# Tool 1: run_battle
# ---------------------------------------------------------------------------

@mcp.tool()
def run_battle(
    technique_id: str,
    rounds: int = 5,
    logs_per_round: int = 10,
) -> dict:
    """
    Run a full adversarial DUEL battle between Attacker and Defender agents.

    The Attacker (llama3.1:8b) generates synthetic Microsoft Sentinel telemetry
    mimicking the specified MITRE ATT&CK or OWASP LLM technique. The Defender
    (mistral:7b) generates KQL detection rules. Each round the Attacker mutates
    based on what was detected; the Defender hardens the rule against evasions.
    Results are saved to output/ and a structured summary is returned.

    Args:
        technique_id: MITRE ATT&CK ID (e.g. 'T1078.004') or OWASP LLM ID (e.g. 'LLM01').
        rounds: Number of adversarial rounds to run (default 5, max 10).
        logs_per_round: Synthetic attack logs generated per round (default 10).
    """
    rounds = min(max(int(rounds), 1), 10)
    logs_per_round = min(max(int(logs_per_round), 3), 30)
    OUTPUT_DIR.mkdir(exist_ok=True)

    technique = _load_technique(technique_id)
    attacker  = AttackerAgent(model="llama3.1:8b", num_logs=logs_per_round)
    defender  = DefenderAgent(model="mistral:7b")
    scorer    = BattleScorer(total_rounds=rounds, technique_id=technique_id)
    errors: list[str] = []

    for round_num in range(1, rounds + 1):
        _log.info("Battle %s round %d/%d", technique_id, round_num, rounds)

        try:
            attack_logs = attacker.generate_logs(
                technique=technique,
                round_num=round_num,
                total_rounds=rounds,
                last_kql=scorer.rounds[-1]["kql_rule"] if scorer.rounds else None,
                detected_logs=scorer.get_last_detected_logs(),
                evaded_logs=scorer.get_last_evaded_logs(),
            )
        except Exception as exc:
            _log.error("Attacker error round %d: %s", round_num, exc)
            errors.append(f"Round {round_num} attacker: {exc}")
            continue

        try:
            kql_rule = defender.generate_rule(
                technique=technique,
                round_num=round_num,
                total_rounds=rounds,
                attack_logs=attack_logs,
                detected_logs=scorer.get_last_detected_logs(),
                evaded_logs=scorer.get_last_evaded_logs(),
            )
        except Exception as exc:
            _log.error("Defender error round %d: %s", round_num, exc)
            errors.append(f"Round {round_num} defender: {exc}")
            kql_rule = "SigninLogs | where ResultType != 0"

        det_result = DetectionEngine(attack_logs).run(kql_rule)
        scorer.record_round(
            round_num=round_num,
            attack_logs=attack_logs,
            kql_rule=kql_rule,
            detected_ids=det_result["detected_ids"],
            kql_valid=det_result["kql_valid"],
        )

    log_path      = scorer.save_full_battle_log()
    report_path   = scorer.generate_report()
    analysis_path = scorer.generate_analysis()

    total_logs     = sum(r["attack_log_count"] for r in scorer.rounds) or 1
    total_detected = sum(r["detected_count"]   for r in scorer.rounds)
    winner = (
        "Attacker" if scorer.attacker_score > scorer.defender_score
        else "Defender" if scorer.defender_score > scorer.attacker_score
        else "Draw"
    )

    _log.info("Battle complete: %s winner=%s att=%d def=%d",
              technique_id, winner, scorer.attacker_score, scorer.defender_score)

    return {
        "technique_id":           technique_id,
        "technique_name":         technique.get("name", technique_id),
        "rounds_completed":       len(scorer.rounds),
        "winner":                 winner,
        "attacker_score":         scorer.attacker_score,
        "defender_score":         scorer.defender_score,
        "overall_detection_rate": round(total_detected / total_logs, 4),
        "overall_evasion_rate":   round(1 - total_detected / total_logs, 4),
        "surviving_kql_count":    len(scorer.surviving_kql),
        "battle_log_path":        str(log_path),
        "report_path":            str(report_path),
        "analysis_path":          str(analysis_path),
        "errors":                 errors,
        "round_summaries": [
            {
                "round":          r["round"],
                "detected":       r["detected_count"],
                "evaded":         r["evaded_count"],
                "detection_rate": r["detection_rate"],
                "evasion_rate":   r["evasion_rate"],
                "kql_valid":      r["kql_valid"],
            }
            for r in scorer.rounds
        ],
    }


# ---------------------------------------------------------------------------
# Tool 2: get_coverage
# ---------------------------------------------------------------------------

@mcp.tool()
def get_coverage() -> dict:
    """
    Return MITRE ATT&CK and OWASP LLM Top 10 coverage heatmap data.

    Scans all completed battle logs and returns per-technique statistics:
    evasion rates, detection rates, and tactic-level aggregations. Use this
    to understand which techniques have been tested and where detection gaps exist.
    """
    techniques_meta: dict[str, dict] = {}
    for tid in _available_techniques():
        try:
            tech = _load_technique(tid)
            techniques_meta[tid] = {
                "name":   tech.get("name", tid),
                "tactic": tech.get("tactic", "Unknown"),
            }
        except Exception:
            pass

    battle_stats: dict[str, dict] = {}
    for log_path in sorted(OUTPUT_DIR.glob("full_battle_log_*.json")):
        try:
            with open(log_path, encoding="utf-8") as f:
                battle = json.load(f)
        except Exception:
            continue

        tid = battle.get("technique_id", "")
        if not tid or not isinstance(battle.get("rounds"), list):
            continue

        rounds     = battle["rounds"]
        total_logs = sum(r.get("attack_log_count", 0) for r in rounds) or 1
        total_det  = sum(r.get("detected_count", 0)   for r in rounds)
        best_round = max(rounds, key=lambda r: r.get("detection_rate", 0), default={})

        battle_stats[tid] = {
            "total_rounds":           len(rounds),
            "overall_detection_rate": round(total_det / total_logs, 4),
            "overall_evasion_rate":   round(1 - total_det / total_logs, 4),
            "best_detection_rate":    round(best_round.get("detection_rate", 0), 4),
            "best_kql_preview": (
                (best_round.get("kql_rule", "")[:120] + "...")
                if len(best_round.get("kql_rule", "")) > 120
                else best_round.get("kql_rule", "")
            ),
        }

    coverage_by_tactic: dict[str, dict] = {}
    for tid, meta in techniques_meta.items():
        tactic = meta["tactic"].split(",")[0].strip()
        if tactic not in coverage_by_tactic:
            coverage_by_tactic[tactic] = {"total": 0, "tested": 0, "_evasions": []}
        coverage_by_tactic[tactic]["total"] += 1
        if tid in battle_stats:
            coverage_by_tactic[tactic]["tested"] += 1
            coverage_by_tactic[tactic]["_evasions"].append(
                battle_stats[tid]["overall_evasion_rate"]
            )

    for data in coverage_by_tactic.values():
        evs = data.pop("_evasions")
        data["avg_evasion_rate"] = round(sum(evs) / len(evs), 4) if evs else None

    heatmap = [
        {
            "technique_id":   tid,
            "technique_name": meta["name"],
            "tactic":         meta["tactic"],
            "tested":         tid in battle_stats,
            "evasion_rate":   battle_stats[tid]["overall_evasion_rate"] if tid in battle_stats else None,
            "detection_rate": battle_stats[tid]["overall_detection_rate"] if tid in battle_stats else None,
        }
        for tid, meta in techniques_meta.items()
    ]

    all_evasions = [s["overall_evasion_rate"] for s in battle_stats.values()]

    return {
        "total_techniques":     len(techniques_meta),
        "techniques_tested":    len(battle_stats),
        "techniques_untested":  len(techniques_meta) - len(battle_stats),
        "average_evasion_rate": round(sum(all_evasions) / len(all_evasions), 4) if all_evasions else None,
        "coverage_by_tactic":   coverage_by_tactic,
        "heatmap":              heatmap,
    }


# ---------------------------------------------------------------------------
# Tool 3: generate_kql
# ---------------------------------------------------------------------------

@mcp.tool()
def generate_kql(technique_id: str) -> dict:
    """
    Return the best surviving KQL detection rule for a MITRE ATT&CK technique.

    Scans completed battle logs for the technique and returns the KQL rule with
    the highest detection rate. The rule has been adversarially tested against
    a live LLM attacker across multiple rounds.

    Args:
        technique_id: MITRE ATT&CK ID (e.g. 'T1078.004') or OWASP LLM ID (e.g. 'LLM01').
    """
    technique = _load_technique(technique_id)

    best: dict = {}
    log_path = OUTPUT_DIR / f"full_battle_log_{technique_id}.json"
    if log_path.exists():
        try:
            with open(log_path, encoding="utf-8") as f:
                battle = json.load(f)
            for r in battle.get("rounds", []):
                kql  = r.get("kql_rule", "").strip()
                rate = r.get("detection_rate", 0.0)
                if kql and rate > best.get("detection_rate", -1):
                    best = {
                        "technique_id":   technique_id,
                        "technique_name": technique.get("name", technique_id),
                        "tactic":         technique.get("tactic", ""),
                        "kql_rule":       kql,
                        "detection_rate": round(rate, 4),
                        "evasion_rate":   round(r.get("evasion_rate", 0.0), 4),
                        "round":          r.get("round", 0),
                        "kql_valid":      r.get("kql_valid", True),
                    }
        except Exception as exc:
            _log.error("generate_kql: failed to read log: %s", exc)

    if not best:
        return {
            "technique_id":   technique_id,
            "technique_name": technique.get("name", technique_id),
            "kql_rule":       None,
            "message": (
                f"No battle log found for {technique_id}. "
                f"Run run_battle('{technique_id}') first to generate KQL rules."
            ),
            "kql_hints": technique.get("detection_kql_hints", []),
        }

    return best


# ---------------------------------------------------------------------------
# Tool 4: plan_campaign
# ---------------------------------------------------------------------------

@mcp.tool()
def plan_campaign(objective: str) -> dict:
    """
    Plan an autonomous kill chain campaign for the given security objective.

    Pass a named campaign ('cloud-takeover', 'identity-attack') or free-text
    such as 'exfiltrate email', 'escalate privileges in Azure AD', or
    'bypass MFA'. Returns a structured kill-chain plan with ordered stages,
    technique mappings, attacker IOCs, evasion hints, and the MCP call sequence
    needed to run the full campaign.

    Args:
        objective: Named campaign key or free-text attack objective.
    """
    obj_lower = objective.lower().strip()

    for key, campaign in CAMPAIGNS.items():
        if key in obj_lower or campaign["name"].lower() in obj_lower:
            stages = []
            for i, (tid, narrative) in enumerate(
                zip(campaign["techniques"], campaign["narrative"])
            ):
                try:
                    tech = _load_technique(tid)
                    stages.append({
                        "stage":          i + 1,
                        "technique_id":   tid,
                        "technique_name": tech.get("name", tid),
                        "tactic":         tech.get("tactic", ""),
                        "narrative":      narrative,
                        "iocs":           tech.get("iocs", []),
                        "evasion_hints":  tech.get("evasion_variants", []),
                    })
                except Exception:
                    stages.append({"stage": i + 1, "technique_id": tid, "narrative": narrative})

            return {
                "campaign_key":  key,
                "campaign_name": campaign["name"],
                "description":   campaign["description"],
                "total_stages":  len(stages),
                "kill_chain":    stages,
                "run_command":   f"python campaign.py --campaign {key} --rounds 5",
                "mcp_sequence":  [f"run_battle('{s['technique_id']}', rounds=5)" for s in stages],
            }

    # Fuzzy keyword match across all techniques
    keywords = set(obj_lower.split())
    scored: list[tuple[int, str, dict]] = []
    for tid in _available_techniques():
        try:
            tech = _load_technique(tid)
        except Exception:
            continue
        blob = " ".join([
            tech.get("name", ""),
            tech.get("tactic", ""),
            tech.get("description", ""),
        ]).lower().split()
        score = sum(1 for kw in keywords if any(kw in w for w in blob))
        if score > 0:
            scored.append((score, tid, tech))

    scored.sort(key=lambda x: -x[0])
    matched = scored[:6]

    if not matched:
        return {
            "campaign_name":     f"Custom: {objective}",
            "message": (
                "No techniques matched the objective. "
                "Available named campaigns: 'cloud-takeover', 'identity-attack'. "
                "Or call list_techniques() to browse all 38 techniques."
            ),
            "available_campaigns": list(CAMPAIGNS.keys()),
        }

    stages = [
        {
            "stage":           i + 1,
            "technique_id":    tid,
            "technique_name":  tech.get("name", tid),
            "tactic":          tech.get("tactic", ""),
            "relevance_score": score,
            "iocs":            tech.get("iocs", [])[:3],
            "evasion_hints":   tech.get("evasion_variants", [])[:3],
        }
        for i, (score, tid, tech) in enumerate(matched)
    ]

    return {
        "campaign_name": f"Custom: {objective}",
        "description": (
            f"Auto-generated kill chain for: {objective}. "
            "Techniques ranked by keyword relevance against the DUEL library."
        ),
        "total_stages":  len(stages),
        "kill_chain":    stages,
        "mcp_sequence":  [f"run_battle('{s['technique_id']}', rounds=5)" for s in stages],
    }


# ---------------------------------------------------------------------------
# Tool 5: get_attacker_memory
# ---------------------------------------------------------------------------

@mcp.tool()
def get_attacker_memory(technique_id: str) -> dict:
    """
    Return what the Attacker LLM has learned about evading detection for a technique.

    The attacker memory accumulates across all battles: stable evasion patterns,
    dangerous field values that reliably get detected, successful mutation strategies,
    and high-level evasion heuristics derived from evaded logs. Use this to
    understand persistent detection blind spots and attacker adaptation.

    Args:
        technique_id: MITRE ATT&CK ID (e.g. 'T1078.004') or OWASP LLM ID (e.g. 'LLM01').
    """
    memory_path = OUTPUT_DIR / "attacker_memory.json"
    if not memory_path.exists():
        return {
            "technique_id": technique_id,
            "message": "No attacker memory file found. Run at least one battle first.",
        }

    with open(memory_path, encoding="utf-8") as f:
        memory = json.load(f)

    if technique_id not in memory:
        return {
            "technique_id": technique_id,
            "message": (
                f"No memory for {technique_id} yet. "
                f"Run run_battle('{technique_id}') to build attacker memory."
            ),
            "available_techniques": list(memory.keys()),
        }

    data = memory[technique_id]

    dangerous_summary: dict[str, list] = {}
    for field, counts in data.get("dangerous_fields", {}).items():
        top = sorted(counts.items(), key=lambda x: -x[1])[:3]
        dangerous_summary[field] = [{"value": v, "detection_count": c} for v, c in top]

    return {
        "technique_id":       technique_id,
        "total_battles":      data.get("total_battles", 0),
        "total_rounds":       data.get("total_rounds", 0),
        "successful_evasions_count": len(data.get("successful_evasions", [])),
        "failed_mutations_count":    len(data.get("failed_mutations", [])),
        "evasion_patterns":          data.get("evasion_patterns", [])[-5:],
        "stable_signatures":         data.get("stable_signatures", {}),
        "dangerous_fields":          dangerous_summary,
        "top_evasion_examples":      data.get("successful_evasions", [])[-3:],
    }


# ---------------------------------------------------------------------------
# Tool 6: export_sentinel
# ---------------------------------------------------------------------------

@mcp.tool()
def export_sentinel(severity: str = "all") -> dict:
    """
    Return a Microsoft Sentinel ARM template with KQL analytics rules.

    Severity filter: 'High', 'Medium', 'Low', or 'all' (default).
    Severity is derived from evasion rate: High = evasion > 80% (hardest to
    evade), Medium = 50–80%, Low = under 50%. The returned ARM template can be
    deployed directly to any Sentinel workspace via the Azure CLI or portal.

    Args:
        severity: Severity level to filter by — 'High', 'Medium', 'Low', or 'all'.
    """
    exporter  = SentinelExporter()
    all_rules = exporter.load_rules()

    if severity.lower() != "all":
        sev_cap = severity.capitalize()
        rules = [r for r in all_rules if r["severity"] == sev_cap]
    else:
        rules = all_rules

    if not rules:
        return {
            "severity_filter": severity,
            "rule_count":      0,
            "arm_template":    None,
            "message": (
                f"No rules found with severity '{severity}'. "
                "Run battles first to generate KQL rules. "
                f"Available severities: {sorted({r['severity'] for r in all_rules})}."
            ),
        }

    arm_template = exporter.to_arm_template(rules)

    return {
        "severity_filter": severity,
        "rule_count":      len(rules),
        "rule_summaries": [
            {
                "id":             r["id"],
                "technique_id":   r["technique_id"],
                "technique_name": r["technique_name"],
                "severity":       r["severity"],
                "detection_rate": r["detection_rate"],
                "evasion_rate":   r["evasion_rate"],
            }
            for r in rules
        ],
        "arm_template": arm_template,
        "deploy_command": (
            "az deployment group create "
            "--resource-group <rg> "
            "--template-file sentinel_rules.json "
            "--parameters workspaceName=<workspace>"
        ),
    }


# ---------------------------------------------------------------------------
# Tool 7: get_battle_analysis
# ---------------------------------------------------------------------------

@mcp.tool()
def get_battle_analysis(technique_id: str) -> dict:
    """
    Return the full battle analysis for a technique.

    Includes mutation patterns, detection gaps, field-level stability analysis,
    KQL evolution across rounds, and hardening recommendations generated by the
    BattleAnalyst engine after the battle.

    Args:
        technique_id: MITRE ATT&CK ID (e.g. 'T1078.004') or OWASP LLM ID (e.g. 'LLM01').
    """
    log_path = OUTPUT_DIR / f"full_battle_log_{technique_id}.json"
    if not log_path.exists():
        return {
            "technique_id": technique_id,
            "message": (
                f"No battle log for {technique_id}. "
                f"Run run_battle('{technique_id}') first."
            ),
        }

    with open(log_path, encoding="utf-8") as f:
        battle = json.load(f)

    rounds     = battle.get("rounds", [])
    total_logs = sum(r.get("attack_log_count", 0) for r in rounds) or 1
    total_det  = sum(r.get("detected_count",   0) for r in rounds)

    winner = (
        battle.get("winner")
        or ("Attacker" if battle.get("attacker_score", 0) > battle.get("defender_score", 0)
            else "Defender")
    )

    analysis_md = ""
    analysis_path = OUTPUT_DIR / "battle_analysis.md"
    if analysis_path.exists():
        analysis_md = analysis_path.read_text(encoding="utf-8")

    return {
        "technique_id":           technique_id,
        "technique_name":         battle.get("technique_name", technique_id),
        "total_rounds":           len(rounds),
        "winner":                 winner,
        "attacker_score":         battle.get("attacker_score", 0),
        "defender_score":         battle.get("defender_score", 0),
        "overall_detection_rate": round(total_det / total_logs, 4),
        "overall_evasion_rate":   round(1 - total_det / total_logs, 4),
        "surviving_kql":          battle.get("surviving_kql", []),
        "kql_evolution": [
            {
                "round":          r["round"],
                "kql_rule":       r.get("kql_rule", ""),
                "detection_rate": r.get("detection_rate", 0),
                "evasion_rate":   r.get("evasion_rate", 0),
                "kql_valid":      r.get("kql_valid", True),
            }
            for r in rounds
        ],
        "analysis_markdown": analysis_md[:4000] if analysis_md else None,
    }


# ---------------------------------------------------------------------------
# Tool 8: list_techniques
# ---------------------------------------------------------------------------

@mcp.tool()
def list_techniques() -> dict:
    """
    Return all available techniques with metadata.

    Includes all MITRE ATT&CK techniques (cloud/identity/SaaS focused) and
    OWASP LLM Top 10 2025 techniques. Each entry includes the technique ID,
    name, tactic, Sentinel tables, and whether it has been battle-tested.
    """
    tested = {
        log_path.stem.replace("full_battle_log_", "")
        for log_path in OUTPUT_DIR.glob("full_battle_log_*.json")
    }

    mitre: list[dict] = []
    llm:   list[dict] = []

    for tid in _available_techniques():
        try:
            tech = _load_technique(tid)
        except Exception:
            continue

        entry = {
            "technique_id":    tid,
            "technique_name":  tech.get("name", tid),
            "tactic":          tech.get("tactic", ""),
            "platforms":       tech.get("platforms", []),
            "data_sources":    tech.get("data_sources", []),
            "sentinel_tables": tech.get("sentinel_tables", []),
            "battle_tested":   tid in tested,
        }

        if tid.upper().startswith("LLM"):
            llm.append(entry)
        else:
            mitre.append(entry)

    return {
        "total_techniques":      len(mitre) + len(llm),
        "mitre_count":           len(mitre),
        "owasp_llm_count":       len(llm),
        "tested_count":          len(tested),
        "mitre_techniques":      mitre,
        "owasp_llm_techniques":  llm,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _log.info("DUEL MCP Server starting — stdio transport")
    mcp.run()
