"""
DUEL Web UI — FastAPI server with WebSocket battle streaming.
Run: python server.py  →  http://localhost:8000
"""

import asyncio
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).parent))

from agents.attacker import AttackerAgent
from agents.defender import DefenderAgent
from engine.detection import DetectionEngine
from engine.scoring import BattleScorer
from engine.tournament_scorer import TournamentScorer
from campaign import CAMPAIGNS, build_campaign_context
from engine.sentinel_export import SentinelExporter

TECHNIQUES_DIR = Path(__file__).parent / "techniques"
STATIC_DIR    = Path(__file__).parent / "static"
OUTPUT_DIR    = Path(__file__).parent / "output"

app = FastAPI(title="DUEL")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_executor = ThreadPoolExecutor(max_workers=4)

_DETECTABLE_FIELDS = re.compile(
    r"\b(UserPrincipalName|IPAddress|AppDisplayName|ResultType|EventID|Account|"
    r"Computer|OperationName|Location|CountryOrRegion|RiskLevelDuringSignIn|"
    r"LogonType|RiskState|AuthenticationRequirement)\b"
)


def _load_technique(technique_id: str) -> dict:
    if technique_id.upper().startswith("LLM"):
        path = TECHNIQUES_DIR / "llm" / f"{technique_id.upper()}.json"
    else:
        path = TECHNIQUES_DIR / f"{technique_id}.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _available_techniques() -> list[str]:
    mitre = sorted(p.stem for p in TECHNIQUES_DIR.glob("*.json"))
    llm_dir = TECHNIQUES_DIR / "llm"
    llm = sorted(p.stem for p in llm_dir.glob("*.json")) if llm_dir.exists() else []
    return mitre + llm


def _attacker_strategy(
    round_num: int,
    last_kql: Optional[str],
    evaded_logs: list,
    detected_logs: list,
) -> str:
    if round_num == 1:
        return "Initial attack — generating baseline telemetry that matches the target technique schema."

    evaded = len(evaded_logs)
    detected = len(detected_logs)

    targeted: list[str] = []
    if last_kql:
        fields = _DETECTABLE_FIELDS.findall(last_kql)
        targeted = list(dict.fromkeys(fields))[:3]

    field_str = ", ".join(targeted) if targeted else "known indicators"
    return (
        f"Round {round_num} mutation — {detected} log(s) caught last round, {evaded} evaded. "
        f"Rotating {field_str} to slip past the detection rule."
    )


def _defender_reasoning(round_num: int, evaded_logs: list, detected_logs: list) -> str:
    if round_num == 1:
        return "Initial rule — scanning attack logs for detectable patterns and suspicious field values."

    evaded = len(evaded_logs)
    detected = len(detected_logs)
    return (
        f"Round {round_num} hardening — {evaded} log(s) evaded last round, {detected} caught. "
        "Analysing evaded samples to close the remaining detection gaps."
    )


async def _in_thread(fn, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, lambda: fn(*args, **kwargs))


# ── Routes ──────────────────────────────────────────────────────────────────


@app.get("/")
async def root():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/heatmap")
async def heatmap():
    return FileResponse(str(STATIC_DIR / "heatmap.html"))


@app.get("/tournament")
async def tournament():
    return FileResponse(str(STATIC_DIR / "tournament.html"))


@app.get("/campaign")
async def campaign():
    return FileResponse(str(STATIC_DIR / "campaign.html"))


@app.get("/export")
async def export_page():
    return FileResponse(str(STATIC_DIR / "export.html"))


@app.get("/autonomous")
async def autonomous_page():
    return FileResponse(str(STATIC_DIR / "autonomous.html"))


@app.get("/mcp")
async def mcp_page():
    return FileResponse(str(STATIC_DIR / "mcp.html"))


@app.get("/api/mcp/log")
async def api_mcp_log():
    """Return the last 40 lines of the MCP server log for the live log viewer."""
    import time
    log_path = OUTPUT_DIR / "mcp_server.log"
    if not log_path.exists():
        return JSONResponse({"lines": [], "running": False})
    try:
        text  = log_path.read_text(encoding="utf-8", errors="replace")
        lines = [l for l in text.splitlines() if l.strip()][-40:]
        mtime = log_path.stat().st_mtime
        running = (time.time() - mtime) < 30
        return JSONResponse({"lines": lines, "running": running})
    except Exception as exc:
        return JSONResponse({"lines": [str(exc)], "running": False})


@app.get("/api/export/rules")
async def api_export_rules():
    """Return all exportable rules as JSON for the export UI table."""
    exporter = SentinelExporter()
    rules = await _in_thread(exporter.load_rules)
    return JSONResponse(rules)


@app.get("/api/export")
async def api_export(severity: str = "", ids: str = ""):
    """
    Generate and return the Sentinel ARM template as a downloadable file.
    ?severity=High,Medium,Low  — filter by severity (comma-separated)
    ?ids=T1078.004_round1,...  — filter by specific rule IDs
    Both params are optional; omitting both exports all surviving rules.
    """
    exporter = SentinelExporter()
    id_filter  = [x.strip() for x in ids.split(",")  if x.strip()] if ids else None
    sev_filter = [x.strip() for x in severity.split(",") if x.strip()] if severity else None

    arm, _, _ = await _in_thread(exporter.export, sev_filter, id_filter)

    return Response(
        content=json.dumps(arm, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="sentinel_export.json"'},
    )


@app.get("/api/report/{technique_id}")
async def api_report(technique_id: str):
    """Generate and return the PDF battle report for the given technique."""
    from engine.report_generator import ReportGenerator
    from engine.scoring import BattleScorer

    log_path = OUTPUT_DIR / f"full_battle_log_{technique_id}.json"
    if not log_path.exists():
        return JSONResponse(
            {"error": f"No battle log found for technique {technique_id}"},
            status_code=404,
        )

    with open(log_path, encoding="utf-8") as f:
        data = json.load(f)

    scorer = BattleScorer.from_log(data)
    pdf_path = await _in_thread(ReportGenerator(scorer).generate)
    filename = f"duel_report_{technique_id}.pdf"
    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/threatintel")
async def api_threatintel():
    """Return current cached threat intel summary (sources, IOC counts, samples)."""
    from engine.threat_intel import ThreatIntelFeed
    try:
        feed = ThreatIntelFeed()
        return JSONResponse(feed.get_status())
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.get("/api/memory")
async def api_memory():
    """Return current attacker memory as JSON (per-technique intel)."""
    from engine.attacker_memory import MemoryStore
    store = MemoryStore()
    return JSONResponse(store.get_all())


@app.get("/api/technique/{technique_id}/history")
async def api_technique_history(technique_id: str):
    """Return structured battle history for a technique from its full battle log."""
    log_path = OUTPUT_DIR / f"full_battle_log_{technique_id}.json"
    if not log_path.exists():
        return JSONResponse(
            {"error": f"No battle data for {technique_id}"},
            status_code=404,
        )
    try:
        with open(log_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)

    try:
        meta = _load_technique(technique_id)
    except FileNotFoundError:
        meta = {}

    rounds_raw = data.get("rounds", [])
    n = len(rounds_raw)
    avg_ev  = sum(r.get("evasion_rate",  0) for r in rounds_raw) / n if n else 0.0
    avg_det = sum(r.get("detection_rate", 0) for r in rounds_raw) / n if n else 0.0

    rounds_summary = []
    for r in rounds_raw:
        det = r.get("detected_count", 0)
        evd = r.get("evaded_count",   0)
        rounds_summary.append({
            "round":          r["round"],
            "detected":       det,
            "evaded":         evd,
            "total":          r.get("attack_log_count", det + evd),
            "detection_rate": r.get("detection_rate", 0.0),
            "evasion_rate":   r.get("evasion_rate",   0.0),
            "winner":         "Defender" if det >= evd else "Attacker",
            "kql_rule":       r.get("kql_rule", ""),
        })

    # Count field presence across all evaded logs (≥30% presence threshold)
    field_counts: dict[str, int] = {}
    total_evaded = 0
    for r in rounds_raw:
        for log in r.get("evaded_logs", []):
            total_evaded += 1
            for k, v in log.items():
                if k.startswith("_") or k == "TimeGenerated":
                    continue
                if v is not None and str(v).strip() not in ("", "none", "None", "{}"):
                    field_counts[k] = field_counts.get(k, 0) + 1

    top_fields: list[dict] = []
    if total_evaded > 0:
        top_fields = sorted(
            [
                {"field": f, "presence_pct": round(c / total_evaded, 3)}
                for f, c in field_counts.items()
                if c / total_evaded >= 0.3
            ],
            key=lambda x: x["presence_pct"],
            reverse=True,
        )[:10]

    tbl = meta.get("sentinel_table")
    if not tbl:
        tbls = meta.get("sentinel_tables")
        tbl = tbls[0] if isinstance(tbls, list) and tbls else None

    return JSONResponse({
        "technique_id":         technique_id,
        "name":                 meta.get("name", technique_id),
        "tactic":               meta.get("tactic", meta.get("owasp_category", "")),
        "sentinel_table":       tbl,
        "risk_level":           meta.get("risk_level"),
        "total_rounds":         n,
        "winner":               data.get("winner", "—"),
        "final_attacker_score": data.get("final_attacker_score", 0),
        "final_defender_score": data.get("final_defender_score", 0),
        "avg_evasion_rate":     round(avg_ev,  4),
        "avg_detection_rate":   round(avg_det, 4),
        "rounds":               rounds_summary,
        "surviving_kql":        data.get("surviving_kql_rules", []),
        "top_evaded_fields":    top_fields,
    })


@app.get("/coverage")
async def coverage():
    """Aggregate all full battle logs in /output and return per-technique stats."""
    # Load technique metadata (MITRE + LLM subfolder)
    tech_meta: dict[str, dict] = {}
    sources = list(TECHNIQUES_DIR.glob("*.json"))
    llm_dir = TECHNIQUES_DIR / "llm"
    if llm_dir.exists():
        sources += list(llm_dir.glob("*.json"))
    for p in sources:
        try:
            with open(p, encoding="utf-8") as f:
                t = json.load(f)
            tech_meta[t["technique_id"]] = t
        except Exception:
            pass

    # Aggregate from per-technique full battle logs only
    battle_data: dict[str, dict] = {}
    for p in OUTPUT_DIR.glob("full_battle_log_*.json"):
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        if "technique_id" not in d or not isinstance(d.get("rounds"), list):
            continue
        tid = d["technique_id"]
        if tid not in battle_data:
            battle_data[tid] = {"battles": 0, "sum_evasion": 0.0, "sum_detection": 0.0, "total_rounds": 0}
        bd = battle_data[tid]
        bd["battles"] += 1
        for r in d["rounds"]:
            bd["total_rounds"] += 1
            bd["sum_evasion"]   += float(r.get("evasion_rate", 0.0))
            bd["sum_detection"] += float(r.get("detection_rate", 0.0))

    result: dict[str, dict] = {}
    for tid, t in tech_meta.items():
        bd = battle_data.get(tid)
        n  = bd["total_rounds"] if bd else 0
        result[tid] = {
            "name":               t["name"],
            "tactic":             t.get("tactic", t.get("owasp_category", "LLM Top 10")),
            "risk_level":         t.get("risk_level"),
            "owasp_category":     t.get("owasp_category"),
            "battles":            bd["battles"] if bd else 0,
            "avg_evasion_rate":   round(bd["sum_evasion"]   / n, 4) if n else None,
            "avg_detection_rate": round(bd["sum_detection"] / n, 4) if n else None,
            "total_rounds":       n,
        }
    return JSONResponse(result)


@app.get("/techniques")
async def techniques():
    return JSONResponse(_available_techniques())


@app.get("/run")
async def run_info(technique: str = "T1078.004", rounds: int = 3):
    """Informational endpoint — actual battles start via WebSocket /ws."""
    return JSONResponse({
        "technique": technique,
        "rounds": rounds,
        "ui": "http://localhost:8000",
        "websocket": "ws://localhost:8000/ws",
        "instructions": "Open the UI and click Start Battle, or connect to /ws directly.",
    })


# ── WebSocket battle loop ────────────────────────────────────────────────────


@app.websocket("/ws")
async def ws_battle(websocket: WebSocket):
    await websocket.accept()

    async def send(payload: dict):
        await websocket.send_text(json.dumps(payload, default=str))

    try:
        cfg = await websocket.receive_json()
        technique_id: str = cfg.get("technique", "T1078.004")
        rounds: int = max(1, int(cfg.get("rounds", 3)))
        logs_per_round: int = max(5, int(cfg.get("logs_per_round", 10)))
        attacker_model: str = cfg.get("attacker_model", "llama3.1:8b")
        defender_model: str = cfg.get("defender_model", "mistral:7b")

        try:
            technique = await _in_thread(_load_technique, technique_id)
        except FileNotFoundError:
            await send({"type": "error", "message": f"Technique {technique_id} not found."})
            return

        Path("output").mkdir(exist_ok=True)
        attacker = AttackerAgent(model=attacker_model, num_logs=logs_per_round)
        defender = DefenderAgent(model=defender_model)
        scorer = BattleScorer(total_rounds=rounds, technique_id=technique_id)

        for round_num in range(1, rounds + 1):
            await send({
                "type": "round_start",
                "round": round_num,
                "total": rounds,
                "technique": technique_id,
            })

            last_kql = scorer.rounds[-1]["kql_rule"] if scorer.rounds else None
            detected_logs = scorer.get_last_detected_logs()
            evaded_logs = scorer.get_last_evaded_logs()

            # ── Attacker phase ──────────────────────────────────────────────
            await send({"type": "attacker_thinking"})

            try:
                attack_logs = await _in_thread(
                    attacker.generate_logs,
                    technique=technique,
                    round_num=round_num,
                    total_rounds=rounds,
                    last_kql=last_kql,
                    detected_logs=detected_logs,
                    evaded_logs=evaded_logs,
                )
            except Exception as exc:
                await send({"type": "error", "message": f"Attacker error: {exc}"})
                return

            strategy = _attacker_strategy(round_num, last_kql, evaded_logs, detected_logs)
            logs_sample = [
                {k: v for k, v in log.items() if not k.startswith("_duel")}
                for log in attack_logs[:3]
            ]
            await send({
                "type": "attacker_done",
                "strategy": strategy,
                "logs_sample": logs_sample,
            })

            # ── Defender phase ──────────────────────────────────────────────
            await send({"type": "defender_thinking"})

            try:
                kql_rule = await _in_thread(
                    defender.generate_rule,
                    technique=technique,
                    round_num=round_num,
                    total_rounds=rounds,
                    attack_logs=attack_logs,
                    detected_logs=detected_logs,
                    evaded_logs=evaded_logs,
                )
            except Exception as exc:
                kql_rule = "SigninLogs | where ResultType != 0"
                await send({"type": "error", "message": f"Defender fallback: {exc}"})

            reasoning = _defender_reasoning(round_num, evaded_logs, detected_logs)
            await send({
                "type": "defender_done",
                "kql": kql_rule,
                "reasoning": reasoning,
            })

            # ── Detection phase ─────────────────────────────────────────────
            if technique_id.upper().startswith("LLM"):
                from engine.llm_detection import LLMDetectionEngine
                engine = LLMDetectionEngine(attack_logs)
            else:
                engine = DetectionEngine(attack_logs)
            det_result = engine.run(kql_rule)

            total_logs = len(attack_logs)
            detected_count = len(det_result["detected_ids"])
            evaded_count = total_logs - detected_count
            rate = detected_count / total_logs if total_logs else 0.0

            await send({
                "type": "detection_result",
                "detected": detected_count,
                "evaded": evaded_count,
                "rate": rate,
            })

            # ── Scoring phase ───────────────────────────────────────────────
            record = scorer.record_round(
                round_num=round_num,
                attack_logs=attack_logs,
                kql_rule=kql_rule,
                detected_ids=det_result["detected_ids"],
                kql_valid=det_result["kql_valid"],
            )

            round_result = "detected" if detected_count >= evaded_count else "evaded"
            await send({
                "type": "round_result",
                "result": round_result,
                "attacker_score": scorer.attacker_score,
                "defender_score": scorer.defender_score,
            })

        # ── Battle complete ─────────────────────────────────────────────────
        scorer.save_full_battle_log()
        scorer.generate_report()

        if scorer.attacker_score > scorer.defender_score:
            winner = "Attacker"
        elif scorer.defender_score > scorer.attacker_score:
            winner = "Defender"
        else:
            winner = "Draw"

        await send({
            "type": "battle_complete",
            "winner": winner,
            "final_attacker": scorer.attacker_score,
            "final_defender": scorer.defender_score,
        })

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await send({"type": "error", "message": str(exc)})
        except Exception:
            pass


# ── WebSocket tournament loop ────────────────────────────────────────────────


@app.websocket("/ws/tournament")
async def ws_tournament(websocket: WebSocket):
    await websocket.accept()

    async def send(payload: dict):
        await websocket.send_text(json.dumps(payload, default=str))

    try:
        cfg = await websocket.receive_json()
        technique_id: str  = cfg.get("technique", "T1078.004")
        rounds: int        = max(1, int(cfg.get("rounds", 3)))
        logs_per_round: int = max(5, int(cfg.get("logs_per_round", 10)))
        attacker_model: str = cfg.get("attacker_model", "llama3.1:8b")
        raw_defenders: str  = cfg.get("defenders", "mistral:7b")
        defenders: list[str] = [m.strip() for m in raw_defenders.split(",") if m.strip()]

        if not defenders:
            await send({"type": "error", "message": "No defender models specified."})
            return

        try:
            technique = await _in_thread(_load_technique, technique_id)
        except FileNotFoundError:
            await send({"type": "error", "message": f"Technique {technique_id} not found."})
            return

        Path("output").mkdir(exist_ok=True)
        await send({
            "type": "tournament_start",
            "technique": technique_id,
            "rounds": rounds,
            "defenders": defenders,
        })

        # ── Phase 1: pre-generate attack logs (identical for all defenders) ──
        attacker = AttackerAgent(model=attacker_model, num_logs=logs_per_round)
        all_attack_logs: dict[int, list[dict]] = {}

        for round_num in range(1, rounds + 1):
            await send({"type": "attack_phase_start", "round": round_num, "total_rounds": rounds})
            try:
                logs = await _in_thread(
                    attacker.generate_logs,
                    technique=technique,
                    round_num=round_num,
                    total_rounds=rounds,
                    last_kql=None,
                    detected_logs=[],
                    evaded_logs=[],
                )
                all_attack_logs[round_num] = logs
            except Exception as exc:
                await send({"type": "error", "message": f"Attacker error round {round_num}: {exc}"})
                return
            await send({"type": "attack_phase_done", "round": round_num, "log_count": len(logs)})

        # ── Phase 2: run each defender ────────────────────────────────────────
        defender_results: dict[str, dict] = {}

        for defender_model in defenders:
            await send({"type": "defender_battle_start", "defender": defender_model})
            defender_agent = DefenderAgent(model=defender_model)
            scorer = BattleScorer(total_rounds=rounds, technique_id=technique_id)

            for round_num in range(1, rounds + 1):
                attack_logs = all_attack_logs[round_num]
                await send({
                    "type": "defender_round_start",
                    "defender": defender_model,
                    "round": round_num,
                    "total_rounds": rounds,
                })

                try:
                    kql_rule = await _in_thread(
                        defender_agent.generate_rule,
                        technique=technique,
                        round_num=round_num,
                        total_rounds=rounds,
                        attack_logs=attack_logs,
                        detected_logs=scorer.get_last_detected_logs(),
                        evaded_logs=scorer.get_last_evaded_logs(),
                    )
                except Exception as exc:
                    kql_rule = "SigninLogs | where ResultType != 0"
                    await send({
                        "type": "error",
                        "message": f"Defender {defender_model} fallback round {round_num}: {exc}",
                    })

                engine_inst = DetectionEngine(attack_logs)
                det_result = engine_inst.run(kql_rule)

                record = scorer.record_round(
                    round_num=round_num,
                    attack_logs=attack_logs,
                    kql_rule=kql_rule,
                    detected_ids=det_result["detected_ids"],
                    kql_valid=det_result["kql_valid"],
                )

                await send({
                    "type": "defender_round_done",
                    "defender": defender_model,
                    "round": round_num,
                    "kql": kql_rule,
                    "detection_rate": record["detection_rate"],
                    "evasion_rate": record["evasion_rate"],
                    "detected": record["detected_count"],
                    "evaded": record["evaded_count"],
                    "kql_valid": det_result["kql_valid"],
                })

            defender_results[defender_model] = {
                "rounds": scorer.rounds,
                "attacker_score": scorer.attacker_score,
                "defender_score": scorer.defender_score,
                "surviving_kql": scorer.surviving_kql,
            }
            avg_det = scorer.defender_score / sum(
                len(all_attack_logs[r]) for r in range(1, rounds + 1)
            ) if rounds else 0.0
            await send({
                "type": "defender_battle_done",
                "defender": defender_model,
                "defender_score": scorer.defender_score,
                "attacker_score": scorer.attacker_score,
            })

        # ── Phase 3: rank and emit results ────────────────────────────────────
        ts = TournamentScorer(technique_id=technique_id, defender_results=defender_results)
        rankings = ts.rank()
        ts.save(all_attack_logs)
        ts.generate_report(rankings)

        await send({"type": "tournament_complete", "rankings": rankings})

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await send({"type": "error", "message": str(exc)})
        except Exception:
            pass


# ── WebSocket campaign loop ──────────────────────────────────────────────────


@app.websocket("/ws/campaign")
async def ws_campaign(websocket: WebSocket):
    await websocket.accept()

    async def send(payload: dict):
        await websocket.send_text(json.dumps(payload, default=str))

    try:
        cfg = await websocket.receive_json()
        campaign_name: str  = cfg.get("campaign", "cloud-takeover")
        rounds: int         = max(1, int(cfg.get("rounds", 3)))
        logs_per_round: int = max(5, int(cfg.get("logs_per_round", 10)))
        attacker_model: str = cfg.get("attacker_model", "llama3.1:8b")
        defender_model: str = cfg.get("defender_model", "mistral:7b")

        if campaign_name not in CAMPAIGNS:
            await send({"type": "error", "message": f"Unknown campaign: {campaign_name}"})
            return

        campaign_def = CAMPAIGNS[campaign_name]
        technique_ids: list[str] = campaign_def["techniques"]

        try:
            techniques = [await _in_thread(_load_technique, t) for t in technique_ids]
        except FileNotFoundError as exc:
            await send({"type": "error", "message": str(exc)})
            return

        Path("output").mkdir(exist_ok=True)

        await send({
            "type": "campaign_start",
            "campaign": campaign_name,
            "campaign_name": campaign_def["name"],
            "techniques": [
                {"id": t["technique_id"], "name": t["name"]} for t in techniques
            ],
            "total_stages": len(techniques),
        })

        # Single attacker carries context across all stages
        attacker = AttackerAgent(model=attacker_model, num_logs=logs_per_round)
        stage_results: list[dict] = []
        campaign_context: str | None = None

        for stage_idx, technique in enumerate(techniques):
            stage_num = stage_idx + 1
            technique_id = technique["technique_id"]
            narrative = (
                campaign_def["narrative"][stage_idx]
                if stage_idx < len(campaign_def["narrative"])
                else ""
            )

            await send({
                "type": "stage_start",
                "stage": stage_num,
                "technique_id": technique_id,
                "technique_name": technique["name"],
                "total_stages": len(techniques),
                "narrative": narrative,
            })

            defender_agent = DefenderAgent(model=defender_model)
            scorer = BattleScorer(total_rounds=rounds, technique_id=technique_id)

            for round_num in range(1, rounds + 1):
                last_kql      = scorer.rounds[-1]["kql_rule"] if scorer.rounds else None
                detected_logs = scorer.get_last_detected_logs()
                evaded_logs   = scorer.get_last_evaded_logs()

                await send({
                    "type": "round_start",
                    "stage": stage_num,
                    "round": round_num,
                    "total_rounds": rounds,
                })

                # ── Attacker ────────────────────────────────────────────────
                await send({"type": "attacker_thinking", "stage": stage_num})
                try:
                    attack_logs = await _in_thread(
                        attacker.generate_logs,
                        technique=technique,
                        round_num=round_num,
                        total_rounds=rounds,
                        last_kql=last_kql,
                        detected_logs=detected_logs,
                        evaded_logs=evaded_logs,
                        campaign_context=campaign_context if round_num == 1 else None,
                    )
                except Exception as exc:
                    await send({
                        "type": "error",
                        "message": f"Attacker error stage {stage_num} round {round_num}: {exc}",
                    })
                    return

                strategy = _attacker_strategy(round_num, last_kql, evaded_logs, detected_logs)
                if campaign_context and round_num == 1:
                    strategy = f"[Stage {stage_num}] Using kill chain foothold — " + strategy
                logs_sample = [
                    {k: v for k, v in log.items() if not k.startswith("_duel")}
                    for log in attack_logs[:3]
                ]
                await send({
                    "type": "attacker_done",
                    "stage": stage_num,
                    "strategy": strategy,
                    "logs_sample": logs_sample,
                })

                # ── Defender ────────────────────────────────────────────────
                await send({"type": "defender_thinking", "stage": stage_num})
                try:
                    kql_rule = await _in_thread(
                        defender_agent.generate_rule,
                        technique=technique,
                        round_num=round_num,
                        total_rounds=rounds,
                        attack_logs=attack_logs,
                        detected_logs=detected_logs,
                        evaded_logs=evaded_logs,
                    )
                except Exception as exc:
                    kql_rule = "SigninLogs | where ResultType != 0"
                    await send({
                        "type": "error",
                        "message": f"Defender fallback stage {stage_num}: {exc}",
                    })

                reasoning = _defender_reasoning(round_num, evaded_logs, detected_logs)
                await send({
                    "type": "defender_done",
                    "stage": stage_num,
                    "kql": kql_rule,
                    "reasoning": reasoning,
                })

                # ── Detection ───────────────────────────────────────────────
                engine_inst = DetectionEngine(attack_logs)
                det_result  = engine_inst.run(kql_rule)
                total_count = len(attack_logs)
                detected_n  = len(det_result["detected_ids"])
                evaded_n    = total_count - detected_n
                rate        = detected_n / total_count if total_count else 0.0

                await send({
                    "type": "detection_result",
                    "stage": stage_num,
                    "detected": detected_n,
                    "evaded": evaded_n,
                    "rate": rate,
                })

                record = scorer.record_round(
                    round_num=round_num,
                    attack_logs=attack_logs,
                    kql_rule=kql_rule,
                    detected_ids=det_result["detected_ids"],
                    kql_valid=det_result["kql_valid"],
                )

                round_result = "detected" if detected_n >= evaded_n else "evaded"
                await send({
                    "type": "round_result",
                    "stage": stage_num,
                    "result": round_result,
                    "attacker_score": scorer.attacker_score,
                    "defender_score": scorer.defender_score,
                })

            # ── Stage complete ──────────────────────────────────────────────
            scorer.save_full_battle_log()

            total_stage_logs   = sum(r["attack_log_count"] for r in scorer.rounds)
            total_stage_evaded = sum(r["evaded_count"]     for r in scorer.rounds)
            evasion_rate = (
                total_stage_evaded / total_stage_logs if total_stage_logs else 0.0
            )

            if scorer.attacker_score > scorer.defender_score:
                stage_winner = "Attacker"
            elif scorer.defender_score > scorer.attacker_score:
                stage_winner = "Defender"
            else:
                stage_winner = "Draw"

            stage_results.append({
                "stage": stage_num,
                "technique_id": technique_id,
                "technique_name": technique["name"],
                "winner": stage_winner,
                "evasion_rate": round(evasion_rate, 4),
                "attacker_score": scorer.attacker_score,
                "defender_score": scorer.defender_score,
                "surviving_kql_count": len(scorer.surviving_kql),
            })

            await send({
                "type": "stage_complete",
                "stage": stage_num,
                "technique_id": technique_id,
                "winner": stage_winner,
                "evasion_rate": round(evasion_rate, 4),
                "attacker_score": scorer.attacker_score,
                "defender_score": scorer.defender_score,
                "surviving_kql_count": len(scorer.surviving_kql),
            })

            # Build context for next stage
            if stage_num < len(techniques):
                campaign_context = build_campaign_context(technique, scorer, stage_num)

        # ── Campaign complete ───────────────────────────────────────────────
        attacker_wins = sum(1 for s in stage_results if s["winner"] == "Attacker")
        overall_success = attacker_wins / len(stage_results) if stage_results else 0.0

        await send({
            "type": "campaign_complete",
            "campaign": campaign_name,
            "campaign_name": campaign_def["name"],
            "stages": stage_results,
            "attacker_wins": attacker_wins,
            "overall_success_rate": round(overall_success, 4),
        })

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await send({"type": "error", "message": str(exc)})
        except Exception:
            pass


# ── WebSocket autonomous loop ────────────────────────────────────────────────


@app.websocket("/ws/autonomous")
async def ws_autonomous(websocket: WebSocket):
    await websocket.accept()

    async def send(payload: dict):
        await websocket.send_text(json.dumps(payload, default=str))

    try:
        cfg = await websocket.receive_json()
        objective:      str = cfg.get("objective", "full-compromise")
        max_techniques: int = max(1, min(6, int(cfg.get("max_techniques", 4))))
        logs_per_round: int = max(5, int(cfg.get("logs_per_round", 10)))
        attacker_model: str = cfg.get("attacker_model", "llama3.1:8b")
        defender_model: str = cfg.get("defender_model", "mistral:7b")

        from engine.autonomous_attacker import AutonomousRedTeam
        from campaign import build_campaign_context

        Path("output").mkdir(exist_ok=True)

        # ── Plan campaign ───────────────────────────────────────────────
        await send({"type": "planning", "objective": objective})
        red_team = AutonomousRedTeam(model=attacker_model)
        plan = await _in_thread(red_team.plan_campaign, objective, max_techniques)
        await send({"type": "plan_ready", "objective": objective, "plan": plan})

        # ── Execute each stage ──────────────────────────────────────────
        attacker = AttackerAgent(model=attacker_model, num_logs=logs_per_round)
        stage_results: list[dict] = []
        campaign_context: str | None = None

        for idx, stage_plan in enumerate(plan):
            technique_id = stage_plan["technique_id"]
            rounds       = stage_plan["rounds"]

            await send({
                "type":            "decision",
                "stage":           idx + 1,
                "total_stages":    len(plan),
                "technique_id":    technique_id,
                "reasoning":       stage_plan["reasoning"],
                "suggested_rounds": rounds,
                "priority":        stage_plan.get("priority", "explore"),
            })

            try:
                technique = await _in_thread(_load_technique, technique_id)
            except FileNotFoundError:
                await send({"type": "error", "message": f"Technique {technique_id} not found."})
                continue

            await send({
                "type":           "technique_start",
                "stage":          idx + 1,
                "total_stages":   len(plan),
                "technique_id":   technique_id,
                "technique_name": technique["name"],
                "rounds":         rounds,
            })

            defender_agent = DefenderAgent(model=defender_model)
            scorer = BattleScorer(total_rounds=rounds, technique_id=technique_id)

            for round_num in range(1, rounds + 1):
                last_kql      = scorer.rounds[-1]["kql_rule"] if scorer.rounds else None
                detected_logs = scorer.get_last_detected_logs()
                evaded_logs   = scorer.get_last_evaded_logs()

                await send({
                    "type":    "round_start",
                    "stage":   idx + 1,
                    "round":   round_num,
                    "total":   rounds,
                    "technique": technique_id,
                })

                # Attacker
                await send({"type": "attacker_thinking", "stage": idx + 1})
                try:
                    attack_logs = await _in_thread(
                        attacker.generate_logs,
                        technique=technique,
                        round_num=round_num,
                        total_rounds=rounds,
                        last_kql=last_kql,
                        detected_logs=detected_logs,
                        evaded_logs=evaded_logs,
                        campaign_context=campaign_context if round_num == 1 else None,
                    )
                except Exception as exc:
                    await send({"type": "error", "message": f"Attacker error: {exc}"})
                    return

                strategy = _attacker_strategy(round_num, last_kql, evaded_logs, detected_logs)
                logs_sample = [
                    {k: v for k, v in log.items() if not k.startswith("_duel")}
                    for log in attack_logs[:3]
                ]
                await send({
                    "type":        "attacker_done",
                    "stage":       idx + 1,
                    "strategy":    strategy,
                    "logs_sample": logs_sample,
                })

                # Defender
                await send({"type": "defender_thinking", "stage": idx + 1})
                try:
                    kql_rule = await _in_thread(
                        defender_agent.generate_rule,
                        technique=technique,
                        round_num=round_num,
                        total_rounds=rounds,
                        attack_logs=attack_logs,
                        detected_logs=detected_logs,
                        evaded_logs=evaded_logs,
                    )
                except Exception as exc:
                    kql_rule = "SigninLogs | where ResultType != 0"
                    await send({"type": "error", "message": f"Defender fallback: {exc}"})

                reasoning = _defender_reasoning(round_num, evaded_logs, detected_logs)
                await send({
                    "type":      "defender_done",
                    "stage":     idx + 1,
                    "kql":       kql_rule,
                    "reasoning": reasoning,
                })

                # Detection
                det_result  = DetectionEngine(attack_logs).run(kql_rule)
                total_count = len(attack_logs)
                detected_n  = len(det_result["detected_ids"])
                evaded_n    = total_count - detected_n
                rate        = detected_n / total_count if total_count else 0.0

                await send({
                    "type":     "detection_result",
                    "stage":    idx + 1,
                    "detected": detected_n,
                    "evaded":   evaded_n,
                    "rate":     rate,
                })

                record = scorer.record_round(
                    round_num=round_num,
                    attack_logs=attack_logs,
                    kql_rule=kql_rule,
                    detected_ids=det_result["detected_ids"],
                    kql_valid=det_result["kql_valid"],
                )

                round_result = "detected" if detected_n >= evaded_n else "evaded"
                await send({
                    "type":           "round_result",
                    "stage":          idx + 1,
                    "result":         round_result,
                    "attacker_score": scorer.attacker_score,
                    "defender_score": scorer.defender_score,
                })

            # Stage complete
            scorer.save_full_battle_log()
            total_stage_logs   = sum(r["attack_log_count"] for r in scorer.rounds)
            total_stage_evaded = sum(r["evaded_count"]     for r in scorer.rounds)
            evasion_rate = total_stage_evaded / total_stage_logs if total_stage_logs else 0.0

            if scorer.attacker_score > scorer.defender_score:
                stage_winner = "Attacker"
            elif scorer.defender_score > scorer.attacker_score:
                stage_winner = "Defender"
            else:
                stage_winner = "Draw"

            stage_result = {
                "stage":               idx + 1,
                "technique_id":        technique_id,
                "technique_name":      technique["name"],
                "winner":              stage_winner,
                "evasion_rate":        round(evasion_rate, 4),
                "attacker_score":      scorer.attacker_score,
                "defender_score":      scorer.defender_score,
                "surviving_kql_count": len(scorer.surviving_kql),
                "surviving_kql":       scorer.surviving_kql,
            }
            stage_results.append(stage_result)

            await send({
                "type":                "technique_complete",
                "stage":               idx + 1,
                "technique_id":        technique_id,
                "winner":              stage_winner,
                "evasion_rate":        round(evasion_rate, 4),
                "attacker_score":      scorer.attacker_score,
                "defender_score":      scorer.defender_score,
                "surviving_kql_count": len(scorer.surviving_kql),
            })

            if idx + 1 < len(plan):
                campaign_context = build_campaign_context(technique, scorer, idx + 1)

        # ── Report + complete ───────────────────────────────────────────
        report_path = await _in_thread(
            red_team.generate_report, objective, plan, stage_results
        )

        attacker_wins  = sum(1 for s in stage_results if s["winner"] == "Attacker")
        overall_success = attacker_wins / len(stage_results) if stage_results else 0.0

        await send({
            "type":         "autonomous_complete",
            "objective":    objective,
            "stages":       [{k: v for k, v in s.items() if k != "surviving_kql"}
                             for s in stage_results],
            "decisions":    red_team._decisions,
            "success_rate": round(overall_success, 4),
            "report_path":  str(report_path),
        })

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await send({"type": "error", "message": str(exc)})
        except Exception:
            pass


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
