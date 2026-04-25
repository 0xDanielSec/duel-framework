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
    path = TECHNIQUES_DIR / f"{technique_id}.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _available_techniques() -> list[str]:
    return sorted(p.stem for p in TECHNIQUES_DIR.glob("*.json"))


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


@app.get("/api/memory")
async def api_memory():
    """Return current attacker memory as JSON (per-technique intel)."""
    from engine.attacker_memory import MemoryStore
    store = MemoryStore()
    return JSONResponse(store.get_all())


@app.get("/coverage")
async def coverage():
    """Aggregate all full battle logs in /output and return per-technique stats."""
    # Load technique metadata
    tech_meta: dict[str, dict] = {}
    for p in TECHNIQUES_DIR.glob("*.json"):
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
            "tactic":             t["tactic"],
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


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
