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
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).parent))

from agents.attacker import AttackerAgent
from agents.defender import DefenderAgent
from engine.detection import DetectionEngine
from engine.scoring import BattleScorer

TECHNIQUES_DIR = Path(__file__).parent / "techniques"
STATIC_DIR = Path(__file__).parent / "static"

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


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
