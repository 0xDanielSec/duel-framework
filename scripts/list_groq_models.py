#!/usr/bin/env python3
"""
List models currently available on the Groq API and infer scaling-grid metadata.

Usage:
    python scripts/list_groq_models.py

Requires GROQ_API_KEY in the environment or in a .env file at the project
root (loaded via python-dotenv). Without it, fails gracefully with a clear
message and exit code 1 — no traceback, no invented data.

For each model returned by GET /openai/v1/models this prints:
  groq_id | family | params_b (unverified) | context_window

`params_b` is parsed from the model id itself (e.g. "llama-3.1-70b-versatile"
-> 70.0) purely as a starting point for grid planning. It is NEVER treated as
a verified parameter count — per CLAUDE.md/mission rules, every model that
enters the actual scaling grid needs a params_b confirmed against an official
model card, with that source_url recorded. This script cannot do that
confirmation itself; it only flags candidates and their unverified guess.

Also filters out non-chat models (audio transcription/TTS, moderation-only)
since the scaling benchmark needs chat-completion models that can generate
attacker telemetry / defender KQL rules.

Output is also saved to output/benchmarks/groq_models_<timestamp>.json
(versioned in git) so the grid can be built from a fixed snapshot rather than
re-querying — Groq's catalog changes over time.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")  # no-op if the file doesn't exist

_MODELS_URL = "https://api.groq.com/openai/v1/models"

# Model ids containing any of these substrings are not general-purpose chat
# completion models and are excluded from the scaling-grid candidate list:
# audio (whisper/tts/orpheus = text-to-speech), classifier-only guard models
# (prompt-guard = injection/safety classifier, not a generative LM), and
# Groq's own "compound" agentic systems (a tool-calling orchestration layer
# over one or more underlying models, not a single model with one parameter
# count — has no single official model-card params_b to cite).
_NON_CHAT_MARKERS = (
    "whisper", "tts", "-tts", "orpheus",       # audio / TTS
    "prompt-guard", "llamaguard", "llama-guard",  # classifier-only, not generative
    "compound",                                 # agentic system, not a single model
)

# Known family display names by id prefix/substring — extend as Groq's
# catalog changes. Order matters: more specific patterns first.
_FAMILY_PATTERNS: list[tuple[str, str]] = [
    (r"llama-?guard",        "Llama Guard"),
    (r"llama-?3\.3",         "Llama 3.3"),
    (r"llama-?3\.2",         "Llama 3.2"),
    (r"llama-?3\.1",         "Llama 3.1"),
    (r"llama-?3\b",          "Llama 3"),
    (r"llama-?4",            "Llama 4"),
    (r"mixtral",             "Mixtral"),
    (r"mistral",             "Mistral"),
    (r"gemma-?2",            "Gemma 2"),
    (r"gemma",               "Gemma"),
    (r"qwen",                "Qwen"),
    (r"deepseek",            "DeepSeek"),
    (r"gpt-oss",             "GPT-OSS"),
    (r"kimi",                "Kimi"),
]

# Matches a parameter-count token in a model id, e.g. "70b", "8x7b", "3.2b".
_PARAMS_RE = re.compile(r"(\d+(?:\.\d+)?)(x(\d+(?:\.\d+)?))?b\b", re.IGNORECASE)


def _infer_family(model_id: str) -> str:
    for pattern, label in _FAMILY_PATTERNS:
        if re.search(pattern, model_id, re.IGNORECASE):
            return label
    return "unknown"


def _infer_params_b(model_id: str) -> float | None:
    """
    Best-effort parse of a parameter count from the model id. Returns the
    NOMINAL figure only (e.g. "8x7b" -> 56.0 as a naive product, which is
    NOT the same as Mixtral's real ~46.7B total / ~12.9B active — this is
    exactly why every value from this function is marked "unverified").
    """
    m = _PARAMS_RE.search(model_id)
    if not m:
        return None
    base = float(m.group(1))
    if m.group(3):
        return round(base * float(m.group(3)), 1)
    return base


def fetch_models(api_key: str) -> list[dict]:
    resp = requests.get(
        _MODELS_URL,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("data", [])


def build_candidates(raw_models: list[dict]) -> list[dict]:
    candidates = []
    for m in raw_models:
        model_id = m.get("id", "")
        if not model_id:
            continue
        if any(marker in model_id.lower() for marker in _NON_CHAT_MARKERS):
            continue
        note = None
        if "safeguard" in model_id.lower():
            note = "safety/moderation-tuned variant — not a general-purpose chat model; " \
                   "using it as a Defender is a different research question than the other candidates"

        candidates.append({
            "groq_id":         model_id,
            "family":          _infer_family(model_id),
            "params_b":        _infer_params_b(model_id),
            "params_status":   "unverified",  # never trust this without an official model card
            "context_window":  m.get("context_window"),
            "owned_by":        m.get("owned_by"),
            "active":          m.get("active", True),
            "note":            note,
        })
    return sorted(candidates, key=lambda c: (c["family"], c["params_b"] or 0))


def main() -> int:
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        print(
            "list_groq_models.py: GROQ_API_KEY not set in environment -- "
            "cannot query the Groq API. No data fetched, nothing invented.",
            file=sys.stderr,
        )
        return 1

    try:
        raw_models = fetch_models(api_key)
    except requests.exceptions.RequestException as exc:
        print(f"list_groq_models.py: Groq API request failed: {exc}", file=sys.stderr)
        return 1

    candidates = build_candidates(raw_models)

    if not candidates:
        print("list_groq_models.py: Groq returned 0 usable chat-completion models.", file=sys.stderr)
        return 1

    print(f"{'groq_id':<40} {'family':<16} {'params_b':>10}  {'status':<12} {'context':>8}")
    print("-" * 92)
    for c in candidates:
        params = f"{c['params_b']:.1f}" if c["params_b"] is not None else "?"
        ctx = str(c["context_window"]) if c["context_window"] is not None else "?"
        print(f"{c['groq_id']:<40} {c['family']:<16} {params:>10}  {c['params_status']:<12} {ctx:>8}")

    out_dir = _PROJECT_ROOT / "output" / "benchmarks"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"groq_models_{ts}.json"
    out_path.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source_url": _MODELS_URL,
        "candidates": candidates,
    }, indent=2), encoding="utf-8")
    print(f"\nSaved snapshot -> {out_path.relative_to(_PROJECT_ROOT)}")
    print(
        "\nNOTE: params_b above is parsed from the model id and is UNVERIFIED. "
        "No model enters the scaling grid without a params_b confirmed against "
        "an official model card and its source_url recorded (see engine/scaling_laws.py::MODEL_REGISTRY)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
