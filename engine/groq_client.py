"""
Groq API client — drop-in replacement for the `ollama` module.

Auto-detects backend at first call:
  - GROQ_API_KEY set  → Groq cloud inference
  - GROQ_API_KEY unset → local Ollama (unchanged behaviour)

Agents import this as `ollama` and call ollama.chat() unchanged.
"""

import logging
import os

import requests

logger = logging.getLogger(__name__)

_GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Ollama model name -> Groq model name, for the (currently empty) case where
# an Ollama-style tag needs remapping to a Groq id. The previous entries here
# (llama3.1:8b -> llama-3.1-70b-versatile, mistral -> mixtral-8x7b-32768)
# were themselves the root cause of the weekly-badge incident documented in
# CHANGELOG.md / docs/ERRATA.md item 3 (mixtral-8x7b-32768 was decommissioned)
# and were never a real "same model, different name" mapping — llama3.1:8b
# and llama-3.1-70b-versatile are different models. Removed rather than left
# to bite the next person. The hybrid grid (scripts/run_groq_grid.py) passes
# exact Groq ids directly (e.g. "openai/gpt-oss-20b"), which need no mapping.
_MODEL_MAP: dict[str, str] = {}

# Reasoning-capable model families (currently just gpt-oss). Both Ollama
# (think=) and Groq (reasoning_effort=) expose the same "low"/"medium"/"high"
# scale for these models — see chat()'s reasoning_effort param. Any model not
# matched here silently gets no reasoning-effort argument at all (most models
# don't support one and would error or ignore an unexpected field).
_REASONING_MODEL_MARKERS = ("gpt-oss",)


def is_reasoning_model(model: str) -> bool:
    return any(m in model.lower() for m in _REASONING_MODEL_MARKERS)


# Fixed identically across BOTH platforms for every reasoning-model call in
# this experiment (2026-09-05 decision) — an unfixed reasoning_effort would
# be its own confound in the gpt-oss cross-platform control (§5,
# docs/scaling_v2_results.md): a different effort level per platform could
# by itself explain a DABS delta having nothing to do with the platform.
# "medium": not "low" (would underuse the reasoning capability that is the
# whole point of including this model), not "high" (would multiply latency/
# token cost across the grid's ~45 Groq calls and every local gpt-oss round).
DEFAULT_REASONING_EFFORT = "medium"


class GroqClient:
    """
    Mimics the ollama module interface so agents need no logic changes.
    chat() accepts the same kwargs as ollama.chat() and returns the same
    dict shape: {"message": {"content": "..."}}.
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def chat(
        self,
        model: str,
        messages: list[dict],
        options: dict | None = None,
        reasoning_effort: str | None = None,
    ) -> dict:
        groq_model = _MODEL_MAP.get(model, model)
        opts = options or {}

        payload = {
            "model": groq_model,
            "messages": messages,
            "temperature": opts.get("temperature", 0.7),
            "max_tokens": opts.get("num_predict", 2048),
        }
        if reasoning_effort is not None:
            payload["reasoning_effort"] = reasoning_effort

        logger.debug("Groq request model=%s (mapped from %r)", groq_model, model)
        # Generous timeout — this is the actual LLM generation call (the Groq
        # equivalent of an Ollama round), not an auxiliary network fetch, so it
        # gets the same "per round" budget as engine/groq_client.py's Ollama
        # fallback client below (600s), not the 5s used for threat-intel calls.
        resp = requests.post(
            _GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=(10, 600),  # (connect, read)
        )
        resp.raise_for_status()

        content = resp.json()["choices"][0]["message"]["content"]
        return {"message": {"content": content}}


def _build_backend() -> object:
    """Resolve backend once: Groq if key present, else a local Ollama client."""
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if api_key:
        logger.info("GROQ_API_KEY detected — using Groq inference backend")
        return GroqClient(api_key)
    from ollama import Client as OllamaClient  # noqa: PLC0415
    logger.info("No GROQ_API_KEY — using local Ollama backend")
    # The bare `ollama` module's default client is constructed with
    # timeout=None, i.e. NO timeout at all — a hung Ollama server or a stuck
    # generation blocks forever. Build our own client with a generous but
    # finite per-request timeout instead.
    return OllamaClient(timeout=600)


# Lazy singleton — not resolved until first chat() call so that tests and
# scripts can set GROQ_API_KEY in the environment before importing agents.
_backend: object | None = None
_ollama_client: object | None = None  # forced-platform client, independent of the singleton


def get_client(platform: str | None = None) -> object:
    """
    Return a backend client for an explicit platform, bypassing the
    auto-detected singleton — needed when Attacker and Defender must run on
    DIFFERENT platforms in the same process (e.g. Attacker always local
    Ollama, Defender on Groq for the scaling grid). platform=None preserves
    the original auto-detect-by-env-var singleton behaviour.
    """
    global _backend, _ollama_client

    if platform is None:
        if _backend is None:
            _backend = _build_backend()
        return _backend

    if platform == "groq":
        api_key = os.environ.get("GROQ_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("platform='groq' requested but GROQ_API_KEY is not set")
        return GroqClient(api_key)

    if platform == "ollama":
        if _ollama_client is None:
            from ollama import Client as OllamaClient  # noqa: PLC0415
            _ollama_client = OllamaClient(timeout=600)
        return _ollama_client

    raise ValueError(f"Unknown platform {platform!r} — must be 'ollama', 'groq', or None")


def chat(
    model: str,
    messages: list[dict],
    options: dict | None = None,
    platform: str | None = None,
    reasoning_effort: str | None = None,
) -> dict:
    """
    Transparent ollama.chat() replacement. Backend is auto-detected once when
    platform=None (original behaviour). Pass platform="ollama"/"groq" to force
    a specific backend for this call regardless of GROQ_API_KEY, so a single
    process can run e.g. Attacker on Ollama and Defender on Groq at once.

    reasoning_effort ("low"/"medium"/"high") controls thinking depth for
    reasoning models (currently gpt-oss). Ollama and Groq expose the same
    scale under DIFFERENT parameter names — Ollama's client takes `think=`,
    Groq's chat-completions API takes `reasoning_effort=` in the request
    body — translated here so callers pass one uniform argument regardless
    of which platform this call resolves to.
    """
    client = get_client(platform)
    if reasoning_effort is None:
        return client.chat(model=model, messages=messages, options=options)
    if isinstance(client, GroqClient):
        return client.chat(model=model, messages=messages, options=options, reasoning_effort=reasoning_effort)
    return client.chat(model=model, messages=messages, options=options, think=reasoning_effort)
