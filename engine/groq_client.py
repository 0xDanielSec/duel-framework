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

# Ollama model name → Groq model name (pass-through if already a Groq ID)
_MODEL_MAP: dict[str, str] = {
    "llama3.1:8b":   "llama-3.1-70b-versatile",
    "llama3.1:70b":  "llama-3.1-70b-versatile",
    "llama3.2:3b":   "llama-3.1-70b-versatile",
    "mistral:7b":    "mixtral-8x7b-32768",
    "mistral":       "mixtral-8x7b-32768",
}


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
    ) -> dict:
        groq_model = _MODEL_MAP.get(model, model)
        opts = options or {}

        payload = {
            "model": groq_model,
            "messages": messages,
            "temperature": opts.get("temperature", 0.7),
            "max_tokens": opts.get("num_predict", 2048),
        }

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


def chat(
    model: str,
    messages: list[dict],
    options: dict | None = None,
) -> dict:
    """Transparent ollama.chat() replacement. Backend is auto-detected once."""
    global _backend
    if _backend is None:
        _backend = _build_backend()
    if isinstance(_backend, GroqClient):
        return _backend.chat(model=model, messages=messages, options=options)
    # Real Ollama client: force immediate unload after each call (keep_alive=0)
    # instead of the server's default ~5min residency. Attacker and Defender
    # models are often both several GB; observed OOM on a 16GB machine when
    # qwen2.5:14b (9GB) tried to load while llama3.1:8b (7GB) was still
    # resident from the previous call — see docs/scaling_v2_results.md.
    # Reload cost per call (~10-30s) is noise next to multi-minute rounds.
    return _backend.chat(model=model, messages=messages, options=options, keep_alive=0)
