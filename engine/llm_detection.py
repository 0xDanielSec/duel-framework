"""
LLM attack detection engine.

Instead of KQL rules the Defender generates structured detection POLICIES —
JSON documents describing input validation patterns, output monitoring rules,
rate-limiting thresholds, and prompt sanitization patterns.

The engine evaluates each attacker payload against the active policy and
returns the same {detected_ids, kql_valid} interface as DetectionEngine so
the existing BattleScorer and WebSocket loop need no changes.
"""

import json
import logging
import re
import uuid
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Payload factory
# ---------------------------------------------------------------------------

def make_llm_payloads(entries: list[dict]) -> list[dict]:
    """Apply schema defaults to attacker-generated payload dicts."""
    defaults = {
        "technique_id": "LLM01",
        "payload_type": "direct_injection",
        "prompt": "",
        "expected_impact": "unknown",
        "obfuscation": "none",
        "context": "user chat",
        "encoding": "plaintext",
        "token_count": 0,
        "_duel_id": "",
    }
    result = []
    for e in entries:
        entry = {**defaults, **e}
        if not entry["_duel_id"]:
            entry["_duel_id"] = str(uuid.uuid4())
        if not entry["token_count"] and entry["prompt"]:
            entry["token_count"] = len(entry["prompt"].split())
        result.append(entry)
    return result


# ---------------------------------------------------------------------------
# Policy parser
# ---------------------------------------------------------------------------

class LLMDetectionPolicy:
    """
    Parses a Defender-generated detection policy from free-form text.

    Resolution order:
      1. ```json ... ``` code fence
      2. Bare JSON object anywhere in the text
      3. Prose heuristics: extract quoted patterns, numeric thresholds
    """

    def __init__(self, policy_text: str):
        self.raw = policy_text
        self._data = self._parse(policy_text)
        self.valid = bool(self._data)

    # ── Parsing ─────────────────────────────────────────────────────────────

    def _parse(self, text: str) -> dict:
        # 1. Try ```json``` fence
        m = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
        if m:
            try:
                return json.loads(m.group(1))
            except (json.JSONDecodeError, ValueError):
                pass

        # 2. Greedy JSON object
        m = re.search(r"(\{[\s\S]*\})", text)
        if m:
            try:
                return json.loads(m.group(1))
            except (json.JSONDecodeError, ValueError):
                pass

        # 3. Prose heuristics
        policy: dict = {}

        quoted = re.findall(r'"([^"]{3,80})"', text)
        if quoted:
            policy["input_validation"] = {"blocked_patterns": quoted[:12]}

        m_tok = re.search(
            r"(?:max|limit|maximum)[^\d]{0,20}(\d+)\s*token", text, re.IGNORECASE
        )
        if m_tok:
            policy.setdefault("input_validation", {})["max_token_count"] = int(m_tok.group(1))

        m_len = re.search(
            r"(?:max|limit|maximum)[^\d]{0,20}(\d+)\s*(?:char|character|length)", text, re.IGNORECASE
        )
        if m_len:
            policy.setdefault("rate_limiting", {})["max_prompt_length"] = int(m_len.group(1))

        m_rpm = re.search(
            r"(\d+)\s*(?:req(?:uest)?s?)[^\d]{0,10}(?:per|/)\s*(?:minute|min)", text, re.IGNORECASE
        )
        if m_rpm:
            policy.setdefault("rate_limiting", {})["requests_per_minute"] = int(m_rpm.group(1))

        return policy if policy else {}

    # ── Accessors ────────────────────────────────────────────────────────────

    @property
    def blocked_patterns(self) -> list[str]:
        iv = self._data.get("input_validation", {})
        return [str(p) for p in iv.get("blocked_patterns", []) + iv.get("blocked_keywords", [])]

    @property
    def output_blocked_patterns(self) -> list[str]:
        om = self._data.get("output_monitoring", {})
        return [str(p) for p in om.get("blocked_patterns", [])]

    @property
    def max_prompt_length(self) -> Optional[int]:
        rl = self._data.get("rate_limiting", {})
        v = rl.get("max_prompt_length") or rl.get("max_tokens")
        return int(v) if v is not None else None

    @property
    def max_token_count(self) -> Optional[int]:
        iv = self._data.get("input_validation", {})
        v = iv.get("max_token_count") or iv.get("max_tokens")
        return int(v) if v is not None else None

    @property
    def sanitization_patterns(self) -> list[str]:
        ps = self._data.get("prompt_sanitization", {})
        return [str(p) for p in ps.get("blocked_sequences", []) + ps.get("strip_patterns", [])]


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class LLMDetectionEngine:
    """
    Evaluates a list of LLM attack payloads against a Defender detection
    policy.  Returns the same dict shape as DetectionEngine.run() so the
    existing BattleScorer and server WebSocket loop work without changes:

        {
            "detected_ids": set[str],
            "kql_valid":    bool,       # True when policy parsed successfully
            "policy_valid": bool,       # alias — same value
            "match_details": list[dict] # per-payload match breakdown
        }
    """

    def __init__(self, payloads: list[dict]):
        self.payloads = make_llm_payloads(payloads)

    def run(self, policy_text: str) -> dict:
        policy = LLMDetectionPolicy(policy_text)

        if not policy.valid:
            logger.warning("LLM policy parse failed — zero detections this round")
            return {
                "detected_ids": set(),
                "kql_valid": False,
                "policy_valid": False,
                "match_details": [],
            }

        detected_ids: set[str] = set()
        match_details: list[dict] = []

        for payload in self.payloads:
            did = payload["_duel_id"]
            prompt = str(payload.get("prompt", ""))
            token_count = int(payload.get("token_count", 0)) or len(prompt.split())
            matched_rule: Optional[str] = None

            # 1. Input validation — blocked patterns (regex with literal fallback)
            if not matched_rule:
                for pat in policy.blocked_patterns:
                    try:
                        if re.search(pat, prompt, re.IGNORECASE):
                            matched_rule = f"input_validation › {pat[:60]}"
                            break
                    except re.error:
                        if pat.lower() in prompt.lower():
                            matched_rule = f"input_validation (literal) › {pat[:60]}"
                            break

            # 2. Rate limiting — max prompt character length
            if not matched_rule and policy.max_prompt_length is not None:
                if len(prompt) > policy.max_prompt_length:
                    matched_rule = (
                        f"rate_limiting.max_prompt_length "
                        f"({len(prompt)} > {policy.max_prompt_length})"
                    )

            # 3. Input validation — max token count
            if not matched_rule and policy.max_token_count is not None:
                if token_count > policy.max_token_count:
                    matched_rule = (
                        f"input_validation.max_token_count "
                        f"({token_count} > {policy.max_token_count})"
                    )

            # 4. Prompt sanitization — blocked sequences
            if not matched_rule:
                for seq in policy.sanitization_patterns:
                    try:
                        if re.search(seq, prompt, re.IGNORECASE):
                            matched_rule = f"prompt_sanitization › {seq[:60]}"
                            break
                    except re.error:
                        if seq.lower() in prompt.lower():
                            matched_rule = f"prompt_sanitization (literal) › {seq[:60]}"
                            break

            if matched_rule:
                detected_ids.add(did)

            match_details.append({
                "_duel_id": did,
                "detected": matched_rule is not None,
                "rule": matched_rule,
                "payload_type": payload.get("payload_type", ""),
                "prompt_preview": prompt[:120],
            })

        return {
            "detected_ids": detected_ids,
            "kql_valid": True,      # compatible field name for BattleScorer
            "policy_valid": True,
            "match_details": match_details,
        }
