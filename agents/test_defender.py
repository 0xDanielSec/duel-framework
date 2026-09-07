"""
Regression tests for the threat-intel default (docs/ERRATA.md item 4): live
enrichment is an uncontrolled external dependency and must be opt-in only via
an explicit CLI flag, never something a DefenderAgent() call site falls back
to silently.
"""
import inspect
import re
from pathlib import Path

from agents.defender import DefenderAgent

REPO_ROOT = Path(__file__).parent.parent


def test_default_threat_intel_mode_is_off():
    """DefenderAgent() with no threat_intel_mode arg must not touch the network."""
    defender = DefenderAgent(model="mistral:7b")
    assert defender.threat_intel_mode == "off"
    assert defender.threat_intel is None


def test_init_signature_default_is_off():
    """
    Pin the source-level default directly -- fails if agents/defender.py's
    threat_intel_mode parameter is ever flipped back to "live" or "snapshot",
    independent of the instance-behavior check above.
    """
    default = inspect.signature(DefenderAgent.__init__).parameters["threat_intel_mode"].default
    assert default == "off", (
        f"DefenderAgent.__init__'s threat_intel_mode default is {default!r}, not 'off' -- "
        "live/snapshot enrichment must be opt-in only (docs/ERRATA.md item 4)."
    )


# Call sites may legitimately pass threat_intel_mode="off"/"snapshot", or a
# variable sourced from an explicit CLI flag (e.g. args.threat_intel) -- never
# the literal "live" hardcoded as a kwarg. The three-way enum string ("live"/
# "snapshot"/"off") legitimately appears elsewhere in the codebase (argparse
# choices=[...], docstrings, the if/elif chain inside agents/defender.py
# itself) -- this only flags a hardcoded `threat_intel_mode="live"` kwarg.
_LIVE_KWARG_RE = re.compile(r"""threat_intel_mode\s*=\s*["']live["']""")
_SKIP_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__", "output"}


def test_no_call_site_hardcodes_live():
    offenders = []
    for path in REPO_ROOT.rglob("*.py"):
        if path == Path(__file__) or any(part in _SKIP_DIRS for part in path.parts):
            continue  # this file's own error message contains the pattern it scans for
        text = path.read_text(encoding="utf-8", errors="ignore")
        if _LIVE_KWARG_RE.search(text):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, (
        f'threat_intel_mode="live" hardcoded as a kwarg in: {offenders} -- '
        "live enrichment must only be reachable via an explicit CLI flag "
        "(docs/ERRATA.md item 4), never a hardcoded default."
    )
