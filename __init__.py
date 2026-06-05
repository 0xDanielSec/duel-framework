"""
DUEL — Dual Unified Evasion Loop

Adversarial LLM security framework where two AI agents battle across 38
MITRE ATT&CK and OWASP LLM techniques. The Attacker generates synthetic
Microsoft Sentinel telemetry; the Defender writes KQL detection rules.
A deterministic detection engine scores every round.

Quickstart (CLI):
    duel --technique T1078.004 --rounds 5
    duel-server          # → http://localhost:8000
    duel-mcp             # MCP server for Claude Desktop / Cursor

Full installation (web UI + MCP require data files from source):
    git clone https://github.com/0xDanielSec/duel-framework.git
    pip install -e .
"""

__version__ = "1.0.0"
__author__ = "Daniel Gomes"
__email__ = "dani.gomesvr@gmail.com"
__license__ = "MIT"
__description__ = (
    "Adversarial LLM security framework — two AI agents battle across "
    "38 MITRE ATT&CK and OWASP LLM techniques"
)
