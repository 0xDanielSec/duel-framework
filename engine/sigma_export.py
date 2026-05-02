"""
DUEL — Sigma Export Engine
Converts surviving KQL rules from battle logs into Sigma detection rules,
enabling deployment to any SIEM that supports the Sigma standard.
"""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OUTPUT_DIR     = Path(__file__).parent.parent / "output"
SIGMA_DIR      = OUTPUT_DIR / "sigma"
TECHNIQUES_DIR = Path(__file__).parent.parent / "techniques"

# ── Logsource mapping ────────────────────────────────────────────────────────

LOGSOURCE_MAP: dict[str, dict[str, str]] = {
    "SigninLogs":       {"category": "authentication", "product": "azure"},
    "AADSignInLogs":    {"category": "authentication", "product": "azure"},
    "AuditLogs":        {"category": "iam",            "product": "azure"},
    "AzureActivity":    {"category": "cloud",          "product": "azure"},
    "OfficeActivity":   {"category": "email",          "product": "microsoft365"},
    "AzureDiagnostics": {"category": "network",        "product": "azure"},
    "SecurityEvent":    {"service":  "security",       "product": "windows"},
}

TACTIC_SLUG: dict[str, str] = {
    "Initial Access":       "initial_access",
    "Execution":            "execution",
    "Persistence":          "persistence",
    "Privilege Escalation": "privilege_escalation",
    "Defense Evasion":      "defense_evasion",
    "Credential Access":    "credential_access",
    "Discovery":            "discovery",
    "Lateral Movement":     "lateral_movement",
    "Collection":           "collection",
    "Command and Control":  "command_and_control",
    "Exfiltration":         "exfiltration",
    "Impact":               "impact",
}

_LEVEL_MAP = {"High": "high", "Medium": "medium", "Low": "low"}

_FALSE_POSITIVES = [
    "Legitimate administrative activity",
    "Authorized security testing",
]

# ── KQL → Sigma detection parser ─────────────────────────────────────────────

# Patterns to extract conditions from a single `where` expression
_EQ_RE    = re.compile(r'(\w+)\s*==\s*(["\']?)([^|&\)\s]+)\2', re.IGNORECASE)
_NEQ_RE   = re.compile(r'(\w+)\s*!=\s*(["\']?)([^|&\)\s]+)\2', re.IGNORECASE)
_HAS_RE   = re.compile(r'(\w+)\s+(?:has|contains)\s+"([^"]+)"', re.IGNORECASE)
_SW_RE    = re.compile(r'(\w+)\s+startswith\s+"([^"]+)"', re.IGNORECASE)
_EW_RE    = re.compile(r'(\w+)\s+endswith\s+"([^"]+)"', re.IGNORECASE)
_IN_RE    = re.compile(r'(\w+)\s+in[~]?\s*\(([^)]+)\)', re.IGNORECASE)
_HANY_RE  = re.compile(r'(\w+)\s+has_any\s*\(([^)]+)\)', re.IGNORECASE)

# Strip outer quotes from a token
def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] in ('"', "'") and s[-1] == s[0]:
        return s[1:-1]
    return s


def _parse_in_list(raw: str) -> list[str]:
    """Parse a comma-separated, quote-wrapped list from an `in(...)` clause."""
    items = []
    for part in raw.split(","):
        v = _unquote(part.strip())
        if v:
            items.append(v)
    return items


def _coerce(val: str) -> Any:
    """Try int/float coercion; fall back to string."""
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val


def _extract_table(kql: str) -> str:
    """Return the first bare word on the first non-empty line (the table name)."""
    for line in kql.splitlines():
        line = line.strip().lstrip("`'\"")
        if line and not line.startswith("|"):
            return line.split()[0]
    return "SigninLogs"


def _parse_where_clauses(kql: str) -> list[str]:
    """Return the expression part of each `| where ...` pipe stage."""
    clauses = []
    for line in kql.splitlines():
        m = re.match(r'\s*\|\s*where\s+(.+)', line, re.IGNORECASE)
        if m:
            clauses.append(m.group(1).strip())
    return clauses


def _build_sigma_detection(clauses: list[str]) -> tuple[dict, list[str]]:
    """
    Convert a list of KQL where-clause expressions to a Sigma detection dict.
    Returns (detection_dict, notes) where notes describes anything that
    couldn't be converted.
    """
    selection: dict[str, Any] = {}
    notes: list[str] = []

    for clause in clauses:
        # Skip pure negations — Sigma filter blocks are more complex; note them
        if clause.strip().lower().startswith("not "):
            notes.append(f"Negation skipped (add as Sigma filter): {clause[:80]}")
            continue

        # has_any(...)
        for m in _HANY_RE.finditer(clause):
            field, raw = m.group(1), m.group(2)
            vals = _parse_in_list(raw)
            if vals:
                key = f"{field}|contains"
                _merge_list(selection, key, vals)

        # in(...) / in~(...)
        for m in _IN_RE.finditer(clause):
            field, raw = m.group(1), m.group(2)
            vals = _parse_in_list(raw)
            if vals:
                _merge_list(selection, field, [_coerce(v) for v in vals])

        # startswith / endswith (before has/contains to avoid substring clash)
        for m in _SW_RE.finditer(clause):
            field, val = m.group(1), m.group(2)
            _merge_list(selection, f"{field}|startswith", [val])

        for m in _EW_RE.finditer(clause):
            field, val = m.group(1), m.group(2)
            _merge_list(selection, f"{field}|endswith", [val])

        # has / contains
        for m in _HAS_RE.finditer(clause):
            field, val = m.group(1), m.group(2)
            _merge_list(selection, f"{field}|contains", [val])

        # == equality (after in/has to avoid double-matching)
        for m in _EQ_RE.finditer(clause):
            field, val = m.group(1), _unquote(m.group(3))
            # Skip if already covered by an in() or has() match
            if field in selection or f"{field}|contains" in selection:
                continue
            selection[field] = _coerce(val)

        # != — convert to Sigma filter keyword note
        for m in _NEQ_RE.finditer(clause):
            field, val = m.group(1), _unquote(m.group(3))
            notes.append(f"Inequality skipped (add as Sigma filter): {field} != {val}")

    if not selection:
        # Fallback: include entire KQL as a comment so the rule isn't empty
        selection["Keywords"] = ["DUEL-generated-rule"]
        notes.append("KQL too complex to parse; manual conversion required")

    return {"selection": selection, "condition": "selection"}, notes


def _merge_list(d: dict, key: str, vals: list) -> None:
    """Merge values into a list entry, or scalar if single value."""
    existing = d.get(key)
    if existing is None:
        d[key] = vals[0] if len(vals) == 1 else vals
    elif isinstance(existing, list):
        for v in vals:
            if v not in existing:
                existing.append(v)
    else:
        if vals[0] != existing:
            d[key] = [existing] + [v for v in vals if v != existing]


# ── YAML serialiser ───────────────────────────────────────────────────────────

def _sigma_yaml(rule: dict) -> str:
    """
    Serialise a Sigma rule dict to a YAML string that follows Sigma conventions:
    - string scalars quoted only when necessary
    - list items prefixed with '- '
    - nested dicts indented with 2 spaces
    """
    lines: list[str] = []

    def _emit(obj: Any, indent: int = 0) -> None:
        pad = " " * indent
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, dict):
                    lines.append(f"{pad}{k}:")
                    _emit(v, indent + 2)
                elif isinstance(v, list):
                    lines.append(f"{pad}{k}:")
                    for item in v:
                        lines.append(f"{pad}  - {_scalar(item)}")
                else:
                    lines.append(f"{pad}{k}: {_scalar(v)}")
        elif isinstance(obj, list):
            for item in obj:
                lines.append(f"{pad}- {_scalar(item)}")
        else:
            lines.append(f"{pad}{_scalar(obj)}")

    def _scalar(v: Any) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        s = str(v)
        # Quote if contains special YAML chars or starts with special chars
        need_quote = any(c in s for c in (':', '#', '[', ']', '{', '}', ',', '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`', '"', "'", '\n')) or s.lower() in ('true', 'false', 'null', 'yes', 'no') or (s and s[0] in ('"', "'"))
        if need_quote:
            escaped = s.replace("'", "''")
            return f"'{escaped}'"
        return s

    _emit(rule)
    return "\n".join(lines) + "\n"


# ── SigmaExporter ─────────────────────────────────────────────────────────────

class SigmaExporter:
    def __init__(self):
        self._tech_cache: dict[str, dict] = {}

    def _load_technique(self, technique_id: str) -> dict:
        if technique_id not in self._tech_cache:
            path = TECHNIQUES_DIR / f"{technique_id}.json"
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    self._tech_cache[technique_id] = json.load(f)
            else:
                self._tech_cache[technique_id] = {
                    "technique_id": technique_id,
                    "name": technique_id,
                    "tactic": "Defense Evasion",
                }
        return self._tech_cache[technique_id]

    def load_rules(self, technique_filter: str | None = None) -> list[dict]:
        """Load surviving rules from all full_battle_log_*.json files."""
        rules: list[dict] = []

        pattern = (
            f"full_battle_log_{technique_filter}.json"
            if technique_filter else "full_battle_log_*.json"
        )
        for log_path in sorted(OUTPUT_DIR.glob(pattern)):
            try:
                with open(log_path, encoding="utf-8") as f:
                    battle = json.load(f)
            except Exception:
                continue

            tid = battle.get("technique_id", "")
            if not tid or not isinstance(battle.get("rounds"), list):
                continue

            tech = self._load_technique(tid)
            for rnd in battle["rounds"]:
                det = float(rnd.get("detection_rate", 0.0))
                if det <= 0:
                    continue
                kql = rnd.get("kql_rule", "").strip()
                if not kql:
                    continue
                eva = float(rnd.get("evasion_rate", 0.0))
                rules.append({
                    "id":             f"{tid}_round{rnd.get('round', 0)}",
                    "technique_id":   tid,
                    "technique_name": tech.get("name", tid),
                    "tactic":         tech.get("tactic", "Defense Evasion"),
                    "round":          rnd.get("round", 0),
                    "detection_rate": round(det, 4),
                    "evasion_rate":   round(eva, 4),
                    "severity":       _sev(eva),
                    "kql":            kql,
                })

        # Deduplicate: latest battle wins per (technique_id, round)
        seen: dict[str, dict] = {}
        for r in rules:
            key = r["id"]
            if key not in seen or r["detection_rate"] > seen[key]["detection_rate"]:
                seen[key] = r
        return sorted(seen.values(), key=lambda r: (r["technique_id"], r["round"]))

    def to_sigma_rule(self, rule: dict) -> tuple[str, list[str]]:
        """
        Convert a rule dict to a Sigma YAML string.
        Returns (yaml_str, conversion_notes).
        """
        kql    = rule["kql"]
        table  = _extract_table(kql)
        ls     = LOGSOURCE_MAP.get(table, {"category": "cloud", "product": "azure"})
        tid    = rule["technique_id"]
        tactic = rule["tactic"].split(",")[0].strip()
        tslug  = TACTIC_SLUG.get(tactic, tactic.lower().replace(" ", "_"))
        level  = _LEVEL_MAP.get(rule["severity"], "medium")
        today  = datetime.now(timezone.utc).strftime("%Y/%m/%d")
        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, rule["id"] + "-sigma"))

        clauses = _parse_where_clauses(kql)
        detection, notes = _build_sigma_detection(clauses)

        sigma: dict[str, Any] = {
            "title": f"DUEL - {tid} - {tactic} - Round {rule['round']}",
            "id": rule_id,
            "status": "experimental",
            "description": (
                f"Auto-generated by DUEL adversarial testing. "
                f"Technique: {tid} ({rule['technique_name']}). "
                f"Tactic: {rule['tactic']}. "
                f"Simulation detection rate: {rule['detection_rate']:.0%}. "
                f"Evasion rate: {rule['evasion_rate']:.0%}. "
                f"Survived round {rule['round']} of adversarial LLM testing."
            ),
            "author": "DUEL Framework — adversarial generation",
            "date": today,
            "modified": today,
            "logsource": ls,
            "detection": detection,
            "falsepositives": _FALSE_POSITIVES,
            "level": level,
            "tags": [
                f"attack.{tid.lower()}",
                f"attack.{tslug}",
            ],
        }

        return _sigma_yaml(sigma), notes

    def export(
        self,
        technique_filter: str | None = None,
    ) -> tuple[list[Path], Path]:
        """
        Export all surviving rules as individual .yml files to output/sigma/.
        Returns (list_of_yml_paths, summary_md_path).
        """
        SIGMA_DIR.mkdir(parents=True, exist_ok=True)
        rules = self.load_rules(technique_filter)

        paths: list[Path] = []
        summary_rows: list[dict] = []

        for rule in rules:
            yml_str, notes = self.to_sigma_rule(rule)
            fname = f"{rule['technique_id']}_round{rule['round']}.yml"
            path  = SIGMA_DIR / fname
            path.write_text(yml_str, encoding="utf-8")
            paths.append(path)
            summary_rows.append({
                "file":           fname,
                "technique_id":   rule["technique_id"],
                "technique_name": rule["technique_name"],
                "round":          rule["round"],
                "detection_rate": rule["detection_rate"],
                "evasion_rate":   rule["evasion_rate"],
                "severity":       rule["severity"],
                "notes":          notes,
            })

        md_path = self._write_summary(summary_rows)
        return paths, md_path

    def export_all(self) -> dict:
        """
        Export all surviving rules from every battle log to output/sigma/.
        Returns a summary dict: {count, paths, summary_path}.
        """
        paths, summary_path = self.export(technique_filter=None)
        return {
            "count": len(paths),
            "paths": [str(p) for p in paths],
            "summary_path": str(summary_path),
        }

    def _write_summary(self, rows: list[dict]) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            "# DUEL — Sigma Rules Export Summary",
            "",
            f"**Generated:** {ts}  ",
            f"**Total rules exported:** {len(rows)}  ",
            "",
            "Sigma rules are saved individually to `output/sigma/`.  ",
            "Use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) or "
            "[pySigma](https://github.com/SigmaHQ/pySigma) to convert to "
            "your target SIEM backend.",
            "",
            "```bash",
            "# Convert to Splunk SPL",
            "sigma convert -t splunk output/sigma/*.yml",
            "",
            "# Convert to Elastic EQL",
            "sigma convert -t elasticsearch output/sigma/*.yml",
            "",
            "# Convert to QRadar AQL",
            "sigma convert -t qradar output/sigma/*.yml",
            "```",
            "",
            "## Exported Rules",
            "",
            "| File | Technique | Round | Det % | Eva % | Level | Notes |",
            "|------|-----------|:-----:|:-----:|:-----:|:-----:|-------|",
        ]
        for r in rows:
            note_str = "; ".join(r["notes"]) if r["notes"] else "—"
            lines.append(
                f"| `{r['file']}` | {r['technique_id']} | "
                f"R{r['round']} | {r['detection_rate']:.0%} | "
                f"{r['evasion_rate']:.0%} | {r['severity'].lower()} | {note_str} |"
            )

        lines += [
            "",
            "---",
            "",
            "## Logsource Mappings",
            "",
            "| Sentinel Table | Sigma Category | Product |",
            "|----------------|:--------------|:--------|",
        ]
        for table, ls in LOGSOURCE_MAP.items():
            cat = ls.get("category") or ls.get("service", "—")
            prod = ls.get("product", "—")
            lines.append(f"| `{table}` | `{cat}` | `{prod}` |")

        lines += [
            "",
            "---",
            "*Generated by DUEL — Dual Unified Evasion Loop*",
        ]

        md_path = OUTPUT_DIR / "sigma_export_summary.md"
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return md_path


def _sev(evasion_rate: float) -> str:
    if evasion_rate > 0.8:
        return "High"
    if evasion_rate >= 0.5:
        return "Medium"
    return "Low"
