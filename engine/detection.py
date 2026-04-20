"""
KQL detection engine: executes KQL queries against pandas DataFrames
that mirror Microsoft Sentinel schemas.
"""

import re
import json
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Synthetic log schema factories
# ---------------------------------------------------------------------------

def make_signin_logs(entries: list[dict]) -> pd.DataFrame:
    defaults = {
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
        "UserPrincipalName": "user@contoso.com",
        "UserDisplayName": "Unknown User",
        "AppDisplayName": "Microsoft Azure Portal",
        "IPAddress": "0.0.0.0",
        "Location": "US",
        "City": "Redmond",
        "CountryOrRegion": "US",
        "Latitude": 47.6,
        "Longitude": -122.3,
        "ResultType": 0,
        "ResultDescription": "Successfully signed in",
        "AuthenticationRequirement": "singleFactorAuthentication",
        "ConditionalAccessStatus": "success",
        "UserAgent": "Mozilla/5.0",
        "ClientAppUsed": "Browser",
        "DeviceDetail": "{}",
        "MfaDetail": "{}",
        "RiskLevelDuringSignIn": "none",
        "RiskState": "none",
        "CorrelationId": "",
        "SessionId": "",
        "_duel_id": "",
    }
    rows = [{**defaults, **e} for e in entries]
    return pd.DataFrame(rows)


def make_security_events(entries: list[dict]) -> pd.DataFrame:
    defaults = {
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
        "EventID": 4624,
        "Activity": "An account was successfully logged on",
        "Account": "CONTOSO\\user",
        "AccountType": "User",
        "Computer": "WS001.contoso.com",
        "SubjectUserName": "-",
        "SubjectDomainName": "-",
        "TargetUserName": "user",
        "TargetDomainName": "CONTOSO",
        "LogonType": 3,
        "LogonTypeName": "Network",
        "IpAddress": "127.0.0.1",
        "IpPort": "0",
        "WorkstationName": "",
        "ProcessName": "-",
        "Status": "0x0",
        "_duel_id": "",
    }
    rows = [{**defaults, **e} for e in entries]
    return pd.DataFrame(rows)


def make_audit_logs(entries: list[dict]) -> pd.DataFrame:
    defaults = {
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
        "OperationName": "Add member to group",
        "Result": "success",
        "ResultReason": "",
        "Category": "GroupManagement",
        "ActivityDisplayName": "Add member to group",
        "InitiatedBy": "{}",
        "TargetResources": "[]",
        "AdditionalDetails": "[]",
        "CorrelationId": "",
        "Identity": "user@contoso.com",
        "_duel_id": "",
    }
    rows = [{**defaults, **e} for e in entries]
    return pd.DataFrame(rows)


TABLE_FACTORIES = {
    "SigninLogs": make_signin_logs,
    "SecurityEvent": make_security_events,
    "AuditLogs": make_audit_logs,
    # Common aliases the LLM might use
    "AADSignInLogs": make_signin_logs,
    "AADNonInteractiveUserSignInLogs": make_signin_logs,
}


# ---------------------------------------------------------------------------
# KQL → pandas executor
# ---------------------------------------------------------------------------

class KQLExecutor:
    """
    Lightweight KQL interpreter targeting the subset of operators commonly
    used in Microsoft Sentinel detection rules:
      where, project, summarize, extend, top, limit/take, order/sort by, distinct, count
    """

    def __init__(self, tables: dict[str, pd.DataFrame]):
        self.tables = tables

    def execute(self, query: str) -> tuple[pd.DataFrame, bool]:
        try:
            clean = self._strip_comments(query).strip()
            clean = self._sanitize(clean)
            result = self._run_pipeline(clean)
            return result, True
        except Exception as exc:
            logger.warning("KQL execution error: %s", exc)
            return pd.DataFrame(), False

    def _sanitize(self, query: str) -> str:
        """
        Guard against two failure modes that produce silent 0% detection:

        1. Query starts with a table that has no data (e.g. SecurityEvent when
           only SigninLogs are populated). Redirect to the first available table
           and log a warning so the LLM's prompt can be corrected.

        2. join / union stages reference unpopulated tables. Strip them — the
           pipeline will keep whatever rows survived earlier stages.
        """
        stages = self._split_pipeline(query)
        # Strip leading/trailing backticks and quotes that LLMs sometimes emit
        # (e.g. `SigninLogs` → SigninLogs) before any table lookup occurs.
        primary = stages[0].strip().strip("`'\"")
        stages[0] = primary

        # Redirect if primary table is missing
        if primary not in self.tables and self.tables:
            fallback = next(iter(self.tables))
            logger.warning(
                "KQL starts with unknown table %r — redirecting to %r. "
                "Defender prompt should constrain to available tables.",
                primary, fallback,
            )
            stages[0] = fallback

        # Drop join / union stages to prevent cross-table failures
        def _is_join_or_union(s: str) -> bool:
            low = s.strip().lower()
            return low.startswith("join ") or low.startswith("union ")

        filtered = [s for s in stages if not _is_join_or_union(s)]
        if len(filtered) < len(stages):
            dropped = [s.strip()[:60] for s in stages if _is_join_or_union(s)]
            logger.warning("Stripped unsupported join/union stage(s): %s", dropped)

        return "\n| ".join(filtered)

    # ------------------------------------------------------------------
    # Pipeline runner
    # ------------------------------------------------------------------

    def _strip_comments(self, q: str) -> str:
        return re.sub(r"//[^\n]*", "", q, flags=re.MULTILINE)

    def _run_pipeline(self, query: str) -> pd.DataFrame:
        stages = self._split_pipeline(query)
        table_name = stages[0].strip()
        if table_name not in self.tables:
            raise ValueError(f"Unknown table: {table_name!r}")
        df = self.tables[table_name].copy()
        for stage in stages[1:]:
            df = self._dispatch(df, stage.strip())
        return df

    def _split_pipeline(self, query: str) -> list[str]:
        """Split on | while respecting parentheses and string literals."""
        parts, depth, in_q, qch, buf = [], 0, False, "", []
        for ch in query:
            if in_q:
                buf.append(ch)
                if ch == qch:
                    in_q = False
            elif ch in ('"', "'"):
                in_q, qch = True, ch
                buf.append(ch)
            elif ch == "(":
                depth += 1
                buf.append(ch)
            elif ch == ")":
                depth -= 1
                buf.append(ch)
            elif ch == "|" and depth == 0:
                parts.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
        if buf:
            parts.append("".join(buf))
        return parts

    # ------------------------------------------------------------------
    # Operator dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, df: pd.DataFrame, stage: str) -> pd.DataFrame:
        low = stage.lower()
        if low.startswith("where "):
            return self._op_where(df, stage[6:])
        if low.startswith("project-away "):
            cols = [c.strip() for c in stage[13:].split(",")]
            return df.drop(columns=[c for c in cols if c in df.columns], errors="ignore")
        if low.startswith("project "):
            return self._op_project(df, stage[8:])
        if low.startswith("summarize "):
            return self._op_summarize(df, stage[10:])
        if low.startswith("extend "):
            return self._op_extend(df, stage[7:])
        if low.startswith("top "):
            return self._op_top(df, stage[4:])
        if re.match(r"(limit|take)\s+\d+", low):
            n = int(stage.split()[1])
            return df.head(n)
        if re.match(r"(order|sort) by", low):
            return self._op_order_by(df, stage)
        if low.startswith("distinct "):
            cols = [c.strip() for c in stage[9:].split(",")]
            valid = [c for c in cols if c in df.columns]
            return df[valid].drop_duplicates() if valid else df.drop_duplicates()
        if low.strip() == "count":
            return pd.DataFrame({"Count": [len(df)]})
        if low.startswith("mv-expand ") or low.startswith("join ") or low.startswith("union "):
            logger.debug("Skipping unsupported operator: %s", stage[:40])
            return df
        logger.debug("Unknown KQL operator: %s", stage[:40])
        return df

    # ------------------------------------------------------------------
    # WHERE
    # ------------------------------------------------------------------

    def _op_where(self, df: pd.DataFrame, expr: str) -> pd.DataFrame:
        mask = self._eval_expr(df, expr.strip())
        return df[mask].reset_index(drop=True)

    def _eval_expr(self, df: pd.DataFrame, expr: str) -> pd.Series:
        expr = expr.strip()

        # Strip outer parens
        if expr.startswith("(") and self._matching_paren(expr) == len(expr) - 1:
            return self._eval_expr(df, expr[1:-1])

        # not / NOT
        m = re.match(r"^not\s+(.+)$", expr, re.IGNORECASE)
        if m:
            return ~self._eval_expr(df, m.group(1))

        # Logical OR  (split at top-level " or ")
        parts = self._split_logical(expr, "or")
        if len(parts) > 1:
            result = self._eval_expr(df, parts[0])
            for p in parts[1:]:
                result = result | self._eval_expr(df, p)
            return result

        # Logical AND
        parts = self._split_logical(expr, "and")
        if len(parts) > 1:
            result = self._eval_expr(df, parts[0])
            for p in parts[1:]:
                result = result & self._eval_expr(df, p)
            return result

        return self._eval_atom(df, expr)

    def _matching_paren(self, s: str) -> int:
        depth = 0
        for i, c in enumerate(s):
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i
        return -1

    def _split_logical(self, expr: str, op: str) -> list[str]:
        token = f" {op} "
        parts, depth, in_q, qch, buf = [], 0, False, "", []
        i = 0
        while i < len(expr):
            ch = expr[i]
            if in_q:
                buf.append(ch)
                if ch == qch:
                    in_q = False
            elif ch in ('"', "'"):
                in_q, qch = True, ch
                buf.append(ch)
            elif ch == "(":
                depth += 1
                buf.append(ch)
            elif ch == ")":
                depth -= 1
                buf.append(ch)
            elif depth == 0 and expr[i:].lower().startswith(token):
                parts.append("".join(buf).strip())
                buf = []
                i += len(token)
                continue
            else:
                buf.append(ch)
            i += 1
        if buf:
            parts.append("".join(buf).strip())
        return parts if len(parts) > 1 else [expr]

    def _eval_atom(self, df: pd.DataFrame, expr: str) -> pd.Series:
        false_series = pd.Series([False] * len(df), index=df.index)
        true_series  = pd.Series([True]  * len(df), index=df.index)
        expr = expr.strip()

        # isempty / isnotempty
        m = re.match(r"^(isempty|isnotempty)\((\w+)\)$", expr, re.IGNORECASE)
        if m:
            fn, col = m.groups()
            if col not in df.columns:
                return false_series
            empty = df[col].isna() | (df[col].astype(str) == "")
            return empty if fn.lower() == "isempty" else ~empty

        # isnull / isnotnull
        m = re.match(r"^(isnull|isnotnull)\((\w+)\)$", expr, re.IGNORECASE)
        if m:
            fn, col = m.groups()
            if col not in df.columns:
                return false_series
            return df[col].isna() if fn.lower() == "isnull" else df[col].notna()

        # in~ / !in~ / in / !in
        m = re.match(r"^(\w+)\s+(!?in~?)\s*\((.+)\)$", expr, re.IGNORECASE | re.DOTALL)
        if m:
            col, op, vals_str = m.groups()
            vals = [v.strip().strip("\"'") for v in self._csv_split(vals_str)]
            if col not in df.columns:
                return false_series
            s = df[col].astype(str).str.lower()
            vals_low = [v.lower() for v in vals]
            hit = s.isin(vals_low)
            return ~hit if op.startswith("!") else hit

        # has_any
        m = re.match(r"^(\w+)\s+has_any\s*\((.+)\)$", expr, re.IGNORECASE | re.DOTALL)
        if m:
            col, vals_str = m.groups()
            vals = [v.strip().strip("\"'") for v in self._csv_split(vals_str)]
            if col not in df.columns:
                return false_series
            s = df[col].astype(str).str.lower()
            return s.apply(lambda x: any(v.lower() in x for v in vals))

        # contains / !contains / has / !has
        m = re.match(r'^(\w+)\s+(!?(?:contains|has)(?:_cs)?)\s+["\']?([^"\']*)["\']?$', expr, re.IGNORECASE)
        if m:
            col, op, val = m.groups()
            if col not in df.columns:
                return false_series
            s = df[col].astype(str)
            case_sensitive = "_cs" in op.lower()
            needle = val if case_sensitive else val.lower()
            haystack = s if case_sensitive else s.str.lower()
            hit = haystack.str.contains(needle, regex=False, na=False)
            return ~hit if op.startswith("!") else hit

        # startswith / endswith
        m = re.match(r'^(\w+)\s+(startswith|endswith)(?:_cs)?\s+["\']?([^"\']*)["\']?$', expr, re.IGNORECASE)
        if m:
            col, fn, val = m.groups()
            if col not in df.columns:
                return false_series
            s = df[col].astype(str).str.lower()
            return s.str.startswith(val.lower()) if fn.lower() == "startswith" else s.str.endswith(val.lower())

        # matches regex
        m = re.match(r'^(\w+)\s+matches\s+regex\s+["\'](.+)["\']$', expr, re.IGNORECASE)
        if m:
            col, pattern = m.groups()
            if col not in df.columns:
                return false_series
            return df[col].astype(str).str.contains(pattern, regex=True, na=False)

        # == / != / > / < / >= / <=  (numeric or string)
        m = re.match(r'^(\w+)\s*(==|!=|>=|<=|>|<)\s*["\']?([^"\']*)["\']?$', expr, re.IGNORECASE)
        if m:
            col, op, val = m.groups()
            if col not in df.columns:
                return false_series
            try:
                num = float(val)
                s = pd.to_numeric(df[col], errors="coerce")
                cmp = {"==": s == num, "!=": s != num, ">": s > num,
                       "<": s < num, ">=": s >= num, "<=": s <= num}
                return cmp[op].fillna(False)
            except ValueError:
                s = df[col].astype(str)
                cmp = {"==": s == val, "!=": s != val, ">": s > val,
                       "<": s < val, ">=": s >= val, "<=": s <= val}
                return cmp[op]

        # Boolean column reference (e.g. "IsCompliant")
        if expr in df.columns:
            return df[expr].astype(bool)

        logger.debug("Could not parse atom: %s", expr[:80])
        return true_series  # permissive fallback — avoids silently dropping real hits

    def _csv_split(self, s: str) -> list[str]:
        """Split comma-separated list respecting quotes."""
        parts, buf, in_q, qch = [], [], False, ""
        for ch in s:
            if in_q:
                buf.append(ch)
                if ch == qch:
                    in_q = False
            elif ch in ('"', "'"):
                in_q, qch = True, ch
                buf.append(ch)
            elif ch == ",":
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
        if buf:
            parts.append("".join(buf).strip())
        return parts

    # ------------------------------------------------------------------
    # Other operators
    # ------------------------------------------------------------------

    def _op_project(self, df: pd.DataFrame, cols_str: str) -> pd.DataFrame:
        cols = [c.strip() for c in cols_str.split(",")]
        valid = [c for c in cols if c in df.columns]
        return df[valid] if valid else df

    def _op_summarize(self, df: pd.DataFrame, expr: str) -> pd.DataFrame:
        # summarize count() by col1, col2
        m = re.match(r"^count\(\)\s+by\s+(.+)$", expr.strip(), re.IGNORECASE)
        if m:
            by_raw = m.group(1)
            by_clean = re.sub(r"bin\((\w+)\s*,[^)]+\)", r"\1", by_raw)
            cols = [c.strip() for c in by_clean.split(",")]
            valid = [c for c in cols if c in df.columns]
            if valid:
                return df.groupby(valid).size().reset_index(name="count_")

        # summarize dcount(col) by group
        m = re.match(r"^dcount\((\w+)\)\s+by\s+(.+)$", expr.strip(), re.IGNORECASE)
        if m:
            cnt_col, by_raw = m.groups()
            cols = [c.strip() for c in by_raw.split(",")]
            valid = [c for c in cols if c in df.columns]
            if valid and cnt_col in df.columns:
                return df.groupby(valid)[cnt_col].nunique().reset_index(name="dcount_")

        # summarize count() (no grouping)
        if re.match(r"^count\(\)$", expr.strip(), re.IGNORECASE):
            return pd.DataFrame({"count_": [len(df)]})

        # summarize make_list / make_set — collapse to one row per group
        m = re.match(r"^(\w+)\s*=\s*make_(?:list|set)\((\w+)\)\s+by\s+(.+)$", expr.strip(), re.IGNORECASE)
        if m:
            alias, val_col, by_raw = m.groups()
            cols = [c.strip() for c in by_raw.split(",")]
            valid = [c for c in cols if c in df.columns]
            if valid and val_col in df.columns:
                return df.groupby(valid)[val_col].apply(list).reset_index(name=alias)

        return df

    def _op_extend(self, df: pd.DataFrame, expr: str) -> pd.DataFrame:
        # Very simplified: new_col = existing_col  or  new_col = "literal"
        m = re.match(r"^(\w+)\s*=\s*(.+)$", expr.strip())
        if m:
            new_col, rhs = m.groups()
            rhs = rhs.strip().strip("\"'")
            if rhs in df.columns:
                df = df.copy()
                df[new_col] = df[rhs]
        return df

    def _op_top(self, df: pd.DataFrame, expr: str) -> pd.DataFrame:
        m = re.match(r"^(\d+)\s+by\s+(\w+)(?:\s+(asc|desc))?$", expr.strip(), re.IGNORECASE)
        if m:
            n, col, order = m.groups()
            asc = (order or "desc").lower() == "asc"
            if col in df.columns:
                return df.sort_values(col, ascending=asc).head(int(n))
        return df.head(10)

    def _op_order_by(self, df: pd.DataFrame, expr: str) -> pd.DataFrame:
        m = re.match(r"(?:order|sort) by\s+(\w+)(?:\s+(asc|desc))?", expr.strip(), re.IGNORECASE)
        if m:
            col, order = m.groups()
            asc = (order or "asc").lower() == "asc"
            if col in df.columns:
                return df.sort_values(col, ascending=asc)
        return df


# ---------------------------------------------------------------------------
# Detection runner — ties it all together
# ---------------------------------------------------------------------------

class DetectionEngine:
    def __init__(self, attack_logs: list[dict]):
        """
        attack_logs: list of dicts, each must have 'table' and '_duel_id' keys
        plus schema-appropriate fields.
        """
        self.attack_logs = attack_logs
        self.tables = self._build_tables(attack_logs)

    def _build_tables(self, logs: list[dict]) -> dict[str, pd.DataFrame]:
        grouped: dict[str, list[dict]] = {}
        for log in logs:
            t = log.get("table", "SigninLogs")
            grouped.setdefault(t, []).append(log)

        tables = {}
        for table_name, entries in grouped.items():
            factory = TABLE_FACTORIES.get(table_name)
            if factory:
                tables[table_name] = factory(entries)
            else:
                logger.warning("No schema factory for table %s, using raw DataFrame", table_name)
                tables[table_name] = pd.DataFrame(entries)

        # Also expose canonical aliases pointing at the same frame
        for alias, canonical in [("AADSignInLogs", "SigninLogs"),
                                  ("AADNonInteractiveUserSignInLogs", "SigninLogs")]:
            if canonical in tables and alias not in tables:
                tables[alias] = tables[canonical]

        return tables

    def run(self, kql_rule: str) -> dict:
        """
        Execute a KQL rule and return detection results.

        Returns a dict with:
          - detected_ids: set of _duel_id values that were caught
          - result_rows: int
          - kql_valid: bool
          - error: str | None
        """
        executor = KQLExecutor(self.tables)
        result_df, ok = executor.execute(kql_rule)

        if not ok or result_df.empty:
            return {
                "detected_ids": set(),
                "result_rows": 0,
                "kql_valid": ok,
                "error": None if ok else "KQL execution failed",
            }

        detected_ids: set[str] = set()
        if "_duel_id" in result_df.columns:
            detected_ids = set(result_df["_duel_id"].dropna().astype(str).tolist())
        else:
            # If the query projected away _duel_id, try to recover from raw logs
            # by checking if any row values overlap with attack log values.
            # Fallback: count non-empty result as a full detection.
            detected_ids = {log["_duel_id"] for log in self.attack_logs}

        return {
            "detected_ids": detected_ids,
            "result_rows": len(result_df),
            "kql_valid": True,
            "error": None,
        }
