"""
Unit tests for the extended KQL detection engine.
Run with: python -m pytest engine/test_detection.py -v
"""

import pytest
import pandas as pd
from datetime import datetime, timezone, timedelta
from engine.detection import KQLExecutor, make_signin_logs, make_security_events


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(offset_hours: int = 0) -> str:
    t = datetime.now(timezone.utc) + timedelta(hours=offset_hours)
    return t.isoformat()


def signin_table(rows: list[dict]) -> dict[str, pd.DataFrame]:
    return {"SigninLogs": make_signin_logs(rows)}


def dual_tables(signin_rows: list[dict], sec_rows: list[dict]) -> dict[str, pd.DataFrame]:
    return {
        "SigninLogs":    make_signin_logs(signin_rows),
        "SecurityEvent": make_security_events(sec_rows),
    }


def run(query: str, tables: dict) -> tuple[pd.DataFrame, bool]:
    return KQLExecutor(tables).execute(query)


# ---------------------------------------------------------------------------
# let statements
# ---------------------------------------------------------------------------

class TestLetStatements:
    def test_scalar_number(self):
        tables = signin_table([
            {"ResultType": 50126, "_duel_id": "a"},
            {"ResultType": 0,     "_duel_id": "b"},
        ])
        q = """
let failCode = 50126;
SigninLogs
| where ResultType == failCode
"""
        df, ok = run(q, tables)
        assert ok
        assert len(df) == 1
        assert df.iloc[0]["_duel_id"] == "a"

    def test_scalar_string(self):
        tables = signin_table([
            {"AppDisplayName": "Teams",       "_duel_id": "a"},
            {"AppDisplayName": "SharePoint",  "_duel_id": "b"},
            {"AppDisplayName": "AzurePortal", "_duel_id": "c"},
        ])
        q = """
let target = "Teams";
SigninLogs
| where AppDisplayName == target
"""
        df, ok = run(q, tables)
        assert ok
        assert len(df) == 1
        assert df.iloc[0]["_duel_id"] == "a"

    def test_dynamic_list_in(self):
        tables = signin_table([
            {"AppDisplayName": "Teams",       "_duel_id": "a"},
            {"AppDisplayName": "SharePoint",  "_duel_id": "b"},
            {"AppDisplayName": "AzurePortal", "_duel_id": "c"},
        ])
        q = """
let suspiciousApps = dynamic(["Teams", "SharePoint"]);
SigninLogs
| where AppDisplayName in (suspiciousApps)
"""
        df, ok = run(q, tables)
        assert ok
        assert set(df["_duel_id"]) == {"a", "b"}

    def test_multiple_lets(self):
        tables = signin_table([
            {"ResultType": 50126, "Location": "RU", "_duel_id": "a"},
            {"ResultType": 50126, "Location": "US", "_duel_id": "b"},
            {"ResultType": 0,     "Location": "RU", "_duel_id": "c"},
        ])
        q = """
let failCode = 50126;
let riskCountry = "RU";
SigninLogs
| where ResultType == failCode and Location == riskCountry
"""
        df, ok = run(q, tables)
        assert ok
        assert len(df) == 1
        assert df.iloc[0]["_duel_id"] == "a"


# ---------------------------------------------------------------------------
# join
# ---------------------------------------------------------------------------

class TestJoin:
    def test_inner_join(self):
        tables = dual_tables(
            [
                {"IPAddress": "1.2.3.4", "_duel_id": "s1"},
                {"IPAddress": "9.9.9.9", "_duel_id": "s2"},
            ],
            [
                {"IpAddress": "1.2.3.4", "EventID": 4624, "_duel_id": "e1"},
                {"IpAddress": "5.5.5.5", "EventID": 4624, "_duel_id": "e2"},
            ],
        )
        q = """
SigninLogs
| join kind=inner (
    SecurityEvent | where EventID == 4624
) on $left.IPAddress == $right.IpAddress
"""
        df, ok = run(q, tables)
        assert ok
        assert len(df) == 1
        assert df.iloc[0]["IPAddress"] == "1.2.3.4"

    def test_leftanti_join(self):
        tables = dual_tables(
            [
                {"IPAddress": "1.2.3.4", "_duel_id": "s1"},
                {"IPAddress": "9.9.9.9", "_duel_id": "s2"},
            ],
            [
                {"IpAddress": "1.2.3.4", "EventID": 4624, "_duel_id": "e1"},
            ],
        )
        q = """
SigninLogs
| join kind=leftanti (
    SecurityEvent
) on $left.IPAddress == $right.IpAddress
"""
        df, ok = run(q, tables)
        assert ok
        # Only s2 has no matching security event
        assert len(df) == 1
        assert df.iloc[0]["_duel_id"] == "s2"

    def test_leftouter_join(self):
        tables = dual_tables(
            [
                {"IPAddress": "1.2.3.4", "_duel_id": "s1"},
                {"IPAddress": "9.9.9.9", "_duel_id": "s2"},
            ],
            [
                {"IpAddress": "1.2.3.4", "EventID": 4625, "_duel_id": "e1"},
            ],
        )
        q = """
SigninLogs
| join kind=leftouter (
    SecurityEvent
) on $left.IPAddress == $right.IpAddress
"""
        df, ok = run(q, tables)
        assert ok
        # Both sign-in rows preserved; s2's right-side columns are NaN
        assert len(df) == 2

    def test_join_subquery_failure_graceful(self):
        tables = signin_table([{"IPAddress": "1.2.3.4", "_duel_id": "s1"}])
        q = """
SigninLogs
| join kind=inner (
    NonExistentTable | where EventID == 4624
) on $left.IPAddress == $right.IpAddress
"""
        df, ok = run(q, tables)
        # Should degrade gracefully, returning the left side unchanged
        assert ok
        assert len(df) == 1


# ---------------------------------------------------------------------------
# make-series
# ---------------------------------------------------------------------------

class TestMakeSeries:
    def test_count_by_hour(self):
        base = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        rows = [
            {"TimeGenerated": (base + timedelta(minutes=i * 10)).isoformat(),
             "IPAddress": "1.2.3.4", "_duel_id": str(i)}
            for i in range(12)   # 12 rows over 2 hours
        ]
        tables = signin_table(rows)
        q = "SigninLogs | make-series count() on TimeGenerated step 1h by IPAddress"
        df, ok = run(q, tables)
        assert ok
        assert "count_" in df.columns
        assert "IPAddress" in df.columns
        assert df["count_"].sum() == 12

    def test_make_series_missing_time_col_graceful(self):
        tables = signin_table([{"_duel_id": "a"}])
        q = "SigninLogs | make-series count() on NoSuchColumn step 1h by IPAddress"
        df, ok = run(q, tables)
        assert ok   # graceful fallback returns original df


# ---------------------------------------------------------------------------
# arg_max / arg_min
# ---------------------------------------------------------------------------

class TestArgMaxMin:
    def test_arg_max_by_group(self):
        rows = [
            {"UserPrincipalName": "alice@c.com", "TimeGenerated": _ts(-3), "_duel_id": "a1"},
            {"UserPrincipalName": "alice@c.com", "TimeGenerated": _ts(-1), "_duel_id": "a2"},
            {"UserPrincipalName": "bob@c.com",   "TimeGenerated": _ts(-2), "_duel_id": "b1"},
            {"UserPrincipalName": "bob@c.com",   "TimeGenerated": _ts(0),  "_duel_id": "b2"},
        ]
        tables = signin_table(rows)
        q = "SigninLogs | summarize arg_max(TimeGenerated, *) by UserPrincipalName"
        df, ok = run(q, tables)
        assert ok
        assert len(df) == 2
        ids = set(df["_duel_id"])
        assert "a2" in ids
        assert "b2" in ids

    def test_arg_min_by_group(self):
        rows = [
            {"UserPrincipalName": "alice@c.com", "TimeGenerated": _ts(-3), "_duel_id": "a1"},
            {"UserPrincipalName": "alice@c.com", "TimeGenerated": _ts(-1), "_duel_id": "a2"},
        ]
        tables = signin_table(rows)
        q = "SigninLogs | summarize arg_min(TimeGenerated, *) by UserPrincipalName"
        df, ok = run(q, tables)
        assert ok
        assert len(df) == 1
        assert df.iloc[0]["_duel_id"] == "a1"

    def test_arg_max_no_group(self):
        rows = [
            {"TimeGenerated": _ts(-5), "_duel_id": "old"},
            {"TimeGenerated": _ts(0),  "_duel_id": "new"},
        ]
        tables = signin_table(rows)
        q = "SigninLogs | summarize arg_max(TimeGenerated, *)"
        df, ok = run(q, tables)
        assert ok
        assert len(df) == 1
        assert df.iloc[0]["_duel_id"] == "new"


# ---------------------------------------------------------------------------
# mv-expand
# ---------------------------------------------------------------------------

class TestMvExpand:
    def test_explode_list_column(self):
        raw = pd.DataFrame({
            "UserPrincipalName": ["alice@c.com", "bob@c.com"],
            "tags": [["admin", "vip"], ["guest"]],
            "_duel_id": ["a", "b"],
        })
        tables = {"SigninLogs": raw}
        q = "SigninLogs | mv-expand tags"
        df, ok = run(q, tables)
        assert ok
        assert len(df) == 3
        assert set(df["tags"]) == {"admin", "vip", "guest"}

    def test_mv_expand_missing_col_graceful(self):
        tables = signin_table([{"_duel_id": "a"}])
        q = "SigninLogs | mv-expand NoSuchColumn"
        df, ok = run(q, tables)
        assert ok
        assert len(df) == 1


# ---------------------------------------------------------------------------
# parse
# ---------------------------------------------------------------------------

class TestParse:
    def test_extract_version_from_useragent(self):
        rows = [
            {"UserAgent": "Mozilla/5.0 (Windows NT 10.0)", "_duel_id": "a"},
            {"UserAgent": "Mozilla/4.0 (compatible)",      "_duel_id": "b"},
        ]
        tables = signin_table(rows)
        q = 'SigninLogs | parse UserAgent with * "Mozilla/" version:string " " *'
        df, ok = run(q, tables)
        assert ok
        assert "version" in df.columns
        assert df[df["_duel_id"] == "a"]["version"].iloc[0] == "5.0"
        assert df[df["_duel_id"] == "b"]["version"].iloc[0] == "4.0"

    def test_extract_integer_field(self):
        rows = [{"UserAgent": "App/3 build/42", "_duel_id": "a"}]
        tables = signin_table(rows)
        q = 'SigninLogs | parse UserAgent with * "build/" build:int'
        df, ok = run(q, tables)
        assert ok
        assert "build" in df.columns
        assert df.iloc[0]["build"] == "42"

    def test_parse_missing_col_graceful(self):
        tables = signin_table([{"_duel_id": "a"}])
        q = 'SigninLogs | parse NoSuchCol with * "Mozilla/" version:string'
        df, ok = run(q, tables)
        assert ok
        assert len(df) == 1
