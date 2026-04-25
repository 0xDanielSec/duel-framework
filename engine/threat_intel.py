"""
Threat intelligence feed — fetches and caches IOCs from free OSINT sources.
Sources: Abuse.ch URLhaus, Feodo Tracker C2 IPs, AlienVault OTX (key-optional).
Results cached to output/threat_intel_cache.json with a 1-hour TTL.
"""

import json
import logging
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).parent.parent / "output"

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Known scripted/attack-tooling user agents — baseline even when feeds are down
_BASELINE_UAS: list[str] = [
    "python-requests/", "Go-http-client/", "curl/", "libwww-perl/",
    "masscan/", "zgrab/", "nmap scripting engine", "sqlmap/", "nikto/",
    "dirbuster", "gobuster", "nuclei/", "httpx/", "wfuzz/", "ffuf/",
]


def _is_ip(s: str) -> bool:
    return bool(_IP_RE.match(s.strip()))


class ThreatIntelFeed:
    """
    Fetches IOCs from three free OSINT sources and caches them locally.
    On each instantiation: reads cache if fresh, otherwise re-fetches.
    """

    CACHE_PATH = OUTPUT_DIR / "threat_intel_cache.json"
    CACHE_TTL  = 3600   # seconds before a refresh
    TIMEOUT    = 12     # HTTP timeout per source

    def __init__(self):
        self._iocs: dict[str, list[str]] = {
            "malicious_ips":        [],
            "malicious_domains":    [],
            "malicious_useragents": list(_BASELINE_UAS),
        }
        self._source_status: dict[str, str] = {}
        self._last_updated: str = ""
        self._load_or_refresh()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_iocs(self) -> dict[str, list[str]]:
        """Return all current IOC lists."""
        return dict(self._iocs)

    def get_sentinel_context(self) -> str:
        """
        Formatted string with top-20 IOCs per category, ready to inject
        into the Defender prompt as a THREAT INTELLIGENCE section.
        Returns empty string if no IOCs are available.
        """
        ips     = self._iocs["malicious_ips"][:20]
        domains = self._iocs["malicious_domains"][:20]
        uas     = self._iocs["malicious_useragents"][:20]

        if not ips and not domains:
            return ""

        ok_sources = [k for k, v in self._source_status.items() if v == "ok"]
        lines = [
            "╔══ LIVE THREAT INTELLIGENCE ══╗",
            f"  Updated : {self._last_updated[:19].replace('T', ' ') if self._last_updated else 'unknown'} UTC",
            f"  Sources : {', '.join(ok_sources) if ok_sources else 'cache only'}",
        ]

        if ips:
            lines += ["", "▶ KNOWN MALICIOUS / C2 IPs — flag any login from these:"]
            lines.append("  " + ", ".join(ips))

        if domains:
            lines += ["", "▶ KNOWN MALICIOUS DOMAINS:"]
            lines.append("  " + ", ".join(domains))

        if uas:
            lines += ["", "▶ KNOWN ATTACK-TOOL USER AGENTS — detect with has_any:"]
            lines.append("  " + ", ".join(f'"{ua}"' for ua in uas))

        lines += [
            "",
            "DEFENDER INSTRUCTION:",
            "  1. If any attack log IPAddress appears in the C2 list above, write:",
            '       | where IPAddress in ("<ip1>", "<ip2>", ...)',
            "  2. If UserAgent matches a known attack tool, add:",
            '       | where UserAgent has_any ("<ua1>", "<ua2>", ...)',
            "  3. C2 IP matches are HIGH CONFIDENCE — prioritise them over structural rules.",
            "╚════════════════════════════════╝",
        ]
        return "\n".join(lines)

    def match_logs(self, attack_logs: list[dict]) -> dict:
        """
        Cross-reference attack logs against live IOCs.
        Returns {matched_ips, matched_uas, has_c2_match}.
        """
        known_ips = set(self._iocs["malicious_ips"])
        matched_ips: list[str] = []
        matched_uas: list[str] = []

        for log in attack_logs:
            ip = str(log.get("IPAddress", "")).strip()
            if ip and ip in known_ips and ip not in matched_ips:
                matched_ips.append(ip)

            ua = str(log.get("UserAgent", "")).lower()
            if ua:
                for bad in self._iocs["malicious_useragents"]:
                    if bad.lower().rstrip("/") in ua:
                        raw_ua = str(log.get("UserAgent", ""))
                        if raw_ua not in matched_uas:
                            matched_uas.append(raw_ua)
                        break

        return {
            "matched_ips":  matched_ips,
            "matched_uas":  matched_uas,
            "has_c2_match": bool(matched_ips),
        }

    def get_status(self) -> dict:
        """Summary for the /api/threatintel endpoint."""
        return {
            "last_updated":   self._last_updated,
            "source_status":  self._source_status,
            "ip_count":       len(self._iocs["malicious_ips"]),
            "domain_count":   len(self._iocs["malicious_domains"]),
            "ua_count":       len(self._iocs["malicious_useragents"]),
            "sample_ips":     self._iocs["malicious_ips"][:10],
            "sample_domains": self._iocs["malicious_domains"][:10],
        }

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _load_or_refresh(self) -> None:
        cached = self._read_cache()
        if cached and self._is_fresh(cached.get("last_updated", "")):
            self._iocs = {
                "malicious_ips":        cached.get("malicious_ips", []),
                "malicious_domains":    cached.get("malicious_domains", []),
                "malicious_useragents": cached.get("malicious_useragents", list(_BASELINE_UAS)),
            }
            self._source_status = cached.get("source_status", {})
            self._last_updated  = cached.get("last_updated", "")
            logger.info(
                "Threat intel loaded from cache: %d IPs, %d domains",
                len(self._iocs["malicious_ips"]),
                len(self._iocs["malicious_domains"]),
            )
        else:
            self._fetch_all()

    def _read_cache(self) -> dict | None:
        try:
            if self.CACHE_PATH.exists():
                with open(self.CACHE_PATH, encoding="utf-8") as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
        return None

    def _write_cache(self) -> None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        with open(self.CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "last_updated":  self._last_updated,
                    "source_status": self._source_status,
                    **self._iocs,
                },
                f,
                indent=2,
            )

    @staticmethod
    def _is_fresh(ts: str) -> bool:
        if not ts:
            return False
        try:
            dt  = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - dt).total_seconds()
            return age < ThreatIntelFeed.CACHE_TTL
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Fetchers
    # ------------------------------------------------------------------

    def _fetch_all(self) -> None:
        ips: list[str]     = []
        domains: list[str] = []
        uas: list[str]     = list(_BASELINE_UAS)

        self._fetch_urlhaus(ips, domains)
        self._fetch_feodo(ips)
        self._fetch_otx(ips, domains)

        self._iocs = {
            "malicious_ips":        list(dict.fromkeys(ips))[:500],
            "malicious_domains":    list(dict.fromkeys(domains))[:500],
            "malicious_useragents": list(dict.fromkeys(uas))[:50],
        }
        self._last_updated = datetime.now(timezone.utc).isoformat()
        self._write_cache()
        logger.info(
            "Threat intel refreshed: %d IPs, %d domains — sources: %s",
            len(self._iocs["malicious_ips"]),
            len(self._iocs["malicious_domains"]),
            self._source_status,
        )

    def _fetch_urlhaus(self, ips: list[str], domains: list[str]) -> None:
        """Abuse.ch URLhaus recent malicious URLs — POST, no auth required."""
        try:
            req = urllib.request.Request(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                data=b"{}",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                data = json.loads(resp.read())
            count = 0
            for entry in data.get("urls", [])[:500]:
                host = entry.get("host", "").strip()
                if not host:
                    continue
                if _is_ip(host):
                    ips.append(host)
                else:
                    domains.append(host)
                count += 1
            self._source_status["urlhaus"] = "ok"
            logger.info("URLhaus: %d hosts fetched", count)
        except urllib.error.HTTPError as exc:
            self._source_status["urlhaus"] = f"http_{exc.code}"
            logger.warning("URLhaus HTTP %s", exc.code)
        except Exception as exc:
            self._source_status["urlhaus"] = "error"
            logger.warning("URLhaus error: %s", exc)

    def _fetch_feodo(self, ips: list[str]) -> None:
        """Abuse.ch Feodo Tracker C2 IP blocklist — GET, no auth required."""
        try:
            with urllib.request.urlopen(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                timeout=self.TIMEOUT,
            ) as resp:
                data = json.loads(resp.read())
            for entry in data[:500]:
                ip = entry.get("ip_address", "").strip()
                if ip:
                    ips.append(ip)
            self._source_status["feodo"] = "ok"
            logger.info("Feodo: %d C2 IPs fetched", len(data))
        except urllib.error.HTTPError as exc:
            self._source_status["feodo"] = f"http_{exc.code}"
            logger.warning("Feodo HTTP %s", exc.code)
        except Exception as exc:
            self._source_status["feodo"] = "error"
            logger.warning("Feodo error: %s", exc)

    def _fetch_otx(self, ips: list[str], domains: list[str]) -> None:
        """
        AlienVault OTX indicators export.
        Requires an API key — skipped gracefully if unauthenticated (401/403).
        """
        try:
            req = urllib.request.Request(
                "https://otx.alienvault.com/api/v1/indicators/export",
                headers={"X-OTX-API-KEY": ""},
            )
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            count = 0
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj   = json.loads(line)
                    itype = obj.get("type", "")
                    val   = obj.get("indicator", "").strip()
                    if not val:
                        continue
                    if itype == "IPv4":
                        ips.append(val)
                    elif itype in ("domain", "hostname", "FQDN"):
                        domains.append(val)
                    count += 1
                except json.JSONDecodeError:
                    continue
            self._source_status["otx"] = "ok"
            logger.info("OTX: %d indicators fetched", count)
        except urllib.error.HTTPError as exc:
            status = "auth_required" if exc.code in (401, 403) else f"http_{exc.code}"
            self._source_status["otx"] = status
            logger.info("OTX: %s — API key not configured, skipping", status)
        except Exception as exc:
            self._source_status["otx"] = "error"
            logger.warning("OTX error: %s", exc)
