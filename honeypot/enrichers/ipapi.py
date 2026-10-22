"""ip-api.com enricher.

Free tier is 45 req/min over HTTP, HP_IPAPI_KEY switches to pro.

Author: Markus Fritz (wirehack7)
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .base import Enricher
from ..config import Config

logger = logging.getLogger(__name__)

FIELDS = (
    "status,message,country,countryCode,regionName,city,lat,lon,"
    "isp,org,as,asname,mobile,proxy,hosting"
)


class IpApiEnricher(Enricher):
    """Lookups against ip-api.com, honouring its rate limit headers."""

    name = "ipapi"

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        self.key = os.environ.get("HP_IPAPI_KEY", "").strip()
        default = "https://pro.ip-api.com" if self.key else "http://ip-api.com"
        self.base = os.environ.get("HP_IPAPI_URL", default).rstrip("/")
        self._blocked_until = 0.0

    def query(self, ip: str) -> dict | None:
        if time.monotonic() < self._blocked_until:
            return None
        params = {"fields": FIELDS, **({"key": self.key} if self.key else {})}
        url = (
            f"{self.base}/json/{urllib.parse.quote(ip)}"
            f"?{urllib.parse.urlencode(params)}"
        )
        req = urllib.request.Request(
            url, headers={"User-Agent": "php2shell-honeypot (enrichment)"}
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                self._note_limit(resp.headers)
                d = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            logger.debug("ip-api lookup for %s: HTTP %s", ip, e.code)
            with e:
                if e.code == 429:
                    self._note_limit(e.headers, exhausted=True)
            return None
        if d.get("status") != "success":
            return None
        return _to_ecs(d)

    def _note_limit(self, headers, exhausted: bool = False) -> None:
        remaining, reset = headers.get("X-Rl"), headers.get("X-Ttl")
        if exhausted or remaining == "0":
            pause = int(reset) if reset and reset.isdigit() else 60
            self._blocked_until = time.monotonic() + pause
            logger.warning("ip-api rate limit reached, pausing %d s", pause)


def _to_ecs(d: dict) -> dict:
    """Map an ip-api.com response to ECS "as", "geo" and "network"."""
    out: dict = {}
    m = re.match(r"AS(\d+)\s*(.*)", d.get("as") or "")
    if m:
        out["as"] = {
            "number": int(m.group(1)),
            "organization": {
                "name": m.group(2) or d.get("org") or d.get("asname", "")
            },
        }
    geo = {
        k: v
        for k, v in (
            ("country_iso_code", d.get("countryCode")),
            ("country_name", d.get("country")),
            ("region_name", d.get("regionName")),
            ("city_name", d.get("city")),
        )
        if v
    }
    if d.get("lat") is not None and d.get("lon") is not None:
        geo["location"] = {"lat": d["lat"], "lon": d["lon"]}
    if geo:
        out["geo"] = geo
    out["network"] = {
        "isp": d.get("isp", ""),
        "hosting": bool(d.get("hosting")),
        "proxy": bool(d.get("proxy")),
        "mobile": bool(d.get("mobile")),
    }
    return out
