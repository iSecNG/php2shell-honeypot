"""MaxMind GeoLite2 ASN + City from HP_GEOIP_DIR."""

import logging
import os
import threading
from pathlib import Path

import maxminddb

from .base import Enricher
from ..config import Config

logger = logging.getLogger(__name__)


# small wrapper around one database file, get() is all it needs
class _Db:  # pylint: disable=too-few-public-methods
    """Reopens the file when it changes."""

    def __init__(self, path: Path):
        self.path = path
        self._reader = None
        self._mtime: float | None = None
        self._missing_logged = False
        self._lock = threading.Lock()

    def get(self, ip: str):
        """Record for ip, or None if the database is missing or unreadable."""
        try:
            mtime = self.path.stat().st_mtime
        except OSError as e:
            if not self._missing_logged:
                self._missing_logged = True
                logger.warning("GeoLite database unavailable: %s", e)
            return None
        self._missing_logged = False
        if mtime != self._mtime:
            with self._lock:
                if mtime != self._mtime:
                    try:
                        reader = maxminddb.open_database(
                            str(self.path), maxminddb.MODE_MMAP
                        )
                    except (
                        OSError,
                        ValueError,
                        maxminddb.InvalidDatabaseError,
                    ) as e:
                        logger.warning(
                            "cannot open GeoLite database %s: %s", self.path, e
                        )
                        return None
                    old, self._reader, self._mtime = (
                        self._reader,
                        reader,
                        mtime,
                    )
                    if old is not None:
                        old.close()
                    logger.info("GeoLite database loaded: %s", self.path)
        return self._reader.get(ip) if self._reader else None


class GeoLiteEnricher(Enricher):
    """Local lookups in the GeoLite2 ASN and City databases."""

    name = "geolite"
    ttl = 3600

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        d = Path(os.environ.get("HP_GEOIP_DIR", "./geoip"))
        self.asn_db = _Db(
            d / os.environ.get("HP_GEOIP_ASN", "GeoLite2-ASN.mmdb")
        )
        self.city_db = _Db(
            d / os.environ.get("HP_GEOIP_CITY", "GeoLite2-City.mmdb")
        )

    def query(self, ip: str) -> dict | None:
        return _to_ecs(self.asn_db.get(ip), self.city_db.get(ip))


def _to_ecs(asn: dict | None, city: dict | None) -> dict | None:
    """Map MaxMind ASN/City records to ECS "as" and "geo"."""
    out: dict = {}
    if asn and asn.get("autonomous_system_number"):
        out["as"] = {
            "number": asn["autonomous_system_number"],
            "organization": {
                "name": asn.get("autonomous_system_organization", "")
            },
        }
    if city:
        country = city.get("country") or city.get("registered_country") or {}
        geo = {
            "country_iso_code": country.get("iso_code"),
            "country_name": (country.get("names") or {}).get("en"),
            "continent_name": (
                (city.get("continent") or {}).get("names") or {}
            ).get("en"),
            "city_name": ((city.get("city") or {}).get("names") or {}).get(
                "en"
            ),
        }
        subdivisions = city.get("subdivisions") or []
        if subdivisions:
            geo["region_name"] = (subdivisions[0].get("names") or {}).get("en")
            geo["region_iso_code"] = subdivisions[0].get("iso_code")
        loc = city.get("location") or {}
        if (
            loc.get("latitude") is not None
            and loc.get("longitude") is not None
        ):
            geo["location"] = {"lat": loc["latitude"], "lon": loc["longitude"]}
            if loc.get("time_zone"):
                geo["timezone"] = loc["time_zone"]
        geo = {k: v for k, v in geo.items() if v}
        if geo:
            out["geo"] = geo
    return out or None
