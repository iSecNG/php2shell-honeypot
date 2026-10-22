"""Base class for IP enrichers.

query() returns {"as": ..., "geo": ...} in ECS layout, merged into "source".

Author: Markus Fritz (wirehack7)
"""

import ipaddress
import logging
import threading
import time

from ..config import Config

logger = logging.getLogger(__name__)


class Enricher:
    """IP lookup with a thread-safe TTL cache around query()."""

    name = ""
    ttl = 24 * 3600
    negative_ttl = 600
    max_entries = 50000

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._cache: dict[str, tuple[float, dict | None]] = {}
        self._lock = threading.Lock()

    def query(self, ip: str) -> dict | None:
        """Look up ip without caching, may raise."""
        raise NotImplementedError

    def cached(self, ip: str) -> dict | None:
        """Cached result for ip, None if missing or expired."""
        with self._lock:
            hit = self._cache.get(ip)
        if hit and time.monotonic() < hit[0]:
            return hit[1]
        return None

    def lookup(self, ip: str) -> dict | None:
        """Cached lookup of public IPs; never raises."""
        if not _is_public(ip):
            return None
        with self._lock:
            hit = self._cache.get(ip)
        if hit and time.monotonic() < hit[0]:
            return hit[1]
        try:
            data = self.query(ip)
        # enrichment must never break request handling
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("%s lookup for %s failed: %s", self.name, ip, e)
            data = None
        with self._lock:
            if len(self._cache) >= self.max_entries:
                now = time.monotonic()
                self._cache = {
                    k: v for k, v in self._cache.items() if v[0] > now
                }
            self._cache[ip] = (
                time.monotonic() + (self.ttl if data else self.negative_ttl),
                data,
            )
        return data


def _is_public(ip: str | None) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global
    except ValueError:
        return False
