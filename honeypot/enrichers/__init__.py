"""IP enrichers that add AS and geo data to the event source."""

import logging

from ..config import Config
from .base import Enricher
from .geolite import GeoLiteEnricher
from .ipapi import IpApiEnricher

logger = logging.getLogger(__name__)

ENRICHERS: dict[str, type[Enricher]] = {
    e.name: e for e in (GeoLiteEnricher, IpApiEnricher)
}

__all__ = ["ENRICHERS", "Enricher", "load"]


def load(cfg: Config) -> Enricher | None:
    """Instantiate the enricher selected by HP_ENRICHER, if any."""
    if not cfg.enricher:
        return None
    try:
        cls = ENRICHERS[cfg.enricher]
    except KeyError:
        raise ValueError(
            f"unknown HP_ENRICHER {cfg.enricher!r}, "
            f"choose one of: {', '.join(ENRICHERS)}"
        ) from None
    logger.info("enricher enabled: %s", cfg.enricher)
    return cls(cfg)
