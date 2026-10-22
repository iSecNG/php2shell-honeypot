"""Notifiers that push selected events to external services."""

import logging

from ..config import Config
from .base import Dispatcher, Notifier
from .discord import DiscordNotifier

logger = logging.getLogger(__name__)

NOTIFIERS: dict[str, type[Notifier]] = {n.name: n for n in (DiscordNotifier,)}

__all__ = ["NOTIFIERS", "Dispatcher", "Notifier", "load"]


def load(cfg: Config) -> Dispatcher | None:
    """Build a dispatcher for the notifiers listed in HP_NOTIFIERS."""
    if not cfg.notifiers:
        return None
    unknown = [n for n in cfg.notifiers if n not in NOTIFIERS]
    if unknown:
        raise ValueError(
            f"unknown HP_NOTIFIERS {', '.join(unknown)}, "
            f"choose from: {', '.join(NOTIFIERS)}"
        )
    dispatcher = Dispatcher([NOTIFIERS[n](cfg) for n in cfg.notifiers])
    logger.info("notifiers enabled: %s", ", ".join(cfg.notifiers))
    return dispatcher
