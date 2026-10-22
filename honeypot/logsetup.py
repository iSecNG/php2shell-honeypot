"""Operational logging via the standard ``logging`` module.

This is the sensor's own diagnostic log (startup, errors, notable
events), written to stderr. Attack data goes to events.jsonl through
:class:`honeypot.eventlog.EventLog`, which is unaffected by this.
"""

import logging
import os
import sys

DEFAULT_LEVEL = "INFO"
FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


def parse_level(value: str | None) -> int | None:
    """Map a level name (``debug``) or number (``10``) to an int.

    Returns None for unknown names.
    """
    value = (value or DEFAULT_LEVEL).strip()
    if value.isdigit():
        return int(value)
    level = logging.getLevelNamesMapping().get(value.upper())
    return level


def setup_logging(level: str | None = None) -> None:
    """Configure the root logger from ``level`` or ``HP_LOG_LEVEL``.

    Defaults to INFO; an invalid value falls back to INFO with a warning.
    """
    raw = level if level is not None else os.environ.get("HP_LOG_LEVEL")
    parsed = parse_level(raw)
    logging.basicConfig(
        level=DEFAULT_LEVEL if parsed is None else parsed,
        format=FORMAT,
        stream=sys.stderr,
        force=True,
    )
    if parsed is None:
        logging.getLogger(__name__).warning(
            "invalid HP_LOG_LEVEL %r, using %s", raw, DEFAULT_LEVEL
        )
