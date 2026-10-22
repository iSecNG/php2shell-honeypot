"""events.jsonl writer.

Author: Markus Fritz (wirehack7)
"""

import json
import sys
import threading
from datetime import datetime, timezone

from .config import Config


class EventLog:  # pylint: disable=too-few-public-methods
    """Thread-safe ECS-style JSON lines writer with listener fan-out.

    Every event is appended to ``cfg.events_file`` (reopened if it was
    rotated away), optionally mirrored to stdout, enriched with cached
    source data and passed to all registered listeners.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._fh = self._open()
        self.listeners: list = []
        self.enricher = None

    def _open(self):
        """Open the events file for line-buffered appending."""
        # long-lived handle, closed on rotation; a with-block cannot work
        return open(  # pylint: disable=consider-using-with
            self.cfg.events_file, "a", encoding="utf-8", buffering=1
        )

    def emit(self, action: str, **fields) -> dict:
        """Build, write and broadcast one event; return the event dict."""
        event = {
            "@timestamp": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "event": {
                "kind": "alert" if fields.get("tags") else "event",
                "module": "php2shell_honeypot",
                "dataset": "php2shell_honeypot.events",
                "action": action,
            },
            "observer": {"name": self.cfg.sensor, "type": "honeypot"},
        }
        event.update(fields)
        src = event.get("source")
        if (
            self.enricher is not None
            and isinstance(src, dict)
            and src.get("ip")
        ):
            extra = self.enricher.cached(src["ip"])
            if extra:
                event["source"] = {**src, **extra}
        line = json.dumps(event, ensure_ascii=False, default=str)
        with self._lock:
            # rotated away
            if not self.cfg.events_file.exists():
                self._fh.close()
                self._fh = self._open()
            self._fh.write(line + "\n")
            if self.cfg.log_stdout:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
        for listener in self.listeners:
            listener(event)
        return event
