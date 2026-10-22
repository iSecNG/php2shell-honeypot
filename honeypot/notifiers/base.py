"""Notifier base class and the thread that runs them.

Author: Markus Fritz (wirehack7)
"""

import logging
import queue
import threading

from ..config import Config

logger = logging.getLogger(__name__)


class Notifier:
    """Base notifier: filters events with wants() and delivers with send()."""

    name = ""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def wants(self, event: dict) -> bool:
        """Called for every event."""
        del event  # the base class wants nothing
        return False

    def send(self, event: dict) -> None:
        """Runs in the dispatcher thread, may block or raise."""
        raise NotImplementedError


class Dispatcher:
    """Queues events and runs the notifiers in a background thread."""

    def __init__(self, notifiers: list[Notifier], maxsize: int = 1000):
        self.notifiers = notifiers
        self._queue: queue.Queue[dict | None] = queue.Queue(maxsize)
        self.dropped = 0
        self._thread = threading.Thread(
            target=self._run, name="notifiers", daemon=True
        )
        self._thread.start()

    def __call__(self, event: dict) -> None:
        """Enqueue event without blocking, drop it if the queue is full."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                logger.warning(
                    "notifier queue full, %d event(s) dropped so far",
                    self.dropped,
                )

    def _run(self) -> None:
        while True:
            event = self._queue.get()
            if event is None:
                return
            for n in self.notifiers:
                try:
                    if n.wants(event):
                        n.send(event)
                # a failing notifier must not stop the dispatcher thread
                # pylint: disable-next=broad-exception-caught
                except Exception as e:
                    logger.warning(
                        "notifier %s: %s: %s", n.name, type(e).__name__, e
                    )
                    logger.debug("notifier %s traceback", n.name, exc_info=e)
            self._queue.task_done()

    def flush(self, timeout: float = 10.0) -> None:
        """Wait up to timeout seconds for queued events to be processed."""
        done = threading.Event()
        threading.Thread(
            target=lambda: (self._queue.join(), done.set()), daemon=True
        ).start()
        done.wait(timeout)
