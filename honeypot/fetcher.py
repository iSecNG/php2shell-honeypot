"""Downloads payload URLs from attacker commands (HP_FETCH_SAMPLES=1).

Private targets are refused.

Author: Markus Fritz (wirehack7)
"""

import hashlib
import ipaddress
import logging
import socket
import urllib.parse
import urllib.request

from .config import Config
from .eventlog import EventLog

logger = logging.getLogger(__name__)


class _NoRedirectToPrivate(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow redirects to private hosts."""

    # signature is fixed by HTTPRedirectHandler
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return the redirected request, or None for non-public targets."""
        if not _public_host(urllib.parse.urlsplit(newurl).hostname):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _public_host(host: str | None) -> bool:
    """True if every address the host resolves to is globally routable."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return False
    return True


class Fetcher:  # pylint: disable=too-few-public-methods
    """Callable that downloads, stores and logs attacker payload samples.

    Each URL is fetched at most once; samples are stored by SHA-256 under
    ``data_dir/samples``.
    """

    def __init__(self, cfg: Config, log: EventLog):
        self.cfg = cfg
        self.log = log
        self._opener = urllib.request.build_opener(_NoRedirectToPrivate)
        self._seen: dict[str, str | None] = {}

    def __call__(self, url: str, ctx: dict) -> str | None:
        """Returns the payload as text if it's a script, for curl | sh."""
        if not self.cfg.fetch_samples:
            return None
        if url in self._seen:
            return self._seen[url]
        self._seen[url] = None
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            logger.debug("sample skipped (unsupported scheme): %s", url)
            self.log.emit(
                "sample_skipped",
                url={"original": url},
                reason="unsupported scheme",
                **ctx,
            )
            return None
        if not _public_host(parts.hostname):
            logger.info("sample skipped (non-public destination): %s", url)
            self.log.emit(
                "sample_skipped",
                url={"original": url},
                reason="non-public destination",
                **ctx,
            )
            return None
        logger.debug("fetching sample %s", url)
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Wget/1.21.4", "Accept": "*/*"}
            )
            with self._opener.open(req, timeout=15) as resp:
                data = resp.read(self.cfg.fetch_max_bytes + 1)
                status = resp.status
        # any failure of a hostile download must only be logged
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("sample download failed: %s: %s", url, e)
            self.log.emit(
                "sample_failed",
                url={"original": url},
                error={"message": str(e)[:300]},
                **ctx,
            )
            return None
        truncated = len(data) > self.cfg.fetch_max_bytes
        data = data[: self.cfg.fetch_max_bytes]
        sha = hashlib.sha256(data).hexdigest()
        path = self.cfg.data_dir / "samples" / f"{sha}.bin"
        if not path.exists():
            path.write_bytes(data)
            path.chmod(0o400)
        kind = _magic(data)
        logger.info(
            "sample fetched: %s -> %s (%d bytes, %s%s)",
            url,
            sha,
            len(data),
            kind,
            ", truncated" if truncated else "",
        )
        self.log.emit(
            "sample_fetched",
            url={"original": url},
            file={
                "sha256": sha,
                "size": len(data),
                "path": str(path),
                "type": kind,
                "truncated": truncated,
            },
            http={"response": {"status_code": status}},
            **ctx,
        )
        text = None
        if kind == "script" and len(data) < 256 * 1024:
            text = data.decode("utf-8", "replace")
        self._seen[url] = text
        return text


_MAGIC_PREFIXES = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\x1f\x8b", "gzip"),
    (b"PK\x03\x04", "zip"),
)


def _magic(data: bytes) -> str:
    """Rough file type of a sample: elf, pe, gzip, zip, php, script, data."""
    for prefix, kind in _MAGIC_PREFIXES:
        if data.startswith(prefix):
            return kind
    if b"<?php" in data[:200]:
        return "php"
    sample = data[:4096]
    if (
        sample
        and sum(32 <= b < 127 or b in (9, 10, 13) for b in sample)
        / len(sample)
        > 0.95
    ):
        return "script"
    return "data"
