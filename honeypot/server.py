"""HTTP server posing as Apache 2.4 + mod_php 8.3.

Author: Markus Fritz (wirehack7)
"""

import gzip
import hashlib
import json
import logging
import posixpath
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.parse
from typing import NamedTuple
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import analysis, enrichers, multipart, notifiers, personas, stack
from .config import Config
from .eventlog import EventLog
from .fakeshell import FakeShell, looks_like_php
from .fetcher import Fetcher
from .personas.base import APACHE_HTML, HTML

PHP_EXT_RE = re.compile(r"\.(php\d?|phtml|phar|pht|inc)(\.|$)", re.I)
SID_RE = re.compile(r"^[a-z0-9,-]{22,256}$", re.I)
ACME_PREFIX = "/.well-known/acme-challenge/"
ACME_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")

logger = logging.getLogger(__name__)


class WebshellRegistry:
    """PHP files the attackers think they dropped."""

    def __init__(self, cfg: Config):
        self.path = cfg.data_dir / "webshells.json"
        self._lock = threading.Lock()
        try:
            self._map: dict[str, dict] = json.loads(self.path.read_text())
        except FileNotFoundError:
            self._map = {}
        except (OSError, ValueError) as e:
            logger.warning("cannot load %s, starting empty: %s", self.path, e)
            self._map = {}
        logger.debug("%d known webshell(s) loaded", len(self._map))

    def add(self, name: str, info: dict) -> None:
        """Record `name` (case-insensitive) and persist the registry."""
        with self._lock:
            self._map[name.lower()] = info
            self.path.write_text(json.dumps(self._map, indent=1))

    def get(self, name: str) -> dict | None:
        """Info for the dropped file `name`, or None if unknown."""
        return self._map.get(name.lower())

    def names(self) -> list[str]:
        """All registered (lower-cased) file names."""
        return list(self._map)


class RecentAttackers:
    """IPs with a PHP2Shell attempt in the last `window` seconds."""

    def __init__(self, window: int, max_entries: int = 50000):
        self.window = window
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def add(self, ip: str) -> None:
        """Mark `ip` as seen now, pruning expired entries when full."""
        now = time.monotonic()
        with self._lock:
            if len(self._seen) >= self.max_entries:
                self._seen = {
                    k: t
                    for k, t in self._seen.items()
                    if now - t < self.window
                }
            self._seen[ip] = now

    def __contains__(self, ip: str) -> bool:
        t = self._seen.get(ip)
        return t is not None and time.monotonic() - t < self.window


class TLSContext:  # pylint: disable=too-few-public-methods
    """Reloads cert/key when the cert file changes (certbot renewal)."""

    def __init__(self, cert: Path, key: Path):
        self.cert, self.key = cert, key
        self._ctx: ssl.SSLContext | None = None
        self._mtime: float | None = None
        self._lock = threading.Lock()

    def get(self) -> ssl.SSLContext | None:
        """Current context, reloaded first if the cert file changed."""
        try:
            mtime = self.cert.stat().st_mtime
        except OSError as e:
            if self._ctx is None:
                logger.debug("TLS certificate not available: %s", e)
            return self._ctx
        if mtime != self._mtime:
            with self._lock:
                if mtime != self._mtime:
                    try:
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                        ctx.load_cert_chain(self.cert, self.key)
                        ctx.sni_callback = lambda sock, name, _ctx: setattr(
                            sock, "hp_sni", name
                        )
                        self._ctx, self._mtime = ctx, mtime
                        logger.info(
                            "TLS certificate loaded from %s", self.cert
                        )
                    except (OSError, ssl.SSLError) as e:
                        # probably mid-copy, try again next time
                        logger.warning(
                            "cannot load TLS certificate %s: %s", self.cert, e
                        )
        return self._ctx


class HoneypotServer(  # pylint: disable=too-many-instance-attributes
    ThreadingHTTPServer,
):
    """Threaded HTTP(S) server holding the sensor-wide shared state."""

    daemon_threads = True
    request_queue_size = 128

    def __init__(
        self,
        cfg: Config,
        port: int | None = None,
        tls: TLSContext | None = None,
        shared: "HoneypotServer | None" = None,
    ):
        # shared: the HTTP server when this is the HTTPS one, so both use
        # the same state
        self.cfg = cfg
        self.tls = tls
        self.scheme = "https" if tls else "http"
        self.public_port = 443 if tls else 80
        if shared is None:
            cfg.ensure_dirs()
            self.persona = personas.load(cfg)
            self.log = EventLog(cfg)
            self.log.enricher = self.enricher = enrichers.load(cfg)
            self.notify = notifiers.load(cfg)
            if self.notify is not None:
                self.log.listeners.append(self.notify)
            self.fetcher = Fetcher(cfg, self.log)
            self.webshells = WebshellRegistry(cfg)
            self.uploads: list[str] = []
            self.recent = RecentAttackers(cfg.followup_window)
            self._slots = threading.BoundedSemaphore(cfg.max_concurrency)
        else:
            self.persona, self.log, self.fetcher, self.enricher = (
                shared.persona,
                shared.log,
                shared.fetcher,
                shared.enricher,
            )
            self.webshells, self.uploads, self._slots = (
                shared.webshells,
                shared.uploads,
                shared._slots,
            )
            self.recent = shared.recent
        super().__init__(
            (cfg.bind, cfg.port if port is None else port), Handler
        )

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            logger.warning(
                "concurrency limit reached, dropping connection from %s",
                client_address[0],
            )
            self.log.emit(
                "connection_dropped",
                source={"ip": client_address[0], "port": client_address[1]},
                reason="concurrency limit",
            )
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            if self.tls is not None:
                request = self._handshake(request, client_address)
                if request is None:
                    return
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def _handshake(self, request, client_address):
        # in the worker thread, not in accept()
        ctx = self.tls.get()
        if ctx is None:
            logger.debug(
                "no TLS certificate, closing connection from %s",
                client_address[0],
            )
            self.shutdown_request(request)
            return None
        request.settimeout(self.cfg.socket_timeout)
        try:
            return ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as e:
            logger.debug(
                "TLS handshake with %s failed: %s", client_address[0], e
            )
            if self.cfg.log_all:
                self.log.emit(
                    "tls_error",
                    source={
                        "ip": client_address[0],
                        "port": client_address[1],
                    },
                    error={"message": str(e)[:500]},
                )
            self.shutdown_request(request)
            return None


class Body(NamedTuple):
    """A request body as read off the wire, plus its parsed forms."""

    raw: bytes
    truncated: bool
    chunked: bool
    ctype: str
    mp: multipart.MultipartResult | None
    is_form: bool
    form: dict[str, list[str]]


@dataclass
class Exchange:  # pylint: disable=too-many-instance-attributes
    """One request with everything derived from it while handling it."""

    src: dict
    hdrs: dict[str, list[str]]
    split: urllib.parse.SplitResult
    path: str
    query: dict[str, list[str]]
    body: Body
    an: analysis.Analysis
    shell_info: dict | None
    # indicator in this request, or a webshell dropped by such a request
    attempt: bool
    # anything else from an IP that just tried PHP2Shell, e.g. the GETs
    # that follow an upload
    followup: bool


class Handler(BaseHTTPRequestHandler):
    """Request handler: analyses, emulates, answers and logs."""

    server: HoneypotServer
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return self.server.cfg.server_header

    def log_message(  # pylint: disable=redefined-builtin
        self, format, *args
    ):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(self.server.cfg.socket_timeout)

    def send_error(self, code, message=None, explain=None):
        # broken requests (e.g. >100 headers) don't reach do_*
        logger.debug(
            "HTTP error %s for %s: %s", code, self.client_address[0], message
        )
        if self.server.cfg.log_all:
            self.server.log.emit(
                "http_error",
                source=self._source(),
                http={"response": {"status_code": code}},
                error={"message": message or ""},
                raw_requestline=getattr(self, "raw_requestline", b"")[:2000],
            )
        body = stack.apache_error(
            self.server.cfg,
            code if code in (400, 403, 404, 500, 503) else 400,
            port=self.server.public_port,
        ).encode()
        try:
            self.send_response(code, message)
            self.send_header("Content-Type", "text/html; charset=iso-8859-1")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass
        self.close_connection = True

    def _source(self) -> dict:
        ip, port = self.client_address[:2]
        src = {"ip": ip, "port": port}
        if self.server.cfg.trust_xff and getattr(self, "headers", None):
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                src = {
                    "ip": xff.split(",")[0].strip(),
                    "port": None,
                    "proxy_ip": ip,
                }
        return src

    def _headers_dict(self) -> dict[str, list[str]]:
        d: dict[str, list[str]] = {}
        for k, v in self.headers.items():
            d.setdefault(k.lower(), []).append(v)
        return d

    def _read_body(self) -> tuple[bytes, bool, bool]:
        """-> (body, truncated, chunked)"""
        cfg = self.server.cfg
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            buf = bytearray()
            truncated = False
            while True:
                line = self.rfile.readline(1024)
                if not line:
                    break
                try:
                    size = int(line.split(b";")[0].strip(), 16)
                except ValueError:
                    break
                if size == 0:
                    while self.rfile.readline(8192) not in (
                        b"\r\n",
                        b"\n",
                        b"",
                    ):
                        pass
                    break
                take = min(size, cfg.max_body - len(buf))
                if take > 0:
                    buf += self.rfile.read(take)
                if take < size:
                    truncated = True
                    self.close_connection = True
                    break
                self.rfile.readline(16)
            return bytes(buf), truncated, True
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        length = max(length, 0)
        take = min(length, cfg.max_body)
        data = bytearray()
        while len(data) < take:
            chunk = self.rfile.read(min(1 << 20, take - len(data)))
            if not chunk:
                break
            data += chunk
        truncated = length > take or len(data) < take
        if truncated:
            self.close_connection = True
        return bytes(data), truncated, False

    def _store_body(self, body: bytes) -> dict | None:
        if not body:
            return None
        sha = hashlib.sha256(body).hexdigest()
        path = self.server.cfg.data_dir / "bodies" / f"{sha}.bin.gz"
        if not path.exists():
            with gzip.open(path, "wb", compresslevel=6) as fh:
                fh.write(body)
        return {"sha256": sha, "path": str(path)}

    def _handle(self):
        """Analyse one request, answer it, then log what was seen."""
        cfg = self.server.cfg
        ex = self._parse()
        shell = self._emulate(ex)
        stored_files = self._store_uploads(ex)
        self._register_php_writes(ex)
        an = ex.an
        if ex.shell_info is not None:
            an.tag("postexploit.webshell_access")
            an.stage = "post_exploitation"
            if not an.obs.commands and not an.obs.php_snippets:
                an.output = self._webshell_fallback(ex, shell)

        req = personas.Request(
            method=self.command,
            path=ex.path,
            host=(ex.hdrs.get("host") or [cfg.hostname])[0][:255],
            scheme=self.server.scheme,
            port=self.server.public_port,
            form=ex.body.form,
            body=ex.body.raw,
            files=[f["name"] for f in stored_files],
            output=an.output,
        )
        if cfg.log_all:
            self._observe_persona(ex, req)

        resp = self._route(req, an, ex.shell_info is not None)
        session_id, new_cookie = self._session(ex.hdrs)
        # send first, logging and the geo lookup shouldn't add latency
        self._send(
            resp.status, resp.ctype, resp.body, new_cookie, resp.headers
        )
        logger.debug(
            "%s %s %s -> %s (stage %s)",
            ex.src["ip"],
            self.command,
            ex.path[:200],
            resp.status,
            an.stage,
        )
        if an.stage != "none":
            logger.info(
                "%s: %s %s stage=%s tags=%s",
                ex.src["ip"],
                self.command,
                ex.path[:200],
                an.stage,
                ",".join(an.tags),
            )
        if an.stage != "none" and self.server.enricher is not None:
            # EventLog adds it from the cache
            self.server.enricher.lookup(ex.src["ip"])

        if an.stage != "none" or ex.followup or cfg.log_all:
            self.server.log.emit(
                "http_request",
                **self._request_event(
                    ex, resp.status, session_id, stored_files
                ),
            )
        self._log_observations(ex)

    # BaseHTTPRequestHandler dispatches to do_<METHOD>
    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle
    do_OPTIONS = _handle
    do_PATCH = _handle
    do_DELETE = _handle

    def _parse(self) -> Exchange:
        """Read and classify the request; mark the source if it attacks."""
        cfg = self.server.cfg
        src = self._source()
        hdrs = self._headers_dict()
        split = urllib.parse.urlsplit(self.path)
        path = posixpath.normpath(urllib.parse.unquote(split.path or "/"))
        if split.path.endswith("/") and path != "/":
            path += "/"
        query = urllib.parse.parse_qs(split.query, keep_blank_values=True)
        body = self._parse_body(hdrs)
        an = analysis.classify(
            self.command,
            hdrs,
            body.raw,
            body.truncated,
            body.mp,
            cfg.arm_threshold,
            body.chunked,
        )
        basename = posixpath.basename(path)
        shell_info = self.server.webshells.get(basename) if basename else None
        attempt = bool(an.php2shell_indicators) or bool(
            shell_info and shell_info.get("php2shell_attempt")
        )
        followup = not attempt and src["ip"] in self.server.recent
        if attempt:
            self.server.recent.add(src["ip"])
        return Exchange(
            src=src,
            hdrs=hdrs,
            split=split,
            path=path,
            query=query,
            body=body,
            an=an,
            shell_info=shell_info,
            attempt=attempt,
            followup=followup,
        )

    def _parse_body(self, hdrs: dict[str, list[str]]) -> Body:
        """Read the body (for methods that carry one) and parse forms."""
        cfg = self.server.cfg
        raw, truncated, chunked = (
            self._read_body()
            if self.command in ("POST", "PUT", "PATCH")
            else (b"", False, False)
        )
        ctype = (hdrs.get("content-type") or [""])[0]
        boundary = multipart.get_boundary(ctype)
        mp = (
            multipart.parse(raw, boundary, cfg.max_parts)
            if boundary and raw
            else None
        )
        is_form = "application/x-www-form-urlencoded" in ctype.lower()
        form = (
            urllib.parse.parse_qs(
                raw.decode("utf-8", "replace"), keep_blank_values=True
            )
            if is_form
            else {}
        )
        return Body(raw, truncated, chunked, ctype, mp, is_form, form)

    def _emulate(self, ex: Exchange) -> FakeShell:
        """Run the attacker's payloads in a fake shell, filling `ex.an`."""
        cfg = self.server.cfg
        ctx = {"source": ex.src, "php2shell": {"attempt": True}}
        attempt = ex.attempt
        shell = FakeShell(
            cfg.hostname,
            cfg.php_version,
            on_download=lambda u: (
                self.server.fetcher(u, ctx) if attempt else None
            ),
        )
        analysis.emulate(
            analysis.text_candidates(
                ex.query,
                ex.body.form,
                ex.hdrs,
                ex.body.mp,
                ex.body.raw,
                ex.body.is_form,
            ),
            shell,
            ex.an,
        )
        return shell

    def _store_uploads(self, ex: Exchange) -> list[dict]:
        """Record every non-empty uploaded file; returns their infos."""
        if ex.body.mp is None:
            return []
        return [
            self._store_upload(p, ex.src, ex.an, ex.attempt)
            for p in ex.body.mp.parts
            if p.filename and p.size > 0
        ]

    def _register_php_writes(self, ex: Exchange) -> None:
        """Register PHP files the emulated code wrote as webshells."""
        for target in ex.an.obs.write_targets:
            name = posixpath.basename(target)
            if name and PHP_EXT_RE.search(name):
                logger.info(
                    "%s: webshell written via PHP: %s", ex.src["ip"], target
                )
                self.server.webshells.add(
                    name,
                    {
                        "via": "php_write",
                        "target": target,
                        "source_ip": ex.src["ip"],
                        "php2shell_attempt": ex.attempt,
                    },
                )
                self.server.log.emit(
                    "webshell_registered",
                    source=ex.src,
                    file={"name": name, "path": target},
                    via="php_write",
                    php2shell={"attempt": ex.attempt},
                    tags=["postexploit.webshell_written"],
                )

    def _observe_persona(self, ex: Exchange, req: personas.Request) -> None:
        """Log login attempts and let the persona log its own events."""
        log = self.server.log
        persona = self.server.persona
        login_fields = persona.login_forms.get(ex.path)
        if login_fields and self.command == "POST":
            user_field, pass_field = login_fields
            form = ex.body.form
            log.emit(
                "login_attempt",
                source=ex.src,
                url={"path": ex.path},
                user={"name": (form.get(user_field) or [""])[0][:256]},
                password=(form.get(pass_field) or [""])[0][:256],
                user_agent={
                    "original": (ex.hdrs.get("user-agent") or [""])[0]
                },
            )
        persona.observe(
            req,
            lambda action, **fields: log.emit(
                action, source=ex.src, **fields
            ),
        )

    def _request_event(
        self,
        ex: Exchange,
        status: int,
        session_id: str | None,
        stored_files: list[dict],
    ) -> dict:
        """Build the fields of the `http_request` event."""
        an, body = ex.an, ex.body
        event = {
            "source": ex.src,
            "url": {
                "original": self.path[:8192],
                "scheme": self.server.scheme,
                "path": ex.path,
                "query": ex.split.query[:8192],
            },
            "http": {
                "version": self.request_version,
                "request": {
                    "method": self.command,
                    "mime_type": body.ctype[:500],
                    "body": {
                        "bytes": len(body.raw),
                        "truncated": body.truncated,
                        "chunked": body.chunked,
                        **(
                            {"stored": self._store_body(body.raw)}
                            if body.raw and ex.attempt
                            else {}
                        ),
                    },
                    "headers": ex.hdrs,
                },
                "response": {"status_code": status},
            },
            "user_agent": {
                "original": (ex.hdrs.get("user-agent") or [""])[0]
            },
            "php_session_id": session_id,
            "persona": {"name": self.server.persona.name},
            "tags": an.tags,
            "php2shell": {
                "attempt": ex.attempt,
                "followup": ex.followup,
                "indicators": an.php2shell_indicators,
                "stage": an.stage,
                "upload_progress_values": an.upload_progress_values,
            },
        }
        if isinstance(self.connection, ssl.SSLSocket):
            event["tls"] = self._tls_info()
        if body.mp is not None:
            event["multipart"] = _multipart_summary(body.mp)
        if body.form:
            event["form"] = {
                k: [v[:2000] for v in vs][:20]
                for k, vs in list(body.form.items())[:50]
            }
        obs = an.obs.as_dict()
        if obs:
            event["attacker"] = obs
            event["attacker"]["code_origins"] = getattr(
                an, "code_origins", []
            )
            event["emulated_output"] = an.output[:4000]
        if stored_files:
            event["files"] = stored_files
        return event

    def _tls_info(self) -> dict:
        """TLS version, cipher and SNI of the current connection."""
        cipher = self.connection.cipher()
        return {
            "version": self.connection.version(),
            "cipher": cipher[0] if cipher else None,
            "client": {
                "server_name": getattr(self.connection, "hp_sni", None)
            },
        }

    def _log_observations(self, ex: Exchange) -> None:
        """Emit one event per emulated command and per download URL."""
        log = self.server.log
        php2shell = {"attempt": ex.attempt, "stage": ex.an.stage}
        for cmd in ex.an.obs.commands:
            logger.debug("%s: command %r", ex.src["ip"], cmd[:500])
            log.emit(
                "command_emulated",
                source=ex.src,
                process={"command_line": cmd},
                url={"path": ex.path},
                php2shell=dict(php2shell),
                tags=ex.an.tags,
            )
        for u in ex.an.obs.urls:
            logger.info("%s: download URL seen: %s", ex.src["ip"], u[:500])
            log.emit(
                "download_url_seen",
                source=ex.src,
                url={"original": u, "path": ex.path},
                php2shell=dict(php2shell),
                tags=["postexploit.download_url"],
            )

    def _store_upload(
        self, p: multipart.Part, src: dict, an: analysis.Analysis, store: bool
    ) -> dict:
        name = (
            posixpath.basename(p.filename.replace("\\", "/")) or "upload.bin"
        )
        info = {
            "name": name,
            "field": p.name,
            "size": p.size,
            "sha256": p.sha256,
            "declared_type": p.content_type,
        }
        if store:
            path = self.server.cfg.data_dir / "files" / f"{p.sha256}.bin"
            if not path.exists():
                path.write_bytes(p.content)
                path.chmod(0o400)
            info["path"] = str(path)
        text = p.content[:65536].decode("utf-8", "replace")
        if PHP_EXT_RE.search(name) or looks_like_php(text):
            info["php_like"] = True
            logger.info(
                "%s: webshell uploaded: %s (%s)", src["ip"], name, p.sha256
            )
            self.server.webshells.add(
                name,
                {
                    "via": "upload",
                    "sha256": p.sha256,
                    "source_ip": src["ip"],
                    "php2shell_attempt": store,
                },
            )
            an.tag("postexploit.webshell_upload")
            an.stage = "post_exploitation"
            self.server.log.emit(
                "webshell_registered",
                source=src,
                file=info,
                via="upload",
                php2shell={"attempt": store},
                tags=["postexploit.webshell_upload"],
            )
        if p.content[:4] == b"\x7fELF":
            info["elf"] = True
            logger.info(
                "%s: ELF binary uploaded: %s (%s)", src["ip"], name, p.sha256
            )
            an.tag("postexploit.binary_upload")
        if name not in self.server.uploads:
            self.server.uploads.append(name)
        return info

    def _webshell_fallback(self, ex: Exchange, shell: FakeShell) -> str:
        """Run every parameter as a shell command (?cmd=, ?c=, ...)."""
        vals = [v for vs in ex.query.values() for v in vs] + [
            v for vs in ex.body.form.values() for v in vs
        ]
        if ex.body.mp is not None:
            vals += [
                p.content[:65536].decode("utf-8", "replace")
                for p in ex.body.mp.parts
                if not p.filename
            ]
        out = []
        for v in vals:
            if v.strip():
                out.append(shell.run_shell(v, ex.an.obs))
        return "".join(out)

    def _route(
        self, req: personas.Request, an: analysis.Analysis, is_shell: bool
    ) -> personas.Response:
        """Pick the response; the first handler that answers wins."""
        # Response objects are always truthy, so `or` only skips None
        return (
            self._acme_response(req)
            or self._php_response(req, an, is_shell)
            or self.server.persona.route(req)
            or self._uploads_response(req)
            or self._fallback_response(req, an)
        )

    def _acme_response(
        self, req: personas.Request
    ) -> personas.Response | None:
        """Serve an ACME http-01 challenge from the configured webroot."""
        webroot = self.server.cfg.acme_webroot
        if not webroot or not req.path.startswith(ACME_PREFIX):
            return None
        token = req.path.removeprefix(ACME_PREFIX)
        if not ACME_TOKEN_RE.fullmatch(token):
            return None
        try:
            key_auth = (
                Path(webroot) / ".well-known" / "acme-challenge" / token
            ).read_text()
        except OSError:
            return None
        return personas.Response(200, "text/plain", key_auth)

    def _php_response(
        self, req: personas.Request, an: analysis.Analysis, is_shell: bool
    ) -> personas.Response | None:
        """Webshell output, the out-of-memory 500, or phpinfo()."""
        cfg = self.server.cfg
        php = self.server.persona.php_headers()
        if is_shell:
            return personas.Response(200, HTML, an.output, php)
        # PHP runs out of memory before the script starts
        if an.arm and not an.output:
            return personas.Response(
                500, APACHE_HTML, stack.apache_error(cfg, 500, port=req.port)
            )
        if req.path in stack.PHPINFO_PATHS:
            return personas.Response(200, HTML, stack.phpinfo(cfg), php)
        return None

    def _uploads_response(
        self, req: personas.Request
    ) -> personas.Response | None:
        """The uploads directory listing, or an (empty) uploaded file."""
        persona = self.server.persona
        updir = persona.uploads_dir()
        uploads = persona.decoy_uploads + self.server.uploads
        if req.path in (updir, updir.rstrip("/")):
            return personas.Response(
                200,
                HTML,
                stack.directory_listing(
                    self.server.cfg, updir, uploads, req.port
                ),
            )
        if (
            req.path.startswith(updir)
            and posixpath.basename(req.path) in uploads
        ):
            return personas.Response(200, "application/octet-stream", "")
        return None

    def _fallback_response(
        self, req: personas.Request, an: analysis.Analysis
    ) -> personas.Response:
        """Payload output for PHP URLs, else Apache's or the persona's 404."""
        persona = self.server.persona
        # the bug is in request startup, so any .php "runs" the payload
        if an.output and (
            PHP_EXT_RE.search(req.path) or req.path.endswith("/")
        ):
            return personas.Response(
                200, HTML, an.output, persona.php_headers()
            )
        if PHP_EXT_RE.search(req.path):
            return personas.Response(
                404,
                APACHE_HTML,
                stack.apache_error(self.server.cfg, 404, req.path, req.port),
            )
        return persona.not_found(req)

    def _session(self, hdrs: dict) -> tuple[str | None, str | None]:
        cookie = ";".join(hdrs.get("cookie", []))
        m = re.search(r"PHPSESSID=([^;\s]+)", cookie)
        if m and SID_RE.match(m.group(1)):
            return m.group(1), None
        sid = secrets.token_hex(16)
        return (m.group(1)[:512] if m else sid), sid

    def _send(
        self,
        status: int,
        ctype: str,
        page: str,
        new_cookie: str | None,
        extra: dict,
    ):
        data = page.encode("utf-8", "replace")
        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            for k, v in extra.items():
                self.send_header(k, v)
            if "X-Powered-By" in extra and ctype.startswith("text/html"):
                if new_cookie:
                    self.send_header(
                        "Set-Cookie", f"PHPSESSID={new_cookie}; path=/"
                    )
                    self.send_header(
                        "Expires", "Thu, 19 Nov 1981 08:52:00 GMT"
                    )
                    self.send_header(
                        "Cache-Control", "no-store, no-cache, must-revalidate"
                    )
            self.send_header("Vary", "Accept-Encoding")
            self.send_header("Content-Length", str(len(data)))
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
        except (OSError, socket.timeout) as e:
            logger.debug("sending response failed: %s", e)
            self.close_connection = True


def _multipart_summary(mp: multipart.MultipartResult) -> dict:
    """Structural facts about a multipart body for the request event."""
    return {
        "boundary": mp.boundary,
        "part_count": mp.part_count,
        "closed": mp.closed,
        "truncated": mp.truncated,
        "empty_filename_parts": mp.empty_filename_parts,
        "max_part_header_lines": mp.max_part_header_lines,
        "max_repeated_header": mp.max_repeated_header,
        "top_field_names": mp.field_name_counts.most_common(10),
        "parts": [_part_summary(p) for p in mp.parts[:50]],
    }


def _part_summary(p: multipart.Part) -> dict:
    preview = p.content[:256]
    return {
        "name": (p.name or "")[:256],
        "filename": None if p.filename is None else p.filename[:256],
        "filename_len": None if p.filename is None else len(p.filename),
        "content_type": p.content_type,
        "size": p.size,
        "header_lines": p.header_lines,
        "sha256": p.sha256,
        "preview": (
            preview.decode("utf-8", "replace")
            if preview.isascii()
            else preview.hex()
        ),
    }
