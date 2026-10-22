"""Shared helpers for the test suite (python -m unittest discover -s tests).

Importing this module puts the repository root on sys.path, so test
modules must import it before any ``honeypot`` module.
"""

import http.client
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# The imports below need the sys.path entry added above.
# pylint: disable=wrong-import-position
from honeypot.config import Config  # noqa: E402
from honeypot.server import HoneypotServer  # noqa: E402

# pylint: enable=wrong-import-position

FORM_URLENCODED = {"Content-Type": "application/x-www-form-urlencoded"}


def multipart_body(
    boundary: str, fields: list[tuple[str, str | None, bytes]]
) -> bytes:
    """Build a multipart/form-data body from (name, filename, content)."""
    out = b""
    for name, filename, content in fields:
        disp = f'form-data; name="{name}"' + (
            f'; filename="{filename}"' if filename is not None else ""
        )
        out += (
            f"--{boundary}\r\nContent-Disposition: {disp}\r\n\r\n".encode()
            + content
            + b"\r\n"
        )
    return out + f"--{boundary}--\r\n".encode()


def multipart_headers(boundary: str) -> dict:
    """Return the Content-Type header for a multipart body."""
    return {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def make_cert(directory: Path, cn: str) -> None:
    """Create a self-signed certificate and key in directory."""
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            f"/CN={cn}",
            "-keyout",
            str(directory / "privkey.pem"),
            "-out",
            str(directory / "fullchain.pem"),
        ],
        check=True,
        capture_output=True,
    )


def serve_in_background(server: http.server.HTTPServer) -> None:
    """Run server.serve_forever in a daemon thread."""
    threading.Thread(target=server.serve_forever, daemon=True).start()


class QuietHandler(http.server.BaseHTTPRequestHandler):
    """Request handler that does not log to stderr."""

    def log_message(self, *args):
        """Suppress request logging."""


class ServerTestCase(unittest.TestCase):
    """Base class running a honeypot server in a temporary data dir."""

    persona = "wordpress"
    log = "all"

    @classmethod
    def setUpClass(cls):
        """Start the honeypot server for the test class."""
        cls.tmp = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, cls.tmp)
        os.environ.update(
            HP_DATA_DIR=cls.tmp,
            HP_PORT="0",
            HP_BIND="127.0.0.1",
            HP_LOG_STDOUT="0",
            HP_ARM_THRESHOLD=str(1024 * 1024),
            HP_PERSONA=cls.persona,
            HP_LOG=cls.log,
        )
        cls.srv = HoneypotServer(Config())
        cls.port = cls.srv.server_address[1]
        serve_in_background(cls.srv)

    @classmethod
    def tearDownClass(cls):
        """Stop the honeypot server."""
        cls.srv.shutdown()
        cls.srv.server_close()

    def req(self, method, path, body=None, headers=None):
        """Send one request and return (response, decoded body)."""
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        time.sleep(0.05)
        return r, data.decode("utf-8", "replace")

    def events(self, action=None):
        """Return logged events, optionally filtered by action."""
        path = Path(self.tmp) / "events.jsonl"
        evs = [json.loads(line) for line in path.read_text().splitlines()]
        return [
            e for e in evs if action is None or e["event"]["action"] == action
        ]
