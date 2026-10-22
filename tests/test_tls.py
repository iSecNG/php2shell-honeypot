"""HTTPS listener and ACME tests (python -m unittest discover -s tests)."""

import http.client
import json
import os
import shutil
import socket
import ssl
import tempfile
import time
import unittest
from pathlib import Path

from helpers import make_cert, serve_in_background
from honeypot.config import Config
from honeypot.server import HoneypotServer, TLSContext


@unittest.skipUnless(
    shutil.which("openssl"), "openssl CLI needed to create a test certificate"
)
class TLSTest(unittest.TestCase):
    """HTTP and HTTPS servers sharing state, with an ACME webroot."""

    TOKEN = "Abc123_-xyzXYZ0123456789"

    @classmethod
    def setUpClass(cls):
        """Create a certificate and start the HTTP and HTTPS servers."""
        cls.tmp = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, cls.tmp)
        d = Path(cls.tmp)
        (d / "tls").mkdir()
        make_cert(d / "tls", "first.example")
        challenges = d / "acme" / ".well-known" / "acme-challenge"
        challenges.mkdir(parents=True)
        (challenges / cls.TOKEN).write_text(cls.TOKEN + ".keyauth")
        os.environ.update(
            HP_DATA_DIR=str(d / "data"),
            HP_PORT="0",
            HP_BIND="127.0.0.1",
            HP_LOG_STDOUT="0",
            HP_PERSONA="wordpress",
            HP_LOG="all",
            HP_ACME_WEBROOT=str(d / "acme"),
        )
        cfg = Config()
        cls.http = HoneypotServer(cfg)
        cls.https = HoneypotServer(
            cfg,
            port=0,
            tls=TLSContext(
                d / "tls" / "fullchain.pem", d / "tls" / "privkey.pem"
            ),
            shared=cls.http,
        )
        for srv in (cls.http, cls.https):
            serve_in_background(srv)
        del os.environ["HP_ACME_WEBROOT"]

    @classmethod
    def tearDownClass(cls):
        """Stop both servers."""
        for srv in (cls.http, cls.https):
            srv.shutdown()
            srv.server_close()

    def events(self, action):
        """Return logged events with the given action."""
        lines = (
            (Path(self.tmp) / "data" / "events.jsonl")
            .read_text()
            .splitlines()
        )
        return [
            e for e in map(json.loads, lines) if e["event"]["action"] == action
        ]

    def https_get(self, path, sni="www.tidewell.test"):
        """GET path over TLS with SNI; return (response, body, cert)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        port = self.https.server_address[1]
        c = http.client.HTTPSConnection(
            "127.0.0.1", port, timeout=10, context=ctx
        )
        # http.client sends no SNI for IPs
        c.sock = ctx.wrap_socket(
            socket.create_connection(("127.0.0.1", port), timeout=10),
            server_hostname=sni,
        )
        c.request("GET", path, headers={"Host": sni})
        r = c.getresponse()
        body = r.read().decode()
        cert = c.sock.getpeercert(binary_form=True)
        c.close()
        time.sleep(0.05)
        return r, body, cert

    def test_https_request_logged_with_sni(self):
        """HTTPS requests are logged with scheme, SNI and TLS version."""
        r, body, _ = self.https_get("/")
        self.assertEqual(r.status, 200)
        self.assertIn("PHP_SESSION_UPLOAD_PROGRESS", body)
        self.assertIn(
            "<https://www.tidewell.test/wp-json/>", r.getheader("Link")
        )
        ev = self.events("http_request")[-1]
        self.assertEqual(ev["url"]["scheme"], "https")
        self.assertEqual(
            ev["tls"]["client"]["server_name"], "www.tidewell.test"
        )
        self.assertTrue(ev["tls"]["version"].startswith("TLSv1."))

    def test_apache_404_port(self):
        """The Apache 404 page reports port 443 on the TLS listener."""
        r, body, _ = self.https_get("/nothing.php")
        self.assertEqual(r.status, 404)
        self.assertIn("Port 443</address>", body)

    def test_acme_challenge(self):
        """Known ACME tokens are served, unknown ones return 404."""
        c = http.client.HTTPConnection(
            "127.0.0.1", self.http.server_address[1], timeout=10
        )
        c.request("GET", "/.well-known/acme-challenge/" + self.TOKEN)
        r = c.getresponse()
        self.assertEqual(
            (r.status, r.read().decode()), (200, self.TOKEN + ".keyauth")
        )
        c.request(
            "GET", "/.well-known/acme-challenge/unknown-token-0123456789"
        )
        r = c.getresponse()
        r.read()
        c.close()
        self.assertEqual(r.status, 404)

    def test_plain_http_on_tls_port(self):
        """Plain HTTP on the TLS port fails and logs a tls_error."""
        c = http.client.HTTPConnection(
            "127.0.0.1", self.https.server_address[1], timeout=10
        )
        with self.assertRaises((http.client.HTTPException, OSError)):
            c.request("GET", "/")
            c.getresponse()
        c.close()
        time.sleep(0.1)
        self.assertTrue(self.events("tls_error"))

    def test_reload_on_renewal(self):
        """A renewed certificate on disk is picked up without restart."""
        _, _, before = self.https_get("/")
        d = Path(self.tmp) / "tls"
        make_cert(d, "second.example")
        st = (d / "fullchain.pem").stat()
        os.utime(d / "fullchain.pem", (st.st_atime, st.st_mtime + 5))
        _, _, after = self.https_get("/")
        self.assertNotEqual(before, after)


if __name__ == "__main__":
    unittest.main()
