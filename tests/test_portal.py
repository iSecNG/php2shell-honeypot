"""Portal persona tests (python -m unittest discover -s tests)."""

import unittest

from helpers import (
    FORM_URLENCODED,
    ServerTestCase,
    multipart_body,
    multipart_headers,
)
from honeypot import personas
from honeypot.config import Config


class PortalPersonaTest(ServerTestCase):
    """End-to-end tests against the generic upload portal persona."""

    persona = "portal"

    def test_index(self):
        """The portal index offers an upload form without WordPress."""
        r, body = self.req("GET", "/")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("X-Powered-By").startswith("PHP/8.3"))
        self.assertIn("PHP_SESSION_UPLOAD_PROGRESS", body)
        self.assertNotIn("wp-", body)
        self.assertEqual(
            self.events("http_request")[-1]["persona"]["name"], "portal"
        )

    def test_sitemap(self):
        """robots.txt and sitemap.xml use the request host."""
        r, body = self.req(
            "GET", "/robots.txt", headers={"Host": "portal.test"}
        )
        self.assertIn("Sitemap: http://portal.test/sitemap.xml", body)
        r, body = self.req(
            "GET", "/sitemap.xml", headers={"Host": "portal.test"}
        )
        self.assertEqual(r.status, 200)
        self.assertIn("<loc>http://portal.test/upload.php</loc>", body)

    def test_no_wordpress_surface(self):
        """WordPress paths return the Apache 404 page."""
        for path in ("/wp-login.php", "/wp-json/", "/does-not-exist/"):
            r, body = self.req("GET", path)
            self.assertEqual(r.status, 404, path)
            self.assertIn("<address>Apache/2.4.58", body)

    def test_login(self):
        """Login attempts are logged and /admin/ redirects to login."""
        _, body = self.req(
            "POST",
            "/login.php",
            "username=admin&password=hunter2",
            FORM_URLENCODED,
        )
        self.assertIn("Invalid username or password", body)
        ev = self.events("login_attempt")[-1]
        self.assertEqual(
            (ev["user"]["name"], ev["password"]), ("admin", "hunter2")
        )
        r, _ = self.req("GET", "/admin/")
        self.assertEqual(
            (r.status, r.getheader("Location")), (302, "/login.php")
        )

    def test_upload_and_listing(self):
        """Uploaded files appear in the /uploads/ directory listing."""
        b = "----portal1"
        body = multipart_body(
            b,
            [
                ("PHP_SESSION_UPLOAD_PROGRESS", None, b"upl_1"),
                ("document", "note.pdf", b"%PDF-1.4"),
            ],
        )
        _, page = self.req("POST", "/upload.php", body, multipart_headers(b))
        self.assertIn('href="/uploads/note.pdf"', page)
        _, listing = self.req("GET", "/uploads/")
        self.assertIn("Index of /uploads", listing)
        self.assertIn("note.pdf", listing)

    def test_webshell(self):
        """An uploaded PHP webshell runs emulated commands."""
        b = "----portal2"
        body = multipart_body(
            b, [("document", "x.php", b'<?php system($_GET["c"]); ?>')]
        )
        self.req("POST", "/upload.php", body, multipart_headers(b))
        _, out = self.req("GET", "/uploads/x.php?c=whoami")
        self.assertEqual(out.strip(), "www-data")


class PersonaConfigTest(unittest.TestCase):
    """Persona loading from configuration."""

    def test_unknown_persona(self):
        """An unknown persona name raises ValueError."""
        cfg = Config()
        cfg.persona = "joomla"
        with self.assertRaises(ValueError):
            personas.load(cfg)


if __name__ == "__main__":
    unittest.main()
