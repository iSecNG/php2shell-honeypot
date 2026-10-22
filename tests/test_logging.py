"""Attack-only logging and storage tests.

Run with: python -m unittest discover -s tests

Author: Markus Fritz (wirehack7)
"""

import os
import unittest
from pathlib import Path

from helpers import (
    FORM_URLENCODED,
    ServerTestCase,
    multipart_body,
    multipart_headers,
)

# LeakIX CVE-2024-4577 check
LEAKIX_CODE = (
    '<?php $env["USERNAME"] = @get_current_user(); '
    '$env["HOSTNAME"] = @gethostname(); '
    "$env['USERNAME_SIGN'] = @md5($env[\"USERNAME\"]); "
    "echo @json_encode($env); @die(); ?>"
)
LEAKIX_PATH = (
    "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3D1"
    "+%ADd+auto_prepend_file%3Dphp://input"
)


class AttackOnlyLoggingTest(ServerTestCase):
    """With HP_LOG=attacks, benign traffic is not logged."""

    log = "attacks"

    def actions(self):
        """Return the actions of all logged events."""
        path = Path(self.tmp) / "events.jsonl"
        return (
            [e["event"]["action"] for e in self.events()]
            if path.exists()
            else []
        )

    def test_only_attacks_logged(self):
        """Only the exploit request and its command are logged."""
        self.req("GET", "/")
        self.req("GET", "/wp-json/")
        self.req("POST", "/wp-login.php", "log=admin&pwd=x", FORM_URLENCODED)
        self.req(
            "POST",
            "/xmlrpc.php",
            "<methodCall><methodName>system.listMethods</methodName>"
            "</methodCall>",
        )
        self.assertEqual(
            [a for a in self.actions() if a != "sensor_started"], []
        )
        b = "----p2sLOG"
        body = multipart_body(
            b, [("PHP_SESSION_UPLOAD_PROGRESS", None, b"x|id")]
        )
        self.req("POST", "/upload.php", body, multipart_headers(b))
        ev = self.events("http_request")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["php2shell"]["stage"], "exploit")
        self.assertIn("command_emulated", self.actions())


class Php2ShellAttemptTest(ServerTestCase):
    """Only PHP2Shell attempts get bodies and files stored."""

    log = "attacks"

    def stored(self, sub):
        """Return the sorted file names in a data subdirectory."""
        return sorted(p.name for p in (Path(self.tmp) / sub).iterdir())

    def test_other_exploit_logged_without_storage(self):
        """Non-PHP2Shell exploits are logged but nothing is stored."""
        self.req("POST", LEAKIX_PATH, LEAKIX_CODE, FORM_URLENCODED)
        ev = self.events("http_request")[-1]
        self.assertFalse(ev["php2shell"]["attempt"])
        self.assertEqual(ev["php2shell"]["indicators"], [])
        self.assertEqual(ev["php2shell"]["stage"], "exploit")
        self.assertNotIn("stored", ev["http"]["request"]["body"])
        self.assertEqual(self.stored("bodies"), [])
        self.assertEqual(ev["attacker"]["code_origins"], ["body"])
        self.assertIn(
            "get_current_user", " ".join(ev["attacker"]["php_snippets"])
        )
        self.assertIn("json_encode", " ".join(ev["attacker"]["php_snippets"]))

    def test_php2shell_attempt_stores_body_and_files(self):
        """A PHP2Shell attempt stores its body and uploaded files."""
        b = "----p2sATT"
        body = multipart_body(
            b,
            [
                ("PHP_SESSION_UPLOAD_PROGRESS", None, b"x"),
                ("f", "w.phtml", b"<?php system($_GET[1]); ?>"),
            ],
        )
        self.req("POST", "/upload.php", body, multipart_headers(b))
        ev = self.events("http_request")[-1]
        self.assertTrue(ev["php2shell"]["attempt"])
        self.assertIn(
            "php2shell.upload_progress_field", ev["php2shell"]["indicators"]
        )
        self.assertTrue(
            Path(ev["http"]["request"]["body"]["stored"]["path"]).exists()
        )
        self.assertTrue(Path(ev["files"][0]["path"]).exists())
        self.req("GET", "/wp-content/uploads/2026/10/w.phtml?1=id")
        ev = self.events("http_request")[-1]
        self.assertTrue(ev["php2shell"]["attempt"])
        self.assertEqual(ev["php2shell"]["stage"], "post_exploitation")

    def test_upload_without_indicator_not_stored(self):
        """A plain PHP upload without indicators is not stored."""
        b = "----plain"
        body = multipart_body(b, [("f", "plain.php", b"<?php phpinfo(); ?>")])
        self.req("POST", "/upload.php", body, multipart_headers(b))
        ev = self.events("http_request")[-1]
        self.assertFalse(ev["php2shell"]["attempt"])
        self.assertNotIn("path", ev["files"][0])
        self.req("GET", "/wp-content/uploads/2026/10/plain.php")
        self.assertFalse(
            self.events("http_request")[-1]["php2shell"]["attempt"]
        )


class FollowupLoggingTest(ServerTestCase):
    """Requests following an attempt from the same IP are logged."""

    log = "attacks"

    def test_requests_after_attempt_are_logged(self):
        """Follow-up requests are logged only for the attacking IP."""
        os.environ["HP_TRUST_XFF"] = "1"
        self.srv.cfg.trust_xff = True
        b = "----p2sFOLLOW"
        body = multipart_body(
            b,
            [
                ("PHP_SESSION_UPLOAD_PROGRESS", None, b"x"),
                ("f", "a.txt", b"Z"),
            ],
        )
        self.req(
            "POST",
            "/index.php",
            body,
            multipart_headers(b) | {"X-Forwarded-For": "9.9.9.9"},
        )
        self.req(
            "GET",
            "/vuln.php?page=/tmp/sessions/sess_abc",
            headers={"X-Forwarded-For": "9.9.9.9"},
        )
        self.req(
            "GET",
            "/vuln.php?page=/etc/hosts",
            headers={"X-Forwarded-For": "8.8.4.4"},
        )
        del os.environ["HP_TRUST_XFF"]
        reqs = self.events("http_request")
        self.assertEqual(
            [e["source"]["ip"] for e in reqs], ["9.9.9.9", "9.9.9.9"]
        )
        follow = reqs[-1]
        self.assertEqual(
            follow["url"]["original"], "/vuln.php?page=/tmp/sessions/sess_abc"
        )
        self.assertTrue(follow["php2shell"]["followup"])
        self.assertFalse(follow["php2shell"]["attempt"])


if __name__ == "__main__":
    unittest.main()
