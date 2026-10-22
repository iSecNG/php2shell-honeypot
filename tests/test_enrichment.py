"""IP enrichment tests (python -m unittest discover -s tests)."""

import http.server
import json
import os
import unittest

from helpers import (
    QuietHandler,
    ServerTestCase,
    multipart_body,
    multipart_headers,
    serve_in_background,
)
from honeypot.config import Config
from honeypot.enrichers import load
from honeypot.enrichers.geolite import _to_ecs

IPAPI_RESPONSE = {
    "status": "success",
    "country": "Germany",
    "countryCode": "DE",
    "regionName": "Hesse",
    "city": "Frankfurt am Main",
    "lat": 50.11,
    "lon": 8.68,
    "isp": "Example Hosting",
    "org": "Example Org",
    "as": "AS64500 Example Hosting GmbH",
    "asname": "EXAMPLE",
    "mobile": False,
    "proxy": False,
    "hosting": True,
}


class FakeIpApi(QuietHandler):
    """Stub ip-api.com that records queried IPs."""

    queries: list = []
    remaining = "44"

    def do_GET(self):  # pylint: disable=invalid-name  # stdlib API name
        """Answer with a fixed lookup result and rate-limit headers."""
        ip = self.path.split("?")[0].rsplit("/", 1)[-1]
        FakeIpApi.queries.append(ip)
        data = json.dumps(IPAPI_RESPONSE).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Rl", FakeIpApi.remaining)
        self.send_header("X-Ttl", "60")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class EnrichmentTest(ServerTestCase):
    """Attack events are enriched via the ip-api enricher."""

    log = "attacks"

    @classmethod
    def setUpClass(cls):
        """Start the stub API and a server configured to use it."""
        cls.api = http.server.HTTPServer(("127.0.0.1", 0), FakeIpApi)
        serve_in_background(cls.api)
        os.environ.update(
            HP_ENRICHER="ipapi",
            HP_IPAPI_URL=f"http://127.0.0.1:{cls.api.server_address[1]}",
            HP_TRUST_XFF="1",
        )
        super().setUpClass()
        for key in ("HP_ENRICHER", "HP_IPAPI_URL", "HP_TRUST_XFF"):
            del os.environ[key]

    @classmethod
    def tearDownClass(cls):
        """Stop the server and the stub API."""
        super().tearDownClass()
        cls.api.shutdown()

    def attack(self, ip: str):
        """Send an exploit from ip and return that IP's events."""
        b = "----p2sENR"
        body = multipart_body(
            b, [("PHP_SESSION_UPLOAD_PROGRESS", None, b"x|id")]
        )
        self.req(
            "POST",
            "/upload.php",
            body,
            multipart_headers(b) | {"X-Forwarded-For": ip},
        )
        return [
            e for e in self.events() if e.get("source", {}).get("ip") == ip
        ]

    def test_attack_events_enriched_and_cached(self):
        """Request and command events get AS/geo data, cached per IP."""
        FakeIpApi.queries.clear()
        evs = self.attack("9.9.9.9")

        def last(action):
            return [e for e in evs if e["event"]["action"] == action][-1]

        for ev in (last("http_request"), last("command_emulated")):
            self.assertEqual(
                ev["source"]["as"],
                {
                    "number": 64500,
                    "organization": {"name": "Example Hosting GmbH"},
                },
            )
            self.assertEqual(ev["source"]["geo"]["country_iso_code"], "DE")
            self.assertEqual(
                ev["source"]["geo"]["location"], {"lat": 50.11, "lon": 8.68}
            )
            self.assertTrue(ev["source"]["network"]["hosting"])
        self.attack("9.9.9.9")
        self.assertEqual(FakeIpApi.queries, ["9.9.9.9"])

    def test_private_and_benign_not_queried(self):
        """Private IPs and benign requests trigger no lookup."""
        FakeIpApi.queries.clear()
        self.attack("10.1.2.3")
        self.req("GET", "/", headers={"X-Forwarded-For": "1.0.0.1"})
        self.assertEqual(FakeIpApi.queries, [])

    def test_rate_limit_pauses_lookups(self):
        """An exhausted rate limit pauses further lookups."""
        FakeIpApi.queries.clear()
        FakeIpApi.remaining = "0"
        try:
            self.attack("1.1.1.2")
            self.attack("1.1.1.3")
        finally:
            FakeIpApi.remaining = "44"
            # pylint: disable-next=protected-access  # reset backoff state
            self.srv.enricher._blocked_until = 0
        self.assertEqual(FakeIpApi.queries, ["1.1.1.2"])


class GeoLiteTest(unittest.TestCase):
    """MaxMind GeoLite2 enricher."""

    def test_mapping(self):
        """GeoLite2 ASN and City records map to ECS fields."""
        asn = {
            "autonomous_system_number": 1221,
            "autonomous_system_organization": "Telstra Pty Ltd",
        }
        city = {
            "city": {"names": {"en": "London"}},
            "continent": {"names": {"en": "Europe"}},
            "country": {"iso_code": "GB", "names": {"en": "United Kingdom"}},
            "location": {
                "latitude": 51.5142,
                "longitude": -0.0931,
                "time_zone": "Europe/London",
            },
            "subdivisions": [{"iso_code": "ENG", "names": {"en": "England"}}],
        }
        self.assertEqual(
            _to_ecs(asn, city),
            {
                "as": {
                    "number": 1221,
                    "organization": {"name": "Telstra Pty Ltd"},
                },
                "geo": {
                    "country_iso_code": "GB",
                    "country_name": "United Kingdom",
                    "continent_name": "Europe",
                    "city_name": "London",
                    "region_name": "England",
                    "region_iso_code": "ENG",
                    "location": {"lat": 51.5142, "lon": -0.0931},
                    "timezone": "Europe/London",
                },
            },
        )
        self.assertIsNone(_to_ecs(None, None))

    @unittest.skipUnless(
        os.environ.get("HP_TEST_GEOIP_DIR"),
        "set HP_TEST_GEOIP_DIR to a directory with MaxMind's "
        "GeoLite2-*-Test.mmdb files",
    )
    def test_lookup_with_maxmind_test_databases(self):
        """Lookups against MaxMind's test databases return known data."""
        os.environ.update(
            HP_GEOIP_DIR=os.environ["HP_TEST_GEOIP_DIR"],
            HP_GEOIP_ASN="GeoLite2-ASN-Test.mmdb",
            HP_GEOIP_CITY="GeoLite2-City-Test.mmdb",
        )
        try:
            cfg = Config()
            cfg.enricher = "geolite"
            enricher = load(cfg)
        finally:
            for key in ("HP_GEOIP_DIR", "HP_GEOIP_ASN", "HP_GEOIP_CITY"):
                del os.environ[key]
        self.assertEqual(
            enricher.lookup("81.2.69.160")["geo"]["city_name"], "London"
        )
        self.assertEqual(enricher.lookup("1.128.0.0")["as"]["number"], 1221)
        self.assertIsNone(enricher.lookup("10.0.0.1"))


if __name__ == "__main__":
    unittest.main()
