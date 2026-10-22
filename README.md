# php2shell-honeypot

Honeypot for PHP2Shell (CVE-2026-109618 / CVE-2026-109619). Pretends to be a PHP site on an unpatched Ubuntu 24.04 box (Apache 2.4.58, mod_php, PHP 8.3.6, `session.upload_progress.enabled=On`), logs the attacks and fakes a successful exploitation so attackers keep going and you get to see their follow-up commands, droppers and webshells.

There is no PHP in the container. Commands and PHP snippets found in requests are interpreted by `fakeshell.py`, nothing gets executed.

> [!IMPORTANT]
> This honeypot is a work in progress. It already runs well, but it isn't finished yet: expect missing features, rough edges and changes to the event format between versions.

## Quick start

```bash
cp .env.example .env
mkdir -p data && sudo chown 10001 data
docker compose up -d --build
tail -f data/events.jsonl
```

Port 80 on the host goes to 8080 in the container. The container runs as UID 10001 with a read-only root fs, no capabilities and memory/pid/cpu limits.

Without Docker:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
HP_PORT=8080 HP_DATA_DIR=./data .venv/bin/python -m honeypot
```

Run it on a dedicated VPS/VM that has no access to internal networks.

## Code

```
honeypot/
  server.py      HTTP server, routing, logging, webshell registry
  stack.py       Apache/PHP pages (error pages, phpinfo, autoindex)
  analysis.py    PHP2Shell indicators, stages, code extraction
  multipart.py   multipart parser that tolerates broken bodies
  fakeshell.py   fake shell / PHP
  fetcher.py     sample download
  eventlog.py    events.jsonl writer
  personas/      site look (wordpress, portal)
  enrichers/     AS/geo lookup (geolite, ipapi)
  notifiers/     alerts (discord)
tools/report.py
tests/
```

## Personas

`HP_PERSONA=wordpress` (default) or `portal`. Company name via `HP_SITE_TITLE` / `HP_SITE_TAGLINE`.

Both answer on the upload paths seen in PHP2Shell scans (`/upload.php`, `/app/upload.php`, `/api/endpoint.php`, `/api/upload.php`, `/uploads.php`), on `/progress.php` and on the usual phpinfo paths (`/phpinfo.php`, `/info.php`, `/test.php`, ...). The upload forms contain a hidden `PHP_SESSION_UPLOAD_PROGRESS` field, which is what the scanners look for.

**wordpress**: WordPress 6.6.2 site with Twenty Twenty-Four styling and a made-up upload plugin "simple-file-upload".

| Path | |
|---|---|
| `/`, `/services/`, `/careers/`, `/blog/`, `/contact/`, posts | pages with the upload widget |
| `/wp-admin/admin-ajax.php`, `/wp-content/plugins/simple-file-upload/upload.php`, `/wp-json/sfu/v1/upload` | upload endpoints, uploads end up in `/wp-content/uploads/YYYY/MM/` |
| `/wp-content/uploads/YYYY/MM/` | directory listing with decoy files |
| `/wp-login.php` | login, always "password is incorrect" |
| `/wp-admin/` | 302 to wp-login |
| `/wp-json/`, `/wp-json/wp/v2/users` | REST index, user `editor` |
| `/xmlrpc.php` | fault 403 on POST |
| `/readme.html`, `/license.txt`, `/feed/`, `/author/editor/` | |
| `/robots.txt`, `/wp-sitemap.xml`, `/wp-sitemap-*-1.xml` | core sitemaps |
| everything else | themed 404, Apache 404 for files |

**portal**: plain PHP customer portal, Bootstrap look, no CMS.

| Path | |
|---|---|
| `/`, `/index.php`, `/services.php`, `/contact.php` | pages with upload form |
| `/upload.php` | upload form / result, uploads go to `/uploads/` |
| `/uploads/` | directory listing |
| `/login.php` | login, always "Invalid username or password." |
| `/admin/`, `/admin.php`, `/account.php`, `/logout.php` | 302 to `/login.php` |
| `/robots.txt`, `/sitemap.xml` | |
| everything else | Apache 404 |

New persona: subclass `Persona` in `personas/<name>.py` (see `portal.py`, it's the small one), add it to `PERSONAS` in `personas/__init__.py`. Append `req.output` to pages that are supposed to have run PHP, that's where the fake command output goes.

## What happens to attacks

- Arm phase (huge bodies from 7 MiB, lots of empty filenames, repeated part headers/field names, long one-character filenames): Apache 500, like PHP died during request startup. Lots of small parts alone get a normal 200, PHP 8.3 just stops parsing at `max_multipart_body_parts` (1020).
- Shell or PHP code in query, form fields, multipart fields, headers or base64 blobs gets emulated and the output is appended to the response, so canary checks pass. Covers `id`, `uname`, `cat`, `echo`, `base64 -d | sh`, `sh -c`, `php -r`, `md5()`, pipes through `head`/`grep`/`wc`/`cut`/`awk` etc.
- Uploaded or written `.php`/`.phtml`/`.php5`/`.php.jpg` files become webshells: later requests to that file name run `?c=...` and friends through the fake shell.
- `wget`/`curl`/`tftp` URLs are logged. With `HP_FETCH_SAMPLES=1` they are downloaded to `data/samples/` (0400, never executed, private targets blocked) and `curl ... | sh` scripts are emulated as well, which gets you the next stage URLs. This means the honeypot connects to attacker infrastructure.

Exploits that use the info leak (CVE-2026-109619) to build their payload won't get usable leak data and will probably stop after the probe/arm requests. You still get those with full bodies. The mass scanning stuff (templates with base64 commands, webshell uploads, Mirai loaders) works end to end.

## Logs

`data/events.jsonl`, one JSON object per line, ECS-ish field names. JSONL because it can be appended to from many threads, survives a crash mid-write and works with `tail -f`, `grep`, `jq` and log shippers. `jq -s . events.jsonl` if you need an array.

```
data/
  events.jsonl
  bodies/<sha256>.bin.gz   request bodies
  files/<sha256>.bin       uploads
  samples/<sha256>.bin     downloaded payloads
  webshells.json
```

Separately from the events, the sensor writes its own diagnostic log to stderr with Python's `logging` module (`docker compose logs`). `HP_LOG_LEVEL` sets the level, default `INFO`: startup, attack summaries per request, webshells, download URLs, samples and TLS certificate problems. `DEBUG` adds every request, emulated command and TLS handshake error.

By default (`HP_LOG=attacks`) only requests with a `php2shell.stage` other than `none` are logged, plus everything from an IP during `HP_FOLLOWUP_WINDOW` seconds (default 3600) after its last PHP2Shell attempt. Those get `php2shell.followup: true`, so the GETs that come after an upload (LFI calls, triggers, checks) are in the log too. `HP_LOG=all` logs every request plus login attempts, XML-RPC calls and TLS/HTTP errors.

`php2shell.stage`: `probe` (PHP2Shell indicator), `arm` (memory exhaustion), `exploit` (code in request), `post_exploitation` (webshell upload or use).

`php2shell.attempt` is true if the request has at least one PHP2Shell indicator (`php2shell.indicators`) or uses a webshell that was dropped by such a request. Other exploits with code, e.g. the PHP-CGI CVE-2024-4577 checks, show up as `stage: exploit`, `attempt: false`. Bodies, uploads and samples are only stored for attempts.

Events (`event.action`):

| | |
|---|---|
| `http_request` | headers, body size/hash, multipart stats, tags, `php2shell.*`, TLS version/cipher/SNI, and if code was found `attacker.{commands, php_snippets, decoded_b64, urls, ips, write_targets}` + `emulated_output` |
| `command_emulated` | one per command |
| `download_url_seen` | |
| `sample_fetched`, `sample_failed`, `sample_skipped` | |
| `webshell_registered` | |
| `login_attempt`, `xmlrpc_call`, `tls_error`, `http_error` | only with `HP_LOG=all` |
| `connection_dropped` | connection limit hit |
| `sensor_started` | |

```bash
python3 tools/report.py data/events.jsonl
python3 tools/report.py data/events.jsonl --ip 1.2.3.4      # timeline
python3 tools/report.py data/events.jsonl --since 2026-10-22
jq -c 'select(.php2shell.attempt)' data/events.jsonl
jq -r 'select(.event.action == "command_emulated") | .process.command_line' data/events.jsonl
zcat data/bodies/<sha256>.bin.gz | less
```

In Docker: `docker exec php2shell-honeypot python tools/report.py /data/events.jsonl`.

Log rotation: logrotate with `copytruncate` or a plain move, the file is reopened.

Wiping the data (files belong to UID 10001), e.g. to get rid of your own test requests:

```bash
docker exec php2shell-honeypot sh -c 'rm -f /data/events.jsonl /data/webshells.json /data/bodies/* /data/files/* /data/samples/*'
docker compose restart php2shell-honeypot
```

## HTTPS

TLS is done by the honeypot itself and not by a reverse proxy, otherwise you'd get the proxy's TLS fingerprint and lose the SNI. Certificates come from a certbot container via HTTP-01: certbot writes the challenge to `./acme`, the honeypot serves it on port 80, the cert gets copied to `./tls` and is picked up on the next connection after a renewal.

Point DNS at the host, then in `.env`:

```
COMPOSE_FILE=docker-compose.yml:docker-compose.tls.yml
HP_DOMAIN=example.com
HP_EXTRA_DOMAINS=www.example.com
ACME_EMAIL=you@example.org
```

```bash
mkdir -p tls acme letsencrypt
docker compose up -d --build
docker logs -f php2shell-certbot
```

`ACME_STAGING=1` for testing. Port 443 closes connections until the first cert exists.

The cert shows up in the CT logs within minutes and scanners pick it up from there.

Without Docker: `HP_TLS_PORT`, `HP_TLS_CERT`, `HP_TLS_KEY`, and `HP_ACME_WEBROOT` for the challenge directory.

## IP enrichment

`HP_ENRICHER=geolite` or `ipapi`. The source IP of every attack is looked up after the response has been sent and cached. The result is added as `source.as` and `source.geo` (ECS) to all events of that IP:

```json
"source": {
  "ip": "203.0.113.50",
  "as": {"number": 64500, "organization": {"name": "Example Hosting GmbH"}},
  "geo": {"country_iso_code": "DE", "city_name": "Frankfurt am Main", "location": {"lat": 50.11, "lon": 8.68}, ...}
}
```

geolite reads `GeoLite2-ASN.mmdb` and `GeoLite2-City.mmdb` from `./geoip` (mounted to `/geoip`). Download them from your MaxMind account and extract:

```bash
tar -xzf GeoLite2-ASN_*.tar.gz --strip-components=1 -C geoip --wildcards '*.mmdb'
tar -xzf GeoLite2-City_*.tar.gz --strip-components=1 -C geoip --wildcards '*.mmdb'
```

Replaced files are reopened automatically. To update them automatically, add `docker-compose.geoip.yml` to `COMPOSE_FILE` and set `GEOIPUPDATE_ACCOUNT_ID` / `GEOIPUPDATE_LICENSE_KEY`. Other mmdb files (GeoIP2, DB-IP) work too, see `HP_GEOIP_ASN` / `HP_GEOIP_CITY`.

ipapi uses ip-api.com (free: HTTP, 45 req/min; `HP_IPAPI_KEY` for pro). Also gives ISP and hosting/proxy/mobile flags in `source.network`.

## Notifications

`HP_NOTIFIERS=discord` plus `HP_DISCORD_WEBHOOK_URL`. Posts PHP2Shell attempts (with commands, URLs, origin), dropped webshells, downloaded samples (with VirusTotal/MalwareBazaar links) and sensor starts.

| | default | |
|---|---|---|
| `HP_DISCORD_COOLDOWN` | 600 | seconds to hold back identical messages per IP |
| `HP_DISCORD_OTHER_EXPLOITS` | 0 | also post non-PHP2Shell exploits |
| `HP_DISCORD_STARTUP` | 1 | post `sensor_started` |

Attacker strings go into code blocks and mentions are disabled.

Notifiers run in their own thread, so a slow webhook doesn't hold up requests. Writing your own: subclass `Notifier` in `notifiers/`, implement `wants(event)` and `send(event)`, add it to `NOTIFIERS`.

## Egress

With `HP_FETCH_SAMPLES=0` and no ipapi/notifiers the honeypot doesn't need outbound connections at all:

```bash
iptables -I DOCKER-USER -s <honeypot-subnet> -m conntrack --ctstate NEW -j DROP
```

Sample downloads often go to odd ports, so either leave egress open or allow 80/443 only and live with some `sample_failed`. Discord needs 443. certbot and geoipupdate run on the default bridge and aren't affected by the rule.

## Configuration

| Variable | Default | |
|---|---|---|
| `HP_PORT` / `HP_BIND` | 8080 / 0.0.0.0 | |
| `HP_DATA_DIR` | ./data | `/data` in Docker |
| `HP_SENSOR` | php2shell-hp-01 | sensor name in events |
| `HP_PERSONA` | wordpress | `wordpress`, `portal` |
| `HP_SITE_TITLE` | Example Logistics LLC | |
| `HP_SITE_TAGLINE` | Logistics that just works. | |
| `HP_WP_VERSION` | 6.6.2 | |
| `HP_PHP_VERSION` | 8.3.6 | |
| `HP_SERVER_HEADER` | Apache/2.4.58 (Ubuntu) | |
| `HP_HOSTNAME` | web-prod-02 | shown in error pages and shell output |
| `HP_ARM_THRESHOLD` | 7 MiB | body size for the fake 500 |
| `HP_MAX_BODY` | 64 MiB | |
| `HP_MAX_CONCURRENCY` | 32 | |
| `HP_TLS_PORT` | 0 | 0 = no HTTPS |
| `HP_TLS_CERT` / `HP_TLS_KEY` | ./tls/fullchain.pem / ./tls/privkey.pem | |
| `HP_ACME_WEBROOT` | | |
| `HP_TRUST_XFF` | 0 | only behind your own proxy |
| `HP_FETCH_SAMPLES` | 0 | |
| `HP_LOG` | attacks | `attacks`, `all` |
| `HP_FOLLOWUP_WINDOW` | 3600 | seconds to keep logging an IP after an attempt |
| `HP_ENRICHER` | | `geolite`, `ipapi` |
| `HP_GEOIP_DIR` | ./geoip | `/geoip` in Docker |
| `HP_NOTIFIERS` | | `discord` |
| `HP_LOG_STDOUT` | 1 | 0 in Docker |
| `HP_LOG_LEVEL` | INFO | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |

## Tests

```bash
.venv/bin/python -m unittest discover -s tests
```

TLS tests need the `openssl` binary. The GeoLite test needs MaxMind's test databases (`test-data/` in github.com/maxmind/MaxMind-DB) in `HP_TEST_GEOIP_DIR`, otherwise it's skipped.

## Author

Built by Markus Fritz ([wirehack7](https://github.com/wirehack7)).

## License

[MIT](LICENSE) © 2026 iSecNG GmbH
