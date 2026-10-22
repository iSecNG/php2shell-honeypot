"""Discord webhook notifier.

Settings: HP_DISCORD_WEBHOOK_URL, HP_DISCORD_COOLDOWN,
HP_DISCORD_OTHER_EXPLOITS, HP_DISCORD_STARTUP
"""

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request

from .base import Notifier
from ..config import Config

logger = logging.getLogger(__name__)

STAGES = {
    "probe": ("PHP2Shell probe", 0xF1C40F),
    "arm": ("PHP2Shell arm (memory exhaustion)", 0xE67E22),
    "exploit": ("PHP2Shell exploit", 0xE74C3C),
    "post_exploitation": ("PHP2Shell post-exploitation", 0x992D22),
}
OTHER_EXPLOIT = ("Exploit attempt (no PHP2Shell indicator)", 0x95A5A6)


def _code(text: str, limit: int = 1000) -> str:
    """Code block for attacker controlled text, truncated to limit."""
    # attacker controlled, so no markdown/links/mentions
    text = text.replace("```", "ʼʼʼ")
    if len(text) > limit:
        text = text[:limit] + "\n[...]"
    return f"```\n{text}\n```"


def _origin(src: dict) -> str:
    """AS, location and network type of an enriched source."""
    parts = []
    asn = src.get("as") or {}
    if asn.get("number"):
        org = (asn.get("organization") or {}).get("name", "")
        parts.append(f'AS{asn["number"]} {org}'.strip())
    geo = src.get("geo") or {}
    place = ", ".join(
        x for x in (geo.get("city_name"), geo.get("country_iso_code")) if x
    )
    if place:
        flag = "".join(
            chr(0x1F1E6 + ord(c) - 65)
            for c in geo.get("country_iso_code", "")
            if "A" <= c <= "Z"
        )
        parts.append(f"{flag} {place}".strip())
    net = src.get("network") or {}
    kinds = [k for k in ("hosting", "proxy", "mobile") if net.get(k)]
    if kinds:
        parts.append(" / ".join(kinds))
    return "\n".join(parts)[:1000]


def _env_flag(name: str, default: bool) -> bool:
    """Boolean environment variable, default if unset."""
    v = os.environ.get(name)
    return (
        default
        if v is None
        else v.strip().lower() in ("1", "true", "yes", "on")
    )


class _Fields(list):
    """Embed fields; a "Source" field is followed by the source's origin."""

    def __init__(self, event: dict):
        super().__init__()
        self.source = event.get("source") or {}
        self.src = self.source.get("ip", "?")

    def add(self, name: str, value: str, inline: bool = False) -> None:
        """Append a field, skipping empty values."""
        if value:
            self.append(
                {"name": name, "value": value[:1024], "inline": inline}
            )
            if name == "Source":
                self.add("Origin", _origin(self.source), True)


def _http_request(event: dict, fields: _Fields) -> tuple[str, int]:
    p2s = event["php2shell"]
    title, color = (
        STAGES.get(p2s["stage"], OTHER_EXPLOIT)
        if p2s["attempt"]
        else OTHER_EXPLOIT
    )
    req = event["http"]["request"]
    a = event.get("attacker") or {}
    fields.add("Source", f"`{fields.src}`", True)
    fields.add(
        "Request",
        _code(f'{req["method"]} {event["url"]["original"]}', 300),
        False,
    )
    fields.add(
        "User agent",
        _code(event["user_agent"]["original"], 200),
        False,
    )
    tls = (event.get("tls") or {}).get("client", {}).get("server_name")
    fields.add(
        "Host",
        f'`{(req["headers"].get("host") or ["-"])[0][:100]}`'
        + (f" (SNI `{tls}`)" if tls else ""),
        True,
    )
    fields.add(
        "Indicators",
        ", ".join(f"`{t}`" for t in p2s["indicators"]),
        False,
    )
    if a.get("commands"):
        fields.add("Commands", _code("\n".join(a["commands"]), 900))
    if a.get("php_snippets") and not a.get("commands"):
        fields.add("PHP", _code("\n".join(a["php_snippets"]), 900))
    if a.get("urls"):
        fields.add("Download URLs", _code("\n".join(a["urls"]), 900))
    if p2s.get("upload_progress_values") and not a.get("commands"):
        fields.add(
            "Upload progress value",
            _code(p2s["upload_progress_values"][0], 300),
        )
    if event.get("files"):
        fields.add(
            "Uploaded files",
            _code(
                "\n".join(
                    f'{f["name"]}  {f["size"]} B  {f["sha256"][:16]}'
                    for f in event["files"][:10]
                ),
                600,
            ),
        )
    return title, color


def _webshell_registered(event: dict, fields: _Fields) -> tuple[str, int]:
    f = event.get("file") or {}
    fields.add("Source", f"`{fields.src}`", True)
    fields.add("Via", f'`{event.get("via", "?")}`', True)
    fields.add("File", _code(f.get("name") or f.get("path") or "?", 300))
    if f.get("sha256"):
        fields.add("SHA256", f'`{f["sha256"]}`')
    return "Webshell planted", 0x8E44AD


def _sample_fetched(event: dict, fields: _Fields) -> tuple[str, int]:
    f = event["file"]
    sha = f["sha256"]
    fields.add("Source", f"`{fields.src}`", True)
    fields.add("Type / size", f'`{f["type"]}` / {f["size"]} B', True)
    fields.add("URL", _code(event["url"]["original"], 500))
    fields.add(
        "SHA256",
        f"`{sha}`\n"
        f"[VirusTotal](https://www.virustotal.com/gui/file/{sha}) · "
        f"[MalwareBazaar](https://bazaar.abuse.ch/sample/{sha}/)",
    )
    return "Sample downloaded", 0x2C3E50


def _sensor_started(event: dict, fields: _Fields) -> tuple[str, int]:
    listen = ", ".join(
        f'{sock["scheme"]}:{sock["port"]}' for sock in event.get("listen", [])
    )
    fields.add("Listen", f"`{listen}`", True)
    fields.add(
        "Persona",
        f'`{(event.get("persona") or {}).get("name", "?")}`',
        True,
    )
    fields.add(
        "Sample download",
        "on" if event.get("fetch_samples") else "off",
        True,
    )
    return "Sensor started", 0x2ECC71


# event.action -> builder that fills the fields and returns (title, color)
EMBEDS = {
    "http_request": _http_request,
    "webshell_registered": _webshell_registered,
    "sample_fetched": _sample_fetched,
    "sensor_started": _sensor_started,
}


# settings plus dedupe and rate limit state
# pylint: disable-next=too-many-instance-attributes
class DiscordNotifier(Notifier):
    """Posts PHP2Shell attempts, webshells and samples as Discord embeds."""

    name = "discord"
    min_interval = 2.0  # webhook limit is 5 per 2 s

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        self.url = os.environ.get("HP_DISCORD_WEBHOOK_URL", "").strip()
        if not self.url.startswith(("https://", "http://")):
            raise ValueError(
                "HP_DISCORD_WEBHOOK_URL must be set to the webhook URL"
            )
        self.cooldown = float(os.environ.get("HP_DISCORD_COOLDOWN", "600"))
        self.other_exploits = _env_flag("HP_DISCORD_OTHER_EXPLOITS", False)
        self.startup = _env_flag("HP_DISCORD_STARTUP", True)
        self._recent: dict[tuple, float] = {}
        self._suppressed: dict[tuple, int] = {}
        self._last_send = 0.0
        self._lock = threading.Lock()

    def wants(self, event: dict) -> bool:
        """Exploit stages, webshells, samples and the startup message."""
        action = event["event"]["action"]
        attempt = (event.get("php2shell") or {}).get("attempt", False)
        if action == "http_request":
            stage = event["php2shell"]["stage"]
            return stage != "none" and (attempt or self.other_exploits)
        if action in ("webshell_registered", "sample_fetched"):
            return attempt or self.other_exploits
        return action == "sensor_started" and self.startup

    def _dedupe_key(self, event: dict) -> tuple:
        """Events with the same key are reported once per cooldown."""
        a = event.get("attacker") or {}
        return (
            event["event"]["action"],
            (event.get("source") or {}).get("ip"),
            (event.get("php2shell") or {}).get("stage"),
            tuple(a.get("commands", [])),
            tuple(a.get("urls", [])),
            (event.get("file") or {}).get("sha256"),
        )

    def _payload(self, event: dict) -> dict | None:
        """Webhook payload for event, None for unsupported actions."""
        build = EMBEDS.get(event["event"]["action"])
        if build is None:
            return None
        fields = _Fields(event)
        title, color = build(event, fields)
        return {
            "username": "php2shell honeypot",
            "allowed_mentions": {"parse": []},
            "embeds": [
                {
                    "title": title,
                    "color": color,
                    "fields": fields[:25],
                    "timestamp": event["@timestamp"],
                    "footer": {"text": event["observer"]["name"]},
                }
            ],
        }

    def send(self, event: dict) -> None:
        """Post event unless an identical one was sent within the cooldown."""
        key = self._dedupe_key(event)
        now = time.monotonic()
        with self._lock:
            if now - self._recent.get(key, -1e9) < self.cooldown:
                self._suppressed[key] = self._suppressed.get(key, 0) + 1
                logger.debug(
                    "discord: suppressed duplicate %s",
                    event["event"]["action"],
                )
                return
            self._recent[key] = now
            suppressed = self._suppressed.pop(key, 0)
            if len(self._recent) > 10000:
                self._recent = {
                    k: t
                    for k, t in self._recent.items()
                    if now - t < self.cooldown
                }
        payload = self._payload(event)
        if payload is None:
            return
        if suppressed:
            payload["embeds"][0]["description"] = (
                f"{suppressed} identical reports suppressed "
                "since the last one."
            )
        self._post(payload)
        logger.debug("discord: posted %s", event["event"]["action"])

    def _post(self, payload: dict, retry: bool = True) -> None:
        """POST payload, waiting for the rate limit and retrying one 429."""
        wait = self.min_interval - (time.monotonic() - self._last_send)
        if wait > 0:
            time.sleep(wait)
        req = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "php2shell-honeypot (notifier, 1.0)",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 429 and retry:
                with e:
                    try:
                        delay = float(
                            json.loads(e.read()).get("retry_after", 2)
                        )
                    except ValueError:
                        delay = 2.0
                logger.warning(
                    "discord: rate limited, retrying in %.1f s", min(delay, 60)
                )
                time.sleep(min(delay, 60))
                self._post(payload, retry=False)
                return
            raise
        finally:
            self._last_send = time.monotonic()
