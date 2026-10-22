"""Settings from HP_* environment variables.

Author: Markus Fritz (wirehack7)
"""

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    return int(v) if v else default


@dataclass
class Config:  # pylint: disable=too-many-instance-attributes
    """Runtime settings; each field reads its HP_* variable on creation."""

    bind: str = field(
        default_factory=lambda: os.environ.get("HP_BIND", "0.0.0.0")
    )
    port: int = field(default_factory=lambda: _env_int("HP_PORT", 8080))
    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("HP_DATA_DIR", "./data"))
    )
    sensor: str = field(
        default_factory=lambda: os.environ.get("HP_SENSOR", "php2shell-hp-01")
    )

    persona: str = field(
        default_factory=lambda: os.environ.get("HP_PERSONA", "wordpress")
        .strip()
        .lower()
    )
    server_header: str = field(
        default_factory=lambda: os.environ.get(
            "HP_SERVER_HEADER", "Apache/2.4.58 (Ubuntu)"
        )
    )
    php_version: str = field(
        default_factory=lambda: os.environ.get("HP_PHP_VERSION", "8.3.6")
    )
    hostname: str = field(
        default_factory=lambda: os.environ.get("HP_HOSTNAME", "web-prod-02")
    )
    site_title: str = field(
        default_factory=lambda: os.environ.get(
            "HP_SITE_TITLE", "Example Logistics LLC"
        )
    )
    site_tagline: str = field(
        default_factory=lambda: os.environ.get(
            "HP_SITE_TAGLINE", "Logistics that just works."
        )
    )
    wp_version: str = field(
        default_factory=lambda: os.environ.get("HP_WP_VERSION", "6.6.2")
    )

    max_body: int = field(
        default_factory=lambda: _env_int("HP_MAX_BODY", 64 * 1024 * 1024)
    )
    max_parts: int = field(
        default_factory=lambda: _env_int("HP_MAX_PARTS", 20000)
    )
    max_concurrency: int = field(
        default_factory=lambda: _env_int("HP_MAX_CONCURRENCY", 32)
    )
    socket_timeout: int = field(
        default_factory=lambda: _env_int("HP_SOCKET_TIMEOUT", 60)
    )

    # bodies from this size get the fake 500
    arm_threshold: int = field(
        default_factory=lambda: _env_int("HP_ARM_THRESHOLD", 7 * 1024 * 1024)
    )

    trust_xff: bool = field(
        default_factory=lambda: _env_bool("HP_TRUST_XFF", False)
    )

    tls_port: int = field(default_factory=lambda: _env_int("HP_TLS_PORT", 0))
    tls_cert: Path = field(
        default_factory=lambda: Path(
            os.environ.get("HP_TLS_CERT", "./tls/fullchain.pem")
        )
    )
    tls_key: Path = field(
        default_factory=lambda: Path(
            os.environ.get("HP_TLS_KEY", "./tls/privkey.pem")
        )
    )
    acme_webroot: str = field(
        default_factory=lambda: os.environ.get("HP_ACME_WEBROOT", "")
    )

    fetch_samples: bool = field(
        default_factory=lambda: _env_bool("HP_FETCH_SAMPLES", False)
    )
    fetch_max_bytes: int = field(
        default_factory=lambda: _env_int(
            "HP_FETCH_MAX_BYTES", 20 * 1024 * 1024
        )
    )

    # HP_LOG=attacks (default) or all
    log_all: bool = field(
        default_factory=lambda: os.environ.get("HP_LOG", "attacks")
        .strip()
        .lower()
        == "all"
    )
    # seconds after an attempt during which every request from that IP
    # is logged
    followup_window: int = field(
        default_factory=lambda: _env_int("HP_FOLLOWUP_WINDOW", 3600)
    )

    enricher: str = field(
        default_factory=lambda: os.environ.get("HP_ENRICHER", "")
        .strip()
        .lower()
    )

    notifiers: list[str] = field(
        default_factory=lambda: [
            n.strip().lower()
            for n in os.environ.get("HP_NOTIFIERS", "").split(",")
            if n.strip()
        ]
    )

    log_stdout: bool = field(
        default_factory=lambda: _env_bool("HP_LOG_STDOUT", True)
    )

    @property
    def events_file(self) -> Path:
        """Path of the JSON Lines event log."""
        return self.data_dir / "events.jsonl"

    def ensure_dirs(self) -> None:
        """Create the data directory and its storage subdirectories."""
        for sub in ("", "bodies", "files", "samples"):
            (self.data_dir / sub).mkdir(parents=True, exist_ok=True)
