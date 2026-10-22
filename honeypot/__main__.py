"""Entry point: `python -m honeypot` starts the HTTP(S) sensor.

Author: Markus Fritz (wirehack7)
"""

import logging
import threading

from .config import Config
from .logsetup import setup_logging
from .server import HoneypotServer, TLSContext

logger = logging.getLogger("honeypot")


def main() -> None:
    """Start the HTTP listener, plus HTTPS when HP_TLS_PORT is set."""
    setup_logging()
    cfg = Config()
    srv = HoneypotServer(cfg)
    listen = [{"address": cfg.bind, "port": cfg.port, "scheme": "http"}]
    if cfg.tls_port:
        tls_srv = HoneypotServer(
            cfg,
            port=cfg.tls_port,
            tls=TLSContext(cfg.tls_cert, cfg.tls_key),
            shared=srv,
        )
        threading.Thread(
            target=tls_srv.serve_forever, name="tls", daemon=True
        ).start()
        listen.append(
            {
                "address": cfg.bind,
                "port": cfg.tls_port,
                "scheme": "https",
                "cert_loaded": tls_srv.tls.get() is not None,
            }
        )
    srv.log.emit(
        "sensor_started",
        listen=listen,
        persona={
            "name": srv.persona.name,
            "server": cfg.server_header,
            "php": cfg.php_version,
        },
        fetch_samples=cfg.fetch_samples,
    )
    logger.info(
        "sensor %s started: persona=%s listen=%s log=%s",
        cfg.sensor,
        srv.persona.name,
        ", ".join(
            f"{x['scheme']}://{x['address']}:{x['port']}" for x in listen
        ),
        "all" if cfg.log_all else "attacks",
    )
    logger.info(
        "enricher=%s notifiers=%s fetch_samples=%s data_dir=%s",
        cfg.enricher or "none",
        ",".join(cfg.notifiers) or "none",
        cfg.fetch_samples,
        cfg.data_dir,
    )
    if cfg.tls_port and not listen[-1]["cert_loaded"]:
        logger.warning(
            "HTTPS on port %d has no certificate yet (%s), "
            "connections are closed until it appears",
            cfg.tls_port,
            cfg.tls_cert,
        )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        logger.info("interrupted, shutting down")
    finally:
        srv.server_close()
        logger.info("sensor stopped")


if __name__ == "__main__":
    main()
