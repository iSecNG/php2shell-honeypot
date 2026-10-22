FROM python:3.12.7-slim-bookworm

LABEL org.opencontainers.image.title="php2shell-honeypot" \
      org.opencontainers.image.description="PHP2Shell honeypot (CVE-2026-109618/109619)"

RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin hp \
 && mkdir -p /data && chown hp /data

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY honeypot/ /app/honeypot/
COPY tools/ /app/tools/

USER hp
ENV HP_DATA_DIR=/data \
    HP_PORT=8080 \
    HP_TLS_CERT=/tls/fullchain.pem \
    HP_TLS_KEY=/tls/privkey.pem \
    HP_GEOIP_DIR=/geoip \
    HP_LOG_STDOUT=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8080 8443
VOLUME ["/data"]

# no HEALTHCHECK, it would end up in the logs
STOPSIGNAL SIGINT
CMD ["python", "-m", "honeypot"]
