#!/bin/sh
# certbot.sh          get/renew cert for HP_DOMAIN, loops forever
# certbot.sh deploy   copy cert to /tls for uid 10001 (deploy hook)
set -eu
: "${HP_DOMAIN:?set HP_DOMAIN}"
: "${ACME_EMAIL:?set ACME_EMAIL}"
umask 077

install_cert() {
    live="/etc/letsencrypt/live/$HP_DOMAIN"
    # key first, the honeypot reloads on fullchain.pem changes
    for f in privkey fullchain; do
        cp "$live/$f.pem" "/tls/.$f.pem.tmp"
        chown 10001 "/tls/.$f.pem.tmp"
        chmod 0400 "/tls/.$f.pem.tmp"
        mv -f "/tls/.$f.pem.tmp" "/tls/$f.pem"
    done
    echo "certificate for $HP_DOMAIN installed in /tls"
}

if [ "${1:-}" = deploy ]; then
    install_cert
    exit 0
fi

domains="-d $HP_DOMAIN"
for d in ${HP_EXTRA_DOMAINS:-}; do domains="$domains -d $d"; done
staging=""
[ "${ACME_STAGING:-0}" = 1 ] && staging="--test-cert"

while :; do
    # shellcheck disable=SC2086
    if certbot certonly --webroot -w /acme $domains --cert-name "$HP_DOMAIN" \
        --email "$ACME_EMAIL" --agree-tos --no-eff-email --non-interactive \
        --keep-until-expiring $staging --deploy-hook "/bin/sh /deploy/certbot.sh deploy"; then
        [ -f /tls/fullchain.pem ] || install_cert
        sleep 43200
    else
        # LE allows 5 failed validations per hour
        echo "certbot failed, retrying in 1h"
        sleep 3600
    fi
done
