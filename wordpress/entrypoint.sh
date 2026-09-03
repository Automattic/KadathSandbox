#!/bin/bash
# Runs as uid 33 in a read-only container. Prepares runtime dirs, installs WordPress
# into the wp_html volume on first boot, links samples in, then hands off to supervisord.
set -euo pipefail

mkdir -p /run/php /run/nginx /run/supervisor /tmp/nginx /tmp/wp-cli-cache
export XDEBUG_MODE=off   # only for the CLI work below; php-fpm gets its own env via supervisord

# 1. The mitmproxy CA must exist, or TLS interception silently breaks.
for _ in $(seq 1 60); do
  [ -r /gateway-ca/mitmproxy-ca-cert.pem ] && break
  sleep 1
done
if [ ! -r /gateway-ca/mitmproxy-ca-cert.pem ]; then
  echo "FATAL: /gateway-ca/mitmproxy-ca-cert.pem not readable after 60s; is the gateway up?" >&2
  exit 1
fi

# 2. Database reachable.
db_ok=0
for _ in $(seq 1 60); do
  if php -r 'exit(@mysqli_connect(getenv("DB_HOST"), getenv("DB_USER"), getenv("DB_PASSWORD"), getenv("DB_NAME")) ? 0 : 1);'; then
    db_ok=1; break
  fi
  sleep 1
done
if [ "$db_ok" != 1 ]; then
  echo "FATAL: database ${DB_HOST} not reachable after 60s" >&2
  exit 1
fi

# 3. Populate the volume once.
if [ ! -f /var/www/html/wp-includes/version.php ]; then
  echo "entrypoint: installing WordPress files into /var/www/html"
  cp -a /usr/src/wordpress/. /var/www/html/
fi

# 4. wp-config.php
if [ ! -f /var/www/html/wp-config.php ]; then
  wp config create \
    --dbhost="$DB_HOST" --dbname="$DB_NAME" --dbuser="$DB_USER" --dbpass="$DB_PASSWORD" \
    --skip-check --extra-php <<'PHP'
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', '/var/log/sandbox/php/wp-debug.log');
define('WP_DEBUG_DISPLAY', false);
define('FS_METHOD', 'direct');
define('WP_AUTO_UPDATE_CORE', false);
define('AUTOMATIC_UPDATER_DISABLED', true);
PHP
fi

# 5. Site install
if ! wp core is-installed >/dev/null 2>&1; then
  wp core install --url="$WP_URL" --title="Kadath Sandbox" \
    --admin_user="$WP_ADMIN_USER" --admin_password="$WP_ADMIN_PASSWORD" \
    --admin_email="$WP_ADMIN_EMAIL" --skip-email
fi

# 6. Samples: drop stale links, then link everything currently present.
find /var/www/html/wp-content/plugins /var/www/html/wp-content/themes /var/www/html \
  -maxdepth 1 -type l -lname '/samples/*' -delete
for d in /samples/plugins/*/; do
  [ -d "$d" ] && ln -sfn "${d%/}" "/var/www/html/wp-content/plugins/$(basename "$d")"
done
for d in /samples/themes/*/; do
  [ -d "$d" ] && ln -sfn "${d%/}" "/var/www/html/wp-content/themes/$(basename "$d")"
done
for f in /samples/webroot/*; do
  [ -e "$f" ] && [ "$(basename "$f")" != ".gitkeep" ] && ln -sfn "$f" "/var/www/html/$(basename "$f")"
done
echo "entrypoint: linked samples:"; ls -l /var/www/html/wp-content/plugins /var/www/html/wp-content/themes | grep -- '-> /samples' || true

# 7. Hand off. php-fpm must trace, so clear the CLI-only override.
unset XDEBUG_MODE
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
