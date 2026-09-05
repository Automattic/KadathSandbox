#!/bin/bash
# Runs as uid 33 in a read-only container. Prepares runtime dirs, installs WordPress
# into the wp_html volume on first boot, links samples in, then hands off to supervisord.
set -euo pipefail

mkdir -p /run/php /run/nginx /run/supervisor /tmp/nginx /tmp/wp-cli-cache
export XDEBUG_MODE=off   # only for the CLI work below; php-fpm gets its own env via supervisord

# 0. The artifact directories are host bind mounts. On Docker Desktop and OrbStack the
# host's ownership is remapped and uid 33 can write them; on a native Linux host they
# arrive owned by the invoking user and PHP's writes fail silently -- traces, dumps and
# the error log would simply never appear and the sandbox would look like it worked.
for d in /var/log/sandbox/xdebug /var/log/sandbox/sp-dumps /var/log/sandbox/php; do
  probe="$d/.write-probe.$$"
  if ! ( : > "$probe" ) 2>/dev/null; then
    echo "FATAL: $d is not writable by uid $(id -u). PHP artifacts would be lost silently." >&2
    echo "       On a native Linux Docker host, run: chown -R 33:33 artifacts/" >&2
    exit 1
  fi
  rm -f "$probe"
done

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
  [ -e "$f" ] || continue
  b="$(basename "$f")"
  case "$b" in .*) continue ;; esac
  # Never let a sample take over WordPress's own entry points, and never replace a real
  # file in the docroot: `ln -sfn` would silently delete it, and the analyst would be
  # looking at a site whose core files are not the ones they think they are.
  case "$b" in
    index.php|wp-config.php)
      echo "entrypoint: WARNING refusing to link /samples/webroot/$b (reserved WordPress entry point)" >&2
      continue ;;
  esac
  if [ -e "/var/www/html/$b" ] && [ ! -L "/var/www/html/$b" ]; then
    echo "entrypoint: WARNING refusing to link /samples/webroot/$b (a real file of that name already exists in the docroot)" >&2
    continue
  fi
  ln -sfn "$f" "/var/www/html/$b"
done
echo "entrypoint: linked samples:"; ls -l /var/www/html/wp-content/plugins /var/www/html/wp-content/themes | grep -- '-> /samples' || true

# 7. Containment gate. netguard runs in wpnet's namespace as a one-shot; if wpnet is
# recreated without it (or netguard is skipped), this namespace keeps Docker's own
# default route straight out to the bridge and the sample would run unproxied and
# unfiltered. Refuse to start rather than offer unguarded. /proc/net/route stores
# addresses little-endian, so 172.30.0.2 (AC 1E 00 02) reads as 02001EAC.
expected_gw="02001EAC"
defaults="$(awk 'NR > 1 && $2 == "00000000" { print toupper($3) }' /proc/net/route)"
n_defaults="$(printf '%s' "$defaults" | grep -c . || true)"
if [ "$n_defaults" != 1 ] || [ "$defaults" != "$expected_gw" ]; then
  echo "FATAL: netns is not guarded: expected exactly one default route via 172.30.0.2," >&2
  echo "       found $n_defaults default route(s) [$defaults]. Did netguard run?" >&2
  echo "       Recreate the whole namespace: make up  (or docker compose up -d --force-recreate wpnet netguard netcap wordpress)" >&2
  exit 1
fi
echo "entrypoint: default route verified via 172.30.0.2"

# 8. Hand off. php-fpm must trace, so clear the CLI-only override.
unset XDEBUG_MODE
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
