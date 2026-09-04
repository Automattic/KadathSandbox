#!/bin/sh
# WP-CLI runs inside the same PHP install as the sample. Without this, every analyst
# `wp` invocation writes an Xdebug trace into artifacts/xdebug/ and fires the same
# Snuffleupagus rules the sample does, burying the sample's own record in noise.
#
# It also loads the sample: WP-CLI bootstraps WordPress and fires `init`, so an active
# malicious plugin runs inside every `wp` command, untraced, and its hooks filter what
# `wp user list` / `wp plugin list` show. By default plugins and themes are therefore
# skipped, which both keeps the sample out of untraced CLI runs and lets the analyst see
# the unfiltered database state. Set WP_LOAD_PLUGINS=1 to load them deliberately.
# The real phar is /usr/local/bin/wp-cli.phar.
if [ -z "${WP_LOAD_PLUGINS:-}" ]; then
  set -- --skip-plugins --skip-themes "$@"
fi
XDEBUG_MODE=off exec /usr/local/bin/wp-cli.phar "$@"
