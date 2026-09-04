#!/bin/sh
# WP-CLI runs inside the same PHP install as the sample. Without this, every analyst
# `wp` invocation writes an Xdebug trace into artifacts/xdebug/ and fires the same
# Snuffleupagus rules the sample does, burying the sample's own record in noise.
# The real phar is /usr/local/bin/wp-cli.phar.
XDEBUG_MODE=off exec /usr/local/bin/wp-cli.phar "$@"
