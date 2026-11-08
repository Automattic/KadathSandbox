<?php
// Benign self-check sample. Exercises every observation layer once.
header('Content-Type: text/plain');

echo "eval: ", eval('return 1+1;'), "\n";

echo "system: ";
system('id');
echo "\n";

$body = @file_get_contents('https://example.com/');
echo "https: ", ($body === false ? 'fail' : 'ok ' . strlen($body)), "\n";

$sock = @fsockopen('1.1.1.1', 6667, $errno, $errstr, 3);
echo "irc: ", ($sock ? 'connected' : "blocked ($errno)"), "\n";
if ($sock) { fclose($sock); }

$host = 'selftest-' . uniqid() . '.invalid';
echo "dns: $host -> ", gethostbyname($host), "\n";

// Last on purpose: if a pin were missing, a successful ini_set() here must not blind
// the trace or the log for the earlier lines. ini_set() returns false when the value
// cannot be changed (php_admin_value in the pool, or Snuffleupagus ini_protection).
echo "ini-pinned: ", (ini_set('xdebug.var_display_max_data', '1') === false && ini_set('error_log', '/dev/null') === false && ini_set('log_errors', '0') === false) ? 'yes' : 'no', "\n";
echo "error_log: ", ini_get('error_log'), "\n";
// precision is pinned nowhere, so this line alone proves that .user.ini files are ignored.
echo "precision: ", ini_get('precision'), "\n";
