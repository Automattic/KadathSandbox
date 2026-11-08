<?php
// Benign self-check sample. Exercises every observation layer once.
header('Content-Type: text/plain');

echo "eval: ", eval('return 1+1;'), "\n";

echo "system: ";
system('id');
echo "\n";

// example.com here, www.iana.org for wp_remote_get in selftest.sh, so each flow check can only
// be satisfied by its own request. (Not example.org/.net: some of their Cloudflare addresses are
// unreachable from containers on at least one host this was developed on.)
$body = @file_get_contents('https://example.com/');
echo "https: ", ($body === false ? 'fail' : 'ok ' . strlen($body)), "\n";

// 1.1.1.1:853 (DNS-over-TLS) is open on the public internet, so a connect that got past the
// gateway would succeed and this line would say "connected". (6667 is closed there anyway,
// which made "blocked" a foregone conclusion.) The gateway INPUT policy drops it silently.
$sock = @fsockopen('1.1.1.1', 853, $errno, $errstr, 3);
echo "dot: ", ($sock ? 'connected' : "blocked ($errno)"), "\n";
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
// The pool pins error_reporting; the raw ini value must parse to E_ALL (32767), not 0.
echo "error_reporting: ", error_reporting(), "\n";
// Last of all: error_reporting() and @ write the engine's value directly and are not gated by
// php_admin_value, so this is expected to report 0 (a documented limit). selftest.sh prints it as INFO only.
error_reporting(0);
echo "error_reporting after error_reporting(0): ", error_reporting(), "\n";
