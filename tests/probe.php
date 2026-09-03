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
