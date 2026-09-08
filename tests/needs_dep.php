<?php
// e2e fixture: a single file lifted out of a "kit". Without --stub-missing the
// first line fatals and nothing below runs; with it the engine stubs the include
// (round 0/1), shims helper_ping() (round 2), and the egress below is observed.
require_once __DIR__ . '/kit/helpers.php';
$geo = helper_ping('probe');
$body = @file_get_contents('https://example.com/');
echo strlen((string) $body) > 0 ? "fetched\n" : "no body\n";
