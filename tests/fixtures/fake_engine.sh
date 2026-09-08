#!/usr/bin/env bash
# Fake offer engine for web flow tests. Args: <sample> --json [--recipe P] [--reset]
# Prints phase lines to stderr, writes a canned report, prints the summary path.
set -e
echo "bringing the stack up..." >&2
echo "staging..." >&2
echo "triggering..." >&2
REP="$(dirname "$0")/../../.kadath/webtest-report"
mkdir -p "$REP"
cat > "$REP/summary.json" <<JSON
{"sample":{"filename":"x.php","sha256":"a","type":"plugin"},
 "run":{"epoch":1,"utc":"2026-09-05T00:00:00Z","slug":"x","trigger_actions":[],"reset":false},
 "db_diff":{"users_added":[{"id":10,"login":"sys_maint","email":"s@x","roles":["administrator"]}],
 "users_removed":[],"users_role_changed":[],"options_added":[],"options_changed":[],"cron_added":[]},
 "callchain":[{"function":"wp_create_user","file":"/samples/plugins/x/x.php","line":12}],
 "dangerous_calls":[],"files_written":[],
 "network":{"dns":[],"flows":[],"dropped":[]},
 "artifacts":{"traces":[],"sp_dumps":[],"pcaps":[]},"warnings":[]}
JSON
echo '{"sample":{"filename":"x.php"},"offered_utc":"2026-09-05T00:00:00Z","classification":"wp-sample/unknown","network":{"observed":false},"indicators":[{"type":"wp_user","value":"sys_maint"}]}' > "$REP/iocs.json"
echo "$REP/summary.json"
