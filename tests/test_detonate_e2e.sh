#!/usr/bin/env bash
# End-to-end acceptance for bin/kadath detonate. Requires the stack (make up) and
# python3. Uses tests/probe.php (benign) and, if present, the integrity-scanner
# backdoor from the jetpack-threat-library.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; else echo "FAIL: $1"; fail=$((fail+1)); fi; }

# 1. benign probe as a webshell
RUN=$(python3 bin/kadath detonate tests/probe.php --json)
echo "probe summary: $RUN"
ck "probe: summary.json exists"            '[ -f "$RUN" ]'
ck "probe: valid json"                     'python3 -c "import json;json.load(open(\"'"$RUN"'\"))"'
ck "probe: no users added"                 'python3 -c "import json;s=json.load(open(\"'"$RUN"'\"));import sys;sys.exit(0 if s[\"db_diff\"][\"users_added\"]==[] else 1)"'
ck "probe: callchain non-empty"            'python3 -c "import json;s=json.load(open(\"'"$RUN"'\"));import sys;sys.exit(0 if s[\"callchain\"] else 1)"'
ck "probe: example.com flow recorded"      'python3 -c "import json;s=json.load(open(\"'"$RUN"'\"));import sys;sys.exit(0 if any(\"example.com\"==f[\"host\"] for f in s[\"network\"][\"flows\"]) else 1)"'
ck "probe: 6667 in dropped"                'python3 -c "import json;s=json.load(open(\"'"$RUN"'\"));import sys;sys.exit(0 if any(d[\"port\"]==6667 for d in s[\"network\"][\"dropped\"]) else 1)"'

# 2. real backdoor, if the library is checked out
BD=~/WORK/jetpack-threat-library/threats/php_backdoor_createhide_admin_001_4/integrity-scanner-156.php
if [ -f "$BD" ]; then
  RUN2=$(python3 bin/kadath detonate "$BD" --json)
  DIR2=$(dirname "$RUN2")
  echo "backdoor summary: $RUN2"
  ck "backdoor: sys_maint added as administrator" 'python3 -c "import json;s=json.load(open(\"'"$RUN2"'\"));import sys;sys.exit(0 if any(u[\"login\"]==\"sys_maint\" and \"administrator\" in u[\"roles\"] for u in s[\"db_diff\"][\"users_added\"]) else 1)"'
  ck "backdoor: callchain non-empty"              'python3 -c "import json;s=json.load(open(\"'"$RUN2"'\"));import sys;sys.exit(0 if s[\"callchain\"] else 1)"'
  ck "backdoor: iocs.json validates vs schema"    'python3 tests/validate_iocs.py "'"$DIR2"'/iocs.json" .claude/skills/kadath-analyze/references/iocs-schema.json'
  ck "backdoor: iocs list the user"               'python3 -c "import json;i=json.load(open(\"'"$DIR2"'/iocs.json\"));import sys;sys.exit(0 if any(x[\"type\"]==\"wp_user\" and x[\"value\"]==\"sys_maint\" for x in i[\"indicators\"]) else 1)"'
else
  echo "SKIP: backdoor sample not present at $BD"
fi

# 3. lock is released (a second run must succeed)
python3 bin/kadath detonate tests/probe.php --json >/dev/null 2>&1
ck "lock released between runs" '[ $? -eq 0 ]'

[ "$fail" -eq 0 ] && echo "E2E PASSED" || echo "E2E FAILED ($fail)"
exit "$fail"
