#!/usr/bin/env bash
# Fake-model, fake-engine end-to-end run of the pilgrimage over the fixture library.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=$((20000 + RANDOM % 20000))
WORK="$(mktemp -d)"
fail=0
trap 'kill $SRV 2>/dev/null || true; if [ "${fail:-0}" -ne 0 ]; then cat "$WORK/err.log" >&2; fi; rm -rf "$WORK" .kadath/webtest-report' EXIT
cp -R tests/fixtures/library "$WORK/lib"
sleep 1; touch "$WORK/ref"     # everything the pilgrimage writes is newer than this
python3 tests/fixtures/fake_ollama.py "$PORT" & SRV=$!
for i in $(seq 1 50); do curl -fs "http://127.0.0.1:$PORT/api/tags" >/dev/null 2>&1 && break; sleep 0.1; done

pass=0; fail=0
check() { if eval "$2"; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }
run() { python3 bin/kadath pilgrimage "$WORK/lib" --ollama "http://127.0.0.1:$PORT" --model fake-model --runes-model fake-model \
          --engine "bash tests/fixtures/fake_engine.sh" --no-stack --no-manifest-backup "$@" 2>"$WORK/err.log"; }

# Pass 1 only, limited: resume must pick up the rest afterwards.
run --pass cavern --limit 2
M="$WORK/lib/kadath-triage.csv"
check "manifest exists" "test -f '$M'"
check "limit processed 2" "test \$(grep -c ',done,' '$M') -eq 2"
run --pass cavern
check "resume finished cavern" "test \$(awk -F, 'NR>1 && \$5==\"done\"' '$M' | wc -l) -eq 4"
check "skipped rows present" "grep -q 'MULTI-1,,,,skipped' '$M' && grep -q 'NOPHP-1,,,,skipped' '$M'"
check "RED-ONE not worthy, decided by cavern" "grep '^RED-ONE,' '$M' | grep -q ',red,webshell,false,' && grep '^RED-ONE,' '$M' | grep -q ',red,cavern,'"
check "RED-WORTHY worthy" "grep '^RED-WORTHY,' '$M' | grep -q ',true,'"
check "AMBER-1 forced worthy" "grep '^AMBER-1,' '$M' | grep -q ',amber,unknown,true,' && grep -q '\"worthy_forced\"' '$WORK/lib/AMBER-1/kadath/cavern.json'"
check "GREEN-1 green not worthy" "grep '^GREEN-1,' '$M' | grep -q ',green,benign,false,'"

run --pass runes
check "runes ran for worthy only" "test \$(awk -F, 'NR>1 && \$10==\"done\"' '$M' | wc -l) -eq 2"
check "runes.json written for RED-WORTHY" "test -s '$WORK/lib/RED-WORTHY/kadath/runes.json'"
check "runes skipped for non-worthy RED-ONE" "grep '^RED-ONE,' '$M' | grep -q ',skipped,,'"

run --pass offer
check "offer ran for worthy only" "test \$(awk -F, 'NR>1 && \$13==\"done\"' '$M' | wc -l) -eq 2"
check "RED-WORTHY red agree" "grep '^RED-WORTHY,' '$M' | grep -q ',done,red,full,'"
check "AMBER-1 disagreement keeps deterministic red, scry pending" "grep '^AMBER-1,' '$M' | grep -q ',done,red,full,' && awk -F, '\$1==\"AMBER-1\" && \$18==\"pending\"' '$M' | grep -q AMBER-1"
check "offer files written" "test -s '$WORK/lib/RED-WORTHY/kadath/report.md' && test -s '$WORK/lib/RED-WORTHY/kadath/draft.yar' && test -s '$WORK/lib/RED-WORTHY/kadath/iocs.json' && grep -q RUN_DIR '$WORK/lib/RED-WORTHY/kadath/run.env'"
check "confident red skips scry" "grep '^RED-WORTHY,' '$M' | grep -q ',skipped,,'"

run --pass scry
check "scry ran for AMBER-1 only" "test \$(awk -F, 'NR>1 && \$18==\"done\"' '$M' | wc -l) -eq 1"
check "AMBER-1 upgraded to red by deepscry" "grep '^AMBER-1,' '$M' | grep -q ',red,deepscry,'"
check "deep scrying appended to report" "grep -q '## Deep Scrying' '$WORK/lib/AMBER-1/kadath/report.md'"
check "no writes outside kadath/ and manifest" "test -z \"\$(find '$WORK/lib' -newer '$WORK/ref' -type f ! -path '*/kadath/*' ! -name kadath-triage.csv)\""

echo "$pass passed, $fail failed"
test "$fail" -eq 0
