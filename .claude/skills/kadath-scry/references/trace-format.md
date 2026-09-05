# Reading Xdebug computerized traces (`.xt`, format 4)

The sandbox writes `xdebug.trace_format=1` (tab-separated "computerized" format). One request = one `artifacts/xdebug/trace.<epoch>.<reqid>.xt` file. Files are large (tens of MB per WordPress page view); use `grep`/`awk`/`sed -n`, never load a whole trace into context.

## Header

```
Version: 3.5.3
File format: 4
TRACE START [2026-09-04 16:21:36.312514]
...records...
TRACE END   [2026-09-04 16:21:41.024222]
```

## Record columns (tab-separated)

Every record after the header is one tab-separated line. The meaning depends on the **third column**, the record type.

**Entry record** (type `0`) — a function was called:

| col | field | example |
|----|-------|---------|
| 1 | depth level | `9` |
| 2 | function # (unique id) | `45142` |
| 3 | record type = `0` | `0` |
| 4 | time index (s) | `0.217334` |
| 5 | memory (bytes) | `4373168` |
| 6 | **function name** | `wp_create_user` |
| 7 | user-defined (1) or internal (0) | `1` |
| 8 | included/require'd filename | (usually empty) |
| 9 | **caller file** | `/samples/plugins/x/x.php` |
| 10 | **caller line** | `172` |
| 11 | argument count | `3` |
| 12+ | **each argument, rendered** | `'sys_maint'` `'sys@localhost.local'` |

**Exit record** (type `1`): cols 1-2 match the entry, col 4-5 are time/memory at return. No name.

**Return record** (type `R`): the return value is the **last** field, e.g. `... R\t\t\t'uid=33(www-data) ...'`.

**Assignment record** (type `A`, present because `collect_assignments=1`): a variable was assigned; col 6 area holds the file, a later col the variable name and value.

Sensitive arguments show as `[Sensitive Parameter]` (PHP's `#[\SensitiveParameter]`, e.g. the password arg of `wp_create_user`) — the plaintext is usually still visible one level deeper, in the `wp_insert_user` call that receives the `user_pass` array key, or in `wp_hash_password`'s caller.

Value rendering is capped at `var_display_max_data=65536` bytes, depth 2, 32 children, so large arrays/objects are truncated with `...`; string payloads up to 64 KB are intact.

## Recipes

Set `T` to one trace file first: `T=$(find artifacts/xdebug -name '*.xt' -newermt "@$RUN_EPOCH" | sort | head -1)`.

**Every function the sample's own file called** (entry records whose caller file is the sample):

```bash
awk -F'\t' '$3=="0" && $9 ~ /\/samples\// {printf "%-30s %s:%s\n", $6, $9, $10}' "$T" | awk '!seen[$0]++'
```

**A specific call with its arguments** (arguments are col 12 onward):

```bash
grep -m1 -P '\twp_create_user\t' "$T" | awk -F'\t' '{printf "%s  (%s:%s)  ", $6,$9,$10; for(i=12;i<=NF;i++) printf "%s | ", $i; print ""}'
```

**The return value of a call** — find the entry's function id (col 2), then its `R` record:

```bash
FID=$(grep -m1 -P '\tsystem\t' "$T" | cut -f2)
awk -F'\t' -v id="$FID" '$2==id && $3=="R"{print $NF}' "$T"
```

**Deobfuscation stages** — where decoded code enters an executor:

```bash
grep -nE '\t(eval|assert|create_function|call_user_func|base64_decode|gzinflate|gzuncompress|str_rot13)\t' "$T" | head
```
The eval'd source is the argument on the `eval` entry line (col 12); read it with `sed -n '<line>p' "$T"`.

**Files the sample wrote** (dropped webshells, modified core):

```bash
grep -nE '\t(file_put_contents|fwrite|fputs|move_uploaded_file|rename|copy|unlink)\t' "$T" \
  | awk -F'\t' '$9 ~ /\/samples\//'
```

**Call chain around one point** — print a window of the raw trace and read the depth column (col 1) to see nesting:

```bash
L=$(grep -n -m1 'sys_integrity_ensure_user' "$T" | cut -d: -f1); sed -n "${L},$((L+40))p" "$T" | cut -f1,3,6,9,10
```

## Gotcha: the in-request object cache can mask a hiding hook

A sample that hides users with `pre_user_query` (or hides via `rest_user_query`, `all_plugins`, etc.) only filters *database queries*. WordPress's in-process object cache can satisfy a `get_user_by()` / `get_userdata()` call from memory within the same request, bypassing the filter entirely — so a single in-request read can return the "hidden" user and fool you into concluding the hook does not work. Judge a hiding hook by (a) the hook being registered and its filter arguments in the trace, and (b) the unfiltered database via `wp --skip-plugins user list`, not by one `get_user_by()` return value inside the same request. Report the hook as effective if it rewrites the query, and note the object-cache caveat rather than calling it broken.

## Snuffleupagus lines

`artifacts/php/php-error.log`, one line per hooked call reached (simulation mode — logged, never blocked):

```
[04-Sep-2026 10:39:26 UTC] PHP Warning:  [snuffleupagus][0.0.0.0][disabled_function][simulation] Aborted execution on call of the function 'system' in /path on line N
```

Filter to the run by the bracketed timestamp, and remember the trap: functions built from legitimate WordPress APIs never appear here. Count what fired:

```bash
grep snuffleupagus artifacts/php/php-error.log | grep -oE "function '[a-z_0-9]+'" | sort | uniq -c | sort -rn
```
