# report.md template

Fill every section. Cite evidence as `file:line` into the sample source and name the exact artifact (trace filename, log, flow) each runtime claim came from. Mark anything reviewed in source but not observed at runtime as such — never assert it as observed.

```markdown
# Triage Report — "<display name>" (<filename>)

**Sample:** <absolute path>
**SHA256:** <hash>   **MD5:** <hash>   **Size:** <n> lines / <n> bytes
**Family / label:** <threat-library family or your classification>
**Offered:** <RUN_UTC> in KadathSandbox, activated via <wp-admin over HTTP | CLI + page view | direct URL>
**Artifacts snapshot:** snapshots/<ts>/

## Summary
Two or three sentences: what it pretends to be, what it actually does, and whether it has network/C2 behaviour. State the bottom line first.

## Behaviour, with runtime evidence
One subsection per distinct behaviour. Each: what it does, the source location (`file:line`), and the runtime proof (trace file + the call chain or arguments you extracted; a DB/HTTP confirmation where relevant). Decode any obfuscated constants and show both the encoded and decoded form.

## Persistence and anti-removal
Accounts, options, cron events, dropped files, hooks that re-assert state. Confirm each against the unfiltered database (`wp --skip-plugins ...`).

## Hiding / evasion
How it hides from the UI, REST, or scanners. Note detectable side effects (count vs row mismatches, generator meta, 403 patterns).

## Network activity
C2, exfil, or next-stage fetches — or an explicit "none observed and none present in source". Cite `flows.mitm`, `dns.log`, `dropped.log`, all filtered to this run. Distinguish sample traffic from WordPress core's own api.wordpress.org calls.

## Indicators of Compromise
A table: type | value | notes. Mirror this into iocs.json.

## Detection notes for defenders
Cheap fleet-wide checks, static signatures, and any property that defeats common scanners (e.g. privilege escalation via legitimate WordPress APIs, which a call-blacklist scanner misses).

## Caveats
What was reviewed in source but not re-triggered at runtime; attribution boundaries; anything time-limited.
```
