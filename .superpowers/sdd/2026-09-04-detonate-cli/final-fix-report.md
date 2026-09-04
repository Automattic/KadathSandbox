# Final fix wave

Applied the three review findings from `final-fix.md` against `feat/detonate-cli`.

## I1 (Important) — `--slug` desyncs the staged dest from the slug

Added a module-level `_apply_slug(det, slug)` helper in `kadath/run.py` that recomputes
the last path segment of `det.dest` from the new slug when `det.type` is `plugin` or
`theme` (webshell dest is a file basename and zip dest is empty/recomputed later, so
those are left alone). `detonate()`'s `--slug` handling now calls
`det = _apply_slug(det, a.slug)` instead of rebuilding `Detected` with the stale dest.

Also added `import re` to `kadath/run.py` — the fix file said `re` was already
imported, but it was not; `_apply_slug` needs `re.sub`, so the import was added at the
top of the file alongside the other stdlib imports.

Added two unit tests to `tests/test_runhelpers.py`:
- `test_apply_slug_plugin_updates_dest` — asserts a plugin's dest tracks the new slug.
- `test_apply_slug_webshell_keeps_dest` — asserts a webshell's dest (a file path) is
  left unchanged.

## I2 (Important) — RUN_UTC / detonated_utc must be ISO-8601

`kadath/run.py` now computes both timestamps where `ts` was previously computed alone:

```python
ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
```

`ts` (compact) is still used for the `reports/<slug>-<ts>` directory name only. `iso`
is now used for:
- `run.env` `RUN_UTC=` (was `ts`)
- `run_meta["utc"]` passed into `summary.build_summary` (was `ts`)
- the `run_utc` positional argument to `summary.build_iocs` (was `ts`)

This makes `summary.json`'s `run.utc` and the IOC file's `detonated_utc` match the
documented ISO-8601 contract (`RUN_UTC = date -u +%FT%TZ`).

## M4 (Minor) — flowdump.py docstring path

`kadath/flowdump.py`'s module docstring example command referenced
`/opt/kadath/flowdump.py`; `run.py` actually copies the addon to `/tmp/flowdump.py`
before invoking mitmdump. Updated the docstring's example command to reference
`/tmp/flowdump.py`.

## Verification

```
$ python3 -m pytest -q
......................................                                   [100%]
38 passed in 0.06s

$ python3 -c "from kadath.run import detonate; print('ok')"
ok
```

The end-to-end test was intentionally not run per instructions (it detonates live
malware).

## Files touched
- `kadath/run.py`
- `kadath/flowdump.py`
- `tests/test_runhelpers.py`
