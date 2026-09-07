# The Pilgrimage — batch triage of the threat library with a local LLM

**Status:** approved design, 2026-09-07
**Depends on:** the `bin/kadath offer` engine, the kadath-scry skill's reading
procedure, Ollama running locally.

## Goal

Triage every PHP case under `~/WORK/jetpack-threat-library/for-later-review/`
(5,375 of 7,134 case directories) without Claude in the loop, using a local
model served by Ollama. Each case ends with a red / amber / green verdict, a
reason, and — where the sample was detonated — a report, an IOC file, and a
draft YARA rule, written beside the sample. A human then promotes cases through
the library's existing PR workflow; the script never moves cases and never
runs git.

## In the lore

| In the lore | In security terms |
|---|---|
| **The Pilgrimage** | the batch run over the whole library |
| **The Cavern of Flame** | tier 0 — the priests Nasht and Kaman-Thah judge, from the source alone, whether the thing is worthy of being carried down as an Offering |
| **The Offering** | tier 1 — detonation in Kadath plus an evidence pack the model turns into a report |
| **The Deep Scrying** | tier 2 — an agentic re-examination, with read-only tools, of what the Offering left uncertain |
| **The Manifest** | `kadath-triage.csv` — stays in the waking tongue |

These four entries are added to `LORE.md`.

## Decisions taken during brainstorming

- Tiered (C): static judgment → detonation → agentic re-examination.
- Model: `orcarouter/Qwen3.8-27B-Uncensored:latest` on Ollama (capabilities:
  tools, thinking, 262k context). Overridable.
- Results beside the sample, never committed (A). No auto-sorting of cases.
- Static tier 0 gates detonation (A): detonate unless tier 0 is *confidently*
  settled.
- Phased passes over a manifest, offer via subprocess (1). No overlap between
  model and sandbox in v1.

## Library facts the design relies on

- A case is `for-later-review/<ID>/` holding the sample and usually a
  provenance `README.md`. 5,363 cases hold exactly one `.php`; 11 hold 2–6;
  1,759 hold none. Multi-file cases are skipped with a reason.
- Sizes: 74% < 10 KB, 23% 10–100 KB, 170 cases 100 KB–1 MB, 5 over 1 MB.
- Malicious code is sometimes injected into legitimate code; tier 0 must locate
  the malicious span so downstream prompts and the YARA rule key on it.

## Architecture

### Entry point

```
bin/kadath pilgrimage <library-dir>
    [--pass cavern|offer|scry|all]      default all, in that order
    [--limit N] [--case ID ...]         smoke-testing subsets
    [--model M] [--ollama URL]          env fallback KADATH_MODEL / KADATH_OLLAMA_URL
    [--sampling tier.key=value ...]     repeatable overrides
    [--profiles profiles.json]          replaces the sampling table wholesale
    [--seed N]                          forces one seed in every tier
    [--retry-errors] [--force]
    [--min-free-gb N]                   default 20
```

`<library-dir>` is the `for-later-review` directory itself.

### Modules (stdlib only, Python ≥ 3.9, like the rest of `kadath/`)

| Module | Responsibility |
|---|---|
| `kadath/llm.py` | The only code that knows Ollama exists. `chat(messages, *, model, base_url, profile, json_schema=None, tools=None, timeout, think=False, options_override=None) -> {"content", "tool_calls", "parsed"}`. Sampling profiles table. `preflight(base_url, model)`. `LLMError`. |
| `kadath/library.py` | `walk(dir) -> Iterable[Case]`; `Case(id, dir, php, readme, skip_reason)`. `static_facts(path) -> dict`. `source_view(path) -> (text, truncated: bool)`. |
| `kadath/cavern.py` | Tier 0: prompt assembly, schema, the `worthy` override rules, writes `<case>/kadath/cavern.json`. |
| `kadath/pilgrim_offer.py` | Tier 1: runs the engine as a subprocess, builds the evidence pack, two model calls, YARA denylist check, final-verdict rule, writes `report.md`, `iocs.json`, `draft.yar`, `verdict.json`, `run.env`. |
| `kadath/deepscry.py` | Tier 2: read-only tool set, tool loop with cap, claim verification, revises `verdict.json`, appends to `report.md`. |
| `kadath/manifest.py` | `kadath-triage.csv` load / `ensure_rows` / `pending(pass)` / `update(row)` / atomic `flush()`. |
| `kadath/pilgrimage.py` | Orchestrator: argparse, preflight, the three pass loops, per-case error isolation, breakers, summaries. |
| `kadath/prompts/cavern.md`, `offer_verdict.md`, `offer_report.md`, `deepscry.md` | System prompts as files; sha256 recorded in every verdict. |

`bin/kadath` dispatches `argv[1] == "pilgrimage"` to `kadath.pilgrimage.main(argv[2:])`.

### Reuse

- `web_verdict.compute(summary)` gives the deterministic verdict and reasons.
- `traceparse.callchain` / `dangerous_calls_from_trace` build the trace
  excerpt.
- `summary.validate_iocs` validates the extended IOC file.
- `bin/kadath offer --json --slug <id> --skip-selftest` does the detonation;
  the engine already bundles the run's evidence into `reports/<slug>-<ts>/`.

### Output layout

```
for-later-review/
  kadath-triage.csv
  <ID>/
    README.md, <sample>.php          untouched
    kadath/
      cavern.json                    tier 0
      verdict.json                   final; carries model, profile, prompt sha256
      report.md, iocs.json, draft.yar   only if offered
      run.env                        RUN_DIR=<KadathSandbox>/reports/<ID>-<ts>
```

The run bundle (gzipped traces, flows) stays in KadathSandbox `reports/`; the
case directory gets the pointer. The script writes only under `<ID>/kadath/`
and the manifest.

## The model adapter

- Ollama `/api/chat`, `stream: false`, `urllib` only.
- Structured output via `format: <json-schema>`. Ollama guarantees syntax; the
  adapter validates semantics (enums, bounds, required keys). One retry with the
  validation error appended; a second failure raises `LLMError`. Never guess.
- `num_ctx` set explicitly per tier so Ollama never silently truncates to its
  default.
- `think` off for Cavern and Offering, on for Deep Scrying.
- Preflight before case 1: `GET /api/tags` lists the model; a one-token chat
  succeeds.

### Sampling profiles (in `llm.py`, overridable)

| Profile | temperature | top_p | top_k | min_p | repeat_penalty | seed | num_ctx | num_predict |
|---|---|---|---|---|---|---|---|---|
| `cavern` | 0.1 | 0.8 | 20 | 0 | 1.05 | 42 | 16384 | 1024 |
| `offer` | 0.2 | 0.8 | 20 | 0 | 1.05 | 42 | 32768 | 4096 |
| `deepscry` | 0.6 | 0.95 | 20 | 0 | 1.05 | none | 65536 | 8192 |

Deep Scrying must not run greedy: Qwen3 with thinking on loops at temperature 0.
`repeat_penalty` above ~1.1 degrades JSON and YARA; documented. The profile
used is recorded in `verdict.json` under `sampling`.

## Injection posture

Every byte the model reads is attacker-authored; the defence is structural.

1. Evidence is fenced: user message, delimited blocks, fixed preamble stating it
   is untrusted data. System prompt never mixes with evidence.
2. Verdict outputs are schema-constrained with enum verdicts and bounded strings.
3. The model can argue, not overrule silently: the deterministic verdict travels
   with the evidence; the final rule is `max(deterministic, model)` on
   red > amber > green, **and** `amber` whenever they disagree. Injection can
   only make a case more scrutinised.
4. Deep Scrying tools are read-only, argument-validated, capped at 25 calls.
   `wp_read` accepts only `user list`, `option get <name>`, `cron event list`,
   `plugin list`, and always adds `--skip-plugins`.
5. `report.md` is verbatim model text and treated as data; `verdict.json` and
   the manifest carry only enum / bounded fields.

## Tier contracts

### Tier 0 — Cavern (`cavern.json`)

Input: static facts (sha1, sha256, size, Shannon entropy, dangerous-function
inventory, `wp_` API inventory, longest string literal, base64/hex blob
presence, README provenance line) plus the source: full up to 64 KB; above that
the first 24 KB + last 8 KB + every line holding a dangerous function or a long
blob, with a truncation note.

Schema:

```json
{
  "verdict":     "red | amber | green",
  "confidence":  0.0-1.0,
  "family":      "webshell | backdoor | dropper | injector | spam-seo | credential-stealer | mailer | uploader | defacement | benign | fragment | unknown",
  "host_code":   "none | legitimate | unknown",
  "regions":     [{"start_line": int, "end_line": int, "why": "<=200 chars"}],
  "runnable":    true,
  "needs_input": "none | password | parameter | cookie | post-body | unknown",
  "worthy":      true,
  "reason":      "<=300 chars"
}
```

Worthiness rules in the system prompt: fully explained statically → red, not
worthy; obfuscated, legitimate-API-only, second-stage fetch, or DB-touching →
worthy even if already red (the Offering yields IOCs a static read cannot);
`fragment` / non-runnable → never worthy.

Script override, one direction only: `worthy` forced `true` when static facts
show `wp_` API usage, a network primitive, or a blob; when `confidence < 0.7`;
or when `verdict == amber`. `runnable == false` and `family == fragment` from
the model are respected only if no override fires.

### Tier 1 — Offering

Runs `bin/kadath offer <php> --json --slug <id> --skip-selftest` as a
subprocess, timeout 600 s; reads the printed `summary.json` path.

Evidence pack (deterministic, fenced): Cavern `regions` + `family`; the
deterministic verdict and reasons; `summary.json` `db_diff`,
`dangerous_calls`, `files_written`, non-core `network`; trace excerpt — frames
whose file is under `/samples/`, ±3 frames of context, hard cap 400 lines;
decrypted flow bodies for non-core hosts, 4 KB each.

Call 1 (schema): `verdict`, `confidence`, `iocs_extra[]` (conforming to
`iocs-schema.json` entries), `persistence[]`, `coverage: full | unauthenticated
| errored`, `reason`. `coverage` defaults from Cavern `needs_input` (anything
but `none` → `unauthenticated`) and from a PHP fatal in the run (→ `errored`).

Call 2 (free text): `report.md` following
`.claude/skills/kadath-scry/references/report-template.md`, and `draft.yar`.
YARA strings must come from Cavern `regions` or observed constants. The script
rejects any rule containing a bare WordPress API name from a denylist
(`wp_create_user`, `add_action`, `add_filter`, `update_option`, `wp_remote_get`,
`wp_schedule_event`, `file_put_contents`, `base64_decode`, `eval`); regenerates
once; on a second violation writes the rule with `yara: needs-review` in
`verdict.json`.

`iocs.json` = engine output + `iocs_extra`, validated by `summary.validate_iocs`.

Final verdict: `max(deterministic, model)`; `amber` if they disagree.
`verdict.json` records both verdicts, `decided_by`, `coverage`, model name,
profile, prompt sha256, timestamps.

### Tier 2 — Deep Scrying

Runs for cases with tier-1 `amber`, or `red` with `confidence < 0.6`. Thinking
on, `deepscry` profile, 15-minute timeout, 25-tool-call cap.

Tools (all read-only, over the case's run bundle and the live stack):
`read_trace(pattern, max_lines<=200)`, `read_flows()`, `read_dns()`,
`read_dropped()`, `read_sample(start_line, end_line)`, `wp_read(subcommand)`.

Output schema: the tier-1 verdict schema plus
`evidence: [{claim<=300, source: tool-name, quote<=200}]`. The script verifies
each `quote` is a substring of a tool result it actually returned; claims that
fail are dropped, and if any were dropped the verdict is held at `amber` with
`deepscry: unverified-claims`. Cap exceeded → verdict unchanged, `amber`, note
`tool-cap`. Findings are appended to `report.md` under a "Deep Scrying" heading.

## Manifest — `kadath-triage.csv`

Columns:

```
case_id, php, sha256, size,
cavern_status, cavern_verdict, cavern_family, cavern_worthy, cavern_at,
offer_status,  offer_verdict,  offer_coverage, run_dir, offer_at,
scry_status,   scry_verdict,   scry_at,
final_verdict, decided_by, error
```

- `*_status ∈ {pending, done, skipped, error, timeout}`; `*_at` ISO-8601 UTC.
- A pass processes rows where its status is `pending`. That is the resume logic.
- `ensure_rows` adds a row for every directory the walk sees, including
  skipped ones (`cavern_status=skipped`, reason in `error`), so the manifest
  accounts for all 7,134.
- `--retry-errors` flips `error`/`timeout` to `pending` for the requested
  pass(es). `--force` flips `done` too. Nothing else re-runs a done case.
- Rewritten atomically (`.tmp` + `os.replace`) after every case.
- Pass eligibility: `offer` needs `cavern_status=done` and `cavern_worthy=true`;
  `scry` needs `offer_status=done` and (`offer_verdict=amber` or `red` with
  confidence < 0.6, read from `verdict.json`).

## Failure handling

| Failure | Behaviour |
|---|---|
| Model invalid twice / timeout | row `error`/`timeout` + message; next case. Three consecutive → abort the pass. |
| Engine non-zero / timeout | row `offer_status=error`, stderr tail in `error`; `docker compose ps`; if unhealthy, `make down && make up` once; continue. Two consecutive stack failures → abort the pass. |
| PHP fatal in the sample | a result: `offer_status=done`, `coverage=errored`, fatal in the evidence pack. |
| Deep Scrying tool cap | `scry_status=done`, `scry_verdict=amber`, note `tool-cap`. |
| Ctrl-C | in-flight case left `pending` or fully written; rerun resumes. |
| Disk below `--min-free-gb` before an Offering | abort the pass with a clear message. |

## The loop

```
main(argv):
    parse; load profiles + overrides
    llm.preflight(); if offer or scry in passes: stack up + selftest once
    cases = library.walk(dir) filtered by --case, then [:limit]
    manifest.ensure_rows(cases)
    for pass in passes:
        for row in manifest.pending(pass):
            try: run_tier(pass, row)            # writes case files; updates row
            except Exception: mark error; consecutive-failure breaker
            manifest.flush()
        print pass summary: counts per status, verdict histogram
    print final histogram; top-N red by confidence
```

Ordering by case ID. Intended first command:
`bin/kadath pilgrimage <dir> --pass cavern --limit 50`.

## Testing

Unit (`unittest`, no GPU, no Docker): `test_library.py`, `test_llm.py`
(monkeypatched `urlopen`), `test_cavern.py`, `test_pilgrim_offer.py`,
`test_deepscry.py`, `test_manifest.py`, `test_pilgrimage.py` — covering the
walk and skip reasons, static facts and truncation, request shaping
(`format`, `options`, `num_ctx`), retry-then-fail, tool round-trips, the
`worthy` override rules, evidence-pack construction and caps, the final-verdict
rule, the YARA denylist, `iocs_extra` validation, the `wp_read` allowlist, the
tool cap, claim verification, manifest idempotence / pending selection /
atomic rewrite, the loop's error isolation and breakers, `--limit` / `--case`,
and resume.

Fake-model e2e (`tests/test_pilgrimage_e2e.sh`, CI): `tests/fixtures/fake_ollama.py`
serves `/api/tags` and `/api/chat` with canned replies keyed on prompt markers;
`tests/fixtures/fake_engine.sh` stands in for the engine. Six fixture cases,
all three passes, asserts manifest, per-case files, one amber case reaching tier
2, and resume after a simulated interruption.

Live smoke (`make pilgrimage-smoke`, manual): `--pass all --limit 3` over three
hand-picked cases against real Ollama and the real stack. The pre-flight before
a real pilgrimage.

Prompt drift: prompts are files; their sha256, the model name, and the sampling
profile are recorded in every `verdict.json`.

## Documentation

- `LORE.md`: the four new entries.
- `README.md`: a "Pilgrimage" section — prerequisites (Ollama, model pull),
  the first command, runtime expectations (~20–30 s per Cavern case, ~2–3 min
  per Offering), disk budget (~30 MB per offered case), the sampling knobs.
- `.claude/skills/kadath-scry/SKILL.md`: a pointer that a local model can do
  this in batch via `bin/kadath pilgrimage`.
- `Makefile`: `pilgrimage` and `pilgrimage-smoke` targets.

## Rulings during implementation

1. `wp_read` answers from the run's recorded `db_diff`, not the live stack, because the sandbox holds a later case by the time the scry pass runs.
2. The "red with confidence < 0.6" scry gate is decided inside the pass; the manifest keeps the listed columns.
3. Flow bodies come from a second mitmproxy addon, `kadath/flowbody.py`, run like `flowdump.py`.
4. `--engine CMD` and `--no-stack` are test hooks so the fake-model e2e runs without Docker.
5. The final verdict is strictly `max(deterministic, model)`; a disagreement never lowers it (that would let a model "green" erase a deterministic red) — it routes the case to the Deep Scrying instead, alongside ambers and reds with confidence < 0.6.
6. When the Cavern model says `runnable: false` or `family: fragment`, the `confidence < 0.7` and `verdict == amber` forces are suppressed; the fact-based forces (`wp_` API usage, network primitive, blob) always apply. A file that cannot run is not worth an Offering, but a fragment that calls `wp_create_user` still gets one attempt.
7. The Deep Scrying verdict is `max(deterministic, model)` in every outcome — verified, `unverified-claims`, and `tool-cap` — so deterministic evidence (an administrator created, non-core egress) is never cleared by a model; a model-only red can still be lowered. Its `wp_read` tool answers from the run's recorded `db_diff` (ruling 1) and its description says so.
8. `evidence.json` (trace excerpt, flow bodies, network, DB diff, deterministic verdict) is written into the run bundle under KadathSandbox `reports/<slug>-<ts>/`, not under `<case>/kadath/`; the write constraint is about the threat library, and the Deep Scrying toolbox reads it from the bundle.
9. **Missing dependencies and runtime silence** (from the first live smoke run, FIO-8491: Cavern red, then a PHP fatal on a missing include produced a green "agree" that erased the Cavern's verdict). Three changes: (a) the Cavern reports `missing_deps` and treats a verdict that hinges on a missing file as amber (confidence ≤ 0.6), and distinguishes data used as a value from code that is executed; `phishing` joins the family enum. (b) The engine gains `--stub-missing` (which the pilgrimage passes): fatals naming a missing include under `/samples/` become empty stubs on the host side of the bind mount, undefined functions become `return null` shims in the stub, and the sample is triggered again, up to three rounds; `summary.json` records `run.stubs` and `run.fatal`. (c) The Offering's final verdict is `max(cavern, deterministic, model)` with `decided_by` gaining `cavern`; `coverage` gains `stubbed`; and only a `coverage: full` run can settle a case — `stubbed`, `unauthenticated`, and `errored` runs route to the Deep Scrying, which is told the coverage and the stubs.
10. **WordPress fragments are adopted as plugins** (from the first 38-case Offering pass: 12 of 18 `errored` runs were files lifted out of a plugin or theme dying on `add_action`, `is_robots`, `ABSPATH`, `WP_Error`, `$wpdb` in a bare webroot). The engine gains `--adopt-wp` (the pilgrimage passes it when `library.wants_wordpress` matches): the loose file is wrapped as a synthetic plugin — a `Plugin Name` header, a shims file loaded first, then the sample — staged through the plugin path and activated. Undefined functions *and classes* are shimmed into that file (`stubs.add_class_shims`). `summary.json` records `run.adopted`. Also from that pass: a fatal is not evidence of intent (Offering prompt); the trigger session records a dropped connection as `connection-failed` instead of crashing the engine; the Ollama client retries a dropped connection once.

## Out of scope (v1)

- Overlapping the model and the sandbox (approach 3).
- Multi-file cases (11) and non-PHP samples.
- Any write to the library outside `<ID>/kadath/` and the manifest; any git.
- A web view of the manifest.
