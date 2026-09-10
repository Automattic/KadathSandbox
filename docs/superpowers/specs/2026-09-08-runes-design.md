# The Runes — static deobfuscation + a security LLM, before and instead of detonation

**Status:** approved design (Phase 1), 2026-09-08
**Depends on:** the Pilgrimage (merged, PR #1), Ollama, the CyberSecQwen-4B model.

## Why

Two problems the live Offering passes exposed:
1. **The errored tail never ends.** A large share of the library is broken code
   — PHP-5 syntax, missing includes we can't stub, `Path cannot be empty`,
   redeclares. Each fix to the detonation path buys a few cases; there is no
   bottom to "malware that won't run as found". A tier that reads the code
   instead of running it settles those in one move.
2. **The Offering is blind on obfuscation.** `eval(gzinflate(base64_decode('…')))`
   is opaque to the runtime evidence pack until it runs, and often it won't.

## What (Phase 1)

A new tier, **the Runes** — reading what is carved rather than watching what
moves. It runs BEFORE the Offering for every worthy case (its output enriches
the Offering) and IS the deciding tier when the Offering cannot run the sample.
No new container in Phase 1; a PHP-Parser AST oracle is Phase 2.

Pipeline: `cavern → runes → offer → scry`.

### The static unpacker (pure Python, no execution)

`kadath/runes.py` walks literal decoder chains and evaluates them statically —
never with `eval`, only Python stdlib transforms:

| PHP | Python |
|---|---|
| `base64_decode` | `base64.b64decode(…, validate)` |
| `gzinflate` | `zlib.decompress(…, -15)` |
| `gzuncompress` | `zlib.decompress` |
| `gzdecode` | `gzip.decompress` |
| `str_rot13` | `codecs.decode(…, 'rot13')` |
| `strrev` | `[::-1]` |
| `hex2bin` / `pack('H*')` | `bytes.fromhex` |
| `urldecode` / `rawurldecode` | `urllib.parse.unquote` |
| `convert_uudecode` | `binascii.a2b_uu` (best effort) |

It finds a string literal wrapped in a chain of these decoders and applies them
inside-out; a decoded layer that itself contains such a chain recurses, up to
**5 layers**. Guards: each layer's output capped at **2 MB**, total at **8 MB**
(decompression-bomb bound); a decoder that raises ends that chain. Each layer is
written to `<case>/kadath/unpacked/layer-<n>.php` — the deobfuscated code is
itself the most useful artifact for a YARA rule.

### Facts across the layers

Static facts (reusing `library.static_facts` on each written layer file):
dangerous/network/wp_api inventories, blobs, plus literal URLs, IPs, emails,
paths harvested from every layer. This is the structural evidence the model
reads alongside the source.

### The verdict call

One call to a security-tuned model (default **CyberSecQwen-4B**,
`hf.co/ree2raz/CyberSecQwen-4B-GGUF:Q4_K_M`; spike-confirmed: honours Ollama
structured output, no tools/thinking needed, ~12 s). Fenced evidence, untrusted
preamble, schema-constrained output: `verdict` (enum), `confidence`, `family`
(the Cavern enum, incl. `phishing`), `iocs_extra`, `persistence`, `flows`
(`[{source, sink, line}]`, optional), `reason`. The Cavern judgment and, on the
error path, the run's fatal lines travel with it.

### Verdict rule and routing

- Runes verdict alone: `max(cavern, runes_model)`; `decided_by = "runes"` when
  Runes raises it.
- **Before the Offering:** `runes.json` is written; the Offering's evidence pack
  gains a RUNES section (decoded layers' facts + the runes read). The final
  Offering verdict becomes `max(cavern, runes, deterministic, model)`.
- **On an Offering that cannot run the sample** (EngineError, or `coverage`
  `errored`/`stubbed`-with-fatal): the case is NOT left as an error row. The
  Offering records a done row with `coverage: errored`, verdict
  `max(cavern, runes)`, `decided_by: runes` — the broken-sample loop ends. A row
  errors only when Runes is also unavailable.
- Settled: a Runes-decided errored case is settled if Cavern and Runes agree and
  confidence ≥ 0.6 (no runtime evidence can ever be added for a sample that
  won't run). Amber still never settles.

## Model config

`--runes-model` (env `KADATH_RUNES_MODEL`, default CyberSecQwen-4B); the
pilgrimage builds a second `llm.Client` for it. Preflight checks BOTH models.
A `runes` sampling profile: temp 0.1, top_p 0.8, num_ctx 32768, num_predict 2048,
seed 42.

## Manifest migration

Three columns added — `runes_status`, `runes_verdict`, `runes_at` — inserted
between `cavern_at` and `offer_status`. The live `kadath-triage.csv` already has
the old columns, and `Manifest.load` currently rejects any header != COLUMNS.
Relax it: accept a header whose columns are all known and in COLUMNS order (an
older, shorter schema), filling missing columns with ""; still reject unknown or
reordered columns. Additive migration then just works, and resume across
versions works. `pending("runes")` = worthy cavern-done cases; `pending("offer")`
additionally requires `runes_status == done`.

## Outputs (beside the sample)

`<case>/kadath/runes.json` (layers + facts + the read), `unpacked/layer-<n>.php`,
IOCs merged into `iocs.json`, a `## Runes` section in `report.md`.

## Injection posture

Unchanged and inherited: decoded layers and facts are attacker data, fenced in
the user message after the untrusted preamble; the verdict is schema-constrained;
Runes can only raise a verdict (`max`), never lower one; decoding executes no
sample code and is size-bounded.

## Out of scope (Phase 1)

The PHP-Parser AST oracle and source→sink dataflow (Phase 2); any change to the
Cavern/Deep Scrying tiers beyond routing.
