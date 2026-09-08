"""Tier between the Cavern and the Offering — the Runes. Read what is carved
rather than watch what moves: statically walk literal decoder chains (no
execution), harvest facts from every unpacked layer, and have a security-tuned
model judge the deobfuscated code. Runs before the Offering to enrich it, and
is the deciding tier when the Offering cannot run the sample at all."""
import base64
import binascii
import codecs
import gzip
import hashlib
import json
import os
import re
import urllib.parse
import zlib
from kadath import cavern, library, llm, manifest
from kadath.cavern import UNTRUSTED_PREAMBLE, load_prompt
from kadath.pilgrim_offer import IOC_TYPES, ORDER, final_verdict

MAX_LAYERS = 5
LAYER_CAP = 2 * 1024 * 1024      # 2 MB per decoded layer
TOTAL_CAP = 8 * 1024 * 1024      # 8 MB across all layers (decompression-bomb bound)

_URL = re.compile(rb"(?:https?|ftp)://[^\s'\"<>)]{4,300}")
_IP = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}")


def _b64(b):
    return base64.b64decode(b, validate=True)


def _gzinflate(b):
    return zlib.decompress(b, -15)


def _rot13(b):
    return codecs.encode(b.decode("latin-1"), "rot13").encode("latin-1")


# php decoder name -> pure Python transform on bytes (never executes sample code)
DECODERS = {
    "base64_decode": _b64,
    "gzinflate": _gzinflate,
    "gzuncompress": zlib.decompress,
    "gzdecode": gzip.decompress,
    "str_rot13": _rot13,
    "strrev": lambda b: b[::-1],
    "hex2bin": lambda b: bytes.fromhex(b.decode("latin-1").strip()),
    "urldecode": lambda b: urllib.parse.unquote_to_bytes(b),
    "rawurldecode": lambda b: urllib.parse.unquote_to_bytes(b),
    "convert_uudecode": binascii.a2b_uu,
}

# <decoder>( <decoder>( ... 'literal' ... ) ) — captures the chain and the literal
_CHAIN = re.compile(
    r"((?:\b(?:" + "|".join(map(re.escape, DECODERS)) + r")\s*\(\s*)+)"
    r"(['\"])(?P<lit>(?:\\.|(?!\2).){16,})\2")
_DEC_NAME = re.compile(r"\b(" + "|".join(map(re.escape, DECODERS)) + r")\s*\(")


def _unescape_php(lit, quote):
    # single-quoted PHP only honours \\ and \'; double-quoted honours more, but
    # obfuscated blobs are near-universally single-quoted base64/hex — decode
    # the common escapes and leave the rest verbatim
    out = lit.replace("\\\\", "\\")
    out = out.replace("\\'" if quote == "'" else '\\"', quote)
    return out


def _apply_chain(names, literal):
    """Apply decoder names (outermost first in source => innermost last) to the
    literal, inside-out. Returns bytes or None if any step fails."""
    data = literal.encode("latin-1", "replace")
    for name in reversed(names):
        fn = DECODERS.get(name)
        if fn is None:
            return None
        try:
            data = fn(data)
        except (binascii.Error, zlib.error, ValueError, OSError, UnicodeError):
            return None
        if len(data) > LAYER_CAP:
            return None
    return data


def unpack(source, max_layers=MAX_LAYERS):
    """Statically evaluate literal decoder chains, layer by layer. Returns a list
    of {"n", "decoders", "text", "sha256", "bytes"} for each successfully decoded
    layer (empty when the sample is not packed this way)."""
    layers = []
    total = 0
    current = source
    for n in range(1, max_layers + 1):
        m = _CHAIN.search(current)
        if not m:
            break
        names = _DEC_NAME.findall(m.group(1))
        decoded = _apply_chain(names, _unescape_php(m.group("lit"), m.group(2)))
        if decoded is None:
            break
        total += len(decoded)
        if total > TOTAL_CAP:
            break
        text = decoded.decode("utf-8", "replace")
        layers.append({"n": n, "decoders": names, "text": text,
                       "sha256": hashlib.sha256(decoded).hexdigest(), "bytes": decoded})
        current = text
    return layers


def _iocs_from_bytes(data):
    def uniq(rx):
        seen, out = set(), []
        for m in rx.findall(data):
            v = m.decode("latin-1", "replace")
            if v not in seen:
                seen.add(v); out.append(v)
        return out[:50]
    return {"urls": uniq(_URL), "ips": uniq(_IP), "emails": uniq(_EMAIL)}


def gather(case_php, layers, kd):
    """Static facts of the original plus each unpacked layer (written to
    unpacked/), and the literal network indicators harvested across all of them."""
    facts = {"original": library.static_facts(case_php), "layers": []}
    unp = os.path.join(kd, "unpacked")
    with open(case_php, "rb") as f:
        blob = f.read()
    for layer in layers:
        os.makedirs(unp, exist_ok=True)
        lp = os.path.join(unp, f"layer-{layer['n']}.php")
        with open(lp, "wb") as f:
            f.write(layer["bytes"])
        lf = library.static_facts(lp)
        lf["decoders"] = layer["decoders"]
        facts["layers"].append(lf)
        blob += b"\n" + layer["bytes"]
    facts["indicators"] = _iocs_from_bytes(blob)
    return facts


SCHEMA = {
    "type": "object",
    "required": ["verdict", "confidence", "family", "iocs_extra", "persistence", "reason"],
    "properties": {
        "verdict": {"type": "string", "enum": ["red", "amber", "green"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "family": {"type": "string", "enum": cavern.FAMILIES},
        "iocs_extra": {"type": "array", "items": {
            "type": "object", "required": ["type", "value"],
            "properties": {"type": {"type": "string", "enum": IOC_TYPES},
                           "value": {"type": "string", "maxLength": 500},
                           "notes": {"type": "string", "maxLength": 200},
                           "evidence": {"type": "string", "maxLength": 200}}}},
        "persistence": {"type": "array", "items": {"type": "string", "maxLength": 200}},
        "flows": {"type": "array", "items": {
            "type": "object", "required": ["source", "sink"],
            "properties": {"source": {"type": "string", "maxLength": 80},
                           "sink": {"type": "string", "maxLength": 80},
                           "line": {"type": "integer"}}}},
        "reason": {"type": "string", "maxLength": 400},
    },
}


def _fence(title, body, lang=""):
    body = body.replace("```", "'''")
    return f"\n=== {title} ===\n```{lang}\n{body}\n```\n" if lang else f"\n=== {title} ===\n{body}\n"


def build_messages(system, cav, facts, layers, source_view, fatals):
    layer_src = "\n".join(f"--- layer {l['n']} (via {' <- '.join(l['decoders'])}) ---\n{l['text'][:20000]}"
                          for l in layers) or "(no static decoding was possible)"
    user = (UNTRUSTED_PREAMBLE
            + _fence("STATIC JUDGMENT (Cavern)", json.dumps(
                {"verdict": cav.get("verdict"), "family": cav.get("family"),
                 "regions": cav.get("regions"), "missing_deps": cav.get("missing_deps", [])}), "json")
            + _fence("STATIC FACTS (original + unpacked layers)", json.dumps(facts, indent=1), "json")
            + (_fence("FATAL LINES (the detonation could not run this sample)", "\n".join(fatals), "text")
               if fatals else "")
            + _fence("SOURCE (line-numbered)", source_view, "php")
            + _fence("DEOBFUSCATED LAYERS", layer_src, "php")
            + "\nJudge this sample from what the code is, not from whether it ran. Reply with the JSON object only.")
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def run(case, cav, client, prompts_dir, fatals=None):
    """Read the sample, unpack it statically, and get a security-model verdict.
    Writes <case>/kadath/runes.json and unpacked/layer-*.php, merges iocs.json.
    Returns the runes dict (verdict floored at the Cavern's)."""
    kd = os.path.join(case.dir, "kadath")
    os.makedirs(kd, exist_ok=True)
    with open(case.php, "rb") as f:
        source = f.read().decode("utf-8", "replace")
    layers = unpack(source)
    facts = gather(case.php, layers, kd)
    view, _trunc = library.source_view(case.php)
    system, sha = load_prompt(prompts_dir, "runes")
    msgs = build_messages(system, cav, facts, layers, view, fatals or [])
    r = client.chat(msgs, profile="runes", json_schema=SCHEMA, think=False,
                    validate=lambda o: llm.validate_against(SCHEMA, o))
    m = r["parsed"]
    level, decided = final_verdict("green", m["verdict"], cav.get("verdict"))
    decided = "runes" if decided == "model" else decided
    out = {"verdict": level, "decided_by": decided, "model_verdict": m["verdict"],
           "cavern_verdict": cav.get("verdict"), "confidence": m["confidence"],
           "family": m["family"], "layers": [{k: l[k] for k in ("n", "decoders", "sha256")} for l in layers],
           "facts": facts, "iocs_extra": m["iocs_extra"], "persistence": m["persistence"],
           "flows": m.get("flows", []), "reason": m["reason"], "model": client.model,
           "sampling": dict(client.profiles["runes"]), "prompt_sha256": sha, "at": manifest.now_iso()}
    with open(os.path.join(kd, "runes.json"), "w") as f:
        json.dump(out, f, indent=2)
    _merge_iocs(kd, m["iocs_extra"], facts["indicators"])
    return out


def _merge_iocs(kd, iocs_extra, indicators):
    path = os.path.join(kd, "iocs.json")
    try:
        with open(path) as f:
            iocs = json.load(f)
    except (OSError, ValueError):
        return    # no offering iocs yet; the Offering (or a hand run) owns this file
    have = {(i.get("type"), i.get("value")) for i in iocs.get("indicators", [])}
    for e in iocs_extra:
        if (e.get("type"), e.get("value")) not in have:
            iocs.setdefault("indicators", []).append(e)
    for kind, key in (("urls", "url"), ("ips", "ip"), ("emails", "wp_user_email")):
        for v in indicators.get(kind, []):
            if (key, v) not in have:
                iocs.setdefault("indicators", []).append({"type": key, "value": v, "evidence": "runes:static"})
    with open(path, "w") as f:
        json.dump(iocs, f, indent=2)
