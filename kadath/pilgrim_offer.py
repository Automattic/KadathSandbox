"""Tier 1 — the Offering. Detonate the sample with the existing engine, build a
compact deterministic evidence pack, and have the model write the verdict, the
report, and a draft YARA rule. The model argues; it never silently overrules."""
import gzip
import json
import os
import re
import subprocess
import sys
from kadath import cavern, library, llm, manifest, summary as summary_mod, web_verdict
from kadath.cavern import UNTRUSTED_PREAMBLE, load_prompt

ORDER = {"green": 0, "amber": 1, "red": 2}
MARKER = "=====DRAFT.YAR====="
YARA_DENYLIST = ("wp_create_user", "add_action", "add_filter", "update_option", "wp_remote_get",
                 "wp_schedule_event", "file_put_contents", "base64_decode", "eval")
IOC_TYPES = ["wp_user", "wp_user_email", "wp_password", "wp_option", "wp_usermeta_key",
             "wp_cron_hook", "plugin_slug", "theme_slug", "file_path", "file_hash", "url",
             "domain", "ip", "php_function", "hook", "string", "behavioural"]

VERDICT_SCHEMA = {
    "type": "object",
    "required": ["verdict", "confidence", "coverage", "iocs_extra", "persistence", "reason"],
    "properties": {
        "verdict": {"type": "string", "enum": ["red", "amber", "green"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "coverage": {"type": "string", "enum": ["full", "unauthenticated", "stubbed", "errored"]},
        "iocs_extra": {"type": "array", "items": {
            "type": "object", "required": ["type", "value"],
            "properties": {"type": {"type": "string", "enum": IOC_TYPES},
                           "value": {"type": "string", "maxLength": 500},
                           "notes": {"type": "string", "maxLength": 200},
                           "evidence": {"type": "string", "maxLength": 200}}}},
        "persistence": {"type": "array", "items": {"type": "string", "maxLength": 200}},
        "reason": {"type": "string", "maxLength": 300},
    },
}


class EngineError(RuntimeError):
    def __init__(self, stderr):
        super().__init__(f"engine failed: {stderr[-500:]}")
        self.stderr = stderr


def final_verdict(det_level, model_level, cavern_level=None, runes_level=None):
    """max on red > amber > green over the deterministic, model, and (when
    given) the Cavern and Runes static verdicts; who won is recorded, ties going
    to the evidence in order deterministic > runes > cavern > model. A
    disagreement is routed to the Deep Scrying by the orchestrator, never
    downgraded here."""
    levels = {"deterministic": det_level, "model": model_level}
    if cavern_level is not None:
        levels["cavern"] = cavern_level
    if runes_level is not None:
        levels["runes"] = runes_level
    if len(set(levels.values())) == 1:
        return det_level, "agree"
    top = max(ORDER[v] for v in levels.values())
    for who in ("deterministic", "runes", "cavern", "model"):
        if who in levels and ORDER[levels[who]] == top:
            return levels[who], who


def check_yara(text):
    m = re.search(r"strings:(.*?)condition:", text, re.S)
    body = m.group(1) if m else text
    return [n for n in YARA_DENYLIST if re.search(re.escape(n), body)]


def split_report(text):
    if MARKER not in text:
        raise ValueError("report reply lacks the =====DRAFT.YAR===== marker")
    md, yar = text.split(MARKER, 1)
    return md.strip(), yar.strip()


def run_engine(engine_cmd, php, slug, cwd, timeout=600, adopt=False):
    args = [php, "--json", "--slug", slug, "--skip-selftest", "--stub-missing"] + (["--adopt-wp"] if adopt else [])
    p = subprocess.run(list(engine_cmd) + args,
                       cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                       timeout=timeout)
    if p.returncode != 0:
        raise EngineError(p.stderr)
    lines = [l for l in p.stdout.splitlines() if l.strip()]
    if not lines:
        raise EngineError("engine printed no summary path\n" + p.stderr)
    return lines[-1].strip()


def open_text(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def trace_excerpt(paths, cap=400, context=3, sample_dirs=("/samples/",)):
    kept = []
    for p in paths:
        try:
            f = open_text(p)
        except OSError:
            continue
        with f:
            lines = [l.rstrip("\n") for l in f]
        hits = [i for i, l in enumerate(lines)
                if any(d in l for d in sample_dirs) or (l.split("\t")[2:3] == ["R"] and i > 0 and
                                                          any(d in lines[i - 1] for d in sample_dirs))]
        want = set()
        for i in hits:
            want.update(range(max(0, i - context), min(len(lines), i + context + 1)))
        prev = -1
        for i in sorted(want):
            if i != prev + 1 and prev >= 0:
                kept.append("...")
            kept.append(lines[i][:1000])
            prev = i
            if len(kept) >= cap:
                kept.append(f"[excerpt capped at {cap} lines]")
                return "\n".join(kept)
    return "\n".join(kept)


def flow_bodies(root, epoch, timeout=120):
    try:
        subprocess.run(["docker", "compose", "cp", "kadath/flowbody.py", "gateway:/tmp/flowbody.py"],
                       cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        out = subprocess.run(
            ["docker", "compose", "exec", "-T", "-e", f"RUN_EPOCH={epoch}", "gateway",
             "mitmdump", "-nq", "-r", "/artifacts/mitm/flows.mitm", "-s", "/tmp/flowbody.py"],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout)
        return [json.loads(l) for l in out.stdout.splitlines() if l.startswith("{")], None
    except Exception as e:
        print(f"[offer] flow bodies unavailable: {e}", file=sys.stderr)
        return [], str(e)


def _fence(title, body, lang=""):
    body = body.replace("```", "'''")
    if lang:
        return f"\n=== {title} ===\n```{lang}\n{body}\n```\n"
    return f"\n=== {title} ===\n{body}\n"


def evidence_pack(summary, cav, det, trace_text, bodies, runes=None):
    net = summary.get("network", {})
    non_core = {"flows": [f for f in net.get("flows", []) if not f.get("wp_core")],
                "dns": net.get("dns", []), "dropped": net.get("dropped", [])}
    parts = [UNTRUSTED_PREAMBLE,
             _fence("DETERMINISTIC VERDICT", json.dumps(det), "json"),
             _fence("STATIC READ (Runes: deobfuscated payload)", json.dumps(
                 {"verdict": (runes or {}).get("verdict"), "family": (runes or {}).get("family"),
                  "layers": (runes or {}).get("layers", []), "flows": (runes or {}).get("flows", []),
                  "reason": (runes or {}).get("reason")} if runes else {"note": "no runes read available"}), "json"),
             _fence("STATIC JUDGMENT (Cavern)", json.dumps(
                 {"verdict": cav.get("verdict"), "family": cav.get("family"),
                  "regions": cav.get("regions"), "needs_input": cav.get("needs_input"),
                  "missing_deps": cav.get("missing_deps", [])}), "json"),
             _fence("SAMPLE", json.dumps(summary.get("sample", {})), "json"),
             _fence("DEPENDENCY STUBS (empty stand-ins created so the sample could run)",
                    json.dumps({"adopted_as_plugin": summary.get("run", {}).get("adopted", False),
                                "stubs": summary.get("run", {}).get("stubs", []),
                                "fatal_lines": summary.get("run", {}).get("fatals", [])}), "json"),
             _fence("DB DIFF", json.dumps(summary.get("db_diff", {}), indent=1), "json"),
             _fence("DANGEROUS CALLS REACHED", json.dumps(summary.get("dangerous_calls", [])), "json"),
             _fence("FILES WRITTEN", json.dumps(summary.get("files_written", [])), "json"),
             _fence("NETWORK (non-core)", json.dumps(non_core, indent=1), "json"),
             _fence("WARNINGS", json.dumps(summary.get("warnings", [])), "json"),
             _fence("TRACE EXCERPT (sample frames ±3)", trace_text or "(no trace)", "text"),
             _fence("FLOW BODIES (non-core, 4KB cap)", json.dumps(bodies, indent=1), "json")]
    return "".join(parts)


def _fatal_in_run(run_dir):
    for name in ("compose-logs.txt",):
        p = os.path.join(run_dir, name)
        try:
            with open(p, errors="replace") as f:
                if "PHP Fatal error" in f.read():
                    return True
        except OSError:
            pass
    return False


def _finish_from_runes(kd, cav, runes_read, stderr, client):
    """The Offering could not run the sample; record a verdict from the Runes'
    static read (coverage errored) so the broken-sample loop ends here."""
    static = {"cavern": cav.get("verdict") or "green", "runes": runes_read["verdict"]}
    level = max(static.values(), key=lambda x: ORDER[x])
    decided = "runes" if ORDER[static["runes"]] == ORDER[level] else "cavern"
    fatals = [l for l in stderr.splitlines() if "Fatal" in l or "Parse error" in l][-3:]
    out = {"verdict": level, "decided_by": decided, "confidence": runes_read.get("confidence", 0.5),
           "deterministic": {"level": "green", "reasons": []}, "model_verdict": None,
           "cavern_verdict": cav.get("verdict"), "runes_verdict": runes_read["verdict"],
           "coverage": "errored", "stubs": [], "adopted": False, "fatals": fatals,
           "iocs_extra": runes_read.get("iocs_extra", []), "persistence": runes_read.get("persistence", []),
           "reason": "the Offering did not complete (engine or verdict model); verdict from the Runes static read. "
                     + runes_read.get("reason", "")[:300],
           "yara": "runes-only", "run_dir": "", "model": client.model,
           "sampling": dict(client.profiles["offer"]), "prompt_sha256": {}, "at": manifest.now_iso()}
    with open(os.path.join(kd, "verdict.json"), "w") as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(kd, "report.md"), "w") as f:
        f.write("# Offering - did not complete\n\nThe detonation or the verdict model did not "
                "complete; the verdict is the Runes static read of the (deobfuscated) code.\n\n"
                + "**Verdict:** " + level + " (" + decided + ").  " + out["reason"] + "\n")
    return out


def run(case, row, client, root, prompts_dir, engine_cmd):
    kd = os.path.join(case.dir, "kadath")
    os.makedirs(kd, exist_ok=True)
    cav = {}
    _cp = os.path.join(kd, "cavern.json")
    if os.path.exists(_cp):
        with open(_cp) as f:
            cav = json.load(f)
    else:
        print(f"warning: {_cp} missing; offering without the Cavern floor", file=sys.stderr)
    runes_read = None
    rp = os.path.join(kd, "runes.json")
    if os.path.exists(rp):
        try:
            with open(rp) as f:
                runes_read = json.load(f)
        except (OSError, ValueError):
            runes_read = None
    try:
        summary_path = run_engine(engine_cmd, case.php, case.id, root, adopt=library.wants_wordpress(case.php))
    except EngineError as e:
        with open(os.path.join(kd, "engine-stderr.txt"), "w") as f:
            f.write(e.stderr)
        raise      # the orchestrator decides whether the Runes stand in (stack healthy) or this is an outage
    run_dir = os.path.dirname(summary_path)
    with open(summary_path) as f:
        summ = json.load(f)
    det = web_verdict.compute(summ)
    traces = summ.get("artifacts", {}).get("traces", []) or []
    if not traces or not all(os.path.exists(t) for t in traces):
        bundle = os.path.join(run_dir, "artifacts", "xdebug")
        traces = sorted(os.path.join(bundle, n) for n in os.listdir(bundle)) if os.path.isdir(bundle) else []
    trace_text = trace_excerpt(traces)
    bodies, flow_bodies_error = flow_bodies(root, summ.get("run", {}).get("epoch", 0))
    pack = evidence_pack(summ, cav, det, trace_text, bodies, runes_read)
    with open(os.path.join(run_dir, "evidence.json"), "w") as f:
        json.dump({"trace_excerpt": trace_text, "flow_bodies": bodies, "network": summ.get("network"),
                   "db_diff": summ.get("db_diff"), "deterministic": det,
                   "flow_bodies_error": flow_bodies_error}, f, indent=1)

    run_meta = summ.get("run", {})
    fatal = run_meta["fatal"] if "fatal" in run_meta else _fatal_in_run(run_dir)
    stubs_made = run_meta.get("stubs", []) or []
    hint = (f"\nCavern verdict={cav.get('verdict', 'unknown')} needs_input={cav.get('needs_input', 'unknown')}; "
            f"php_fatal={fatal}; dependency_stubs={len(stubs_made)}; "
            f"adopted_as_plugin={run_meta.get('adopted', False)}\n")
    sys_v, sha_v = load_prompt(prompts_dir, "offer_verdict")
    r1 = client.chat([{"role": "system", "content": sys_v},
                      {"role": "user", "content": pack + hint + "\nReply with the verdict JSON only."}],
                     profile="offer", json_schema=VERDICT_SCHEMA, think=False,
                     validate=lambda o: llm.validate_against(VERDICT_SCHEMA, o))
    mv = r1["parsed"]
    # coverage: a fatal beats everything; a sample that never got its password
    # ran only its idle path; a sample that ran against empty stand-ins is
    # "stubbed" — none of these can settle a case (the orchestrator checks)
    coverage = mv["coverage"]
    if fatal:
        coverage = "errored"
    elif cav.get("needs_input", "none") not in ("none",) and coverage in ("full", "stubbed"):
        coverage = "unauthenticated"
    elif stubs_made and coverage in ("full", "errored"):
        coverage = "stubbed"
    elif coverage == "errored":
        coverage = "full"          # the engine saw no fatal; the model's claim does not stand
    level, decided_by = final_verdict(det["level"], mv["verdict"], cav.get("verdict"),
                                      (runes_read or {}).get("verdict"))

    sys_r, sha_r = load_prompt(prompts_dir, "offer_report")
    verdict_note = (f"\nRecorded verdict: {level} (deterministic {det['level']}, model {mv['verdict']}, "
                    f"cavern {cav.get('verdict', 'n/a')}); coverage {coverage}; case_id {case.id}\n")
    yara_status = "ok"
    msgs = [{"role": "system", "content": sys_r}, {"role": "user", "content": pack + verdict_note}]
    report_md = None
    yara = None
    for attempt in range(2):
        r2 = client.chat(msgs, profile="offer", think=False)
        try:
            report_md, yara = split_report(r2["content"])
        except ValueError:
            if attempt == 0:
                # First attempt: send corrective message and retry
                msgs = r2["messages"] + [{"role": "user", "content":
                                         "Your reply lacked the required `=====DRAFT.YAR=====` separator line; reply again with report.md, then that exact line, then the YARA rule."}]
                continue
            else:
                # Second attempt still lacks marker: degrade
                report_md = r2["content"]
                yara = "// no rule produced: model reply lacked the =====DRAFT.YAR===== marker"
                yara_status = "needs-review"
                break
        bad = check_yara(yara)
        if not bad:
            break
        msgs = r2["messages"] + [{"role": "user", "content":
                                  f"The YARA rule keys on generic API names {bad}; rewrite both parts with "
                                  "strings unique to this sample."}]
    else:
        yara_status = "needs-review"

    with open(os.path.join(run_dir, "iocs.json")) as f:
        iocs = json.load(f)
    iocs["indicators"].extend(mv["iocs_extra"])
    summary_mod.validate_iocs(iocs)

    out = {"verdict": level, "decided_by": decided_by, "confidence": mv["confidence"],
           "deterministic": det, "model_verdict": mv["verdict"], "cavern_verdict": cav.get("verdict"),
           "coverage": coverage, "stubs": stubs_made, "adopted": run_meta.get("adopted", False),
           "fatals": run_meta.get("fatals", []),
           "runes_verdict": (runes_read or {}).get("verdict"),
           "iocs_extra": mv["iocs_extra"], "persistence": mv["persistence"], "reason": mv["reason"],
           "yara": yara_status, "run_dir": run_dir, "model": client.model,
           "sampling": dict(client.profiles["offer"]),
           "prompt_sha256": {"offer_verdict": sha_v, "offer_report": sha_r}, "at": manifest.now_iso()}
    with open(os.path.join(kd, "verdict.json"), "w") as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(kd, "report.md"), "w") as f:
        f.write(report_md + "\n")
    with open(os.path.join(kd, "draft.yar"), "w") as f:
        f.write(yara + "\n")
    with open(os.path.join(kd, "iocs.json"), "w") as f:
        json.dump(iocs, f, indent=2)
    with open(os.path.join(kd, "run.env"), "w") as f:
        f.write(f"RUN_DIR={run_dir}\nSUMMARY={summary_path}\n")
    return out
