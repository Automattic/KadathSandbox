"""Tier 1 — the Offering. Detonate the sample with the existing engine, build a
compact deterministic evidence pack, and have the model write the verdict, the
report, and a draft YARA rule. The model argues; it never silently overrules."""
import gzip
import json
import os
import re
import subprocess
from kadath import cavern, llm, manifest, summary as summary_mod, web_verdict
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
        "coverage": {"type": "string", "enum": ["full", "unauthenticated", "errored"]},
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


def final_verdict(det_level, model_level):
    """max on red > amber > green; who won is recorded, a disagreement is
    routed to the Deep Scrying by the orchestrator, never downgraded here."""
    if det_level == model_level:
        return det_level, "agree"
    higher = det_level if ORDER[det_level] > ORDER[model_level] else model_level
    return higher, ("deterministic" if higher == det_level else "model")


def check_yara(text):
    m = re.search(r"strings:(.*?)condition:", text, re.S)
    body = m.group(1) if m else text
    return [n for n in YARA_DENYLIST if re.search(r'["\']' + re.escape(n) + r'["\']', body)]


def split_report(text):
    if MARKER not in text:
        raise ValueError("report reply lacks the =====DRAFT.YAR===== marker")
    md, yar = text.split(MARKER, 1)
    return md.strip(), yar.strip()


def run_engine(engine_cmd, php, slug, cwd, timeout=600):
    p = subprocess.run(list(engine_cmd) + [php, "--json", "--slug", slug, "--skip-selftest"],
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
        return [json.loads(l) for l in out.stdout.splitlines() if l.startswith("{")]
    except Exception:
        return []


def _fence(title, body):
    return f"\n=== {title} ===\n{body}\n"


def evidence_pack(summary, cav, det, trace_text, bodies):
    net = summary.get("network", {})
    non_core = {"flows": [f for f in net.get("flows", []) if not f.get("wp_core")],
                "dns": net.get("dns", []), "dropped": net.get("dropped", [])}
    parts = [UNTRUSTED_PREAMBLE,
             _fence("DETERMINISTIC VERDICT", json.dumps(det)),
             _fence("STATIC JUDGMENT (Cavern)", json.dumps(
                 {"family": cav.get("family"), "regions": cav.get("regions"),
                  "needs_input": cav.get("needs_input")})),
             _fence("SAMPLE", json.dumps(summary.get("sample", {}))),
             _fence("DB DIFF", json.dumps(summary.get("db_diff", {}), indent=1)),
             _fence("DANGEROUS CALLS REACHED", json.dumps(summary.get("dangerous_calls", []))),
             _fence("FILES WRITTEN", json.dumps(summary.get("files_written", []))),
             _fence("NETWORK (non-core)", json.dumps(non_core, indent=1)),
             _fence("WARNINGS", json.dumps(summary.get("warnings", []))),
             _fence("TRACE EXCERPT (sample frames ±3)", "```\n" + (trace_text or "(no trace)") + "\n```"),
             _fence("FLOW BODIES (non-core, 4KB cap)", json.dumps(bodies, indent=1))]
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


def run(case, row, client, root, prompts_dir, engine_cmd):
    kd = os.path.join(case.dir, "kadath")
    os.makedirs(kd, exist_ok=True)
    with open(os.path.join(kd, "cavern.json")) as f:
        cav = json.load(f)
    summary_path = run_engine(engine_cmd, case.php, case.id, root)
    run_dir = os.path.dirname(summary_path)
    with open(summary_path) as f:
        summ = json.load(f)
    det = web_verdict.compute(summ)
    traces = summ.get("artifacts", {}).get("traces", []) or []
    if not all(os.path.exists(t) for t in traces):
        bundle = os.path.join(run_dir, "artifacts", "xdebug")
        traces = sorted(os.path.join(bundle, n) for n in os.listdir(bundle)) if os.path.isdir(bundle) else []
    trace_text = trace_excerpt(traces)
    bodies = flow_bodies(root, summ.get("run", {}).get("epoch", 0))
    pack = evidence_pack(summ, cav, det, trace_text, bodies)
    with open(os.path.join(run_dir, "evidence.json"), "w") as f:
        json.dump({"trace_excerpt": trace_text, "flow_bodies": bodies, "network": summ.get("network"),
                   "db_diff": summ.get("db_diff"), "deterministic": det}, f, indent=1)

    hint = f"\nCavern needs_input={cav.get('needs_input', 'unknown')}; php_fatal={_fatal_in_run(run_dir)}\n"
    sys_v, sha_v = load_prompt(prompts_dir, "offer_verdict")
    r1 = client.chat([{"role": "system", "content": sys_v},
                      {"role": "user", "content": pack + hint + "\nReply with the verdict JSON only."}],
                     profile="offer", json_schema=VERDICT_SCHEMA, think=False,
                     validate=lambda o: llm.validate_against(VERDICT_SCHEMA, o))
    mv = r1["parsed"]
    coverage = mv["coverage"]
    if _fatal_in_run(run_dir):
        coverage = "errored"
    elif cav.get("needs_input", "none") not in ("none",) and coverage == "full":
        coverage = "unauthenticated"
    level, decided_by = final_verdict(det["level"], mv["verdict"])

    sys_r, sha_r = load_prompt(prompts_dir, "offer_report")
    verdict_note = f"\nRecorded verdict: {level} (deterministic {det['level']}, model {mv['verdict']}); coverage {coverage}; case_id {case.id}\n"
    yara_status = "ok"
    msgs = [{"role": "system", "content": sys_r}, {"role": "user", "content": pack + verdict_note}]
    for attempt in range(2):
        r2 = client.chat(msgs, profile="offer", think=False)
        report_md, yara = split_report(r2["content"])
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
           "deterministic": det, "model_verdict": mv["verdict"], "coverage": coverage,
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
