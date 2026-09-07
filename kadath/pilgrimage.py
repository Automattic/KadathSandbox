"""The Pilgrimage: walk the threat library through the Cavern, the Offering,
and the Deep Scrying, one pass at a time, with the manifest as the only state.
One bad case never stops the procession; a run of bad cases does."""
import argparse
import json
import os
import shutil
import subprocess
import sys
from kadath import cavern, deepscry, library, llm, manifest, pilgrim_offer
from kadath.shell import run as sh, ShellError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPTS = os.path.join(ROOT, "kadath", "prompts")


def parse_args(argv):
    ap = argparse.ArgumentParser(prog="kadath pilgrimage",
                                 description="Triage a threat-library for-later-review directory with a local model.")
    ap.add_argument("library")
    ap.add_argument("--pass", dest="passes", choices=["cavern", "offer", "scry", "all"], default="all")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--case", action="append", default=[])
    ap.add_argument("--model")
    ap.add_argument("--ollama")
    ap.add_argument("--sampling", action="append", default=[], metavar="TIER.KEY=VALUE")
    ap.add_argument("--profiles")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--retry-errors", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--min-free-gb", type=float, default=20)
    ap.add_argument("--engine", default="python3 bin/kadath offer", help="test hook: engine command")
    ap.add_argument("--no-stack", action="store_true", help="test hook: skip the stack preflight")
    a = ap.parse_args(argv)
    a.passes = ["cavern", "offer", "scry"] if a.passes == "all" else [a.passes]
    a.engine = a.engine.split()
    return a


def free_gb(path):
    return shutil.disk_usage(path).free / 1e9


def run_pass(name, m, rows, fn, breaker=3):
    counts = {"done": 0, "error": 0, "timeout": 0, "skipped": 0, "aborted": False}
    consecutive = 0
    for row in rows:
        cid = row["case_id"]
        try:
            fields = fn(row) or {}
            status = fields.pop(f"{name}_status", "done")
            m.update(cid, **fields)
            m.update(cid, **{f"{name}_status": status, f"{name}_at": manifest.now_iso()})
            counts[status] += 1
            consecutive = 0
        except subprocess.TimeoutExpired as e:
            m.update(cid, **{f"{name}_status": "timeout", "error": f"timeout after {e.timeout}s"})
            counts["timeout"] += 1
            consecutive += 1
        except Exception as e:  # one bad case never stops the procession
            m.update(cid, **{f"{name}_status": "error", "error": f"{type(e).__name__}: {e}"[:500]})
            counts["error"] += 1
            consecutive += 1
        m.flush()
        print(f"[{name}] {cid}: {m.rows[cid][f'{name}_status']} {m.rows[cid].get(f'{name}_verdict', '')}",
              file=sys.stderr)
        if consecutive >= breaker:
            print(f"[{name}] {breaker} consecutive failures; aborting the pass", file=sys.stderr)
            counts["aborted"] = True
            break
    return counts


def _make_client(a):
    prof = llm.build_profiles(llm.parse_overrides(a.sampling), a.profiles, a.seed)
    return llm.Client(a.ollama, a.model, prof)


def _stack_up():
    sh(["make", "up"], cwd=ROOT, timeout=900)
    sh(["make", "selftest"], cwd=ROOT, timeout=600)


def _stack_recover():
    try:
        ps = sh(["docker", "compose", "ps", "--format", "json"], cwd=ROOT, check=False).stdout
        if "wordpress" in ps and "running" in ps:
            return
        sh(["make", "down"], cwd=ROOT, timeout=300)
        sh(["make", "up"], cwd=ROOT, timeout=900)
    except (ShellError, subprocess.TimeoutExpired) as e:
        print(f"[offer] stack recovery failed: {e}", file=sys.stderr)


def _case_by_id(cases):
    return {c.id: c for c in cases}


def _settled(v):
    """True when an Offering verdict needs no Deep Scrying: the two sides agreed
    and it is green, or agreed on red with confidence >= 0.6."""
    if v.get("decided_by") != "agree":
        return False
    return v["verdict"] == "green" or (v["verdict"] == "red" and v.get("confidence", 0) >= 0.6)


def main(argv):
    a = parse_args(argv)
    lib = os.path.abspath(a.library)
    if not os.path.isdir(lib):
        print(f"error: {lib} is not a directory", file=sys.stderr)
        return 2
    client = _make_client(a)
    try:
        client.preflight()
    except llm.LLMError as e:
        print(f"error: ollama preflight failed: {e}", file=sys.stderr)
        return 2
    if not a.no_stack and ("offer" in a.passes):
        try:
            _stack_up()
        except (ShellError, subprocess.TimeoutExpired) as e:
            print(f"error: stack preflight failed: {e}", file=sys.stderr)
            return 2

    cases = library.walk(lib)
    if a.case:
        cases = [c for c in cases if c.id in set(a.case)]
    if a.limit is not None:
        cases = cases[:a.limit]
    by_id = _case_by_id(cases)
    m = manifest.Manifest(os.path.join(lib, "kadath-triage.csv"))
    m.load()
    m.ensure_rows(cases)
    if a.retry_errors or a.force:
        m.retry(a.passes, force=a.force)
    m.flush()

    def do_cavern(row):
        out = cavern.run(by_id[row["case_id"]], client, PROMPTS)
        facts = out.get("static_facts", {})
        fields = {"cavern_verdict": out["verdict"], "cavern_family": out["family"],
                  "cavern_worthy": "true" if out["worthy"] else "false",
                  "sha256": facts.get("sha256", ""), "size": facts.get("size", "")}
        if not out["worthy"]:
            fields.update(final_verdict=out["verdict"], decided_by="cavern",
                          offer_status="skipped", scry_status="skipped")
        return fields

    def do_offer(row):
        if free_gb(ROOT) < a.min_free_gb:
            raise RuntimeError(f"free disk below {a.min_free_gb} GB; aborting")
        try:
            v = pilgrim_offer.run(by_id[row["case_id"]], row, client, ROOT, PROMPTS, a.engine)
        except pilgrim_offer.EngineError:
            if not a.no_stack:
                _stack_recover()
            raise
        fields = {"offer_verdict": v["verdict"], "offer_coverage": v["coverage"], "run_dir": v["run_dir"],
                  "final_verdict": v["verdict"], "decided_by": "offer"}
        # settled: both sides agree and it is green, or a confident red. Everything
        # else (amber, low-confidence red, any disagreement) goes to the Deep Scrying.
        if _settled(v):
            fields["scry_status"] = "skipped"
        return fields

    def do_scry(row):
        case = by_id[row["case_id"]]
        with open(os.path.join(case.dir, "kadath", "verdict.json")) as f:
            v = json.load(f)
        if _settled(v):
            return {"scry_status": "skipped", "error": "red-confident"}
        v = deepscry.run(case, row, client, PROMPTS)
        return {"scry_verdict": v["verdict"], "final_verdict": v["verdict"], "decided_by": "deepscry"}

    fns = {"cavern": do_cavern, "offer": do_offer, "scry": do_scry}
    for name in a.passes:
        rows = [r for r in m.pending(name) if r["case_id"] in by_id]
        if name == "offer":
            rows = [r for r in rows if free_gb(ROOT) >= a.min_free_gb]
        print(f"== {name}: {len(rows)} case(s) pending", file=sys.stderr)
        counts = run_pass(name, m, rows, fns[name], breaker=3 if name != "offer" else 2)
        print(f"== {name} done: {counts}; verdicts {m.histogram(f'{name}_verdict')}", file=sys.stderr)
        if counts["aborted"]:
            return 1
    print(f"== final verdicts: {m.histogram('final_verdict')} decided_by {m.histogram('decided_by')}")
    reds = sorted((r for r in m.rows.values() if r["final_verdict"] == "red"), key=lambda r: r["case_id"])
    for r in reds[:20]:
        print(f"  red  {r['case_id']}  ({r['decided_by']})")
    return 0
