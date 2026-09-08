"""Tier 2 — the Deep Scrying. An agentic re-examination of an uncertain case
over its preserved run bundle with read-only, argument-validated tools. Every
claim in the final verdict must quote a tool result verbatim or it is dropped."""
import copy
import json
import os
import re
import time
from kadath import llm, manifest
from kadath.cavern import UNTRUSTED_PREAMBLE, load_prompt
from kadath.pilgrim_offer import VERDICT_SCHEMA, final_verdict, open_text

TOOL_CAP = 25
TIME_CAP_S = 900
WP_ALLOW = ("user list", "option get", "cron event list", "plugin list")
_SAFE_ARG = re.compile(r"^[A-Za-z0-9_\-.]{1,100}$")

TOOLS = [
    {"type": "function", "function": {"name": "read_trace",
     "description": "Grep this run's Xdebug traces for a pattern; returns matching lines (function calls with arguments/returns).",
     "parameters": {"type": "object", "required": ["pattern"],
                    "properties": {"pattern": {"type": "string"}, "max_lines": {"type": "integer"}}}}},
    {"type": "function", "function": {"name": "read_flows", "description": "Decrypted non-core HTTP flows of this run with bodies.",
     "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "read_dns", "description": "DNS names resolved during this run.",
     "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "read_dropped", "description": "Blocked non-HTTP egress attempts of this run.",
     "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "read_sample", "description": "Read a line range of the sample source.",
     "parameters": {"type": "object", "required": ["start_line", "end_line"],
                    "properties": {"start_line": {"type": "integer"}, "end_line": {"type": "integer"}}}}},
    {"type": "function", "function": {"name": "wp_read",
     "description": "Read the WordPress database state recorded for this run (users, options, cron added by the sample). Allowed: 'user list', 'option get <name>', 'cron event list', 'plugin list'.",
     "parameters": {"type": "object", "required": ["subcommand"], "properties": {"subcommand": {"type": "string"}}}}},
]

SCRY_SCHEMA = copy.deepcopy(VERDICT_SCHEMA)
SCRY_SCHEMA["required"] = SCRY_SCHEMA["required"] + ["evidence"]
SCRY_SCHEMA["properties"]["evidence"] = {"type": "array", "items": {
    "type": "object", "required": ["claim", "source", "quote"],
    "properties": {"claim": {"type": "string", "maxLength": 300},
                   "source": {"type": "string", "maxLength": 40},
                   "quote": {"type": "string", "maxLength": 200}}}}


class ToolBox:
    def __init__(self, run_dir, sample_path):
        self.run_dir, self.sample_path = run_dir, sample_path
        self.outputs, self.calls = [], 0
        try:
            with open(os.path.join(run_dir, "evidence.json")) as f:
                self.ev = json.load(f)
        except (OSError, ValueError):
            self.ev = {}

    def _traces(self):
        d = os.path.join(self.run_dir, "artifacts", "xdebug")
        return sorted(os.path.join(d, n) for n in os.listdir(d)) if os.path.isdir(d) else []

    def read_trace(self, pattern, max_lines=100):
        try:
            max_lines = max(1, min(int(max_lines), 200))
        except (TypeError, ValueError):
            return "invalid max_lines"
        pat = str(pattern)
        out = []
        for p in self._traces():
            try:
                f = open_text(p)
            except OSError:
                continue
            with f:
                for line in f:
                    if pat in line:
                        out.append(line.rstrip("\n")[:1000])
                        if len(out) >= max_lines:
                            return "\n".join(out)
        return "\n".join(out) if out else "(no match)"

    def read_flows(self, **_):
        net = self.ev.get("network", {}) or {}
        return json.dumps({"flows": [f for f in net.get("flows", []) if not f.get("wp_core")],
                           "bodies": self.ev.get("flow_bodies", [])}, indent=1)

    def read_dns(self, **_):
        return json.dumps((self.ev.get("network", {}) or {}).get("dns", []), indent=1)

    def read_dropped(self, **_):
        return json.dumps((self.ev.get("network", {}) or {}).get("dropped", []), indent=1)

    def read_sample(self, start_line, end_line):
        try:
            a, b = int(start_line), int(end_line)
        except (TypeError, ValueError):
            return "invalid line range"
        if a < 1 or b < a or b - a > 200:
            return "invalid line range (1-based, at most 200 lines)"
        with open(self.sample_path, errors="replace") as f:
            lines = f.read().split("\n")
        return "\n".join(f"{i}| {lines[i - 1]}" for i in range(a, min(b, len(lines)) + 1))

    def wp_read(self, subcommand):
        sub = str(subcommand).strip()
        parts = sub.split()
        db = self.ev.get("db_diff", {}) or {}
        if sub == "user list":
            return json.dumps(db.get("users_added", []), indent=1)
        if sub == "cron event list":
            return json.dumps(db.get("cron_added", []), indent=1)
        if sub == "plugin list":
            return "(recorded run: plugin list not captured; see summary.json)"
        if len(parts) == 3 and parts[0] == "option" and parts[1] == "get" and _SAFE_ARG.match(parts[2]):
            hits = [o for o in db.get("options_added", []) + db.get("options_changed", [])
                    if o.get("name") == parts[2]]
            return json.dumps(hits, indent=1) if hits else "(option not added/changed by this run)"
        return f"not allowed: wp_read accepts only {WP_ALLOW}"

    def dispatch(self, name, args):
        self.calls += 1
        fn = {"read_trace": self.read_trace, "read_flows": self.read_flows, "read_dns": self.read_dns,
              "read_dropped": self.read_dropped, "read_sample": self.read_sample,
              "wp_read": self.wp_read}.get(name)
        if fn is None:
            out = f"unknown tool {name!r}"
        else:
            try:
                out = fn(**(args or {}))
            except TypeError as e:
                out = f"invalid arguments: {e}"
        out = out[:8000]
        self.outputs.append(out)
        return out


def verify_claims(evidence, outputs):
    kept, dropped = [], []
    for e in evidence:
        quote = e.get("quote", "")
        if quote.strip() and any(quote in o for o in outputs):
            kept.append(e)
        else:
            dropped.append(e)
    return kept, dropped


def run(case, row, client, prompts_dir):
    kd = os.path.join(case.dir, "kadath")
    with open(os.path.join(kd, "verdict.json")) as f:
        v = json.load(f)
    tb = ToolBox(v["run_dir"], case.php)
    system, sha = load_prompt(prompts_dir, "deepscry")
    intro = (UNTRUSTED_PREAMBLE + f"\nCase {case.id}. First-pass verdict: {v['verdict']} "
             f"(deterministic {v['deterministic']['level']}, model {v.get('model_verdict')}, "
             f"confidence {v.get('confidence')}, cavern {v.get('cavern_verdict', 'n/a')}); "
             f"coverage {v.get('coverage')}; dependency stubs created: "
             f"{len(v.get('stubs') or [])} (the sample ran against empty stand-ins for those files, "
             "so behaviour that depended on them was not exercised).\n"
             + (("Fatal lines from this run:\n```text\n" + "\n".join(v.get("fatals") or []) + "\n```\n")
                if v.get("fatals") else "")
             + "Deterministic reasons:\n```json\n"
             f"{json.dumps(v['deterministic'].get('reasons', []))}\n```\n"
             "Investigate with the tools, then say you are done.")
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": intro}]
    status = "ok"
    deadline = time.monotonic() + TIME_CAP_S
    while True:
        if time.monotonic() >= deadline:
            status = "time-cap"
            break
        r = client.chat(msgs, profile="deepscry", tools=TOOLS, think=True, timeout=900)
        msgs = r["messages"]
        if not r["tool_calls"]:
            break
        for tc in r["tool_calls"]:
            fn = tc.get("function", {})
            if tb.calls >= TOOL_CAP:
                status = "tool-cap"
                msgs = msgs + [{"role": "tool", "content": "not answered: tool budget exhausted",
                                "tool_name": fn.get("name")}]
                continue
            out = tb.dispatch(fn.get("name"), fn.get("arguments") or {})
            msgs = msgs + [{"role": "tool", "content": out, "tool_name": fn.get("name")}]
        if status == "tool-cap":
            break
    final = client.chat(msgs + [{"role": "user", "content": "Produce the final verdict JSON now."}],
                        profile="deepscry", json_schema=SCRY_SCHEMA, think=False, timeout=600,
                        validate=lambda o: llm.validate_against(SCRY_SCHEMA, o))["parsed"]
    kept, dropped = verify_claims(final["evidence"], tb.outputs)
    if status in ("tool-cap", "time-cap"):
        level, decided = final_verdict(v["deterministic"]["level"], "amber")[0], "deepscry"
    elif dropped or not final["evidence"]:
        status, decided = "unverified-claims", "deepscry"
        level = final_verdict(v["deterministic"]["level"], "amber")[0]
    else:
        level, _ = final_verdict(v["deterministic"]["level"], final["verdict"])
        decided = "deepscry"
    v.update(verdict=level, decided_by=decided, deepscry={
        "status": status, "model_verdict": final["verdict"], "confidence": final["confidence"],
        "reason": final["reason"], "evidence": kept, "dropped_claims": dropped,
        "iocs_extra": final["iocs_extra"], "persistence": final["persistence"],
        "tool_calls": tb.calls, "sampling": dict(client.profiles["deepscry"]),
        "prompt_sha256": sha, "at": manifest.now_iso()})
    with open(os.path.join(kd, "verdict.json"), "w") as f:
        json.dump(v, f, indent=2)
    with open(os.path.join(kd, "report.md"), "a") as f:
        f.write(f"\n## Deep Scrying\n\n**Verdict:** {level} ({status}); model said {final['verdict']} "
                f"at confidence {final['confidence']}.\n\n{final['reason']}\n\n")
        for e in kept:
            f.write(f"- {e['claim']} — `{e['source']}`: `{e['quote']}`\n")
        for e in dropped:
            f.write(f"- ~~{e['claim']}~~ (unverified quote, dropped)\n")
    return v
