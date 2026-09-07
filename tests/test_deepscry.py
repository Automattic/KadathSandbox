# tests/test_deepscry.py
import gzip
import json
import os
import pytest
from kadath import deepscry, library, llm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPTS = os.path.join(ROOT, "kadath", "prompts")


def _run_dir(tmp_path):
    rd = tmp_path / "run"
    (rd / "artifacts" / "xdebug").mkdir(parents=True)
    with gzip.open(rd / "artifacts" / "xdebug" / "t.xt.gz", "wt") as f:
        f.write("2\t1\t0\t0.1\t1\twp_create_user\t0\t\t/samples/webroot/s.php\t2\t2\t'zz_maint'\t'p'\n"
                "2\t1\tR\t\t\t10\n" + "".join(f"2\t{i}\t0\t0.1\t1\tcore{i}\t0\t\t/var/www/x.php\t1\t0\n" for i in range(300)))
    (rd / "evidence.json").write_text(json.dumps({
        "network": {"flows": [{"host": "evil.test", "path": "/c2", "wp_core": False}],
                    "dns": [{"name": "evil.test"}], "dropped": [{"dst": "1.2.3.4", "port": 6667}]},
        "flow_bodies": [{"host": "evil.test", "response_body": "cmd:id"}],
        "db_diff": {"users_added": [{"login": "zz_maint", "roles": ["administrator"]}],
                    "options_added": [{"name": "zz_key", "value": "1"}], "cron_added": []}}))
    return str(rd)


def test_toolbox_reads_and_caps(tmp_path):
    rd = _run_dir(tmp_path)
    s = tmp_path / "s.php"
    s.write_text("<?php\nwp_create_user('zz_maint','p');\necho 1;\n")
    tb = deepscry.ToolBox(rd, str(s))
    out = tb.dispatch("read_trace", {"pattern": "wp_create_user", "max_lines": 10})        # 1
    assert "zz_maint" in out and out.count("\n") < 10
    assert len(tb.dispatch("read_trace", {"pattern": "core", "max_lines": 500}).splitlines()) <= 200  # 2
    flows = tb.dispatch("read_flows", {})                                                    # 3
    assert "evil.test" in flows and "cmd:id" in flows
    assert "evil.test" in tb.dispatch("read_dns", {})                                        # 4
    assert "6667" in tb.dispatch("read_dropped", {})                                         # 5
    assert tb.dispatch("read_sample", {"start_line": 2, "end_line": 2}) == "2| wp_create_user('zz_maint','p');"  # 6
    assert "zz_maint" in tb.dispatch("wp_read", {"subcommand": "user list"})                # 7
    assert "zz_key" in tb.dispatch("wp_read", {"subcommand": "option get zz_key"})          # 8
    assert "not allowed" in tb.dispatch("wp_read", {"subcommand": "user create x"})         # 9
    assert "not allowed" in tb.dispatch("wp_read", {"subcommand": "option get zz_key; rm"})  # 10
    assert "unknown tool" in tb.dispatch("shell", {"cmd": "id"})                             # 11
    assert "invalid" in tb.dispatch("read_sample", {"start_line": "a", "end_line": 2})       # 12
    assert tb.calls == 12 and len(tb.outputs) == 12


def test_verify_claims():
    outputs = ["line with zz_maint here", "other"]
    ev = [{"claim": "creates admin", "source": "read_trace", "quote": "zz_maint"},
          {"claim": "invented", "source": "read_dns", "quote": "not-there"},
          {"claim": "empty quote", "source": "read_dns", "quote": ""},
          {"claim": "whitespace quote", "source": "read_dns", "quote": "   "}]
    kept, dropped = deepscry.verify_claims(ev, outputs)
    assert [k["claim"] for k in kept] == ["creates admin"]
    assert [d["claim"] for d in dropped] == ["invented", "empty quote", "whitespace quote"]


class FakeClient:
    """Tool-loop turns come from `script` in order; the schema-constrained
    final call always returns `final`."""
    model = "fake"
    profiles = dict(llm.PROFILES)
    def __init__(self, script, final):
        self.script, self.final, self.calls = list(script), final, []
    def chat(self, messages, **kw):
        self.calls.append((messages, kw))
        if kw.get("json_schema"):
            kw["validate"](self.final)
            return {"content": json.dumps(self.final), "tool_calls": [], "parsed": self.final, "messages": messages}
        step = self.script.pop(0)
        reply = {"role": "assistant", "content": step.get("content", "")}
        if step.get("tool_calls"):
            reply["tool_calls"] = step["tool_calls"]
        return {"content": reply["content"], "tool_calls": step.get("tool_calls", []),
                "parsed": None, "messages": messages + [reply]}


def _case(tmp_path, rd, verdict="amber", det_level="amber"):
    lib = tmp_path / "lib"
    d = lib / "FIO-3"
    (d / "kadath").mkdir(parents=True)
    (d / "s.php").write_text("<?php\nwp_create_user('zz_maint','p');\n")
    (d / "kadath" / "verdict.json").write_text(json.dumps(
        {"verdict": verdict, "decided_by": "deterministic", "confidence": 0.5, "coverage": "full",
         "deterministic": {"level": det_level, "reasons": []}, "model_verdict": "green",
         "run_dir": rd, "reason": "?"}))
    (d / "kadath" / "report.md").write_text("# Triage\n")
    return library.walk(str(lib))[0]


FINAL = {"verdict": "red", "confidence": 0.9, "coverage": "full", "iocs_extra": [], "persistence": ["user"],
         "reason": "admin created", "evidence": [{"claim": "creates zz_maint", "source": "read_trace", "quote": "zz_maint"}]}


def test_run_tool_loop_and_upgrade(tmp_path):
    rd = _run_dir(tmp_path)
    case = _case(tmp_path, rd)
    client = FakeClient([
        {"tool_calls": [{"function": {"name": "read_trace", "arguments": {"pattern": "wp_create_user", "max_lines": 5}}}]},
        {"content": "Done investigating."},
    ], FINAL)
    v = deepscry.run(case, {"case_id": "FIO-3"}, client, PROMPTS)
    assert v["verdict"] == "red" and v["decided_by"] == "deepscry"
    assert v["deepscry"]["status"] == "ok" and v["deepscry"]["tool_calls"] == 1
    assert v["deepscry"]["evidence"][0]["quote"] == "zz_maint" and v["deepscry"]["dropped_claims"] == []
    msgs, kw = client.calls[0]
    assert kw["profile"] == "deepscry" and kw["think"] is True and kw["tools"] == deepscry.TOOLS
    assert msgs[0]["content"].startswith("# The Deep Scrying")
    assert "```json" in msgs[1]["content"]
    assert client.calls[1][0][-1]["role"] == "tool" and "zz_maint" in client.calls[1][0][-1]["content"]
    assert client.calls[2][1]["json_schema"] == deepscry.SCRY_SCHEMA
    saved = json.loads(open(os.path.join(case.dir, "kadath", "verdict.json")).read())
    assert saved["verdict"] == "red"
    assert "## Deep Scrying" in open(os.path.join(case.dir, "kadath", "report.md")).read()


def test_run_unverified_claim_holds_amber(tmp_path):
    rd = _run_dir(tmp_path)
    case = _case(tmp_path, rd)
    bad = dict(FINAL, verdict="green", evidence=[{"claim": "benign", "source": "read_dns", "quote": "nothing-here"}])
    client = FakeClient([{"content": "done"}], bad)
    v = deepscry.run(case, {"case_id": "FIO-3"}, client, PROMPTS)
    assert v["verdict"] == "amber" and v["deepscry"]["status"] == "unverified-claims"
    assert len(v["deepscry"]["dropped_claims"]) == 1


def test_run_tool_cap(tmp_path):
    rd = _run_dir(tmp_path)
    case = _case(tmp_path, rd)
    tc = {"tool_calls": [{"function": {"name": "read_dns", "arguments": {}}}]}
    client = FakeClient([tc] * 30, FINAL)
    v = deepscry.run(case, {"case_id": "FIO-3"}, client, PROMPTS)
    assert v["verdict"] == "amber" and v["deepscry"]["status"] == "tool-cap" and v["deepscry"]["tool_calls"] == 25


def test_run_tool_cap_keeps_deterministic_red(tmp_path):
    rd = _run_dir(tmp_path)
    case = _case(tmp_path, rd, det_level="red")
    tc = {"tool_calls": [{"function": {"name": "read_dns", "arguments": {}}}]}
    client = FakeClient([tc] * 30, FINAL)
    v = deepscry.run(case, {"case_id": "FIO-3"}, client, PROMPTS)
    assert v["verdict"] == "red" and v["deepscry"]["status"] == "tool-cap" and v["deepscry"]["tool_calls"] == 25


def test_run_empty_evidence_holds_amber(tmp_path):
    rd = _run_dir(tmp_path)
    case = _case(tmp_path, rd)
    bad = dict(FINAL, verdict="green", evidence=[])
    client = FakeClient([{"content": "done"}], bad)
    v = deepscry.run(case, {"case_id": "FIO-3"}, client, PROMPTS)
    assert v["verdict"] == "amber"
    assert v["deepscry"]["status"] == "unverified-claims"


def test_run_tool_cap_mid_batch(tmp_path):
    rd = _run_dir(tmp_path)
    case = _case(tmp_path, rd)
    single = {"tool_calls": [{"function": {"name": "read_dns", "arguments": {}}}]}
    batch3 = {"tool_calls": [{"function": {"name": "read_dns", "arguments": {}}} for _ in range(3)]}
    client = FakeClient([single] * 24 + [batch3, {"content": "done"}], FINAL)
    v = deepscry.run(case, {"case_id": "FIO-3"}, client, PROMPTS)
    assert v["deepscry"]["tool_calls"] == 25
    assert v["deepscry"]["status"] == "tool-cap"
    final_msgs = client.calls[-1][0]
    tool_msgs = [m for m in final_msgs if m.get("role") == "tool"]
    assert len(tool_msgs) == 27
    placeholders = [m for m in tool_msgs if m["content"].startswith("not answered")]
    assert len(placeholders) == 2


def test_run_cannot_clear_deterministic_red(tmp_path):
    rd = _run_dir(tmp_path)
    case = _case(tmp_path, rd, verdict="red", det_level="red")
    green_final = dict(FINAL, verdict="green")
    client = FakeClient([
        {"tool_calls": [{"function": {"name": "read_trace", "arguments": {"pattern": "wp_create_user", "max_lines": 5}}}]},
        {"content": "done"},
    ], green_final)
    v = deepscry.run(case, {"case_id": "FIO-3"}, client, PROMPTS)
    assert v["verdict"] == "red"
    assert v["deepscry"]["model_verdict"] == "green"
    assert v["deepscry"]["status"] == "ok"


def test_run_time_cap_holds_amber(tmp_path, monkeypatch):
    rd = _run_dir(tmp_path)
    case = _case(tmp_path, rd, det_level="amber")
    calls = [0]

    def fake_monotonic():
        calls[0] += 1
        return 0 if calls[0] == 1 else 10_000
    monkeypatch.setattr(deepscry.time, "monotonic", fake_monotonic)
    tc = {"tool_calls": [{"function": {"name": "read_dns", "arguments": {}}}]}
    client = FakeClient([tc] * 5, dict(FINAL, verdict="red"))
    v = deepscry.run(case, {"case_id": "FIO-3"}, client, PROMPTS)
    assert v["deepscry"]["status"] == "time-cap"
    assert v["verdict"] == "amber"
