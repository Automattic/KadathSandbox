# tests/test_pilgrim_offer.py
import gzip
import json
import os
import subprocess
import pytest
from kadath import pilgrim_offer as po, library, llm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPTS = os.path.join(ROOT, "kadath", "prompts")
FIX = os.path.join(ROOT, "tests", "fixtures")


def test_final_verdict_rule():
    assert po.final_verdict("red", "red") == ("red", "agree")
    assert po.final_verdict("green", "green") == ("green", "agree")
    assert po.final_verdict("red", "green") == ("red", "deterministic")
    assert po.final_verdict("green", "red") == ("red", "model")
    assert po.final_verdict("green", "amber") == ("amber", "model")
    assert po.final_verdict("amber", "green") == ("amber", "deterministic")


def test_check_yara_and_split():
    rule = 'rule x { strings: $a = "wp_create_user" $b = "zz_sys_maint" condition: any of them }'
    assert po.check_yara(rule) == ["wp_create_user"]
    assert po.check_yara('rule y { strings: $a = "zz_sys_maint" condition: $a }') == []
    assert po.check_yara(
        'rule z { strings: $a = "add_action(\'kadath_" condition: $a }') == ["add_action"]
    md, yar = po.split_report("# Triage\nbody\n=====DRAFT.YAR=====\nrule z { condition: true }\n")
    assert md == "# Triage\nbody" and yar == "rule z { condition: true }"
    with pytest.raises(ValueError):
        po.split_report("no marker")


def test_trace_excerpt_restricts_to_sample_frames(tmp_path):
    lines = ["Version: 3.5.3", "File format: 4", "TRACE START"]
    for i in range(50):
        lines.append(f"2\t{i}\t0\t0.1\t100\tcore_fn{i}\t0\t\t/var/www/wp-includes/x.php\t{i}\t0")
    lines.append("2\t60\t0\t0.1\t100\twp_create_user\t0\t\t/samples/webroot/s.php\t7\t2\t'a'\t'b'")
    lines.append("2\t60\tR\t\t\t10")
    for i in range(50):
        lines.append(f"2\t{100 + i}\t0\t0.1\t100\tcore_after{i}\t0\t\t/var/www/wp-includes/y.php\t{i}\t0")
    p = tmp_path / "t.xt.gz"
    with gzip.open(p, "wt") as f:
        f.write("\n".join(lines) + "\n")
    out = po.trace_excerpt([str(p)])
    assert "wp_create_user" in out and "core_fn49" in out and "core_after2" in out
    assert "core_fn10" not in out and "core_after40" not in out
    assert "2\t60\tR" in out
    big = tmp_path / "big.xt"
    big.write_text("\n".join(f"2\t{i}\t0\t0.1\t1\tf{i}\t0\t\t/samples/webroot/s.php\t{i}\t0" for i in range(1000)) + "\n")
    out = po.trace_excerpt([str(big)], cap=400)
    assert out.count("\n") <= 401 and "[excerpt capped" in out


def test_evidence_pack_contents():
    with open(os.path.join(FIX, "web_summary.json")) as f:
        s = json.load(f)
    cav = {"family": "backdoor", "regions": [{"start_line": 12, "end_line": 14, "why": "user"}], "needs_input": "none"}
    det = {"level": "red", "reasons": ["administrator 'sys_maint' created"]}
    trace_with_fence = "2\t1\t0\tx ```rm -rf /```"
    pack = po.evidence_pack(s, cav, det, trace_with_fence, [{"host": "evil.test", "path": "/c2", "request_body": "hi", "response_body": "ok"}])
    assert pack.startswith(po.UNTRUSTED_PREAMBLE)
    for needle in ("DETERMINISTIC VERDICT", "red", "sys_maint", "STATIC JUDGMENT", "backdoor",
                   "TRACE EXCERPT", "FLOW BODIES", "evil.test", "DB DIFF"):
        assert needle in pack
    # A trace excerpt containing ``` cannot close the fence early: the whole pack
    # has exactly 2 fence markers per section (10 sections), no stray ones.
    assert pack.count("```") == 22  # 11 sections × 2 fence markers
    # Check that FLOW BODIES section is inside a json fence
    flow_start = pack.find("=== FLOW BODIES")
    flow_end = pack.find("=== ", flow_start + 1)
    flow_section = pack[flow_start:flow_end]
    assert "```json" in flow_section and "evil.test" in flow_section
    assert flow_section.count("```") >= 2, "FLOW BODIES should have opening and closing fences"
    # Check that DB DIFF section is inside a json fence
    db_start = pack.find("=== DB DIFF")
    db_end = pack.find("=== ", db_start + 1)
    db_section = pack[db_start:db_end]
    assert "```json" in db_section and "sys_maint" in db_section
    assert db_section.count("```") >= 2, "DB DIFF should have opening and closing fences"


def test_run_engine_success_and_failure(tmp_path):
    ok = tmp_path / "ok.sh"
    ok.write_text("#!/bin/sh\necho stage >&2\necho /tmp/run/summary.json\n")
    ok.chmod(0o755)
    assert po.run_engine([str(ok)], "/x.php", "FIO-1", str(tmp_path)) == "/tmp/run/summary.json"
    bad = tmp_path / "bad.sh"
    bad.write_text("#!/bin/sh\necho 'error: boom' >&2\nexit 3\n")
    bad.chmod(0o755)
    with pytest.raises(po.EngineError) as ei:
        po.run_engine([str(bad)], "/x.php", "FIO-1", str(tmp_path))
    assert "boom" in ei.value.stderr
    slow = tmp_path / "slow.sh"
    slow.write_text("#!/bin/sh\nsleep 5\n")
    slow.chmod(0o755)
    with pytest.raises(subprocess.TimeoutExpired):
        po.run_engine([str(slow)], "/x.php", "FIO-1", str(tmp_path), timeout=0.2)


class FakeClient:
    model = "fake"
    profiles = dict(llm.PROFILES)
    def __init__(self, verdict, report):
        self.verdict, self.report, self.calls = verdict, report, []
    def chat(self, messages, **kw):
        self.calls.append((messages, kw))
        if kw.get("json_schema"):
            kw["validate"](self.verdict)
            return {"content": json.dumps(self.verdict), "tool_calls": [], "parsed": self.verdict, "messages": messages}
        return {"content": self.report.pop(0), "tool_calls": [], "parsed": None, "messages": messages}


def _setup(tmp_path):
    lib = tmp_path / "lib"
    d = lib / "FIO-7"
    d.mkdir(parents=True)
    (d / "s.php").write_text("<?php\nwp_create_user('sys_maint','p');\n")
    kd = d / "kadath"
    kd.mkdir()
    (kd / "cavern.json").write_text(json.dumps({"family": "backdoor", "regions": [], "needs_input": "none"}))
    case = library.walk(str(lib))[0]
    root = tmp_path / "root"
    (root / "reports").mkdir(parents=True)
    eng = root / "engine.sh"
    run_dir = root / "reports" / "FIO-7-x"
    run_dir.mkdir()
    import shutil
    shutil.copy(os.path.join(FIX, "web_summary.json"), run_dir / "summary.json")
    (run_dir / "iocs.json").write_text(json.dumps({"sample": {"filename": "s.php", "sha256": "a" * 64},
        "offered_utc": "2026-09-05T00:00:00Z", "classification": "wp-sample/webshell",
        "network": {"observed": False}, "indicators": [{"type": "wp_user", "value": "sys_maint"}]}))
    eng.write_text(f"#!/bin/sh\necho {run_dir}/summary.json\n")
    eng.chmod(0o755)
    return case, root, eng


GOOD_VERDICT = {"verdict": "red", "confidence": 0.95, "coverage": "full",
                "iocs_extra": [{"type": "wp_option", "value": "zz_backdoor_key", "evidence": "trace"}],
                "persistence": ["admin user sys_maint"], "reason": "creates admin"}


def test_run_writes_all_outputs(tmp_path, monkeypatch):
    case, root, eng = _setup(tmp_path)
    monkeypatch.setattr(po, "flow_bodies", lambda root, epoch: ([], None))
    client = FakeClient(GOOD_VERDICT, ["# Triage Report\nbody\n=====DRAFT.YAR=====\nrule kadath_FIO_7 { strings: $a = \"zz_backdoor_key\" condition: $a }\n"])
    v = po.run(case, {"case_id": "FIO-7"}, client, str(root), PROMPTS, [str(eng)])
    kd = os.path.join(case.dir, "kadath")
    assert v["verdict"] == "red" and v["decided_by"] == "agree" and v["deterministic"]["level"] == "red"
    assert v["yara"] == "ok" and v["coverage"] == "full" and v["run_dir"].endswith("FIO-7-x")
    assert json.loads(open(os.path.join(kd, "verdict.json")).read()) == v
    assert open(os.path.join(kd, "report.md")).read().startswith("# Triage Report")
    assert "zz_backdoor_key" in open(os.path.join(kd, "draft.yar")).read()
    iocs = json.load(open(os.path.join(kd, "iocs.json")))
    assert any(i["value"] == "zz_backdoor_key" for i in iocs["indicators"])
    assert "RUN_DIR=" in open(os.path.join(kd, "run.env")).read()
    assert os.path.exists(os.path.join(v["run_dir"], "evidence.json"))
    evidence = json.load(open(os.path.join(v["run_dir"], "evidence.json")))
    assert evidence["flow_bodies_error"] is None
    assert client.calls[0][1]["profile"] == "offer" and client.calls[1][1]["profile"] == "offer"


def test_run_disagreement_keeps_red_and_yara_regenerates(tmp_path, monkeypatch):
    case, root, eng = _setup(tmp_path)
    monkeypatch.setattr(po, "flow_bodies", lambda root, epoch: ([], None))
    bad = "# R\n=====DRAFT.YAR=====\nrule k { strings: $a = \"wp_create_user\" condition: $a }\n"
    client = FakeClient(dict(GOOD_VERDICT, verdict="green"), [bad, bad])
    v = po.run(case, {"case_id": "FIO-7"}, client, str(root), PROMPTS, [str(eng)])
    # deterministic red (admin created) is never downgraded by a model 'green'
    assert v["verdict"] == "red" and v["decided_by"] == "deterministic" and v["model_verdict"] == "green"
    assert v["yara"] == "needs-review" and len(client.calls) == 3


def test_run_coverage_defaults_from_cavern_and_fatal(tmp_path, monkeypatch):
    case, root, eng = _setup(tmp_path)
    monkeypatch.setattr(po, "flow_bodies", lambda root, epoch: ([], None))
    with open(os.path.join(case.dir, "kadath", "cavern.json"), "w") as f:
        json.dump({"family": "webshell", "regions": [], "needs_input": "password"}, f)
    client = FakeClient(dict(GOOD_VERDICT, coverage="full"), ["# R\n=====DRAFT.YAR=====\nrule k { strings: $a = \"zz\" condition: $a }\n"])
    v = po.run(case, {"case_id": "FIO-7"}, client, str(root), PROMPTS, [str(eng)])
    assert v["coverage"] == "unauthenticated"
    assert "needs_input=password" in client.calls[0][0][1]["content"]


def test_run_missing_marker_degrades(tmp_path, monkeypatch):
    case, root, eng = _setup(tmp_path)
    monkeypatch.setattr(po, "flow_bodies", lambda root, epoch: ([], None))
    # Two replies without the marker line
    client = FakeClient(GOOD_VERDICT, ["# No marker here\n", "# Still no marker\n"])
    v = po.run(case, {"case_id": "FIO-7"}, client, str(root), PROMPTS, [str(eng)])
    # Verdict still goes red (max of deterministic and model)
    assert v["verdict"] == "red" and v["decided_by"] == "agree"
    # YARA degrades to needs-review
    assert v["yara"] == "needs-review"
    # report_md contains the final reply text
    report_md = open(os.path.join(case.dir, "kadath", "report.md")).read()
    assert "# Still no marker" in report_md
    # draft.yar has the degradation comment
    draft_yar = open(os.path.join(case.dir, "kadath", "draft.yar")).read()
    assert "no rule produced: model reply lacked the =====DRAFT.YAR===== marker" in draft_yar
    # Client was called 3 times: verdict, first report attempt, second report attempt
    assert len(client.calls) == 3


def test_flow_bodies_reports_failure(monkeypatch, capsys):
    def boom(*a, **k):
        raise OSError("no docker")
    monkeypatch.setattr(po.subprocess, "run", boom)
    bodies, err = po.flow_bodies("/x", 0)
    assert bodies == []
    assert "no docker" in err
    assert "no docker" in capsys.readouterr().err


def test_ioc_types_match_schema():
    with open(os.path.join(ROOT, ".claude", "skills", "kadath-scry", "references", "iocs-schema.json")) as f:
        schema = json.load(f)
    assert po.IOC_TYPES == schema["properties"]["indicators"]["items"]["properties"]["type"]["enum"]


def test_final_verdict_with_cavern():
    assert po.final_verdict("green", "green", "green") == ("green", "agree")
    assert po.final_verdict("green", "green", "red") == ("red", "cavern")
    assert po.final_verdict("green", "green", "amber") == ("amber", "cavern")
    assert po.final_verdict("red", "green", "red") == ("red", "deterministic")   # tie: evidence wins
    assert po.final_verdict("green", "red", "amber") == ("red", "model")
    assert po.final_verdict("red", "red", None) == ("red", "agree")


def test_evidence_pack_lists_stubs_and_cavern_verdict():
    with open(os.path.join(FIX, "web_summary.json")) as f:
        s = json.load(f)
    s["run"]["stubs"] = [{"path": "/samples/webroot/functions/functions.php", "kind": "include", "round": 1}]
    cav = {"verdict": "amber", "family": "phishing", "regions": [], "needs_input": "none",
           "missing_deps": [{"path": "signin.php", "kind": "redirect"}]}
    pack = po.evidence_pack(s, cav, {"level": "green", "reasons": []}, "", [])
    assert "DEPENDENCY STUBS" in pack and "functions/functions.php" in pack
    assert '"verdict": "amber"' in pack and "signin.php" in pack


_N = [0]


def _run_with_meta(tmp_path, monkeypatch, run_meta_extra, cav_extra, model_coverage="full"):
    _N[0] += 1
    tmp_path = tmp_path / f"t{_N[0]}"
    tmp_path.mkdir()
    case, root, eng = _setup(tmp_path)
    monkeypatch.setattr(po, "flow_bodies", lambda root, epoch: ([], None))
    run_dir = os.path.join(str(root), "reports", "FIO-7-x")
    with open(os.path.join(run_dir, "summary.json")) as f:
        s = json.load(f)
    s["run"].update(run_meta_extra)
    with open(os.path.join(run_dir, "summary.json"), "w") as f:
        json.dump(s, f)
    cav = {"family": "backdoor", "regions": [], "needs_input": "none"}
    cav.update(cav_extra)
    with open(os.path.join(case.dir, "kadath", "cavern.json"), "w") as f:
        json.dump(cav, f)
    client = FakeClient(dict(GOOD_VERDICT, coverage=model_coverage),
                        ["# R\n=====DRAFT.YAR=====\nrule k { strings: $a = \"zz\" condition: $a }\n"])
    return po.run(case, {"case_id": "FIO-7"}, client, str(root), PROMPTS, [str(eng)]), client


def test_run_coverage_stubbed_and_cavern_floor(tmp_path, monkeypatch):
    stubs = [{"path": "/samples/webroot/functions/functions.php", "kind": "include", "round": 1}]
    v, client = _run_with_meta(tmp_path, monkeypatch, {"stubs": stubs, "fatal": False}, {"verdict": "red"})
    assert v["coverage"] == "stubbed" and v["stubs"] == stubs and v["cavern_verdict"] == "red"
    assert "dependency_stubs=1" in client.calls[0][0][1]["content"]
    # engine-reported fatal wins over the model's coverage claim
    v, _ = _run_with_meta(tmp_path, monkeypatch, {"stubs": stubs, "fatal": True}, {"verdict": "amber"})
    assert v["coverage"] == "errored"
    # a password gate beats stubbing
    v, _ = _run_with_meta(tmp_path, monkeypatch, {"stubs": stubs, "fatal": False},
                          {"verdict": "green", "needs_input": "password"})
    assert v["coverage"] == "unauthenticated"


def test_run_cavern_verdict_is_a_floor(tmp_path, monkeypatch):
    # deterministic green (fixture has an admin user -> red), so make the model green and cavern amber:
    # the fixture's deterministic red wins regardless; test the cavern floor via final_verdict directly
    # and via a green-deterministic summary here
    case, root, eng = _setup(tmp_path)
    monkeypatch.setattr(po, "flow_bodies", lambda root, epoch: ([], None))
    run_dir = os.path.join(str(root), "reports", "FIO-7-x")
    with open(os.path.join(run_dir, "summary.json")) as f:
        s = json.load(f)
    s["db_diff"]["users_added"] = []
    s["run"].update({"stubs": [], "fatal": False})
    with open(os.path.join(run_dir, "summary.json"), "w") as f:
        json.dump(s, f)
    with open(os.path.join(case.dir, "kadath", "cavern.json"), "w") as f:
        json.dump({"verdict": "amber", "family": "phishing", "regions": [], "needs_input": "none"}, f)
    client = FakeClient(dict(GOOD_VERDICT, verdict="green"),
                        ["# R\n=====DRAFT.YAR=====\nrule k { strings: $a = \"zz\" condition: $a }\n"])
    v = po.run(case, {"case_id": "FIO-7"}, client, str(root), PROMPTS, [str(eng)])
    assert v["deterministic"]["level"] == "green" and v["model_verdict"] == "green"
    assert v["verdict"] == "amber" and v["decided_by"] == "cavern"


def test_run_engine_passes_stub_flag(tmp_path):
    ok = tmp_path / "ok.sh"
    ok.write_text("#!/bin/sh\necho \"$@\" >&2\necho /tmp/run/summary.json\n")
    ok.chmod(0o755)
    import subprocess as sp
    p = sp.run([str(ok), "/x.php", "--json", "--slug", "S", "--skip-selftest", "--stub-missing"], capture_output=True, text=True)
    assert "--stub-missing" in p.stderr
    assert po.run_engine([str(ok)], "/x.php", "FIO-1", str(tmp_path)) == "/tmp/run/summary.json"


def test_run_engine_adopt_flag(tmp_path):
    ok = tmp_path / "ok.sh"
    ok.write_text("#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args\"\necho /tmp/run/summary.json\n")
    ok.chmod(0o755)
    po.run_engine([str(ok)], "/x.php", "S", str(tmp_path))
    assert "--adopt-wp" not in (tmp_path / "args").read_text()
    po.run_engine([str(ok)], "/x.php", "S", str(tmp_path), adopt=True)
    assert "--adopt-wp" in (tmp_path / "args").read_text()


def test_run_adopts_when_sample_wants_wordpress(tmp_path, monkeypatch):
    case, root, eng = _setup(tmp_path)
    with open(case.php, "w") as f:
        f.write("<?php\nadd_action('init', 'x');\n")
    eng.write_text(f"#!/bin/sh\necho \"$@\" > {root}/args\necho {root}/reports/FIO-7-x/summary.json\n")
    monkeypatch.setattr(po, "flow_bodies", lambda root, epoch: ([], None))
    client = FakeClient(GOOD_VERDICT, ["# R\n=====DRAFT.YAR=====\nrule k { strings: $a = \"zz\" condition: $a }\n"])
    po.run(case, {"case_id": "FIO-7"}, client, str(root), PROMPTS, [str(eng)])
    assert "--adopt-wp" in (root / "args").read_text()
