# tests/test_pilgrimage.py
import json
import os
import subprocess
import pytest
from kadath import pilgrimage, manifest
from kadath.library import Case


def _fake_client(a, model=None):
    from kadath import llm
    return type("C", (), {"preflight": lambda self: None, "model": "fake",
                          "profiles": dict(llm.PROFILES)})()


def test_parse_args_defaults_and_passes():
    a = pilgrimage.parse_args(["/lib"])
    assert a.passes == ["cavern", "runes", "offer", "scry"] and a.limit is None and a.min_free_gb == 20
    assert a.engine == ["python3", "bin/kadath", "offer"] and a.no_stack is False
    assert "CyberSecQwen" in a.runes_model
    a = pilgrimage.parse_args(["/lib", "--pass", "cavern", "--limit", "5", "--case", "A", "--case", "B",
                               "--sampling", "cavern.temperature=0.5", "--engine", "sh x.sh", "--no-stack"])
    assert a.passes == ["cavern"] and a.limit == 5 and a.case == ["A", "B"]
    assert a.sampling == ["cavern.temperature=0.5"] and a.engine == ["sh", "x.sh"] and a.no_stack


def _m(tmp_path, n=5):
    m = manifest.Manifest(str(tmp_path / "t.csv"))
    m.ensure_rows([Case(f"C{i}", str(tmp_path), "x.php", None, None) for i in range(n)])
    return m


def test_run_pass_isolates_errors_and_flushes(tmp_path):
    m = _m(tmp_path)
    seen = []
    def fn(row):
        seen.append(row["case_id"])
        if row["case_id"] == "C1":
            raise RuntimeError("boom")
        if row["case_id"] == "C2":
            raise subprocess.TimeoutExpired("x", 1)
        return {"cavern_verdict": "red"}
    counts = pilgrimage.run_pass("cavern", m, m.pending("cavern"), fn)
    assert seen == ["C0", "C1", "C2", "C3", "C4"]
    assert m.rows["C0"]["cavern_status"] == "done" and m.rows["C0"]["cavern_verdict"] == "red"
    assert m.rows["C1"]["cavern_status"] == "error" and "boom" in m.rows["C1"]["error"]
    assert m.rows["C2"]["cavern_status"] == "timeout"
    assert counts == {"done": 3, "error": 1, "timeout": 1, "skipped": 0, "aborted": False}
    assert (tmp_path / "t.csv").exists()
    assert m.rows["C0"]["cavern_at"].endswith("Z")


def test_run_pass_breaker(tmp_path):
    m = _m(tmp_path)
    def fn(row):
        raise RuntimeError("down")
    counts = pilgrimage.run_pass("cavern", m, m.pending("cavern"), fn, breaker=3)
    assert counts["aborted"] is True and counts["error"] == 3
    assert m.rows["C3"]["cavern_status"] == "pending"


def test_run_pass_skip_result(tmp_path):
    m = _m(tmp_path, 1)
    counts = pilgrimage.run_pass("scry", m, list(m.rows.values()), lambda row: {"scry_status": "skipped", "error": "settled: no scry needed"})
    assert m.rows["C0"]["scry_status"] == "skipped" and counts["skipped"] == 1


def test_main_resumes_and_filters(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    for cid in ("A", "B", "C"):
        (lib / cid).mkdir(parents=True)
        (lib / cid / "s.php").write_text("<?php\n")
    calls = []
    monkeypatch.setattr(pilgrimage, "_make_client", lambda a, model=None: type("C", (), {"preflight": lambda self: None})())
    monkeypatch.setattr(pilgrimage.cavern, "run", lambda case, client, prompts: calls.append(case.id) or
                        {"verdict": "green", "family": "benign", "worthy": False})
    rc = pilgrimage.main([str(lib), "--pass", "cavern", "--limit", "2", "--no-stack"])
    assert rc == 0 and calls == ["A", "B"]
    rc = pilgrimage.main([str(lib), "--pass", "cavern", "--no-stack"])
    assert rc == 0 and calls == ["A", "B", "C"]
    m = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m.load()
    assert all(r["cavern_status"] == "done" for r in m.rows.values())
    assert m.rows["A"]["cavern_worthy"] == "false" and m.rows["A"]["final_verdict"] == "green"
    assert m.rows["A"]["decided_by"] == "cavern"
    rc = pilgrimage.main([str(lib), "--pass", "offer", "--no-stack"])
    assert rc == 0   # nothing worthy: pass is a no-op


def test_free_gb(tmp_path):
    assert pilgrimage.free_gb(str(tmp_path)) > 0


def test_settled_gate():
    red = {"verdict": "red", "cavern_verdict": "red", "model_verdict": "red",
           "deterministic": {"level": "green"}, "confidence": 0.9, "coverage": "full"}
    assert pilgrimage._settled(red)
    assert pilgrimage._settled(dict(red, coverage="errored"))          # agreed red needs no scry
    assert pilgrimage._settled(dict(red, deterministic={"level": "red"}))
    assert not pilgrimage._settled(dict(red, confidence=0.59))
    assert not pilgrimage._settled(dict(red, model_verdict="green"))    # cavern/model disagree
    assert not pilgrimage._settled(dict(red, verdict="amber", cavern_verdict="amber", model_verdict="amber"))
    green = {"verdict": "green", "cavern_verdict": "green", "model_verdict": "green",
             "deterministic": {"level": "green"}, "confidence": 0.9, "coverage": "full"}
    assert pilgrimage._settled(green)
    assert not pilgrimage._settled(dict(green, deterministic={"level": "amber"}, verdict="amber"))
    assert not pilgrimage._settled(dict(green, cavern_verdict=None, model_verdict="green", coverage="errored"))
    # no cavern recorded (hand-offered): model and deterministic decide
    assert pilgrimage._settled(dict(green, cavern_verdict=None))


def _lib_case(lib, cid, fname="s.php"):
    (lib / cid).mkdir(parents=True)
    (lib / cid / fname).write_text("<?php\n")


def test_main_disk_preflight_aborts_offer(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    _lib_case(lib, "A")
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true", runes_status="done")
    m.flush()

    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    monkeypatch.setattr(pilgrimage, "free_gb", lambda path: 1.0)
    calls = []
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run", lambda *a, **k: calls.append(1))

    rc = pilgrimage.main([str(lib), "--pass", "offer", "--no-stack"])
    assert rc == 2 and calls == []


def test_main_retry_is_scoped(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    _lib_case(lib, "A")
    _lib_case(lib, "B")
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m.ensure_rows(cases)
    m.update("A", cavern_status="error", error="boom")
    m.update("B", cavern_status="error", error="boom")
    m.flush()

    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    monkeypatch.setattr(pilgrimage.cavern, "run", lambda case, client, prompts:
                        {"verdict": "green", "family": "benign", "worthy": False})

    rc = pilgrimage.main([str(lib), "--pass", "cavern", "--case", "A", "--retry-errors", "--no-stack"])
    assert rc == 0

    m2 = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m2.load()
    assert m2.rows["A"]["cavern_status"] == "done"
    assert m2.rows["B"]["cavern_status"] == "error" and m2.rows["B"]["error"] == "boom"


def test_main_offer_routes_to_scry_or_settles(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    for cid in ("A", "B", "C"):
        _lib_case(lib, cid)
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m.ensure_rows(cases)
    for cid in ("A", "B", "C"):
        m.update(cid, cavern_status="done", cavern_worthy="true", runes_status="done")
    m.flush()

    offer_results = {
        # A: Cavern and model agree red, deterministic quiet -> settled red
        "A": {"verdict": "red", "confidence": 0.9, "coverage": "full", "run_dir": "/r/A", "decided_by": "cavern",
              "cavern_verdict": "red", "runes_verdict": "red", "model_verdict": "red", "deterministic": {"level": "green"}},
        # B: deterministic red against a green Cavern and model -> scry
        "B": {"verdict": "red", "confidence": 0.9, "coverage": "full", "run_dir": "/r/B", "decided_by": "deterministic",
              "cavern_verdict": "green", "runes_verdict": "green", "model_verdict": "green", "deterministic": {"level": "red"}},
        # C: amber never settles
        "C": {"verdict": "amber", "confidence": 0.5, "coverage": "full", "run_dir": "/r/C", "decided_by": "agree",
              "cavern_verdict": "amber", "model_verdict": "amber", "deterministic": {"level": "amber"}},
    }

    def fake_offer(case, row, client, root, prompts_dir, engine_cmd):
        v = offer_results[case.id]
        kd = os.path.join(case.dir, "kadath")
        os.makedirs(kd, exist_ok=True)
        with open(os.path.join(kd, "verdict.json"), "w") as f:
            json.dump(v, f)
        return v

    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    monkeypatch.setattr(pilgrimage, "free_gb", lambda path: 999.0)
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run", fake_offer)
    rc = pilgrimage.main([str(lib), "--pass", "offer", "--no-stack"])
    assert rc == 0

    m2 = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m2.load()
    for cid in ("A", "B", "C"):
        assert m2.rows[cid]["offer_status"] == "done"
        assert m2.rows[cid]["final_verdict"] == offer_results[cid]["verdict"]
        assert m2.rows[cid]["decided_by"] == "offer"
    assert m2.rows["A"]["scry_status"] == "skipped"
    assert m2.rows["B"]["scry_status"] == "pending"
    assert m2.rows["C"]["scry_status"] == "pending"

    scry_calls = []

    def fake_deepscry(case, row, client, prompts_dir):
        scry_calls.append(case.id)
        return {"verdict": "red"}

    monkeypatch.setattr(pilgrimage.deepscry, "run", fake_deepscry)
    rc = pilgrimage.main([str(lib), "--pass", "scry", "--no-stack"])
    assert rc == 0
    assert scry_calls == ["B", "C"]

    m3 = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m3.load()
    for cid in ("B", "C"):
        assert m3.rows[cid]["scry_status"] == "done"
        assert m3.rows[cid]["scry_verdict"] == "red"
        assert m3.rows[cid]["final_verdict"] == "red"
        assert m3.rows[cid]["decided_by"] == "deepscry"


def test_main_scry_skips_red_confident_inside_pass(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    _lib_case(lib, "A")
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true", offer_status="done", offer_verdict="red")
    m.flush()
    kd = lib / "A" / "kadath"
    kd.mkdir(parents=True)
    (kd / "verdict.json").write_text(json.dumps({"verdict": "red", "cavern_verdict": "red", "model_verdict": "red",
                                                 "deterministic": {"level": "green"}, "confidence": 0.9,
                                                 "coverage": "errored", "decided_by": "cavern"}))

    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    calls = []
    monkeypatch.setattr(pilgrimage.deepscry, "run", lambda *a, **k: calls.append(1))

    rc = pilgrimage.main([str(lib), "--pass", "scry", "--no-stack"])
    assert rc == 0 and calls == []

    m2 = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m2.load()
    assert m2.rows["A"]["scry_status"] == "skipped"
    assert m2.rows["A"]["error"] == "settled: no scry needed"


def test_main_scry_skips_runes_only_verdict_without_bundle(tmp_path, monkeypatch):
    # an unsettled verdict from the Runes stand-in has run_dir "": scrying it would
    # read the CWD's live artifacts (another sample's evidence), so it is skipped
    lib = tmp_path / "lib"
    _lib_case(lib, "A")
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true", offer_status="done", offer_verdict="red",
             final_verdict="red", decided_by="runes")
    m.flush()
    kd = lib / "A" / "kadath"
    kd.mkdir(parents=True)
    (kd / "verdict.json").write_text(json.dumps({"verdict": "red", "cavern_verdict": "amber", "runes_verdict": "red",
                                                 "model_verdict": None, "deterministic": {"level": "green"},
                                                 "confidence": 0.9, "coverage": "errored", "run_dir": "",
                                                 "decided_by": "runes"}))
    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    calls = []
    monkeypatch.setattr(pilgrimage.deepscry, "run", lambda *a, **k: calls.append(1))

    rc = pilgrimage.main([str(lib), "--pass", "scry", "--no-stack"])
    assert rc == 0 and calls == []

    m2 = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m2.load()
    assert m2.rows["A"]["scry_status"] == "skipped"
    assert "no run bundle" in m2.rows["A"]["error"]
    assert m2.rows["A"]["final_verdict"] == "red" and m2.rows["A"]["decided_by"] == "runes"


def test_main_offer_routes_unexercised_green_to_scry(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    for cid in ("A", "B"):
        _lib_case(lib, cid)
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m.ensure_rows(cases)
    for cid in ("A", "B"):
        m.update(cid, cavern_status="done", cavern_worthy="true", runes_status="done")
    m.flush()

    def green(cov, rd):
        return {"verdict": "green", "confidence": 0.9, "coverage": cov, "run_dir": rd, "decided_by": "agree",
                "cavern_verdict": "green", "runes_verdict": "green", "model_verdict": "green",
                "deterministic": {"level": "green"}}
    offer_results = {"A": green("stubbed", "/r/A"), "B": green("full", "/r/B")}

    def fake_offer(case, row, client, root, prompts_dir, engine_cmd):
        v = offer_results[case.id]
        kd = os.path.join(case.dir, "kadath")
        os.makedirs(kd, exist_ok=True)
        with open(os.path.join(kd, "verdict.json"), "w") as f:
            json.dump(v, f)
        return v

    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    monkeypatch.setattr(pilgrimage, "free_gb", lambda path: 999.0)
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run", fake_offer)
    assert pilgrimage.main([str(lib), "--pass", "offer", "--no-stack"]) == 0

    m2 = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m2.load()
    assert m2.rows["A"]["offer_verdict"] == "green" and m2.rows["A"]["offer_coverage"] == "stubbed"
    assert m2.rows["A"]["scry_status"] == "pending"        # runtime silence on stand-ins is not evidence
    assert m2.rows["B"]["scry_status"] == "skipped"        # a green that actually ran, all agreeing
    assert [r["case_id"] for r in m2.pending("scry")] == ["A"]


def test_do_scry_unsettled_runes_stand_in_never_reaches_deepscry(tmp_path, monkeypatch):
    # end to end from the offer pass: engine fails, the Runes stand in disagreeing
    # with the Cavern (unsettled, run_dir ""), and the Scry pass must skip it
    lib = tmp_path / "lib"; _worthy_case_with_runes(lib, "A")
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv")); m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true", runes_status="done"); m.flush()
    monkeypatch.setattr(pilgrimage, "_make_client", _client_factory(reachable=True))
    monkeypatch.setattr(pilgrimage, "free_gb", lambda p: 999.0)
    monkeypatch.setattr(pilgrimage, "_stack_up", lambda: None)
    monkeypatch.setattr(pilgrimage, "_stack_recover", lambda: True)
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run",
                        lambda *a, **k: (_ for _ in ()).throw(pilgrimage.pilgrim_offer.EngineError("PHP Parse error")))
    calls = []
    monkeypatch.setattr(pilgrimage.deepscry, "run", lambda *a, **k: calls.append(1))
    assert pilgrimage.main([str(lib), "--pass", "offer"]) == 0
    m2 = manifest.Manifest(str(lib / "kadath-triage.csv")); m2.load()
    assert m2.rows["A"]["scry_status"] == "pending" and m2.rows["A"]["run_dir"] == ""
    assert pilgrimage.main([str(lib), "--pass", "scry", "--no-stack"]) == 0
    m3 = manifest.Manifest(str(lib / "kadath-triage.csv")); m3.load()
    assert calls == [] and m3.rows["A"]["scry_status"] == "skipped"
    assert "no run bundle" in m3.rows["A"]["error"]
    assert m3.rows["A"]["final_verdict"] == "red" and m3.rows["A"]["decided_by"] == "runes"


def test_main_engine_error_marks_error_and_recovers_once(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    _lib_case(lib, "A")
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true", runes_status="done")
    m.flush()

    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    monkeypatch.setattr(pilgrimage, "free_gb", lambda path: 999.0)

    def raise_engine_error(*a, **k):
        raise pilgrimage.pilgrim_offer.EngineError("boom")
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run", raise_engine_error)
    recover_calls = []
    monkeypatch.setattr(pilgrimage, "_stack_recover", lambda: recover_calls.append(1))

    rc = pilgrimage.main([str(lib), "--pass", "offer", "--no-stack"])
    assert rc == 0
    m2 = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m2.load()
    assert m2.rows["A"]["offer_status"] == "error"
    assert "boom" in m2.rows["A"]["error"]
    assert recover_calls == []

    monkeypatch.setattr(pilgrimage, "_stack_up", lambda: None)
    rc = pilgrimage.main([str(lib), "--pass", "offer", "--retry-errors"])
    assert rc == 0
    assert recover_calls == [1]


def test_main_warns_on_unknown_case(tmp_path, monkeypatch, capsys):
    lib = tmp_path / "lib"
    _lib_case(lib, "A")
    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    monkeypatch.setattr(pilgrimage.cavern, "run", lambda case, client, prompts:
                        {"verdict": "green", "family": "benign", "worthy": False})
    rc = pilgrimage.main([str(lib), "--pass", "cavern", "--case", "A", "--case", "NOPE", "--no-stack"])
    assert rc == 0
    assert "warning: case(s) not in library: NOPE" in capsys.readouterr().err


def test_settled_green_requires_full_coverage():
    base = {"verdict": "green", "cavern_verdict": "green", "model_verdict": "green",
            "deterministic": {"level": "green"}, "confidence": 0.9}
    assert pilgrimage._settled(dict(base, coverage="full"))
    for cov in ("stubbed", "unauthenticated", "errored"):
        assert not pilgrimage._settled(dict(base, coverage=cov))


def test_run_pass_breaker_ignores_sample_failures(tmp_path):
    m = _m(tmp_path)

    def fn(row):
        e = RuntimeError("engine failed on this sample")
        e.stack_healthy = True
        raise e
    counts = pilgrimage.run_pass("offer", m, m.pending("cavern"), fn, breaker=2)
    assert counts["error"] == 5 and counts["aborted"] is False


def test_run_pass_keeps_error_tail(tmp_path):
    m = _m(tmp_path, 1)

    def fn(row):
        raise RuntimeError("head " + "x" * 600 + " TAIL-MESSAGE")
    pilgrimage.run_pass("cavern", m, m.pending("cavern"), fn)
    err = m.rows["C0"]["error"]
    assert err.endswith("TAIL-MESSAGE") and err.startswith("…") and len(err) <= 500


def test_stack_recover_reports_health(monkeypatch):
    class P:
        def __init__(self, out): self.stdout = out
    calls = []

    def fake(out):
        def sh(args, **k):
            calls.append(args)
            return P(out)
        return sh
    # a JSON array, and one JSON object per line: wordpress running -> healthy, no restart
    for out in ('[{"Service":"gateway","State":"running"},{"Service":"wordpress","State":"running"}]',
                '{"Service":"gateway","State":"running"}\n{"Service":"wordpress","State":"running","Health":"healthy"}\n'):
        monkeypatch.setattr(pilgrimage, "sh", fake(out))
        assert pilgrimage._stack_recover() is True
    assert ["make", "down"] not in calls
    # wordpress exited while the gateway runs: the old substring check called this healthy
    for out in ('[{"Service":"gateway","State":"running"},{"Service":"wordpress","State":"exited"}]',
                '{"Service":"gateway","State":"running"}\n{"Service":"wordpress","State":"exited"}\n', ""):
        calls.clear()
        monkeypatch.setattr(pilgrimage, "sh", fake(out))
        assert pilgrimage._stack_recover() is False and ["make", "down"] in calls and ["make", "up"] in calls


def test_do_offer_runes_stand_in_on_healthy_stack(tmp_path, monkeypatch):
    lib = tmp_path / "lib"; _lib_case(lib, "A")
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv")); m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true", runes_status="done"); m.flush()
    kd = lib / "A" / "kadath"; kd.mkdir(parents=True)
    (kd / "cavern.json").write_text(json.dumps({"verdict": "amber"}))
    (kd / "runes.json").write_text(json.dumps({"verdict": "red", "confidence": 0.9,
                                               "iocs_extra": [], "persistence": [], "reason": "packed shell"}))
    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    monkeypatch.setattr(pilgrimage, "free_gb", lambda p: 999.0)
    monkeypatch.setattr(pilgrimage, "_stack_up", lambda: None)        # don't touch docker
    monkeypatch.setattr(pilgrimage, "_stack_recover", lambda: True)   # stack healthy
    def boom(*a, **k):
        raise pilgrimage.pilgrim_offer.EngineError("PHP Parse error in /samples/x.php")
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run", boom)
    rc = pilgrimage.main([str(lib), "--pass", "offer"])
    assert rc == 0
    m2 = manifest.Manifest(str(lib / "kadath-triage.csv")); m2.load()
    assert m2.rows["A"]["offer_status"] == "done" and m2.rows["A"]["offer_coverage"] == "errored"
    assert m2.rows["A"]["final_verdict"] == "red" and m2.rows["A"]["decided_by"] == "runes"


def test_do_offer_unhealthy_stack_still_errors_and_breaks(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    for cid in ("A", "B"):
        _lib_case(lib, cid)
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv")); m.ensure_rows(cases)
    for cid in ("A", "B"):
        m.update(cid, cavern_status="done", cavern_worthy="true", runes_status="done")
        kd = lib / cid / "kadath"; kd.mkdir(parents=True)
        (kd / "cavern.json").write_text(json.dumps({"verdict": "amber"}))
        (kd / "runes.json").write_text(json.dumps({"verdict": "red", "confidence": 0.9,
                                                   "iocs_extra": [], "persistence": [], "reason": "x"}))
    m.flush()
    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    monkeypatch.setattr(pilgrimage, "free_gb", lambda p: 999.0)
    monkeypatch.setattr(pilgrimage, "_stack_up", lambda: None)         # don't touch docker
    monkeypatch.setattr(pilgrimage, "_stack_recover", lambda: False)   # stack sick
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run",
                        lambda *a, **k: (_ for _ in ()).throw(pilgrimage.pilgrim_offer.EngineError("down")))
    rc = pilgrimage.main([str(lib), "--pass", "offer"])
    # a sick stack must NOT be papered over by the runes fallback: rows error, breaker aborts
    m2 = manifest.Manifest(str(lib / "kadath-triage.csv")); m2.load()
    assert m2.rows["A"]["offer_status"] == "error"


def _worthy_case_with_runes(lib, cid):
    _lib_case(lib, cid)
    kd = lib / cid / "kadath"; kd.mkdir(parents=True)
    (kd / "cavern.json").write_text(json.dumps({"verdict": "amber"}))
    (kd / "runes.json").write_text(json.dumps({"verdict": "red", "confidence": 0.9,
                                               "iocs_extra": [], "persistence": [], "reason": "static shell"}))


def _client_factory(reachable):
    from kadath import llm
    def make(a, model=None):
        return type("C", (), {"preflight": lambda self: None, "model": "fake",
                              "profiles": dict(llm.PROFILES), "reachable": lambda self: reachable})()
    return make


def test_do_offer_llm_timeout_with_reachable_ollama_uses_runes(tmp_path, monkeypatch):
    lib = tmp_path / "lib"; _worthy_case_with_runes(lib, "A")
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv")); m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true", runes_status="done"); m.flush()
    monkeypatch.setattr(pilgrimage, "_make_client", _client_factory(reachable=True))
    monkeypatch.setattr(pilgrimage, "free_gb", lambda p: 999.0)
    monkeypatch.setattr(pilgrimage, "_stack_up", lambda: None)

    def timeout_after_detonation(*a, **k):
        # the sample ran and the deterministic verdict is red; the verdict model then timed out
        e = pilgrimage.llm.LLMError("timed out")
        e.det, e.run_dir = {"level": "red", "reasons": ["admin created"]}, "/r/A-bundle"
        raise e
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run", timeout_after_detonation)
    rc = pilgrimage.main([str(lib), "--pass", "offer"])
    m2 = manifest.Manifest(str(lib / "kadath-triage.csv")); m2.load()
    assert m2.rows["A"]["offer_status"] == "done" and m2.rows["A"]["offer_coverage"] == "errored"
    # cavern amber, runes red, deterministic red: the real det level survives and the bundle is kept
    assert m2.rows["A"]["final_verdict"] == "red" and m2.rows["A"]["run_dir"] == "/r/A-bundle"
    v = json.load(open(lib / "A" / "kadath" / "verdict.json"))
    assert v["verdict"] == "red" and v["run_dir"] == "/r/A-bundle" and v["deterministic"]["level"] == "red"
    # cavern(amber) vs runes(red) disagree -> not settled -> scry stays pending (and can use the bundle)
    assert m2.rows["A"]["scry_status"] == "pending"


def test_do_offer_llm_timeout_deterministic_red_beats_green_static(tmp_path, monkeypatch):
    lib = tmp_path / "lib"; _worthy_case_with_runes(lib, "A")
    (lib / "A" / "kadath" / "runes.json").write_text(json.dumps(
        {"verdict": "green", "confidence": 0.9, "iocs_extra": [], "persistence": [], "reason": "clean"}))
    (lib / "A" / "kadath" / "cavern.json").write_text(json.dumps({"verdict": "green"}))
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv")); m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true", runes_status="done"); m.flush()
    monkeypatch.setattr(pilgrimage, "_make_client", _client_factory(reachable=True))
    monkeypatch.setattr(pilgrimage, "free_gb", lambda p: 999.0)
    monkeypatch.setattr(pilgrimage, "_stack_up", lambda: None)

    def timeout_after_detonation(*a, **k):
        e = pilgrimage.llm.LLMError("timed out")
        e.det, e.run_dir = {"level": "red", "reasons": []}, "/r/A-bundle"
        raise e
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run", timeout_after_detonation)
    pilgrimage.main([str(lib), "--pass", "offer"])
    m2 = manifest.Manifest(str(lib / "kadath-triage.csv")); m2.load()
    assert m2.rows["A"]["final_verdict"] == "red" and m2.rows["A"]["decided_by"] == "deterministic"
    assert m2.rows["A"]["scry_status"] == "pending"    # red vs green static reads: the scry may look


def test_do_offer_runes_fallback_agreed_red_skips_scry(tmp_path, monkeypatch):
    lib = tmp_path / "lib"; _worthy_case_with_runes(lib, "A")
    (lib / "A" / "kadath" / "cavern.json").write_text(json.dumps({"verdict": "red"}))  # agree with runes red
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv")); m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true", runes_status="done"); m.flush()
    monkeypatch.setattr(pilgrimage, "_make_client", _client_factory(reachable=True))
    monkeypatch.setattr(pilgrimage, "free_gb", lambda p: 999.0)
    monkeypatch.setattr(pilgrimage, "_stack_up", lambda: None)
    monkeypatch.setattr(pilgrimage, "_stack_recover", lambda: True)
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run",
                        lambda *a, **k: (_ for _ in ()).throw(pilgrimage.pilgrim_offer.EngineError("PHP Parse error")))
    pilgrimage.main([str(lib), "--pass", "offer"])
    m2 = manifest.Manifest(str(lib / "kadath-triage.csv")); m2.load()
    assert m2.rows["A"]["offer_status"] == "done" and m2.rows["A"]["final_verdict"] == "red"
    # agreed red (cavern==runes, conf 0.9) settles even errored -> no scry
    assert m2.rows["A"]["scry_status"] == "skipped"


def test_do_offer_llm_error_ollama_down_errors_the_row(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    for cid in ("A", "B", "C"):
        _worthy_case_with_runes(lib, cid)
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv")); m.ensure_rows(cases)
    for cid in ("A", "B", "C"):
        m.update(cid, cavern_status="done", cavern_worthy="true", runes_status="done")
    m.flush()
    monkeypatch.setattr(pilgrimage, "_make_client", _client_factory(reachable=False))
    monkeypatch.setattr(pilgrimage, "free_gb", lambda p: 999.0)
    monkeypatch.setattr(pilgrimage, "_stack_up", lambda: None)
    monkeypatch.setattr(pilgrimage.pilgrim_offer, "run",
                        lambda *a, **k: (_ for _ in ()).throw(pilgrimage.llm.LLMError("connection refused")))
    rc = pilgrimage.main([str(lib), "--pass", "offer"])
    # Ollama down is not papered over by the runes fallback: the breaker aborts
    assert rc == 1
    m2 = manifest.Manifest(str(lib / "kadath-triage.csv")); m2.load()
    assert m2.rows["A"]["offer_status"] == "error" and m2.rows["C"]["offer_status"] == "pending"


def test_do_scry_failed_scry_leaves_decided_by(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    for cid in ("A", "B"):
        _lib_case(lib, cid)
        kd = lib / cid / "kadath"; kd.mkdir(parents=True)
        (kd / "verdict.json").write_text(json.dumps(
            {"verdict": "red", "run_dir": "/r/" + cid, "confidence": 0.5, "coverage": "full",
             "cavern_verdict": "red", "model_verdict": "green", "deterministic": {"level": "green"}}))
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv")); m.ensure_rows(cases)
    for cid in ("A", "B"):
        m.update(cid, cavern_status="done", cavern_worthy="true", runes_status="done", offer_status="done",
                 decided_by="offer", scry_status="pending")
    m.flush()
    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    status = {"A": "unverified-claims", "B": "ok"}
    monkeypatch.setattr(pilgrimage.deepscry, "run", lambda case, row, c, p: {
        "verdict": "red" if case.id == "A" else "amber", "deepscry": {"status": status[case.id]}})
    assert pilgrimage.main([str(lib), "--pass", "scry", "--no-stack"]) == 0
    m2 = manifest.Manifest(str(lib / "kadath-triage.csv")); m2.load()
    assert m2.rows["A"]["scry_status"] == "done" and m2.rows["A"]["decided_by"] == "offer"   # failed scry decided nothing
    assert m2.rows["B"]["decided_by"] == "deepscry" and m2.rows["B"]["final_verdict"] == "amber"
