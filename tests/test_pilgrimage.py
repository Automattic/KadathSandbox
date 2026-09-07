# tests/test_pilgrimage.py
import json
import os
import subprocess
import pytest
from kadath import pilgrimage, manifest
from kadath.library import Case


def _fake_client(a):
    return type("C", (), {"preflight": lambda self: None})()


def test_parse_args_defaults_and_passes():
    a = pilgrimage.parse_args(["/lib"])
    assert a.passes == ["cavern", "offer", "scry"] and a.limit is None and a.min_free_gb == 20
    assert a.engine == ["python3", "bin/kadath", "offer"] and a.no_stack is False
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
    counts = pilgrimage.run_pass("scry", m, list(m.rows.values()), lambda row: {"scry_status": "skipped", "error": "red-confident"})
    assert m.rows["C0"]["scry_status"] == "skipped" and counts["skipped"] == 1


def test_main_resumes_and_filters(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    for cid in ("A", "B", "C"):
        (lib / cid).mkdir(parents=True)
        (lib / cid / "s.php").write_text("<?php\n")
    calls = []
    monkeypatch.setattr(pilgrimage, "_make_client", lambda a: type("C", (), {"preflight": lambda self: None})())
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
    assert pilgrimage._settled({"decided_by": "agree", "verdict": "green"})
    assert pilgrimage._settled({"decided_by": "agree", "verdict": "red", "confidence": 0.6})
    assert not pilgrimage._settled({"decided_by": "agree", "verdict": "red", "confidence": 0.59})
    assert not pilgrimage._settled({"decided_by": "agree", "verdict": "amber", "confidence": 0.99})
    assert not pilgrimage._settled({"decided_by": "deterministic", "verdict": "red", "confidence": 0.99})
    assert not pilgrimage._settled({"decided_by": "model", "verdict": "green", "confidence": 0.99})


def _lib_case(lib, cid, fname="s.php"):
    (lib / cid).mkdir(parents=True)
    (lib / cid / fname).write_text("<?php\n")


def test_main_disk_preflight_aborts_offer(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    _lib_case(lib, "A")
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true")
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
        m.update(cid, cavern_status="done", cavern_worthy="true")
    m.flush()

    offer_results = {
        "A": {"verdict": "red", "confidence": 0.9, "coverage": "full", "run_dir": "/r/A", "decided_by": "agree"},
        "B": {"verdict": "red", "confidence": 0.9, "coverage": "full", "run_dir": "/r/B", "decided_by": "deterministic"},
        "C": {"verdict": "amber", "confidence": 0.5, "coverage": "full", "run_dir": "/r/C", "decided_by": "agree"},
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
    (kd / "verdict.json").write_text(json.dumps({"decided_by": "agree", "verdict": "red", "confidence": 0.9}))

    monkeypatch.setattr(pilgrimage, "_make_client", _fake_client)
    calls = []
    monkeypatch.setattr(pilgrimage.deepscry, "run", lambda *a, **k: calls.append(1))

    rc = pilgrimage.main([str(lib), "--pass", "scry", "--no-stack"])
    assert rc == 0 and calls == []

    m2 = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m2.load()
    assert m2.rows["A"]["scry_status"] == "skipped"
    assert m2.rows["A"]["error"] == "red-confident"


def test_main_engine_error_marks_error_and_recovers_once(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    _lib_case(lib, "A")
    cases = pilgrimage.library.walk(str(lib))
    m = manifest.Manifest(str(lib / "kadath-triage.csv"))
    m.ensure_rows(cases)
    m.update("A", cavern_status="done", cavern_worthy="true")
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


def test_settled_requires_full_coverage():
    base = {"decided_by": "agree", "verdict": "green", "confidence": 0.9}
    assert pilgrimage._settled(dict(base, coverage="full"))
    for cov in ("stubbed", "unauthenticated", "errored"):
        assert not pilgrimage._settled(dict(base, coverage=cov))
    assert not pilgrimage._settled(dict(base, verdict="red", coverage="stubbed"))


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
    monkeypatch.setattr(pilgrimage, "sh", lambda *a, **k: P('[{"Service":"wordpress","State":"running"}]'))
    assert pilgrimage._stack_recover() is True
    calls = []

    def sh(args, **k):
        calls.append(args)
        return P("")
    monkeypatch.setattr(pilgrimage, "sh", sh)
    assert pilgrimage._stack_recover() is False and ["make", "down"] in calls and ["make", "up"] in calls
