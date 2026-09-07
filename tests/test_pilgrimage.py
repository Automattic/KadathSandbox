# tests/test_pilgrimage.py
import subprocess
import pytest
from kadath import pilgrimage, manifest
from kadath.library import Case


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
