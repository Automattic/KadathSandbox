import csv
import os
import pytest
from kadath import manifest
from kadath.library import Case


def _cases(tmp_path):
    return [Case("B", str(tmp_path / "B"), str(tmp_path / "B/b.php"), None, None),
            Case("A", str(tmp_path / "A"), None, None, "no-php"),
            Case("C", str(tmp_path / "C"), str(tmp_path / "C/c.php"), None, None)]


def test_ensure_rows_and_flush_idempotent(tmp_path):
    m = manifest.Manifest(str(tmp_path / "kadath-triage.csv"))
    m.ensure_rows(_cases(tmp_path))
    m.flush()
    with open(tmp_path / "kadath-triage.csv") as f:
        rows = list(csv.DictReader(f))
    assert [r["case_id"] for r in rows] == ["B", "A", "C"]
    assert list(rows[0].keys()) == manifest.COLUMNS
    a = next(r for r in rows if r["case_id"] == "A")
    assert a["cavern_status"] == a["offer_status"] == a["scry_status"] == "skipped"
    assert a["error"] == "no-php"
    assert rows[0]["cavern_status"] == "pending" and rows[0]["php"].endswith("b.php")
    m2 = manifest.Manifest(str(tmp_path / "kadath-triage.csv"))
    m2.load()
    m2.update("B", cavern_status="done")
    m2.ensure_rows(_cases(tmp_path))     # must not reset B
    assert m2.rows["B"]["cavern_status"] == "done"
    assert not os.path.exists(str(tmp_path / "kadath-triage.csv.tmp"))


def test_pending_rules(tmp_path):
    m = manifest.Manifest(str(tmp_path / "t.csv"))
    m.ensure_rows(_cases(tmp_path))
    assert [r["case_id"] for r in m.pending("cavern")] == ["B", "C"]
    assert m.pending("offer") == []
    m.update("B", cavern_status="done", cavern_worthy="true")
    m.update("C", cavern_status="done", cavern_worthy="false")
    assert [r["case_id"] for r in m.pending("offer")] == ["B"]
    assert m.pending("scry") == []
    m.update("B", offer_status="done", offer_verdict="green")
    assert m.pending("scry") == []
    m.update("B", offer_verdict="amber")
    assert [r["case_id"] for r in m.pending("scry")] == ["B"]
    m.update("B", offer_verdict="red")
    assert [r["case_id"] for r in m.pending("scry")] == ["B"]
    with pytest.raises(ValueError):
        m.pending("nope")


def test_retry_and_force(tmp_path):
    m = manifest.Manifest(str(tmp_path / "t.csv"))
    m.ensure_rows(_cases(tmp_path))
    m.update("B", cavern_status="error", error="boom")
    m.update("C", cavern_status="done", offer_status="timeout")
    m.retry(["cavern"])
    assert m.rows["B"]["cavern_status"] == "pending" and m.rows["B"]["error"] == ""
    assert m.rows["C"]["offer_status"] == "timeout"
    m.retry(["offer"])
    assert m.rows["C"]["offer_status"] == "pending"
    m.retry(["cavern"], force=True)
    assert m.rows["C"]["cavern_status"] == "pending"
    assert m.rows["A"]["cavern_status"] == "skipped"


def test_retry_scoped(tmp_path):
    m = manifest.Manifest(str(tmp_path / "t.csv"))
    m.ensure_rows(_cases(tmp_path))
    m.update("B", cavern_status="error", error="boom")
    m.update("C", cavern_status="error", error="bang")
    m.retry(["cavern"], case_ids={"B"})
    assert m.rows["B"]["cavern_status"] == "pending" and m.rows["B"]["error"] == ""
    assert m.rows["C"]["cavern_status"] == "error" and m.rows["C"]["error"] == "bang"


def test_atomic_flush_keeps_old_on_crash(tmp_path, monkeypatch):
    p = tmp_path / "t.csv"
    m = manifest.Manifest(str(p))
    m.ensure_rows(_cases(tmp_path))
    m.flush()
    before = p.read_text()
    m.update("B", cavern_status="done")
    def boom(a, b):
        raise OSError("crash")
    monkeypatch.setattr(manifest.os, "replace", boom)
    with pytest.raises(OSError):
        m.flush()
    assert p.read_text() == before


def test_update_unknown_and_histogram(tmp_path):
    m = manifest.Manifest(str(tmp_path / "t.csv"))
    m.ensure_rows(_cases(tmp_path))
    with pytest.raises(KeyError):
        m.update("Z", cavern_status="done")
    with pytest.raises(KeyError):
        m.update("B", nope="x")
    m.update("B", final_verdict="red")
    m.update("C", final_verdict="red")
    assert m.histogram("final_verdict") == {"": 1, "red": 2}
    assert manifest.now_iso().endswith("Z")
