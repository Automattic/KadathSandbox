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
    assert a["cavern_status"] == a["runes_status"] == a["offer_status"] == a["scry_status"] == "skipped"
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
    assert [r["case_id"] for r in m.pending("runes")] == ["B"]     # worthy cavern-done
    assert m.pending("offer") == []                                # runes not done yet
    m.update("B", runes_status="done")
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


def test_load_rejects_unexpected_header(tmp_path):
    p = tmp_path / "bad.csv"
    cols = list(manifest.COLUMNS)
    cols[0], cols[1] = cols[1], cols[0]     # reordered
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
    m = manifest.Manifest(str(p))
    with pytest.raises(ValueError):
        m.load()
    p2 = tmp_path / "missing.csv"
    with open(p2, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "size", "sha256"])   # reordered
        w.writeheader()
    m2 = manifest.Manifest(str(p2))
    with pytest.raises(ValueError):
        m2.load()


def test_load_roundtrips_utf8(tmp_path):
    m = manifest.Manifest(str(tmp_path / "t.csv"))
    m.ensure_rows(_cases(tmp_path))
    m.update("B", error="ração ✓")
    m.flush()
    m2 = manifest.Manifest(str(tmp_path / "t.csv"))
    m2.load()
    assert m2.rows["B"]["error"] == "ração ✓"


def test_load_accepts_older_shorter_schema(tmp_path):
    # a manifest written before runes_* existed: same order, missing the new columns
    old = [c for c in manifest.COLUMNS if not c.startswith("runes_")]
    p = tmp_path / "old.csv"
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=old)
        w.writeheader()
        w.writerow({c: "" for c in old} | {"case_id": "A", "cavern_status": "done",
                                            "cavern_worthy": "true", "offer_status": "pending"})
    m = manifest.Manifest(str(p))
    m.load()
    # the runes column was absent on disk; load backfills it so the worthy
    # done-cavern row resumes into the runes pass with no manual intervention
    assert m.rows["A"]["cavern_status"] == "done"
    assert m.rows["A"]["runes_status"] == "pending"
    assert [r["case_id"] for r in m.pending("runes")] == ["A"]


def test_load_rejects_unknown_column(tmp_path):
    p = tmp_path / "x.csv"
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(manifest.COLUMNS) + ["bogus"])
        w.writeheader()
    import pytest
    with pytest.raises(ValueError):
        manifest.Manifest(str(p)).load()


def test_load_backfills_runes_status_so_old_rows_resume(tmp_path):
    old = [c for c in manifest.COLUMNS if not c.startswith("runes_")]
    p = tmp_path / "old.csv"
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=old)
        w.writeheader()
        base = {c: "" for c in old}
        w.writerow({**base, "case_id": "W", "cavern_status": "done", "cavern_worthy": "true", "offer_status": "pending"})
        w.writerow({**base, "case_id": "N", "cavern_status": "done", "cavern_worthy": "false", "offer_status": "skipped"})
        w.writerow({**base, "case_id": "S", "cavern_status": "skipped", "offer_status": "skipped"})
    m = manifest.Manifest(str(p))
    m.load()
    # a worthy pre-runes row is now resumable into the runes pass with no manual poke
    assert [r["case_id"] for r in m.pending("runes")] == ["W"]
    assert m.rows["N"]["runes_status"] == "skipped" and m.rows["S"]["runes_status"] == "skipped"


def test_backup_mirror_survives_primary_loss(tmp_path):
    prim = tmp_path / "lib" / "kadath-triage.csv"
    bak = tmp_path / "safe" / "lib-kadath-triage.csv"
    m = manifest.Manifest(str(prim), backup=str(bak))
    m.ensure_rows([Case("A", str(tmp_path), "a.php", None, None)])
    m.update("A", cavern_status="done", cavern_worthy="true")
    m.flush()
    assert prim.exists() and bak.exists()          # both written
    # simulate a git clean -fdx of the library: the primary (and its dir) vanish
    import shutil
    shutil.rmtree(tmp_path / "lib")
    m2 = manifest.Manifest(str(prim), backup=str(bak))
    m2.load()                                        # restores the ledger from the backup
    assert m2.rows["A"]["cavern_status"] == "done" and m2.rows["A"]["cavern_worthy"] == "true"
    # and a subsequent flush re-establishes the primary
    m2.flush()
    assert prim.exists()


def test_no_backup_still_works(tmp_path):
    m = manifest.Manifest(str(tmp_path / "t.csv"))   # backup defaults to None
    m.ensure_rows([Case("A", str(tmp_path), "a.php", None, None)])
    m.flush()
    assert (tmp_path / "t.csv").exists()
