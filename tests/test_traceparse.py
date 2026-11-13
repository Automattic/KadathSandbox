from kadath import traceparse

FX = ["tests/fixtures/probe.xt"]

def test_callchain_only_sample_callers_deduped_ordered():
    ch = traceparse.callchain(FX)
    funcs = [c["function"] for c in ch]
    assert funcs == ["{main}", "header", "eval", "system", "file_get_contents",
                     "fsockopen", "file_put_contents", "gethostbyname"]
    assert ch[3] == {"function": "system", "file": "/samples/webroot/probe.php", "line": 8}

def test_files_written():
    fw = traceparse.files_written(FX)
    assert fw == [{"op": "file_put_contents", "path": "/tmp/x",
                   "caller": "/samples/webroot/probe.php:16"}]

def test_dangerous_calls_counts_and_firstarg():
    dc = {d["function"]: d for d in traceparse.dangerous_calls_from_trace(FX)}
    assert dc["system"]["count"] == 1
    assert dc["system"]["first_arg"] == "'id'"
    assert dc["eval"]["first_arg"] == "'return 1+1;'"
    assert "gethostbyname" not in dc


import os
from kadath import traceparse as tp


def _xt(path, calls):
    """A minimal trace: one entry record per (function, arg) called from the sample."""
    with open(path, "w") as f:
        for fn, arg in calls:
            cols = ["1", "1", "0", "0.1", "100", fn, "1", "", "/samples/webroot/x.php", "3", "1", f"'{arg}'"]
            f.write("\t".join(cols) + "\n")


def test_files_written_dedupes_by_op_and_path(tmp_path):
    t = tmp_path / "a.xt"
    _xt(t, [("file_put_contents", "/tmp/a")] * 3 + [("unlink", "/tmp/a"), ("file_put_contents", "/tmp/b")])
    fw = tp.files_written([str(t)])
    assert [(e["op"], e["path"]) for e in fw] == [
        ("file_put_contents", "/tmp/a"), ("unlink", "/tmp/a"), ("file_put_contents", "/tmp/b")]


def test_files_written_caps_with_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(tp, "FILES_WRITTEN_CAP", 3)
    t = tmp_path / "a.xt"
    _xt(t, [("file_put_contents", f"/tmp/{i}") for i in range(5)] + [("file_put_contents", "/tmp/4")])
    fw = tp.files_written([str(t)])
    assert len(fw) == 4 and fw[-1] == {"op": "truncated", "path": "...and 2 more", "caller": ""}


def test_entries_ignore_symlink_and_fifo(tmp_path):
    real = tmp_path / "real.xt"
    _xt(real, [("file_put_contents", "/tmp/a")])
    link = tmp_path / "link.xt"
    link.symlink_to(real)
    fifo = tmp_path / "fifo.xt"
    os.mkfifo(fifo)
    dangling = tmp_path / "dangling.xt"
    dangling.symlink_to(tmp_path / "nope")
    assert tp.files_written([str(link), str(fifo), str(dangling)]) == []     # and no hang
    assert len(tp.files_written([str(real)])) == 1
    assert tp.regular_file(str(real)) and not tp.regular_file(str(link))
    assert not tp.regular_file(str(fifo)) and not tp.regular_file(str(dangling))
    assert not tp.regular_file(str(real) + "\0x")
    import pytest
    with pytest.raises(OSError):
        tp.open_regular(str(link))
    with pytest.raises(OSError):
        tp.open_regular(str(fifo))
