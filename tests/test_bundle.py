import gzip, os, time
from kadath import run

def test_bundle_scopes_by_epoch_and_gzips(tmp_path):
    src = tmp_path / "artifacts" / "xdebug"; src.mkdir(parents=True)
    (tmp_path / "artifacts" / "dns").mkdir()
    # an OLD trace (before the run) and this run's files
    old = src / "old.xt"; old.write_text("OLD" * 1000)
    os.utime(old, (1000, 1000))            # mtime way before epoch
    epoch = int(time.time())
    new = src / "new.xt"; new.write_text("NEW" * 100000)   # a big trace
    log = tmp_path / "artifacts" / "dns" / "dns.log"; log.write_text("query x")
    keep = tmp_path / "artifacts" / "xdebug" / ".gitkeep"; keep.write_text("")
    dest = tmp_path / "report" / "artifacts"
    written, warnings = run._bundle_artifacts(str(tmp_path / "artifacts"), str(dest), epoch)
    assert warnings == []
    # old trace excluded; new trace gzipped; log gzipped; gitkeep skipped
    assert "xdebug/new.xt.gz" in written
    assert not (dest / "xdebug" / "old.xt.gz").exists()
    assert (dest / "xdebug" / "new.xt.gz").exists()
    assert (dest / "dns" / "dns.log.gz").exists()
    assert not (dest / "xdebug" / ".gitkeep").exists()
    # the gzip round-trips to the original bytes
    with gzip.open(dest / "xdebug" / "new.xt.gz", "rb") as f:
        assert f.read() == (b"NEW" * 100000)

def test_bundle_copies_binary_verbatim(tmp_path):
    src = tmp_path / "artifacts" / "pcap"; src.mkdir(parents=True)
    epoch = int(time.time())
    pcap = src / "sandbox.pcap00"; pcap.write_bytes(b"\xd4\xc3\xb2\xa1raw")
    dest = tmp_path / "out"
    run._bundle_artifacts(str(tmp_path / "artifacts"), str(dest), epoch)
    assert (dest / "pcap" / "sandbox.pcap00").read_bytes() == b"\xd4\xc3\xb2\xa1raw"


def test_bundle_run_returns_written_and_warnings(tmp_path, monkeypatch):
    from kadath.shell import ShellError
    (tmp_path / "artifacts" / "xdebug").mkdir(parents=True)
    epoch = int(time.time())
    (tmp_path / "artifacts" / "xdebug" / "t.xt").write_text("T")
    monkeypatch.setattr(run, "ROOT", str(tmp_path))

    def boom(argv, **kw):
        raise ShellError(argv, 1, "no docker")
    monkeypatch.setattr(run, "sh", boom)
    run_dir = tmp_path / "reports" / "r"
    run_dir.mkdir(parents=True)
    res = run._bundle_run(str(run_dir), epoch)
    assert isinstance(res, tuple) and len(res) == 2
    written, warnings = res
    assert written == ["xdebug/t.xt.gz"] and warnings == []
    assert (run_dir / "artifacts" / "xdebug" / "t.xt.gz").exists()
    assert not (run_dir / "compose-logs.txt").exists()

    def no_copy(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(run, "_bundle_artifacts", no_copy)
    assert run._bundle_run(str(run_dir), epoch) == ([], [])
