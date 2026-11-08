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


def test_bundle_skips_planted_symlink_fifo_and_dir_link(tmp_path):
    src = tmp_path / "artifacts" / "php"; src.mkdir(parents=True)
    outside = tmp_path / "host-secret.log"; outside.write_text("HOST SECRET")
    epoch = int(time.time()) - 5
    (src / "ok.log").write_text("fine")
    (src / "leak.log").symlink_to(outside)
    (src / "dangling.xt").symlink_to(tmp_path / "nope")
    os.mkfifo(src / "pipe.log")
    (src / "dirlink").symlink_to(tmp_path)
    dest = tmp_path / "out"
    written, warnings = run._bundle_artifacts(str(tmp_path / "artifacts"), str(dest), epoch)
    assert written == ["php/ok.log.gz"]
    assert sorted(warnings) == sorted(f"skipped non-regular artifact php/{n}"
                                      for n in ("leak.log", "dangling.xt", "pipe.log", "dirlink"))
    assert not (dest / "php" / "leak.log").exists() and not (dest / "php" / "leak.log.gz").exists()
    assert not (dest / "php" / "dirlink").exists()


def test_bundle_one_failing_file_does_not_stop_the_rest(tmp_path, monkeypatch):
    src = tmp_path / "artifacts" / "php"; src.mkdir(parents=True)
    epoch = int(time.time()) - 5
    (src / "a.log").write_text("a")
    (src / "b.log").write_text("b")
    real = run._open_artifact

    def flaky(path):
        if path.endswith("a.log"):
            raise OSError("permission denied")
        return real(path)
    monkeypatch.setattr(run, "_open_artifact", flaky)
    written, warnings = run._bundle_artifacts(str(tmp_path / "artifacts"), str(tmp_path / "out"), epoch)
    assert written == ["php/b.log.gz"]
    assert warnings == ["bundle: php/a.log: permission denied"]


def test_open_artifact_refuses_a_link_swapped_in_after_the_check(tmp_path):
    import pytest
    real = tmp_path / "real"; real.write_text("x")
    link = tmp_path / "link"; link.symlink_to(real)
    with pytest.raises(OSError):
        run._open_artifact(str(link))
    with run._open_artifact(str(real)) as f:
        assert f.read() == b"x"


def test_new_files_regular_only_and_never_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "ROOT", str(tmp_path))
    d = tmp_path / "artifacts" / "xdebug"; d.mkdir(parents=True)
    epoch = int(time.time()) - 5
    (d / "new.xt").write_text("t")
    old = d / "old.xt"; old.write_text("t"); os.utime(old, (1000, 1000))
    (d / "dangling.xt").symlink_to(tmp_path / "nope")
    (d / "leak.xt").symlink_to(tmp_path / "artifacts" / "xdebug" / "new.xt")
    os.mkfifo(d / "pipe.xt")
    warnings = []
    got = run._new_files(str(d / "*.xt"), epoch, warnings)
    assert got == [str(d / "new.xt")]
    assert sorted(warnings) == sorted(f"skipped non-regular artifact xdebug/{n}"
                                      for n in ("dangling.xt", "leak.xt", "pipe.xt"))
    assert run._new_files(str(d / "*.xt"), epoch) == [str(d / "new.xt")]      # warnings optional
    # same skip in the bundle yields the same strings, so the engine's merge dedupes them
    _, bw = run._bundle_artifacts(str(tmp_path / "artifacts"), str(tmp_path / "out"), epoch)
    assert set(warnings) <= set(bw)
