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
    written = run._bundle_artifacts(str(tmp_path / "artifacts"), str(dest), epoch)
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
