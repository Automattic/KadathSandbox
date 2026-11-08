import struct
from kadath import pcapslice

EPOCH = 1000


def _pcap(endian, magic, packets, trunc=0):
    """packets: [(ts_sec, payload)]; trunc chops that many bytes off the end."""
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    for ts, data in packets:
        out += struct.pack(endian + "IIII", ts, 7, len(data), len(data)) + data
    return out[:len(out) - trunc] if trunc else out


def _slice(tmp_path, raw):
    src, dst = tmp_path / "in.pcap", tmp_path / "out.pcap"
    src.write_bytes(raw)
    w = pcapslice.slice_pcap(str(src), str(dst), EPOCH)
    return w, dst.read_bytes()


PKTS = [(999, b"old1"), (1000, b"edge"), (1001, b"new1")]


def test_little_endian_micro_straddling_epoch(tmp_path):
    w, out = _slice(tmp_path, _pcap("<", 0xa1b2c3d4, PKTS))
    assert w is None
    assert out == _pcap("<", 0xa1b2c3d4, PKTS[1:])


def test_big_endian_micro(tmp_path):
    w, out = _slice(tmp_path, _pcap(">", 0xa1b2c3d4, PKTS))
    assert w is None
    assert out == _pcap(">", 0xa1b2c3d4, PKTS[1:])


def test_nanosecond_both_endiannesses(tmp_path):
    for endian in ("<", ">"):
        w, out = _slice(tmp_path, _pcap(endian, 0xa1b23c4d, PKTS))
        assert w is None
        assert out == _pcap(endian, 0xa1b23c4d, PKTS[1:])


def test_all_packets_old_leaves_header_only(tmp_path):
    w, out = _slice(tmp_path, _pcap("<", 0xa1b2c3d4, [(1, b"a"), (2, b"b")]))
    assert w is None and len(out) == 24


def test_truncated_tail_is_tolerated(tmp_path):
    # mid-payload and mid-record-header truncation both stop cleanly
    for trunc in (2, 4 + 16):
        w, out = _slice(tmp_path, _pcap("<", 0xa1b2c3d4, PKTS, trunc=trunc))
        assert w is None
        assert out == _pcap("<", 0xa1b2c3d4, PKTS[1:2])


def test_unknown_magic_copies_whole_file_with_warning(tmp_path):
    raw = b"\x0a\x0d\x0d\x0a" + b"x" * 60       # pcapng section header
    w, out = _slice(tmp_path, raw)
    assert out == raw
    assert w and "magic" in w


def test_short_file_is_copied_verbatim(tmp_path):
    w, out = _slice(tmp_path, b"\xd4\xc3\xb2\xa1raw")
    assert w is None and out == b"\xd4\xc3\xb2\xa1raw"


def test_corrupt_record_length_stops_with_warning(tmp_path):
    raw = _pcap("<", 0xa1b2c3d4, [(1001, b"ok")])
    raw += struct.pack("<IIII", 1002, 0, 0x7fffffff, 0) + b"zz"
    w, out = _slice(tmp_path, raw)
    assert w and "corrupt" in w
    assert out == _pcap("<", 0xa1b2c3d4, [(1001, b"ok")])
