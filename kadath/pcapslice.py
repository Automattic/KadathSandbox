"""Cut a classic libpcap capture down to the packets of one run. The sandbox
capture slice is held open by tcpdump -U and holds up to 100 MB of every run
that shared the slice; a bundle only needs the packets since the run epoch."""
import shutil
import struct

# magic as the first four bytes on disk -> (record header struct, nanosecond?)
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),   # 0xa1b2c3d4 written little-endian
    b"\xa1\xb2\xc3\xd4": (">", False),   # 0xa1b2c3d4 written big-endian
    b"\x4d\x3c\xb2\xa1": ("<", True),    # 0xa1b23c4d, nanosecond timestamps
    b"\xa1\xb2\x3c\x4d": (">", True),
}
_GLOBAL_LEN = 24
_RECORD_LEN = 16
# a record longer than this is a corrupt header, not a packet: stop rather than
# trust it with a read (libpcap's own snaplen ceiling is 262144)
_MAX_RECORD = 64 * 1024 * 1024


def slice_pcap(src_path, dst_path, epoch):
    """Write the global header plus every record of src_path with ts_sec >= epoch
    to dst_path. A truncated trailing record (tcpdump is mid-write) ends the
    slice cleanly. An unrecognised format is copied whole. Returns None when
    fine, else a warning string."""
    with open(src_path, "rb") as fi:
        head = fi.read(_GLOBAL_LEN)
        if len(head) < _GLOBAL_LEN:
            # tcpdump has not flushed a header yet: nothing to slice
            with open(dst_path, "wb") as fo:
                fo.write(head)
            return None
        fmt = _MAGICS.get(head[:4])
        if fmt is None:
            with open(dst_path, "wb") as fo:
                fo.write(head)
                shutil.copyfileobj(fi, fo)
            return f"{src_path}: unrecognised pcap magic {head[:4].hex()}; copied the whole file"
        rec = struct.Struct(fmt[0] + "IIII")
        warning = None
        with open(dst_path, "wb") as fo:
            fo.write(head)
            while True:
                rh = fi.read(_RECORD_LEN)
                if len(rh) < _RECORD_LEN:
                    break
                ts_sec, _frac, incl_len, _orig = rec.unpack(rh)
                if incl_len > _MAX_RECORD:
                    warning = f"{src_path}: corrupt record length {incl_len}; slice ends there"
                    break
                data = fi.read(incl_len)
                if len(data) < incl_len:
                    break
                if ts_sec >= epoch:
                    fo.write(rh)
                    fo.write(data)
        return warning
