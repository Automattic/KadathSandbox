"""mitmproxy addon. Run inside the gateway like flowdump.py, with RUN_EPOCH set:
   mitmdump -nq -r /artifacts/mitm/flows.mitm -s /tmp/flowbody.py
Emits one JSON line per non-core flow in the run window with request and
response bodies truncated to 4 KB each (decoded as text, replacement on error).
Flows that errored before a response (error hook) are emitted too, with
status None, an "error" string and an empty response body."""
import json
import os

CAP = 4096


def _wp_core(host):
    h = (host or "").lower()
    return h == "wordpress.org" or h.endswith(".wordpress.org")


def _dst(flow):
    sc = getattr(flow, "server_conn", None)
    for attr in ("peername", "address"):
        v = getattr(sc, attr, None)
        if isinstance(v, (tuple, list)) and v:
            return str(v[0])
    return None


def _sni(flow):
    return getattr(getattr(flow, "client_conn", None), "sni", None) or None


def _text(body):
    if not body:
        return ""
    return body[:CAP].decode("utf-8", errors="replace")


class FlowBody:
    def __init__(self):
        self.epoch = float(os.environ.get("RUN_EPOCH", "0"))

    def _emit(self, flow, error):
        req = flow.request
        if req is None or getattr(req, "timestamp_start", 0) < self.epoch:
            return
        sni = _sni(flow)
        # every flow is emitted, core-looking ones included: the Host header is the
        # sample's to choose, so whether a flow is really WordPress core is decided
        # by the consumer against the verified flow list (dst vs the DNS log)
        print(json.dumps({
            "host": req.pretty_host, "dst": _dst(flow), "sni": sni, "method": req.method, "path": req.path,
            "status": flow.response.status_code if flow.response else None,
            "error": error,
            "request_body": _text(getattr(req, "raw_content", None)),
            "response_body": _text(flow.response.raw_content if flow.response else b""),
        }), flush=True)

    def response(self, flow):
        self._emit(flow, None)

    def error(self, flow):
        # WHY: the request body of a failed C2 beacon is still evidence.
        self._emit(flow, str(flow.error) if flow.error else "connection failed")


addons = [FlowBody()]
