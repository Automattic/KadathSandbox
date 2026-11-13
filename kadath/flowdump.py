"""mitmproxy addon. Run inside the gateway:
   mitmdump -nq -r /artifacts/mitm/flows.mitm -s /tmp/flowdump.py
with env RUN_EPOCH set. Emits one JSON line per flow in the run window,
including flows that never got a response (error hook): a dead C2, a pinned-
cert TLS failure or a timeout is still an outbound attempt."""
import json
import os


def _wp_core(host):
    h = (host or "").lower()
    return h == "wordpress.org" or h.endswith(".wordpress.org")


def _dst(flow):
    """The IP the connection really went to: the upstream peer, else the
    address the proxy was asked to reach. None when neither is known."""
    sc = getattr(flow, "server_conn", None)
    for attr in ("peername", "address"):
        v = getattr(sc, attr, None)
        if isinstance(v, (tuple, list)) and v:
            return str(v[0])
    return None


def _sni(flow):
    return getattr(getattr(flow, "client_conn", None), "sni", None) or None


class FlowDump:
    def __init__(self):
        self.epoch = float(os.environ.get("RUN_EPOCH", "0"))

    def _emit(self, flow, error):
        req = flow.request
        if req is None or getattr(req, "timestamp_start", 0) < self.epoch:
            return
        host = req.pretty_host
        print(json.dumps({
            "host": host, "method": req.method, "path": req.path,
            "status": flow.response.status_code if flow.response else None,
            "error": error,
            # the Host header is the sample's word: dst/sni let the host side
            # verify it (network.verify_wp_core); wp_core here is only the claim
            "wp_core": _wp_core(host), "dst": _dst(flow), "sni": _sni(flow),
        }), flush=True)

    def response(self, flow):
        self._emit(flow, None)

    def error(self, flow):
        # WHY: response() never fires for a connect/TLS/timeout failure, which
        # would leave the attempt invisible and the verdict green.
        self._emit(flow, str(flow.error) if flow.error else "connection failed")


addons = [FlowDump()]
