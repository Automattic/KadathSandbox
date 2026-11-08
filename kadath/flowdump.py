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
            "wp_core": _wp_core(host),
        }), flush=True)

    def response(self, flow):
        self._emit(flow, None)

    def error(self, flow):
        # WHY: response() never fires for a connect/TLS/timeout failure, which
        # would leave the attempt invisible and the verdict green.
        self._emit(flow, str(flow.error) if flow.error else "connection failed")


addons = [FlowDump()]
