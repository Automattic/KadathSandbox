"""mitmproxy addon. Run inside the gateway:
   mitmdump -nq -r /artifacts/mitm/flows.mitm -s /tmp/flowdump.py
with env RUN_EPOCH set. Emits one JSON line per flow in the run window."""
import json
import os


def _wp_core(host):
    h = (host or "").lower()
    return h == "wordpress.org" or h.endswith(".wordpress.org")


class FlowDump:
    def __init__(self):
        self.epoch = float(os.environ.get("RUN_EPOCH", "0"))

    def response(self, flow):
        req = flow.request
        if getattr(req, "timestamp_start", 0) < self.epoch:
            return
        host = req.pretty_host
        print(json.dumps({
            "host": host, "method": req.method, "path": req.path,
            "status": flow.response.status_code if flow.response else None,
            "wp_core": _wp_core(host),
        }), flush=True)


addons = [FlowDump()]
