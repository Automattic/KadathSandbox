"""mitmproxy addon. Run inside the gateway like flowdump.py, with RUN_EPOCH set:
   mitmdump -nq -r /artifacts/mitm/flows.mitm -s /tmp/flowbody.py
Emits one JSON line per non-core flow in the run window with request and
response bodies truncated to 4 KB each (decoded as text, replacement on error)."""
import json
import os

CAP = 4096


def _wp_core(host):
    h = (host or "").lower()
    return h == "wordpress.org" or h.endswith(".wordpress.org")


def _text(body):
    if not body:
        return ""
    return body[:CAP].decode("utf-8", errors="replace")


class FlowBody:
    def __init__(self):
        self.epoch = float(os.environ.get("RUN_EPOCH", "0"))

    def response(self, flow):
        req = flow.request
        if getattr(req, "timestamp_start", 0) < self.epoch or _wp_core(req.pretty_host):
            return
        print(json.dumps({
            "host": req.pretty_host, "method": req.method, "path": req.path,
            "status": flow.response.status_code if flow.response else None,
            "request_body": _text(req.raw_content),
            "response_body": _text(flow.response.raw_content if flow.response else b""),
        }), flush=True)


addons = [FlowBody()]
