#!/usr/bin/env python3
"""A stand-in for Ollama. Answers /api/tags and /api/chat with canned replies
chosen by the system prompt's first line and by MARK_ tokens in the evidence.
Usage: fake_ollama.py <port>"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MODEL = "fake-model"


def _mark(text):
    for m in ("MARK_RED_ONE", "MARK_RED_WORTHY", "MARK_AMBER", "MARK_GREEN"):
        if m in text:
            return m
    # The Offering pass's evidence pack carries no source text (and so no MARK_
    # token) but does carry the family the Cavern assigned; those families are
    # unique per fixture case, so fall back to them to keep the offer verdict
    # case-aware past the Cavern stage.
    for family, m in (("webshell", "MARK_RED_ONE"), ("backdoor", "MARK_RED_WORTHY"),
                      ("unknown", "MARK_AMBER"), ("benign", "MARK_GREEN")):
        if f'"family": "{family}"' in text:
            return m
    return ""


def cavern(mark):
    base = {"confidence": 0.95, "host_code": "none", "regions": [{"start_line": 1, "end_line": 1, "why": "x"}],
            "runnable": True, "needs_input": "none", "missing_deps": [], "reason": "fixture"}
    return dict(base, **{
        "MARK_RED_ONE": {"verdict": "red", "family": "webshell", "worthy": False},
        "MARK_RED_WORTHY": {"verdict": "red", "family": "backdoor", "worthy": True},
        "MARK_AMBER": {"verdict": "amber", "family": "unknown", "worthy": False, "confidence": 0.5},
        "MARK_GREEN": {"verdict": "green", "family": "benign", "worthy": False},
    }.get(mark, {"verdict": "amber", "family": "unknown", "worthy": True}))


def runes(mark):
    fam = {"MARK_RED_WORTHY": "backdoor", "MARK_AMBER": "unknown"}.get(mark, "injector")
    verdict = "amber" if mark == "MARK_AMBER" else "red"
    return {"verdict": verdict, "confidence": 0.9, "family": fam, "iocs_extra": [],
            "persistence": [], "flows": [], "reason": "fixture runes"}


def offer_verdict(mark):
    v = "green" if mark == "MARK_AMBER" else "red"   # deterministic is red -> AMBER-1 disagrees -> routed to scry
    return {"verdict": v, "confidence": 0.9, "coverage": "full", "iocs_extra": [], "persistence": [], "reason": "fixture"}


REPORT = "# Triage Report\nfixture\n=====DRAFT.YAR=====\nrule kadath_fixture { strings: $a = \"zz_maint\" condition: $a }\n"
scry_state = {}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send({"models": [{"name": MODEL}]})

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        msgs = req["messages"]
        system = msgs[0]["content"] if msgs and msgs[0]["role"] == "system" else ""
        alltext = "\n".join(m.get("content", "") for m in msgs)
        mark = _mark(alltext)
        if system.startswith("# The Cavern of Flame"):
            content = json.dumps(cavern(mark))
        elif system.startswith("# The Runes"):
            content = json.dumps(runes(mark))
        elif system.startswith("# The Offering — verdict"):
            content = json.dumps(offer_verdict(mark))
        elif system.startswith("# The Offering — report"):
            content = REPORT
        elif system.startswith("# The Deep Scrying"):
            if req.get("format"):
                content = json.dumps({"verdict": "red", "confidence": 0.9, "coverage": "full", "iocs_extra": [],
                                      "persistence": ["user"], "reason": "fixture deep",
                                      "evidence": [{"claim": "admin", "source": "wp_read", "quote": "sys_maint"}]})
            elif not any(m["role"] == "tool" for m in msgs):
                self._send({"message": {"role": "assistant", "content": "",
                                        "tool_calls": [{"function": {"name": "wp_read", "arguments": {"subcommand": "user list"}}}]}})
                return
            else:
                content = "Done investigating."
        else:
            content = "ok"
        self._send({"message": {"role": "assistant", "content": content}})


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
