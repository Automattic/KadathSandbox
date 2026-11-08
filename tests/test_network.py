from kadath import network

def test_dns_from_log_full():
    q = network.dns_from_log("tests/fixtures/dns.log")
    assert "api.wordpress.org" in q and "evil-c2.example" in q and "old-run.example" in q

def test_dns_from_log_offset_skips_old():
    # byte offset past the first line -> old-run.example excluded
    with open("tests/fixtures/dns.log", "rb") as f:
        first = f.readline()
    q = network.dns_from_log("tests/fixtures/dns.log", offset=len(first))
    assert "old-run.example" not in q
    assert "evil-c2.example" in q

def test_dropped_from_log_offset():
    with open("tests/fixtures/dropped.log", "rb") as f:
        first = f.readline()
    d = network.dropped_from_log("tests/fixtures/dropped.log", offset=len(first))
    assert d == [{"dst": "1.1.1.1", "port": 6667}]

def test_flag_wp_core():
    assert network.flag_wp_core("api.wordpress.org") is True
    assert network.flag_wp_core("evil-c2.example") is False

def test_parse_flowdump():
    text = '{"host":"example.com","method":"GET","path":"/","status":200,"wp_core":false}\n'
    assert network.parse_flowdump(text)[0]["host"] == "example.com"

def test_parse_flowdump_passes_error_field():
    text = ('{"host":"dead.example","method":"GET","path":"/","status":null,'
            '"error":"Connection refused","wp_core":false}\n'
            '{"host":"ok.example","method":"GET","path":"/","status":200,'
            '"error":null,"wp_core":false}\n')
    flows = network.parse_flowdump(text)
    assert flows[0]["status"] is None and flows[0]["error"] == "Connection refused"
    assert flows[1]["error"] is None


# --- mitmproxy addons, driven with fake flows (they import only json/os) ---
import importlib.util
import json
import os
from types import SimpleNamespace


def _load_addon(name, epoch="100"):
    os.environ["RUN_EPOCH"] = epoch
    spec = importlib.util.spec_from_file_location(name, os.path.join("kadath", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.addons[0]


def _flow(host="dead.example", ts=200, response=None, error=None, body=b"beacon=1", request=True):
    req = SimpleNamespace(timestamp_start=ts, pretty_host=host, method="POST",
                          path="/gate.php", raw_content=body)
    return SimpleNamespace(request=req if request else None, response=response, error=error)


def _lines(capsys):
    return [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.strip()]


def test_flowdump_error_hook_emits_attempt(capsys):
    a = _load_addon("flowdump")
    a.error(_flow(error=None))
    out = _lines(capsys)
    assert out == [{"host": "dead.example", "method": "POST", "path": "/gate.php",
                    "status": None, "error": "connection failed", "wp_core": False}]


def test_flowdump_error_string_from_flow_error(capsys):
    class Err:
        def __str__(self):
            return "TLS handshake failed"
    a = _load_addon("flowdump")
    a.error(_flow(error=Err()))
    assert _lines(capsys)[0]["error"] == "TLS handshake failed"


def test_flowdump_response_has_error_none(capsys):
    a = _load_addon("flowdump")
    a.response(_flow(host="evil.example", response=SimpleNamespace(status_code=200, raw_content=b"ok")))
    out = _lines(capsys)
    assert out[0]["status"] == 200 and out[0]["error"] is None


def test_flowdump_error_respects_epoch_and_none_request(capsys):
    a = _load_addon("flowdump")
    a.error(_flow(ts=50, error=SimpleNamespace(msg="x")))
    a.error(_flow(request=False, error=SimpleNamespace(msg="x")))
    assert _lines(capsys) == []


def test_flowdump_error_marks_wp_core(capsys):
    a = _load_addon("flowdump")
    a.error(_flow(host="api.wordpress.org"))
    assert _lines(capsys)[0]["wp_core"] is True


def test_flowbody_error_hook_emits_request_body(capsys):
    a = _load_addon("flowbody")
    a.error(_flow(body=b"beacon=1"))
    assert _lines(capsys) == [{"host": "dead.example", "method": "POST", "path": "/gate.php",
                               "status": None, "error": "connection failed",
                               "request_body": "beacon=1", "response_body": ""}]


def test_flowbody_error_skips_wp_core_old_and_no_request(capsys):
    a = _load_addon("flowbody")
    a.error(_flow(host="api.wordpress.org"))
    a.error(_flow(ts=50))
    a.error(_flow(request=False))
    assert _lines(capsys) == []


def test_flowbody_response_has_error_none(capsys):
    a = _load_addon("flowbody")
    a.response(_flow(host="evil.example", response=SimpleNamespace(status_code=200, raw_content=b"pong")))
    out = _lines(capsys)[0]
    assert out["error"] is None and out["response_body"] == "pong"
