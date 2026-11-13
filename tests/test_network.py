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
    assert d == [{"dst": "1.1.1.1", "port": 6667, "proto": "tcp"}]

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
                    "status": None, "error": "connection failed", "wp_core": False,
                    "dst": None, "sni": None}]


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
                               "dst": None, "sni": None,
                               "request_body": "beacon=1", "response_body": ""}]


def test_flowbody_error_skips_old_and_no_request_but_emits_core_looking(capsys):
    # a core-looking Host header is the sample's to choose: flowbody emits it and the
    # consumer (pilgrim_offer.drop_core_bodies) filters against the verified flow list
    a = _load_addon("flowbody")
    a.error(_flow(host="api.wordpress.org"))
    a.error(_flow(ts=50))
    a.error(_flow(request=False))
    out = _lines(capsys)
    assert len(out) == 1 and out[0]["host"] == "api.wordpress.org"


def test_flowbody_response_has_error_none(capsys):
    a = _load_addon("flowbody")
    a.response(_flow(host="evil.example", response=SimpleNamespace(status_code=200, raw_content=b"pong")))
    out = _lines(capsys)[0]
    assert out["error"] is None and out["response_body"] == "pong"


# --- dst/sni, verified wp_core ---

def _flow_with_conn(host, peer=None, address=None, sni=None):
    f = _flow(host=host)
    f.server_conn = SimpleNamespace(peername=peer, address=address)
    f.client_conn = SimpleNamespace(sni=sni)
    return f


def test_flowdump_emits_dst_and_sni(capsys):
    a = _load_addon("flowdump")
    a.error(_flow_with_conn("api.wordpress.org", peer=("6.6.6.6", 443), address=("api.wordpress.org", 443),
                            sni="api.wordpress.org"))
    a.error(_flow_with_conn("x.example", address=("5.5.5.5", 80)))
    out = _lines(capsys)
    assert out[0]["dst"] == "6.6.6.6" and out[0]["sni"] == "api.wordpress.org" and out[0]["host"] == "api.wordpress.org"
    assert out[1]["dst"] == "5.5.5.5" and out[1]["sni"] is None


def test_flowbody_emits_every_flow_with_dst_and_sni(capsys):
    a = _load_addon("flowbody")
    a.error(_flow_with_conn("api.wordpress.org", peer=("6.6.6.6", 443), sni="evil.example"))
    a.error(_flow_with_conn("api.wordpress.org", peer=("66.6.42.251", 443), sni="api.wordpress.org"))
    out = _lines(capsys)
    assert len(out) == 2
    assert out[0]["dst"] == "6.6.6.6" and out[0]["sni"] == "evil.example"
    assert out[1]["dst"] == "66.6.42.251" and out[1]["sni"] == "api.wordpress.org"


def test_dns_map_from_log_fixture_and_offset():
    m = network.dns_map_from_log("tests/fixtures/dns.log")
    assert m == {"api.wordpress.org": {"66.6.42.251"}}
    with open("tests/fixtures/dns.log", "rb") as f:
        n = len(f.readline()) + len(f.readline()) + len(f.readline())
    assert network.dns_map_from_log("tests/fixtures/dns.log", offset=n) == {}


def test_dns_map_follows_cname_and_cached(tmp_path):
    log = tmp_path / "dns.log"
    log.write_text(
        "Sep  4 17:15:19 dnsmasq[41]: 6 172.30.0.10/1 query[A] www.example.com from 172.30.0.10\n"
        "Sep  4 17:15:19 dnsmasq[41]: 6 172.30.0.10/1 reply www.example.com is <CNAME>\n"
        "Sep  4 17:15:19 dnsmasq[41]: 6 172.30.0.10/1 reply edge.cdn.example. is 1.2.3.4\n"
        "Sep  4 17:15:20 dnsmasq[41]: 7 172.30.0.10/2 query[A] API.WordPress.org from 172.30.0.10\n"
        "Sep  4 17:15:20 dnsmasq[41]: 7 172.30.0.10/2 cached API.WordPress.org is 9.9.9.9\n"
        "Sep  4 17:15:21 dnsmasq[41]: 8 172.30.0.10/3 reply a.example is b.example\n"
        "Sep  4 17:15:21 dnsmasq[41]: 9 172.30.0.10/3 reply b.example is 7.7.7.7\n")
    m = network.dns_map_from_log(str(log))
    assert m["www.example.com"] == {"1.2.3.4"} and m["edge.cdn.example"] == {"1.2.3.4"}
    assert m["api.wordpress.org"] == {"9.9.9.9"}
    assert m["a.example"] == {"7.7.7.7"}


def test_dns_map_cname_loop_terminates(tmp_path):
    log = tmp_path / "dns.log"
    log.write_text("dnsmasq[1]: 1 c/1 reply a.example is b.example\n"
                   "dnsmasq[1]: 2 c/1 reply b.example is a.example\n")
    assert network.dns_map_from_log(str(log)) == {"a.example": set(), "b.example": set()}


def _core_flow(dst, sni=None):
    return {"host": "api.wordpress.org", "method": "GET", "path": "/", "status": 200,
            "wp_core": True, "dst": dst, "sni": sni}


def test_verify_wp_core_spoofed_host_header():
    flows = network.verify_wp_core([_core_flow("6.6.6.6")], {"api.wordpress.org": {"66.6.42.251"}})
    assert flows[0]["wp_core"] is False and flows[0]["host_spoofed"] is True


def test_verify_wp_core_resolved_ip_is_core():
    dm = {"api.wordpress.org": {"66.6.42.251"}}
    f = network.verify_wp_core([_core_flow("66.6.42.251", "api.wordpress.org")], dm)[0]
    assert f["wp_core"] is True and f["host_spoofed"] is False
    # same IP but a foreign SNI, no dst at all, no DNS answer: none is core
    for flow in (_core_flow("66.6.42.251", "evil.example"), _core_flow(None), _core_flow("66.6.42.251")):
        flow = network.verify_wp_core([flow], dm if flow["dst"] else dm)[0]
        assert flow["host_spoofed"] is (flow["sni"] == "evil.example" or flow["dst"] is None)
    assert network.verify_wp_core([_core_flow("66.6.42.251")], {})[0]["host_spoofed"] is True


def test_verify_wp_core_leaves_other_hosts_alone():
    f = network.verify_wp_core([{"host": "evil.example", "wp_core": True, "dst": "1.1.1.1"}], {})[0]
    assert f["wp_core"] is False and f["host_spoofed"] is False


# --- parse_flowdump tolerance ---

def test_parse_flowdump_skips_malformed_lines():
    text = ('{"host":"a.example","method":"GET","path":"/","status":200}\n'
            '{"host":"trunc\n'
            'mitmdump: some noise\n'
            '[1,2]\n'
            '{"host":"b.example","method":"GET","path":"/","status":200}\n')
    flows = network.parse_flowdump(text)
    assert [f["host"] for f in flows] == ["a.example", "b.example"]
    flows, bad = network.parse_flowdump_checked(text)
    assert len(flows) == 2 and bad == 1


# --- dropped.log: tcp, udp, icmp, mgmt ---

def test_dropped_from_log_all_protocols(tmp_path):
    log = tmp_path / "dropped.log"
    log.write_text(
        "2026-09-04 17:15:00.1 IP 172.30.0.10.52412 > 1.1.1.1.6667: Flags [S], seq 1, win 64240, length 0\n"
        "2026-09-04 17:15:00.2 IP 172.30.0.10.52412 > 1.1.1.1.6667: Flags [S], seq 2, win 64240, length 0\n"
        "2026-09-04 17:15:00.3 IP 172.30.0.10.52412 > 1.1.1.1.6667: Flags [S.], seq 3, ack 1, win 1, length 0\n"
        "2026-09-04 17:15:01.0 IP 172.30.0.10.5353 > 8.8.4.4.123: UDP, length 48\n"
        "2026-09-04 17:15:02.0 IP 172.30.0.10 > 9.9.9.9: ICMP echo request, id 1, seq 1, length 64\n"
        "2026-09-04 17:15:03.0 IP 172.30.0.10 > 9.9.9.8: GREv0, length 40\n"
        "mgmt 2026-09-04 17:15:04.0 IP 172.31.0.10.40000 > 172.31.0.1.22: Flags [S], seq 1, length 0\n"
        "garbage\n")
    assert network.dropped_from_log(str(log)) == [
        {"dst": "1.1.1.1", "port": 6667, "proto": "tcp"},
        {"dst": "8.8.4.4", "port": 123, "proto": "udp"},
        {"dst": "9.9.9.9", "port": 0, "proto": "icmp"},
        {"dst": "9.9.9.8", "port": 0, "proto": "other"},
        {"dst": "172.31.0.1", "port": 22, "proto": "tcp", "iface": "mgmt"},
    ]
