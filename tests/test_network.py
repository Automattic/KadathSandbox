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
