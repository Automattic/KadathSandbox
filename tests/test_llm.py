import json
import pytest
from kadath import llm


def test_profiles_exact_values():
    assert llm.PROFILES["cavern"] == {"temperature": 0.1, "top_p": 0.8, "top_k": 20, "min_p": 0,
                                      "repeat_penalty": 1.05, "seed": 42, "num_ctx": 16384, "num_predict": 1024}
    assert llm.PROFILES["offer"]["temperature"] == 0.2
    assert llm.PROFILES["offer"]["num_ctx"] == 32768 and llm.PROFILES["offer"]["num_predict"] == 4096
    d = llm.PROFILES["deepscry"]
    assert d["temperature"] == 0.6 and d["top_p"] == 0.95 and "seed" not in d
    assert d["num_ctx"] == 65536 and d["num_predict"] == 8192


def test_parse_overrides_and_build():
    ov = llm.parse_overrides(["deepscry.temperature=0.4", "cavern.num_ctx=8192"])
    assert ov == {"deepscry": {"temperature": 0.4}, "cavern": {"num_ctx": 8192}}
    p = llm.build_profiles(overrides=ov, seed=7)
    assert p["deepscry"]["temperature"] == 0.4 and p["deepscry"]["seed"] == 7
    assert p["cavern"]["num_ctx"] == 8192 and p["cavern"]["seed"] == 7
    assert llm.PROFILES["deepscry"]["temperature"] == 0.6  # untouched
    with pytest.raises(ValueError):
        llm.parse_overrides(["nodot=1"])
    with pytest.raises(ValueError):
        llm.parse_overrides(["nope.temperature=1"])


def test_profiles_file_replaces_table(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps({"cavern": {"temperature": 0.9}}))
    p = llm.build_profiles(profiles_file=str(f))
    assert p == {"cavern": {"temperature": 0.9}}


SCHEMA = {"type": "object", "required": ["verdict", "n"],
          "properties": {"verdict": {"type": "string", "enum": ["red", "green"]},
                         "n": {"type": "number", "minimum": 0, "maximum": 1},
                         "note": {"type": "string", "maxLength": 3},
                         "xs": {"type": "array", "items": {"type": "integer"}}}}


def test_validate_against():
    llm.validate_against(SCHEMA, {"verdict": "red", "n": 0.5, "xs": [1]})
    for bad in ({"verdict": "blue", "n": 0.5}, {"verdict": "red"}, {"verdict": "red", "n": 2},
                {"verdict": "red", "n": 0, "note": "toolong"}, {"verdict": "red", "n": 0, "xs": [1.5]},
                {"verdict": "red", "n": "0"}):
        with pytest.raises(ValueError):
            llm.validate_against(SCHEMA, bad)


def _fake_post(replies):
    calls = []
    def post(url, payload, timeout):
        calls.append((url, payload, timeout))
        r = replies.pop(0)
        return {"message": {"role": "assistant", "content": r.get("content", ""),
                            "tool_calls": r.get("tool_calls", [])}}
    return post, calls


def test_chat_shapes_request_and_parses(monkeypatch):
    post, calls = _fake_post([{"content": '{"verdict": "red", "n": 0.2}'}])
    monkeypatch.setattr(llm, "_post", post)
    c = llm.Client("http://x:1", "m")
    r = c.chat([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
               profile="cavern", json_schema=SCHEMA, think=False,
               validate=lambda o: llm.validate_against(SCHEMA, o))
    url, payload, timeout = calls[0]
    assert url == "http://x:1/api/chat" and timeout == 300
    assert payload["model"] == "m" and payload["stream"] is False and payload["think"] is False
    assert payload["format"] == SCHEMA and payload["options"] == llm.PROFILES["cavern"]
    assert "tools" not in payload
    assert r["parsed"] == {"verdict": "red", "n": 0.2}
    assert r["messages"][-1]["role"] == "assistant"


def test_chat_retries_once_then_raises(monkeypatch):
    post, calls = _fake_post([{"content": '{"verdict": "blue", "n": 0}'},
                              {"content": '{"verdict": "green", "n": 0}'}])
    monkeypatch.setattr(llm, "_post", post)
    c = llm.Client("http://x:1", "m")
    r = c.chat([{"role": "user", "content": "u"}], profile="cavern", json_schema=SCHEMA,
               validate=lambda o: llm.validate_against(SCHEMA, o))
    assert r["parsed"]["verdict"] == "green" and len(calls) == 2
    assert "failed validation" in calls[1][1]["messages"][-1]["content"]

    post, calls = _fake_post([{"content": "not json"}, {"content": "{}"}])
    monkeypatch.setattr(llm, "_post", post)
    with pytest.raises(llm.LLMError):
        c.chat([{"role": "user", "content": "u"}], profile="cavern", json_schema=SCHEMA,
               validate=lambda o: llm.validate_against(SCHEMA, o))


def test_chat_tool_calls_pass_through(monkeypatch):
    tc = [{"function": {"name": "read_sample", "arguments": {"start_line": 1, "end_line": 5}}}]
    post, calls = _fake_post([{"content": "", "tool_calls": tc}])
    monkeypatch.setattr(llm, "_post", post)
    c = llm.Client("http://x:1", "m")
    tools = [{"type": "function", "function": {"name": "read_sample", "parameters": {}}}]
    r = c.chat([{"role": "user", "content": "u"}], profile="deepscry", tools=tools, think=True)
    assert calls[0][1]["tools"] == tools and calls[0][1]["think"] is True
    assert r["tool_calls"] == tc and r["parsed"] is None
    assert r["messages"][-1]["tool_calls"] == tc


def test_preflight(monkeypatch):
    monkeypatch.setattr(llm, "_get", lambda url, timeout: {"models": [{"name": "m"}]})
    post, _ = _fake_post([{"content": "ok"}])
    monkeypatch.setattr(llm, "_post", post)
    llm.Client("http://x:1", "m").preflight()
    monkeypatch.setattr(llm, "_get", lambda url, timeout: {"models": [{"name": "other"}]})
    with pytest.raises(llm.LLMError):
        llm.Client("http://x:1", "m").preflight()
