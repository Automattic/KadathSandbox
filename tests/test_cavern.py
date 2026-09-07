import json
import os
import pytest
from kadath import cavern, library, llm

PROMPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kadath", "prompts")


def _good(**kw):
    o = {"verdict": "red", "confidence": 0.9, "family": "webshell", "host_code": "none",
         "regions": [{"start_line": 1, "end_line": 2, "why": "eval"}], "runnable": True,
         "needs_input": "post-body", "worthy": False, "reason": "eval of POST"}
    o.update(kw)
    return o


def test_validate_schema_and_regions():
    cavern.validate(_good(), line_count=5)
    with pytest.raises(ValueError):
        cavern.validate(_good(verdict="blue"), 5)
    with pytest.raises(ValueError):
        cavern.validate(_good(regions=[{"start_line": 3, "end_line": 9, "why": "x"}]), 5)
    with pytest.raises(ValueError):
        cavern.validate(_good(regions=[{"start_line": 4, "end_line": 2, "why": "x"}]), 5)
    with pytest.raises(ValueError):
        cavern.validate(_good(reason="x" * 301), 5)
    with pytest.raises(ValueError):
        cavern.validate(_good(family="ransomware"), 5)
    # Empty file tests
    with pytest.raises(ValueError):
        cavern.validate(_good(), line_count=0)
    cavern.validate(_good(regions=[]), line_count=0)


def test_override_worthy_rules():
    plain = {"wp_api": [], "network": [], "has_blob": False}
    assert cavern.override_worthy(_good(), plain) == []
    assert cavern.override_worthy(_good(confidence=0.69), plain) == ["confidence<0.7"]
    assert cavern.override_worthy(_good(verdict="amber", confidence=0.9), plain) == ["verdict=amber"]
    r = cavern.override_worthy(_good(), {"wp_api": ["wp_create_user"], "network": ["curl_init"], "has_blob": True})
    assert r == ["wp_api", "network", "blob"]
    assert cavern.override_worthy(_good(worthy=True), plain) == []
    # Fragment suppresses model-based forces but allows fact-based
    assert cavern.override_worthy(_good(family="fragment", verdict="amber", confidence=0.5), plain) == []
    assert cavern.override_worthy(_good(family="fragment", verdict="amber", confidence=0.5),
                                   {"wp_api": ["wp_create_user"], "network": [], "has_blob": False}) == ["wp_api"]
    # runnable=False suppresses model-based forces but allows fact-based
    assert cavern.override_worthy(_good(runnable=False, family="webshell", verdict="amber", confidence=0.5), plain) == []
    assert cavern.override_worthy(_good(runnable=False, family="webshell", verdict="amber", confidence=0.5),
                                   {"wp_api": [], "network": ["curl_init"], "has_blob": False}) == ["network"]


def test_build_messages_fences_evidence():
    facts = {"sha256": "a" * 64, "size": 10, "lines": 2, "entropy": 4.1, "dangerous": {"eval": 1},
             "wp_api": [], "network": [], "longest_literal": 3, "has_blob": False}
    msgs = cavern.build_messages("SYS", "FIO-1", "Bulk import", facts, "1| <?php\n2| eval($_POST['x']);", False)
    assert msgs[0] == {"role": "system", "content": "SYS"}
    u = msgs[1]["content"]
    assert u.startswith(cavern.UNTRUSTED_PREAMBLE)
    # Check all three fences exist
    assert "```text" in u and "```json" in u and "```php" in u
    # Check case id and provenance appear in text fence
    text_start = u.find("```text\n")
    text_end = u.find("\n```", text_start + 8)
    text_section = u[text_start + 8:text_end]
    assert "FIO-1" in text_section and "Bulk import" in text_section
    # Check facts appear in json fence
    assert '"eval": 1' in u
    # Check source appears in php fence
    assert "eval($_POST['x'])" in u
    assert "TRUNCATED" not in u
    assert "TRUNCATED" in cavern.build_messages("SYS", "x", "", facts, "1| a", True)[1]["content"]


class FakeClient:
    model = "fake"
    profiles = dict(llm.PROFILES)
    def __init__(self, parsed):
        self.parsed = parsed
        self.calls = []
    def chat(self, messages, **kw):
        self.calls.append((messages, kw))
        kw["validate"](self.parsed)
        return {"content": json.dumps(self.parsed), "tool_calls": [], "parsed": self.parsed,
                "messages": messages}


def test_run_writes_cavern_json(tmp_path):
    d = tmp_path / "FIO-9"
    d.mkdir()
    (d / "s.php").write_text("<?php\n$u = wp_create_user('a','b');\n")
    (d / "README.md").write_text("# FIO-9\nBulk import from X\n")
    case = library.walk(str(tmp_path))[0]
    client = FakeClient(_good(worthy=False))
    out = cavern.run(case, client, PROMPTS)
    assert out["worthy"] is True and out["worthy_forced"] == ["wp_api"]
    assert out["static_facts"]["wp_api"] == ["wp_create_user"]
    assert out["provenance"] == "Bulk import from X"
    assert out["model"] == "fake" and out["sampling"] == llm.PROFILES["cavern"]
    assert len(out["prompt_sha256"]) == 64 and out["at"].endswith("Z")
    saved = json.loads((d / "kadath" / "cavern.json").read_text())
    assert saved == out
    msgs, kw = client.calls[0]
    assert kw["profile"] == "cavern" and kw["think"] is False and kw["json_schema"] == cavern.SCHEMA
    assert msgs[0]["content"].startswith("# The Cavern of Flame")


def test_run_rejects_region_out_of_range(tmp_path):
    d = tmp_path / "FIO-9"
    d.mkdir()
    (d / "s.php").write_text("<?php\n")
    case = library.walk(str(tmp_path))[0]
    with pytest.raises(ValueError):
        cavern.run(case, FakeClient(_good(regions=[{"start_line": 1, "end_line": 50, "why": "x"}])), PROMPTS)
