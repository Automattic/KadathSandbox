from kadath import traceparse

FX = ["tests/fixtures/probe.xt"]

def test_callchain_only_sample_callers_deduped_ordered():
    ch = traceparse.callchain(FX)
    funcs = [c["function"] for c in ch]
    assert funcs == ["{main}", "header", "eval", "system", "file_get_contents",
                     "fsockopen", "file_put_contents", "gethostbyname"]
    assert ch[3] == {"function": "system", "file": "/samples/webroot/probe.php", "line": 8}

def test_files_written():
    fw = traceparse.files_written(FX)
    assert fw == [{"op": "file_put_contents", "path": "/tmp/x",
                   "caller": "/samples/webroot/probe.php:16"}]

def test_dangerous_calls_counts_and_firstarg():
    dc = {d["function"]: d for d in traceparse.dangerous_calls_from_trace(FX)}
    assert dc["system"]["count"] == 1
    assert dc["system"]["first_arg"] == "'id'"
    assert dc["eval"]["first_arg"] == "'return 1+1;'"
    assert "gethostbyname" not in dc
