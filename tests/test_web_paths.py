import json, os
from kadath import web_util

def _summary_with_repo(tmp_path):
    repo = tmp_path
    (repo / "artifacts" / "xdebug").mkdir(parents=True)
    trace = repo / "artifacts" / "xdebug" / "trace.1.xt"
    trace.write_text("TRACE")
    report = repo / "reports" / "x-1"
    report.mkdir(parents=True)
    (report / "summary.json").write_text("{}")
    summary = {"artifacts": {"traces": [str(trace)], "sp_dumps": [], "pcaps": []}}
    return str(repo), summary, str(report)

def test_allowlist_and_safe_path(tmp_path):
    repo, summary, report = _summary_with_repo(tmp_path)
    allow = web_util.artifact_allowlist(summary, report)
    p = web_util.safe_artifact_path(repo, allow, "trace.1.xt")
    assert p and os.path.isfile(p)
    assert web_util.safe_artifact_path(repo, allow, "summary.json")  # report file allowed

def test_reject_non_allowlisted(tmp_path):
    repo, summary, report = _summary_with_repo(tmp_path)
    allow = web_util.artifact_allowlist(summary, report)
    (tmp_path / "secret.txt").write_text("s")
    assert web_util.safe_artifact_path(repo, allow, "secret.txt") is None

def test_reject_traversal(tmp_path):
    repo, summary, report = _summary_with_repo(tmp_path)
    allow = web_util.artifact_allowlist(summary, report)
    assert web_util.safe_artifact_path(repo, allow, "../secret.txt") is None
    assert web_util.safe_artifact_path(repo, allow, "/etc/passwd") is None

def test_same_basename_prefers_in_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "artifacts").mkdir(parents=True)
    good = repo / "artifacts" / "dup.txt"
    good.write_text("in-repo")
    outside = tmp_path / "outside"
    outside.mkdir()
    bad = outside / "dup.txt"
    bad.write_text("escape")
    # both share basename dup.txt; only the in-repo one is valid
    allow = {os.path.realpath(str(good)), os.path.realpath(str(bad))}
    got = web_util.safe_artifact_path(str(repo), allow, "dup.txt")
    assert got == os.path.realpath(str(good))
