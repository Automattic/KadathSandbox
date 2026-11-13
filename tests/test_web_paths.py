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
    allow = [os.path.realpath(str(bad)), os.path.realpath(str(good))]
    got = web_util.safe_artifact_path(str(repo), allow, "dup.txt")
    assert got == os.path.realpath(str(good))


def test_bundle_entry_is_served_by_basename(tmp_path):
    repo, summary, report = _summary_with_repo(tmp_path)
    gz = os.path.join(report, "artifacts", "xdebug", "trace.1.xt.gz")
    os.makedirs(os.path.dirname(gz))
    with open(gz, "wb") as f:
        f.write(b"gz")
    summary["artifacts"]["bundle"] = ["artifacts/xdebug/trace.1.xt.gz"]
    allow = web_util.artifact_allowlist(summary, report)
    assert web_util.safe_artifact_path(repo, allow, "trace.1.xt.gz") == os.path.realpath(gz)


def test_bundle_entry_escaping_repo_is_refused(tmp_path):
    repo = tmp_path / "repo"
    report = repo / "reports" / "x-1"
    report.mkdir(parents=True)
    (tmp_path / "secret.txt").write_text("s")      # outside the repo, exists
    summary = {"artifacts": {"traces": [], "sp_dumps": [], "pcaps": [],
                             "bundle": ["../../../secret.txt"]}}
    allow = web_util.artifact_allowlist(summary, str(report))
    assert os.path.realpath(str(tmp_path / "secret.txt")) in allow
    assert web_util.safe_artifact_path(str(repo), allow, "secret.txt") is None


def test_allowlist_is_ordered_report_then_bundle_then_live(tmp_path):
    report = tmp_path / "reports" / "x-1"
    report.mkdir(parents=True)
    summary = {"artifacts": {"traces": ["/live/t.xt"], "sp_dumps": ["/live/sp.json"],
                             "pcaps": ["/live/c.pcap"], "bundle": ["artifacts/b.gz", "../x-1/summary.json"]}}
    allow = web_util.artifact_allowlist(summary, str(report))
    rp = os.path.realpath
    assert allow == [rp(str(report / n)) for n in ("summary.json", "iocs.json", "run.env")] + [
        rp(str(report / "artifacts/b.gz")), rp("/live/t.xt"), rp("/live/sp.json"), rp("/live/c.pcap")]
    assert isinstance(allow, list) and len(allow) == len(set(allow))   # de-duplicated

def test_report_file_beats_same_basename_bundle_file(tmp_path):
    repo = tmp_path
    report = repo / "reports" / "x-1"
    (report / "artifacts").mkdir(parents=True)
    (report / "summary.json").write_text("report")
    (report / "artifacts" / "summary.json").write_text("bundled")
    summary = {"artifacts": {"bundle": ["artifacts/summary.json"], "traces": [], "sp_dumps": [], "pcaps": []}}
    allow = web_util.artifact_allowlist(summary, str(report))
    assert web_util.safe_artifact_path(str(repo), allow, "summary.json") == os.path.realpath(str(report / "summary.json"))

def test_bundle_beats_same_basename_live_file(tmp_path):
    repo = tmp_path
    report = repo / "reports" / "x-1"
    (report / "artifacts").mkdir(parents=True)
    (repo / "live").mkdir()
    (repo / "live" / "t.xt").write_text("live")
    (report / "artifacts" / "t.xt").write_text("bundled")
    summary = {"artifacts": {"bundle": ["artifacts/t.xt"], "traces": [str(repo / "live" / "t.xt")],
                             "sp_dumps": [], "pcaps": []}}
    allow = web_util.artifact_allowlist(summary, str(report))
    assert web_util.safe_artifact_path(str(repo), allow, "t.xt") == os.path.realpath(str(report / "artifacts" / "t.xt"))
