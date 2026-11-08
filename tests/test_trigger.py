from kadath import trigger, recipe, detect

class FakeSession:
    def __init__(self):
        self.actions = []
        self.calls = []
    def login(self, u, p): self.calls.append(("login", u, p)); self.actions.append(f"LOGIN {u}")
    def get(self, path): self.calls.append(("get", path)); self.actions.append(f"GET {path}")
    def post(self, path, body): self.calls.append(("post", path, body)); self.actions.append(f"POST {path}")

def test_default_actions_webshell():
    d = detect.Detected("webshell", "shell", "samples/webroot/shell.php")
    acts = trigger.default_actions(d)
    assert recipe.Action("get", "/shell.php") in acts
    assert recipe.Action("get", "/") in acts

def test_default_actions_plugin_hits_admin():
    d = detect.Detected("plugin", "p", "samples/plugins/p")
    acts = trigger.default_actions(d)
    paths = [a.a for a in acts if a.kind == "get"]
    assert "/" in paths and "/wp-admin/" in paths

def test_execute_runs_actions_in_order():
    s = FakeSession()
    acts = [recipe.Action("login", "admin", "sandbox"),
            recipe.Action("get", "/a"),
            recipe.Action("post", "/b", "x=1")]
    trigger.execute(s, acts)
    assert s.calls == [("login", "admin", "sandbox"), ("get", "/a"), ("post", "/b", "x=1")]


def test_default_actions_plugin_uses_given_login():
    d = detect.Detected("plugin", "p", "samples/plugins/p")
    mine = recipe.Action("login", "boss", "s3cret")
    acts = trigger.default_actions(d, mine)
    assert acts[0] == mine
    assert [a.a for a in acts[1:]] == ["/", "/wp-admin/"]
    assert trigger.default_actions(d)[0] == recipe.Action("login", "admin", "sandbox")
    # themes and webshells never log in: the login is ignored
    t = detect.Detected("theme", "t", "samples/themes/t")
    assert trigger.default_actions(t, mine) == [recipe.Action("get", "/")]


def test_default_actions_quotes_basename():
    d = detect.Detected("webshell", "x", "samples/webroot/a b?c.php")
    acts = trigger.default_actions(d)
    assert acts[0] == recipe.Action("get", "/a%20b%3Fc.php")
    # and what it builds is a path the session accepts
    from kadath.wpsession import _check_path
    _check_path(acts[0].a)
