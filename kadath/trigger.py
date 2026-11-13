"""Turn a detected sample (or a recipe) into HTTP trigger actions and run them."""
import os
import urllib.parse
from kadath import recipe

_DEFAULT_LOGIN = recipe.Action("login", "admin", "sandbox")


def default_actions(detected, login=None):
    """login is a recipe.Action("login", user, pw); None falls back to the
    stock sandbox admin."""
    if detected.type in ("plugin", "directory-plugin"):
        return [login or _DEFAULT_LOGIN, recipe.Action("get", "/"), recipe.Action("get", "/wp-admin/")]
    if detected.type in ("theme", "directory-theme"):
        return [recipe.Action("get", "/")]
    # webshell / loose php
    basename = os.path.basename(detected.dest)
    return [recipe.Action("get", "/" + urllib.parse.quote(basename, safe="")), recipe.Action("get", "/")]


def execute(session, actions):
    for a in actions:
        if a.kind == "login":
            session.login(a.a, a.b)
        elif a.kind == "get":
            session.get(a.a)
        elif a.kind == "post":
            session.post(a.a, a.b)
    return session.actions
