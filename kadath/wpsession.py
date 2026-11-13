"""Minimal stdlib HTTP client with a cookie jar, for triggering the sandbox
over http://127.0.0.1:8088. No third-party deps."""
import urllib.request
import urllib.parse
import urllib.error
import http.client
import http.cookiejar


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # the sample picks the Location; this runs on the analyst's host, so never follow
    def redirect_request(self, *a, **kw):
        return None


def _check_path(path):
    # exactly one leading "/": "//h/x", "http://h/", "@h/x" would retarget the host
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ValueError(f"refusing trigger path {path!r}: must start with a single '/'")


class WpSession:
    def __init__(self, base_url="http://127.0.0.1:8088"):
        self.base = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        # empty ProxyHandler: HTTP(S)_PROXY from the analyst's env must not apply
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect,
            urllib.request.HTTPCookieProcessor(self.jar))
        self.actions = []
        # None = no login attempted; True/False = the last login's real outcome
        self.logged_in = None

    def _req(self, path, data=None):
        _check_path(path)
        url = self.base + path
        body = data.encode() if data is not None else None
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if body is not None else {}
        r = urllib.request.Request(url, data=body, headers=headers,
                                    method="POST" if data is not None else "GET")
        try:
            with self.opener.open(r, timeout=60) as resp:
                return resp.getcode()
        except urllib.error.HTTPError as e:
            return e.code
        except (urllib.error.URLError, http.client.HTTPException, OSError):
            # the worker died or hung past its limit: that is a result, not a crash
            return "connection-failed"

    def login(self, user, pw):
        body = urllib.parse.urlencode(
            {"log": user, "pwd": pw, "wp-submit": "Log In", "testcookie": "1"})
        self._req("/wp-login.php")  # set the test cookie
        # only a cookie the login POST itself sets (new name or new value) counts: the sample could have
        # planted one on any earlier response
        before = {(c.domain, c.path, c.name, c.value) for c in self.jar}
        code = self._req("/wp-login.php", body)
        # WordPress sets wordpress_logged_in_* only on success (a 302 now, never
        # followed, so the code alone cannot tell success from failure)
        self.logged_in = any(c.name.startswith("wordpress_logged_in_")
                             and (c.domain, c.path, c.name, c.value) not in before for c in self.jar)
        self.actions.append(f"LOGIN {user} -> {code} {'ok' if self.logged_in else 'FAILED'}")
        return code

    def get(self, path):
        code = self._req(path)
        self.actions.append(f"GET {path} -> {code}")
        return code

    def post(self, path, body):
        code = self._req(path, body)
        self.actions.append(f"POST {path} -> {code}")
        return code
