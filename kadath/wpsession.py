"""Minimal stdlib HTTP client with a cookie jar, for triggering the sandbox
over http://127.0.0.1:8088. No third-party deps."""
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar


class WpSession:
    def __init__(self, base_url="http://127.0.0.1:8088"):
        self.base = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.actions = []

    def _req(self, path, data=None):
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

    def login(self, user, pw):
        body = urllib.parse.urlencode(
            {"log": user, "pwd": pw, "wp-submit": "Log In", "testcookie": "1"})
        self._req("/wp-login.php")  # set the test cookie
        code = self._req("/wp-login.php", body)
        self.actions.append(f"LOGIN {user} -> {code}")
        return code

    def get(self, path):
        code = self._req(path)
        self.actions.append(f"GET {path} -> {code}")
        return code

    def post(self, path, body):
        code = self._req(path, body)
        self.actions.append(f"POST {path} -> {code}")
        return code
