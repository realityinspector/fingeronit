import base64
import contextlib
import hashlib
import http.client
import importlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
import unittest
import urllib.parse
from email.header import Header
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib", "providers"))
import gmail  # noqa: E402

API = "http://fake.invalid/gmail/v1/users/me"
TOKEN = "http://fake.invalid/token"
AUTH = "http://fake.invalid/auth"


def b64(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return base64.urlsafe_b64encode(s).decode().rstrip("=")


def hdrs(**kw):
    return [{"name": k.replace("_", "-"), "value": v} for k, v in kw.items()]


SUBJECT = Header("Café menu", "utf-8").encode()

MSG1 = {
    "id": "m1", "threadId": "t1", "internalDate": "1700000000000",
    "payload": {
        "mimeType": "multipart/mixed",
        "headers": hdrs(From="Alice Example <alice@example.com>",
                        To="bob@example.com, Carol <carol@example.com>",
                        Cc="dave@example.com",
                        Subject=SUBJECT, Date="Tue, 14 Nov 2023 22:13:20 +0000"),
        "parts": [
            {"mimeType": "multipart/alternative", "filename": "", "body": {},
             "parts": [
                 {"mimeType": "text/plain", "filename": "",
                  "body": {"data": b64("Hello plain body")}},
                 {"mimeType": "text/html", "filename": "",
                  "body": {"data": b64("<p>Hello <b>html</b></p>")}},
             ]},
            {"mimeType": "application/pdf", "filename": "../.evil\x01 name.pdf",
             "body": {"attachmentId": "ATT1", "size": 5}},
            {"mimeType": "image/png", "filename": "",
             "body": {"attachmentId": "INLINE", "size": 9}},
        ]}}

MSG2 = {
    "id": "m2", "threadId": "t1", "internalDate": "1700003600000",
    "payload": {
        "mimeType": "text/html",
        "headers": hdrs(From="=?UTF-8?B?w4lsw6hnYW50?= <bob@example.com>",
                        To="alice@example.com", Subject="Re: " + SUBJECT,
                        Date="Tue, 14 Nov 2023 23:13:20 +0000"),
        "body": {"data": b64(
            "<html><head><title>T</title><style>p{color:red}</style></head>"
            "<body><script>alert(1)</script><p>Second&nbsp;message &amp; more"
            "</p><ul><li>one</li><li>two</li></ul></body></html>")}}}

THREADS = {"t1": {"id": "t1", "messages": [MSG1, MSG2]},
           "t2": {"id": "t2", "messages": [dict(MSG2, id="m3")]},
           "t3": {"id": "t3", "messages": [dict(MSG2, id="m4")]}}

DRAFT_MSG = {
    "id": "dm1", "internalDate": "1700007200000",
    "payload": {"mimeType": "text/plain",
                "headers": hdrs(From="me@example.com",
                                To="a@example.com, B Person <b@example.com>",
                                Cc="c@example.com", Bcc="d@example.com",
                                Subject="Draft subject"),
                "body": {"data": b64("Draft body text")}}}


class FakeGmail(object):
    def __init__(self):
        self.calls = []
        self.token_calls = []
        self.valid_token = "good-token"
        self.email = "me@example.com"
        self.code_checks = None  # callable for auth-code exchange

    def __call__(self, method, url, headers=None, data=None):
        self.calls.append((method, url, dict(headers or {})))
        if url == TOKEN:
            form = dict(urllib.parse.parse_qsl(data.decode()))
            self.token_calls.append(form)
            if form["grant_type"] == "refresh_token":
                return 200, json.dumps({"access_token": "good-token",
                                        "expires_in": 3600}).encode()
            if self.code_checks:
                err = self.code_checks(form)
                if err:
                    return 400, json.dumps({"error": err}).encode()
            return 200, json.dumps({"access_token": "good-token",
                                    "refresh_token": "refresh-1",
                                    "expires_in": 3600}).encode()
        assert url.startswith(API), url
        if (headers or {}).get("Authorization") != "Bearer " + self.valid_token:
            return 401, b'{"error":{"message":"bad token"}}'
        u = urllib.parse.urlparse(url[len(API):])
        q = urllib.parse.parse_qs(u.query)
        path = u.path
        if path == "/profile":
            return self.ok({"emailAddress": self.email})
        if path == "/threads":
            if q.get("pageToken") == ["p2"]:
                return self.ok({"threads": [{"id": "t3"}]})
            return self.ok({"threads": [{"id": "t1"}, {"id": "t2"}],
                            "nextPageToken": "p2"})
        m = re.match(r"^/threads/(\w+)$", path)
        if m:
            return self.ok(THREADS[m.group(1)])
        if path == "/messages/m1":
            return self.ok(MSG1)
        if path == "/messages/m1/attachments/ATT1":
            return self.ok({"data": b64(b"PDF!\x00"), "size": 5})
        if path == "/drafts":
            return self.ok({"drafts": [{"id": "d1",
                                        "message": {"id": "dm1"}}]})
        if path == "/drafts/d1":
            return self.ok({"id": "d1", "message": DRAFT_MSG})
        return 404, b'{"error":{"message":"not found"}}'

    @staticmethod
    def ok(obj):
        return 200, json.dumps(obj).encode()

    def api_urls(self):
        return [c[1] for c in self.calls if c[1].startswith(API)]


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = gmail.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.xdg = os.path.join(self.tmp, "xdg")
        env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.xdg})
        env.start()
        self.addCleanup(env.stop)
        self.fake = FakeGmail()
        for name, val in (("_http", self.fake), ("API_BASE", API),
                          ("TOKEN_URL", TOKEN), ("AUTH_URL", AUTH),
                          ("_sleep", lambda s: None)):
            p = mock.patch.object(gmail, name, val)
            p.start()
            self.addCleanup(p.stop)
        self.write_client()

    def write_client(self):
        os.makedirs(gmail.config_dir(), exist_ok=True)
        with open(gmail.client_path(), "w") as fh:
            json.dump({"installed": {"client_id": "cid.example.com",
                                     "client_secret": "csecret"}}, fh)

    def login(self, access="good-token", expiry=None):
        gmail.save_creds({"refresh_token": "refresh-1",
                          "access_token": access,
                          "expiry": expiry if expiry is not None
                          else 4102444800,
                          "email_address": "me@example.com"})

    def ok(self, argv):
        code, out, err = run(argv)
        self.assertEqual(code, 0, err)
        return out


class QueryTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(gmail.build_query(None), "-in:drafts")
        self.assertEqual(
            gmail.build_query("invoice", "a@example.com", "b@example.com"),
            "from:a@example.com to:b@example.com invoice -in:drafts")

    def test_quoting(self):
        q = gmail.build_query('say "hi" in:anywhere', from_="Al Ex")
        self.assertIn('from:"Al Ex"', q)
        self.assertIn('"say \\"hi\\" in:anywhere"', q)
        self.assertNotIn(" in:anywhere ", q)

    def test_dates(self):
        self.assertIn("newer_than:7d", gmail.build_query(date="last_7_days"))
        self.assertIn("newer_than:30d", gmail.build_query(date="last_30_days"))
        self.assertIn("newer_than:90d", gmail.build_query(date="last_90_days"))
        self.assertIn("after:2023/01/01 before:2024/01/01",
                      gmail.build_query(date="2023"))
        with self.assertRaises(gmail.CliError) as c:
            gmail.build_query(date="yesterday")
        self.assertEqual(c.exception.code, 2)


class SearchTests(Base):
    def test_shape_and_q(self):
        self.login()
        out = json.loads(self.ok(["search", "hello world", "--from",
                                  "alice@example.com", "--date", "2023",
                                  "--json"]))
        self.assertTrue(out["ok"])
        self.assertEqual([t["topic_id"] for t in out["data"]], ["t1", "t2"])
        t = out["data"][0]
        self.assertEqual(t["subject"], "Café menu")
        self.assertEqual(t["updated_at"], "2023-11-14T23:13:20Z")
        self.assertEqual(t["messages"][0]["created_at"], "2023-11-14T22:13:20Z")
        self.assertEqual(t["messages"][0]["creator"],
                         {"id": "alice@example.com",
                          "email_address": "alice@example.com",
                          "name": "Alice Example"})
        self.assertEqual(t["messages"][1]["creator"]["name"], "Élègant")
        qs = [urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
              for u in self.fake.api_urls() if "/threads?" in u]
        q = qs[0]["q"][0]
        self.assertIn("from:alice@example.com", q)
        self.assertIn('"hello world"', q)
        self.assertIn("after:2023/01/01 before:2024/01/01", q)
        self.assertIn("-in:drafts", q)

    def test_paging(self):
        self.login()
        one = json.loads(self.ok(["search", "--json"]))["data"]
        self.assertEqual(len(one), 2)
        allp = json.loads(self.ok(["search", "--all", "--json"]))["data"]
        self.assertEqual([t["topic_id"] for t in allp], ["t1", "t2", "t3"])
        p2 = json.loads(self.ok(["search", "--page", "2", "--json"]))["data"]
        self.assertEqual([t["topic_id"] for t in p2], ["t3"])

    def test_global_json_anywhere(self):
        self.login()
        self.ok(["--json", "search"])
        self.ok(["auth", "--json", "status"])

    def test_not_logged_in_exit_3(self):
        code, out, err = run(["search", "--json"])
        self.assertEqual(code, 3)
        self.assertFalse(json.loads(err)["ok"])
        self.assertEqual(out, "")


class ReadTests(Base):
    def test_thread_read(self):
        self.login()
        out = self.ok(["thread", "read", "t1", "--markdown"])
        self.assertIn("### Café menu", out)
        self.assertIn("From: Alice Example <alice@example.com>", out)
        self.assertIn("Cc: dave@example.com", out)
        self.assertIn("Date: Tue, 14 Nov 2023 22:13:20 +0000", out)
        self.assertIn("Hello plain body", out)
        self.assertNotIn("<p>", out)
        self.assertIn("Attachments:\n- ../.evil\x01 name.pdf", out)
        # message 2: html only, RFC2047 From, scripts/styles dropped
        self.assertIn("### Re: Café menu", out)
        self.assertIn("From: Élègant <bob@example.com>", out)
        self.assertIn("Second message & more", out)
        self.assertIn("- one", out)
        self.assertNotIn("alert(1)", out)
        self.assertNotIn("color:red", out)

    def test_attachment_list(self):
        self.login()
        d = json.loads(self.ok(["attachment", "list", "t1", "--json"]))
        self.assertEqual(d["data"], [{"id": "m1.ATT1",
                                      "filename": "../.evil\x01 name.pdf",
                                      "size": 5}])


class AttachmentSaveTests(Base):
    def test_save_sanitize_refuse_force(self):
        self.login()
        outdir = os.path.join(self.tmp, "out")
        d = json.loads(self.ok(["attachment", "save", "m1.ATT1",
                                "--output", outdir]))
        path = os.path.join(outdir, "evil name.pdf")
        self.assertEqual(d["data"]["path"], os.path.realpath(path)
                         if os.path.realpath(path) == d["data"]["path"]
                         else path)
        self.assertEqual(os.listdir(outdir), ["evil name.pdf"])
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), b"PDF!\x00")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        # refuse
        code, out, err = run(["attachment", "save", "m1.ATT1",
                              "--output", outdir])
        self.assertEqual(code, 1)
        e = json.loads(err)
        self.assertFalse(e["ok"])
        self.assertIn("destination already exists: ", e["error"])
        self.assertIn("(use --force to replace it)", e["error"])
        # force
        with open(path, "wb") as fh:
            fh.write(b"old")
        self.ok(["attachment", "save", "m1.ATT1", "--output", outdir,
                 "--force"])
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), b"PDF!\x00")
        self.assertEqual(os.listdir(outdir), ["evil name.pdf"])

    def test_sanitize_function(self):
        s = gmail.sanitize_filename
        self.assertEqual(s("../../etc/passwd"), "etcpasswd")
        self.assertEqual(s("..\\x\\y.txt"), "xy.txt")
        self.assertEqual(s(".hidden"), "hidden")
        self.assertEqual(s("a\x00b\nc.txt"), "abc.txt")
        self.assertEqual(s("..."), "attachment")
        self.assertEqual(s(""), "attachment")


class DraftTests(Base):
    def test_list_and_show(self):
        self.login()
        d = json.loads(self.ok(["draft", "list", "--json"]))["data"]
        self.assertEqual(d, [{
            "id": "d1", "subject": "Draft subject",
            "updated_at": "2023-11-15T00:13:20Z",
            "addressed_contacts": [
                {"email_address": "a@example.com", "name": ""},
                {"email_address": "b@example.com", "name": "B Person"},
                {"email_address": "c@example.com", "name": ""},
                {"email_address": "d@example.com", "name": ""}]}])
        s = json.loads(self.ok(["draft", "show", "d1", "--json"]))["data"]
        self.assertEqual(s["id"], "d1")
        self.assertEqual(s["from"], "me@example.com")
        self.assertEqual(s["to"], ["a@example.com", "b@example.com"])
        self.assertEqual(s["cc"], ["c@example.com"])
        self.assertEqual(s["bcc"], ["d@example.com"])
        self.assertEqual(s["body"], "Draft body text")


class TokenTests(Base):
    def test_refresh_when_expired_writes_back(self):
        self.login(access="old", expiry=1)
        self.ok(["search", "--json"])
        with open(gmail.creds_path()) as fh:
            c = json.load(fh)
        self.assertEqual(c["access_token"], "good-token")
        self.assertGreater(c["expiry"], 1000000000 + 3000)
        self.assertEqual(c["refresh_token"], "refresh-1")
        self.assertEqual(stat.S_IMODE(os.stat(gmail.creds_path()).st_mode),
                         0o600)
        self.assertEqual(stat.S_IMODE(os.stat(gmail.config_dir()).st_mode),
                         0o700)
        self.assertEqual(len(self.fake.token_calls), 1)

    def test_refresh_on_401(self):
        self.login(access="stale", expiry=4102444800)
        self.ok(["search", "--json"])
        self.assertEqual(len(self.fake.token_calls), 1)
        with open(gmail.creds_path()) as fh:
            self.assertEqual(json.load(fh)["access_token"], "good-token")

    def test_retry_5xx(self):
        self.login()
        state = {"n": 0}
        real = self.fake

        def flaky(method, url, headers=None, data=None):
            if "/profile" in url and state["n"] < 2:
                state["n"] += 1
                return 503, b"{}"
            return real(method, url, headers, data)
        with mock.patch.object(gmail, "_http", flaky):
            self.assertEqual(gmail.api_get("/profile")["emailAddress"],
                             "me@example.com")
        self.assertEqual(state["n"], 2)

    def test_status_never_prints_tokens(self):
        gmail.save_creds({"refresh_token": "SECRET-REFRESH",
                          "access_token": "SECRET-ACCESS", "expiry": 1,
                          "email_address": "me@example.com"})
        code, out, err = run(["auth", "status", "--json"])
        self.assertEqual(code, 0)
        self.assertNotIn("SECRET", out + err)
        self.assertEqual(json.loads(out), {"ok": True, "data": {
            "logged_in": True, "email_address": "me@example.com"}})
        self.assertEqual(self.fake.calls, [])

    def test_status_logged_out(self):
        out = self.ok(["auth", "status", "--json"])
        self.assertEqual(json.loads(out)["data"]["logged_in"], False)


class LoginTests(Base):
    def setUp(self):
        Base.setUp(self)
        self.threads = []

    def join(self):
        for t in self.threads:
            t.join(10)

    def callback(self, url_holder, mutate=None, holder_out=None):
        def fire(url):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            url_holder.update({k: v[0] for k, v in q.items()})
            state = q["state"][0]
            if mutate:
                state = mutate(state)
            redirect = urllib.parse.urlparse(q["redirect_uri"][0])

            def go():
                c = http.client.HTTPConnection(redirect.hostname,
                                               redirect.port, timeout=10)
                c.request("GET", "/?" + urllib.parse.urlencode(
                    {"code": "authcode", "state": state}))
                r = c.getresponse()
                if holder_out is not None:
                    holder_out.append((r.status, r.read().decode()))
                c.close()
            t = threading.Thread(target=go)
            t.start()
            self.threads.append(t)
        return fire

    def test_login_pkce_and_state(self):
        seen, page = {}, []

        def check(form):
            digest = hashlib.sha256(form["code_verifier"].encode()).digest()
            want = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            if want != seen["code_challenge"]:
                return "bad_pkce"
            if form["redirect_uri"] != seen["redirect_uri"]:
                return "bad_redirect"
            if form["code"] != "authcode":
                return "bad_code"
        self.fake.code_checks = check
        src = os.path.join(self.tmp, "dl.json")
        with open(src, "w") as fh:
            json.dump({"installed": {"client_id": "new.example.com",
                                     "client_secret": "s2"}}, fh)
        os.unlink(gmail.client_path())
        with mock.patch.object(gmail, "_open_browser",
                               self.callback(seen, holder_out=page)):
            code, out, err = run(["auth", "login", "--client", src])
        self.join()
        self.assertEqual(code, 0, err)
        self.assertEqual(seen["code_challenge_method"], "S256")
        self.assertEqual(seen["scope"],
                         "https://www.googleapis.com/auth/gmail.readonly")
        self.assertEqual(seen["client_id"], "new.example.com")
        self.assertEqual(seen["response_type"], "code")
        self.assertTrue(seen["redirect_uri"].startswith("http://127.0.0.1:"))
        self.assertIn(AUTH + "?", out)
        self.assertEqual(page[0][0], 200)
        self.assertIn("You can close this tab", page[0][1])
        self.assertEqual(json.loads(out.splitlines()[-1]),
                         {"ok": True, "data": {"logged_in": True,
                                               "email_address": "me@example.com"}})
        with open(gmail.creds_path()) as fh:
            c = json.load(fh)
        self.assertEqual(c["refresh_token"], "refresh-1")
        self.assertEqual(c["email_address"], "me@example.com")
        self.assertEqual(stat.S_IMODE(os.stat(gmail.creds_path()).st_mode),
                         0o600)
        self.assertEqual(stat.S_IMODE(os.stat(gmail.client_path()).st_mode),
                         0o600)
        with open(gmail.client_path()) as fh:
            self.assertEqual(json.load(fh)["installed"]["client_id"],
                             "new.example.com")
        self.assertNotIn("refresh-1", out + err)
        self.assertNotIn("good-token", out + err)

    def test_state_mismatch_rejected(self):
        seen, page = {}, []
        with mock.patch.object(gmail, "_open_browser",
                               self.callback(seen, lambda s: s + "x", page)):
            code, out, err = run(["auth", "login"])
        self.join()
        self.assertEqual(code, 1)
        self.assertIn("state", json.loads(err)["error"])
        self.assertEqual(page[0][0], 400)
        self.assertEqual(self.fake.token_calls, [])
        self.assertFalse(os.path.exists(gmail.creds_path()))

    def test_no_browser_env_skips_open(self):
        opened = []
        with mock.patch.dict(os.environ, {"FINGERONIT_NO_BROWSER": "1"}), \
                mock.patch.object(gmail, "_open_browser", opened.append), \
                mock.patch.object(gmail, "LOGIN_TIMEOUT", 0.2):
            code, out, err = run(["auth", "login"])
        self.assertEqual(code, 1)
        self.assertEqual(opened, [])
        self.assertIn("timed out", err)


class EndpointTests(unittest.TestCase):
    def test_env_cannot_change_endpoints(self):
        evil = "https://evil.invalid"
        names = ["GMAIL_API_BASE", "API_BASE", "TOKEN_URL", "AUTH_URL",
                 "GOOGLE_TOKEN_URL", "FINGERONIT_GMAIL_API",
                 "FINGERONIT_GMAIL_TOKEN_URL", "FINGERONIT_GMAIL_AUTH_URL"]
        with mock.patch.dict(os.environ, {n: evil for n in names}):
            m = importlib.reload(gmail)
            try:
                self.assertEqual(m.AUTH_URL,
                                 "https://accounts.google.com/o/oauth2/v2/auth")
                self.assertEqual(m.TOKEN_URL,
                                 "https://oauth2.googleapis.com/token")
                self.assertEqual(
                    m.API_BASE,
                    "https://gmail.googleapis.com/gmail/v1/users/me")
                self.assertEqual(
                    m.SCOPE, "https://www.googleapis.com/auth/gmail.readonly")
            finally:
                importlib.reload(gmail)

    def test_source_reads_only_expected_env(self):
        with open(os.path.join(ROOT, "lib", "providers", "gmail.py")) as fh:
            src = fh.read()
        used = set(re.findall(r'environ(?:\.get)?[\[(]\s*"([A-Z_]+)"', src))
        self.assertEqual(used, {"XDG_CONFIG_HOME", "FINGERONIT_NO_BROWSER"})


class CliTests(unittest.TestCase):
    def test_version(self):
        code, out, _ = run(["version"])
        self.assertEqual((code, out), (0, "fingeronit-gmail 0.1.0\n"))

    def test_unknown_command(self):
        self.assertEqual(run(["bogus"])[0], 2)
        self.assertEqual(run([])[0], 2)

    def test_help_lists_flags(self):
        code, out, _ = run(["search", "--help"])
        self.assertEqual(code, 0)
        for f in ("--from", "--to", "--date", "--all", "--json", "--page"):
            self.assertIn(f, out)
        for argv, flags in ((["attachment", "save", "--help"],
                             ["--output", "--force"]),
                            (["draft", "list", "--help"], ["--all"]),
                            (["auth", "login", "--help"], ["--client"]),
                            (["thread", "read", "--help"], ["--markdown"])):
            out = run(argv)[1]
            for f in flags:
                self.assertIn(f, out)

    def test_bad_date_exit_2(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": d}):
            self.assertEqual(run(["search", "--date", "soon"])[0], 2)


if __name__ == "__main__":
    unittest.main()
