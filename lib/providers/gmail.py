#!/usr/bin/env python3
"""fingeronit-gmail: a standalone, read-only Gmail command-line client.

Standard library only. Uses the gmail.readonly scope exclusively; it never
sends, modifies or deletes anything. Only credentials.json is written to disk.

Endpoints are module constants on purpose: no environment variable or flag
can redirect them.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "0.1.0"

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

HTTP_TIMEOUT = 30
LOGIN_TIMEOUT = 300
MAX_RETRIES = 3
MAX_PAGES = 100
CONFIG_SUBDIR = "fingeronit-gmail"

_sleep = time.sleep


class CliError(Exception):
    def __init__(self, message, code=1):
        Exception.__init__(self, message)
        self.message = message
        self.code = code


# ---------------------------------------------------------------- storage

def config_dir():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, CONFIG_SUBDIR)


def client_path():
    return os.path.join(config_dir(), "client.json")


def creds_path():
    return os.path.join(config_dir(), "credentials.json")


def _write_private(path, data):
    """Atomically write bytes to path with mode 600 (dir 700)."""
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_client():
    try:
        with open(client_path(), "r") as fh:
            data = json.load(fh)
        inst = data["installed"]
        return {"client_id": inst["client_id"],
                "client_secret": inst.get("client_secret", "")}
    except (OSError, ValueError, KeyError, TypeError):
        raise CliError("OAuth client not found or invalid at %s "
                       "(run: auth login --client FILE)" % client_path(), 1)


def load_creds():
    try:
        with open(creds_path(), "r") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or not data.get("refresh_token"):
            raise ValueError("no refresh token")
        return data
    except (OSError, ValueError):
        raise CliError("not logged in (run: auth login)", 3)


def save_creds(creds):
    _write_private(creds_path(),
                   json.dumps(creds, indent=2).encode("utf-8"))


# ---------------------------------------------------------------- HTTP

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _http(method, url, headers=None, data=None):
    """Perform one HTTP request. Returns (status, body_bytes)."""
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, body
    except (urllib.error.URLError, OSError) as e:
        raise CliError("network error: %s" % getattr(e, "reason", e), 1)


def _request(method, url, headers=None, data=None):
    """_http with retry on 429/5xx (max MAX_RETRIES retries)."""
    attempt = 0
    while True:
        status, body = _http(method, url, headers, data)
        if (status == 429 or status >= 500) and attempt < MAX_RETRIES:
            _sleep(0.5 * (2 ** attempt))
            attempt += 1
            continue
        return status, body


def _error_message(status, body):
    try:
        d = json.loads(body)
        err = d.get("error")
        if isinstance(err, dict):
            return "Gmail API error %d: %s" % (status, err.get("message", ""))
        if err:
            return "error %d: %s" % (status, d.get("error_description", err))
    except (ValueError, AttributeError):
        pass
    return "HTTP error %d" % status


def _token_post(params):
    data = urllib.parse.urlencode(params).encode("ascii")
    status, body = _request(
        "POST", TOKEN_URL,
        {"Content-Type": "application/x-www-form-urlencoded"}, data)
    try:
        d = json.loads(body)
    except ValueError:
        d = {}
    if status != 200:
        if isinstance(d, dict) and d.get("error") == "invalid_grant":
            raise CliError("login expired or revoked (run: auth login)", 3)
        raise CliError(_error_message(status, body), 1)
    return d


def refresh_access_token(creds):
    client = load_client()
    d = _token_post({
        "grant_type": "refresh_token",
        "refresh_token": creds["refresh_token"],
        "client_id": client["client_id"],
        "client_secret": client["client_secret"],
    })
    creds = dict(creds)
    creds["access_token"] = d["access_token"]
    creds["expiry"] = time.time() + int(d.get("expires_in", 3600))
    if d.get("refresh_token"):
        creds["refresh_token"] = d["refresh_token"]
    save_creds(creds)
    return creds


def api_get(path, params=None):
    creds = load_creds()
    if not creds.get("access_token") or \
            float(creds.get("expiry") or 0) < time.time() + 60:
        creds = refresh_access_token(creds)
    url = API_BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(
            params, doseq=True, quote_via=urllib.parse.quote)
    refreshed = False
    while True:
        status, body = _request(
            "GET", url, {"Authorization": "Bearer " + creds["access_token"],
                         "Accept": "application/json"})
        if status == 401 and not refreshed:
            creds = refresh_access_token(creds)
            refreshed = True
            continue
        break
    if status >= 400:
        raise CliError(_error_message(status, body), 3 if status == 401 else 1)
    try:
        return json.loads(body)
    except ValueError:
        raise CliError("invalid response from Gmail", 1)


def _q(s):
    return urllib.parse.quote(s, safe="")


# ---------------------------------------------------------------- helpers

def decode_hdr(value):
    if not value:
        return ""
    value = re.sub(r"[\r\n]+\s*", " ", value)
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def get_header(msg, name):
    for h in (msg.get("payload") or {}).get("headers") or []:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""


def rfc3339_ms(ms):
    dt = datetime.fromtimestamp(int(ms) / 1000.0, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def msg_time(msg):
    if msg.get("internalDate"):
        try:
            return rfc3339_ms(msg["internalDate"])
        except (ValueError, OverflowError):
            pass
    try:
        dt = parsedate_to_datetime(get_header(msg, "Date"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


def contact(value):
    name, addr = parseaddr(value or "")
    return {"email_address": addr, "name": decode_hdr(name)}


def b64url_decode(s):
    s = s or ""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def walk_parts(part):
    yield part
    for p in part.get("parts") or []:
        for q in walk_parts(p):
            yield q


def _charset(part):
    for h in part.get("headers") or []:
        if h.get("name", "").lower() == "content-type":
            m = re.search(r'charset="?([\w.\-]+)', h.get("value", ""), re.I)
            if m:
                return m.group(1)
    return "utf-8"


def part_text(part):
    raw = b64url_decode((part.get("body") or {}).get("data", ""))
    try:
        return raw.decode(_charset(part), "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


class _HtmlText(HTMLParser):
    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5",
             "h6", "table", "blockquote", "ul", "ol", "hr", "pre"}
    SKIP = {"script", "style", "head"}

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.out = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BLOCK:
            self.out.append("\n- " if tag == "li" else "\n")

    def handle_startendtag(self, tag, attrs):
        if tag in self.BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self.skip = max(0, self.skip - 1)
        elif tag in self.BLOCK and tag != "li":
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data.replace("\n", " "))


def html_to_text(html):
    p = _HtmlText()
    try:
        p.feed(html)
        p.close()
    except Exception:
        pass
    lines = [re.sub(r"[ \t\r\f\v\xa0]+", " ", ln).strip()
             for ln in "".join(p.out).split("\n")]
    text = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def message_body(msg):
    plain, html = [], []
    for p in walk_parts(msg.get("payload") or {}):
        if p.get("filename"):
            continue
        body = p.get("body") or {}
        if not body.get("data"):
            continue
        mt = (p.get("mimeType") or "").lower()
        if mt == "text/plain":
            plain.append(part_text(p))
        elif mt == "text/html":
            html.append(part_text(p))
    if plain:
        return "\n".join(t.strip("\n") for t in plain).strip()
    return "\n".join(html_to_text(t) for t in html).strip()


def attachments_of(msg, require_id=True):
    out = []
    for p in walk_parts(msg.get("payload") or {}):
        fn = p.get("filename")
        body = p.get("body") or {}
        if not fn:
            continue
        if require_id and not body.get("attachmentId"):
            continue
        out.append({"filename": decode_hdr(fn),
                    "attachment_id": body.get("attachmentId", ""),
                    "size": int(body.get("size") or 0)})
    return out


# ---------------------------------------------------------------- query

_BARE = re.compile(r"^[A-Za-z0-9_.@+\-]+$")


def _term(value):
    value = value.strip()
    if _BARE.match(value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_query(query=None, from_=None, to=None, date=None):
    parts = []
    if from_:
        parts.append("from:" + _term(from_))
    if to:
        parts.append("to:" + _term(to))
    if query and query.strip():
        parts.append(_term(query))
    if date:
        m = {"last_7_days": "newer_than:7d", "last_30_days": "newer_than:30d",
             "last_90_days": "newer_than:90d"}
        if date in m:
            parts.append(m[date])
        elif re.match(r"^\d{4}$", date):
            y = int(date)
            parts.append("after:%04d/01/01 before:%04d/01/01" % (y, y + 1))
        else:
            raise CliError("invalid --date %r (use last_7_days, last_30_days, "
                           "last_90_days or YYYY)" % date, 2)
    parts.append("-in:drafts")
    return " ".join(parts)


def collect(path, key, params, all_, page):
    out, token = [], None
    limit = MAX_PAGES if all_ else page
    for n in range(1, limit + 1):
        q = dict(params)
        q["maxResults"] = 100
        if token:
            q["pageToken"] = token
        d = api_get(path, q)
        if all_ or n == page:
            out.extend(d.get(key) or [])
        token = d.get("nextPageToken")
        if not token:
            break
    return out


# ---------------------------------------------------------------- output

def emit(data):
    print(json.dumps({"ok": True, "data": data}))


# ---------------------------------------------------------------- commands

def cmd_search(a):
    q = build_query(a.query, a.from_, a.to, a.date)
    threads = collect("/threads", "threads", {"q": q}, a.all, a.page)
    out = []
    for t in threads:
        th = api_get("/threads/" + _q(t["id"]), {
            "format": "metadata",
            "metadataHeaders": ["From", "To", "Subject", "Date"]})
        msgs = th.get("messages") or []
        if not msgs:
            continue
        out.append({
            "topic_id": th.get("id", t["id"]),
            "subject": decode_hdr(get_header(msgs[0], "Subject")),
            "updated_at": msg_time(msgs[-1]),
            "messages": [{
                "created_at": msg_time(m),
                "creator": {
                    "id": contact(get_header(m, "From"))["email_address"],
                    "email_address": contact(get_header(m, "From"))["email_address"],
                    "name": contact(get_header(m, "From"))["name"],
                }} for m in msgs],
        })
    emit(out)


def cmd_thread_read(a):
    th = api_get("/threads/" + _q(a.thread_id), {"format": "full"})
    blocks = []
    for m in th.get("messages") or []:
        lines = ["### " + (decode_hdr(get_header(m, "Subject")) or "(no subject)"),
                 "From: " + decode_hdr(get_header(m, "From")),
                 "To: " + decode_hdr(get_header(m, "To"))]
        if get_header(m, "Cc"):
            lines.append("Cc: " + decode_hdr(get_header(m, "Cc")))
        lines.append("Date: " + get_header(m, "Date"))
        lines.append("")
        lines.append(message_body(m))
        atts = attachments_of(m, require_id=False)
        if atts:
            lines.append("")
            lines.append("Attachments:")
            lines.extend("- " + x["filename"] for x in atts)
        blocks.append("\n".join(lines))
    print("\n\n".join(blocks))


def cmd_attachment_list(a):
    th = api_get("/threads/" + _q(a.thread_id), {"format": "full"})
    out = []
    for m in th.get("messages") or []:
        for x in attachments_of(m):
            out.append({"id": "%s.%s" % (m["id"], x["attachment_id"]),
                        "filename": x["filename"], "size": x["size"]})
    emit(out)


def sanitize_filename(name):
    name = re.sub(r"[\x00-\x1f\x7f]", "", name or "")
    name = name.replace("/", "").replace("\\", "")
    name = name.lstrip(". ").strip()[:200].strip()
    return name or "attachment"


def cmd_attachment_save(a):
    if "." not in a.attachment_id:
        raise CliError("attachment id must look like MESSAGEID.ATTACHMENTID", 2)
    mid, aid = a.attachment_id.split(".", 1)
    if not mid or not aid:
        raise CliError("attachment id must look like MESSAGEID.ATTACHMENTID", 2)
    msg = api_get("/messages/" + _q(mid), {"format": "full"})
    filename = "attachment"
    for x in attachments_of(msg):
        if x["attachment_id"] == aid:
            filename = x["filename"]
            break
    name = sanitize_filename(filename)
    outdir = os.path.abspath(a.output)
    dest = os.path.join(outdir, name)
    if os.path.lexists(dest) and not a.force:
        raise CliError("destination already exists: %s (use --force to "
                       "replace it)" % dest, 1)
    d = api_get("/messages/%s/attachments/%s" % (_q(mid), _q(aid)))
    data = b64url_decode(d.get("data", ""))
    os.makedirs(outdir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=outdir, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o600)
        if a.force:
            os.replace(tmp, dest)
        else:
            try:
                os.link(tmp, dest)  # fails if dest appeared meanwhile
            finally:
                os.unlink(tmp)
    except FileExistsError:
        raise CliError("destination already exists: %s (use --force to "
                       "replace it)" % dest, 1)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    emit({"path": dest, "size": len(data)})


def _draft_meta(d_id):
    return api_get("/drafts/" + _q(d_id), {
        "format": "metadata",
        "metadataHeaders": ["To", "Cc", "Bcc", "Subject", "From"]})


def cmd_draft_list(a):
    drafts = collect("/drafts", "drafts", {}, a.all, 1)
    out = []
    for dr in drafts:
        full = _draft_meta(dr["id"])
        m = full.get("message") or {}
        contacts = []
        for name, addr in getaddresses(
                [get_header(m, h) for h in ("To", "Cc", "Bcc")]):
            if addr:
                contacts.append({"email_address": addr,
                                 "name": decode_hdr(name)})
        out.append({"id": full.get("id", dr["id"]),
                    "subject": decode_hdr(get_header(m, "Subject")),
                    "updated_at": msg_time(m),
                    "addressed_contacts": contacts})
    emit(out)


def cmd_draft_show(a):
    full = api_get("/drafts/" + _q(a.draft_id), {"format": "full"})
    m = full.get("message") or {}

    def addrs(h):
        return [addr for _, addr in getaddresses([get_header(m, h)]) if addr]
    emit({"id": full.get("id", a.draft_id),
          "subject": decode_hdr(get_header(m, "Subject")),
          "from": decode_hdr(get_header(m, "From")),
          "to": addrs("To"), "cc": addrs("Cc"), "bcc": addrs("Bcc"),
          "body": message_body(m)})


# ---------------------------------------------------------------- auth

def _open_browser(url):
    try:
        subprocess.run(["open", url], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10)
    except Exception:
        pass


_PAGE = (b"<!doctype html><meta charset=utf-8><title>fingeronit</title>"
         b"<body style='font-family:sans-serif;margin:3em'>"
         b"<h2>%s</h2><p>You can close this tab.</p></body>")


def _wait_for_callback(server, state, timeout):
    result = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _reply(self, code, title):
            body = _PAGE % title
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            if u.path != "/" or not ({"code", "error", "state"} & set(q)):
                self._reply(404, b"Not found")
                return
            got = (q.get("state") or [""])[0]
            if not secrets.compare_digest(got.encode(), state.encode()):
                result["error"] = "state mismatch in OAuth callback"
                self._reply(400, b"Login failed")
            elif q.get("error"):
                result["error"] = "authorization denied: %s" % q["error"][0]
                self._reply(400, b"Login failed")
            elif q.get("code"):
                result["code"] = q["code"][0]
                self._reply(200, b"Signed in")
            else:
                result["error"] = "no authorization code received"
                self._reply(400, b"Login failed")

    deadline = time.time() + timeout
    while not result:
        left = deadline - time.time()
        if left <= 0:
            raise CliError("timed out waiting for the browser sign-in", 1)
        server.timeout = left
        server.RequestHandlerClass = Handler
        server.handle_request()
    return result


def cmd_auth_login(a):
    if a.client:
        try:
            with open(a.client, "rb") as fh:
                raw = fh.read()
            inst = json.loads(raw)["installed"]
            inst["client_id"]
        except (OSError, ValueError, KeyError, TypeError):
            raise CliError("not a Google 'Desktop app' client file "
                           "(expected an \"installed\" section)", 1)
        _write_private(client_path(), raw)
    client = load_client()

    server = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    try:
        port = server.server_address[1]
        redirect = "http://127.0.0.1:%d" % port
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        state = secrets.token_urlsafe(24)
        url = AUTH_URL + "?" + urllib.parse.urlencode({
            "client_id": client["client_id"],
            "redirect_uri": redirect,
            "response_type": "code",
            "scope": SCOPE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        })
        print("Open this URL to sign in:\n" + url)
        sys.stdout.flush()
        if os.environ.get("FINGERONIT_NO_BROWSER") != "1":
            _open_browser(url)
        result = _wait_for_callback(server, state, LOGIN_TIMEOUT)
    finally:
        server.server_close()
    if "error" in result:
        raise CliError(result["error"], 1)

    d = _token_post({
        "grant_type": "authorization_code",
        "code": result["code"],
        "client_id": client["client_id"],
        "client_secret": client["client_secret"],
        "code_verifier": verifier,
        "redirect_uri": redirect,
    })
    if not d.get("refresh_token") or not d.get("access_token"):
        raise CliError("no refresh token returned; remove this app at "
                       "myaccount.google.com/permissions and try again", 1)
    creds = {"refresh_token": d["refresh_token"],
             "access_token": d["access_token"],
             "expiry": time.time() + int(d.get("expires_in", 3600)),
             "email_address": ""}
    save_creds(creds)
    prof = api_get("/profile")
    creds = load_creds()
    creds["email_address"] = prof.get("emailAddress", "")
    save_creds(creds)
    emit({"logged_in": True, "email_address": creds["email_address"]})


def cmd_auth_status(a):
    try:
        creds = load_creds()
        emit({"logged_in": True,
              "email_address": creds.get("email_address", "")})
    except CliError:
        emit({"logged_in": False, "email_address": ""})


def cmd_version(a):
    print("fingeronit-gmail " + VERSION)


# ---------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(
        prog="fingeronit-gmail",
        description="Read-only Gmail client (gmail.readonly scope).")
    p.add_argument("--json", dest="json_top", action="store_true",
                   help="JSON output (always on for data commands)")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")
    sub.required = True

    def leaf(parent, name, func, help_):
        sp = parent.add_parser(name, help=help_, description=help_)
        sp.add_argument("--json", dest="json_" + name, action="store_true",
                        help="JSON output")
        sp.set_defaults(func=func)
        return sp

    def group(name, help_):
        g = sub.add_parser(name, help=help_, description=help_)
        g.add_argument("--json", dest="json_g_" + name, action="store_true",
                       help="JSON output")
        gs = g.add_subparsers(dest=name + "_cmd", metavar="SUBCOMMAND")
        gs.required = True
        return gs

    s = leaf(sub, "search", cmd_search, "Search threads")
    s.add_argument("query", nargs="?", help="free-text query")
    s.add_argument("--from", dest="from_", metavar="ADDR")
    s.add_argument("--to", metavar="ADDR")
    s.add_argument("--date", metavar="RANGE",
                   help="last_7_days, last_30_days, last_90_days or YYYY")
    s.add_argument("--all", action="store_true",
                   help="fetch up to %d pages" % MAX_PAGES)
    s.add_argument("--page", type=int, default=1, metavar="N")

    t = group("thread", "Read threads")
    r = leaf(t, "read", cmd_thread_read, "Read a thread as markdown")
    r.add_argument("thread_id")
    r.add_argument("--markdown", action="store_true",
                   help="markdown output (the default)")

    at = group("attachment", "List or save attachments")
    al = leaf(at, "list", cmd_attachment_list, "List a thread's attachments")
    al.add_argument("thread_id")
    sv = leaf(at, "save", cmd_attachment_save, "Save one attachment")
    sv.add_argument("attachment_id", help="MESSAGEID.ATTACHMENTID")
    sv.add_argument("--output", required=True, metavar="DIR")
    sv.add_argument("--force", action="store_true",
                    help="replace an existing file")

    dr = group("draft", "List or show drafts")
    dl = leaf(dr, "list", cmd_draft_list, "List drafts")
    dl.add_argument("--all", action="store_true",
                    help="fetch up to %d pages" % MAX_PAGES)
    ds = leaf(dr, "show", cmd_draft_show, "Show one draft")
    ds.add_argument("draft_id")

    au = group("auth", "Sign in and check status")
    lg = leaf(au, "login", cmd_auth_login, "Sign in with Google (OAuth)")
    lg.add_argument("--client", metavar="FILE",
                    help="Google OAuth client JSON to install first")
    leaf(au, "status", cmd_auth_status, "Show login status")

    leaf(sub, "version", cmd_version, "Print version")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.func is cmd_search and args.page < 1:
            raise CliError("--page must be >= 1", 2)
        args.func(args)
        return 0
    except CliError as e:
        print(json.dumps({"ok": False, "error": e.message}), file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        print(json.dumps({"ok": False, "error": "interrupted"}),
              file=sys.stderr)
        return 130


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(main())
