"""fingeronit jobs: the one shape an agent's mail request may take.

An agent never names a provider command. It asks for lookups, and each lookup
is narrow by construction: one person (a full address), words about the topic,
a time window, and a small number of threads. A whole request also carries a
purpose the human reads before approving it with Touch ID.

This file checks that shape, explains it to the human, turns it into provider
arguments, keeps only threads that really match, and trims what goes back.
The desk checks every request again before it shows it, so nothing an agent
sends can skip these rules.

Usage (python3 -I job.py CMD ...):
  from-args ARGS...          agent flags -> request JSON
  check CFG                  request JSON on stdin -> checked JSON, or refusal (exit 2)
  describe CFG               checked JSON on stdin -> what the human reads
  reason CODE                checked JSON on stdin -> the Touch ID line
  count                      checked JSON on stdin -> number of lookups
  want I                     checked JSON on stdin -> list or read, for lookup I
  args PROVIDER I            checked JSON on stdin -> search arguments, one per line
  pick JOBFILE I             search JSON on stdin -> rows (id, date, from, subject)
  answer JOBFILE DIR CFG     -> the JSON the agent gets
  review                     answer JSON on stdin -> what the human checks before sending
"""
import json
import re
import sys
from datetime import datetime, timedelta, timezone

# Code ceilings. lockenv.cfg can only lower them.
CEILING = {"agent_max_days": 365, "agent_max_threads": 10,
           "agent_max_lookups": 5, "agent_max_chars": 60000}
DEFAULTS = {"agent_max_days": 90, "agent_max_threads": 5,
            "agent_max_lookups": 3, "agent_max_chars": 20000}
DEFAULT_MAX = 3
MAX_WORDS = 6

ADDRESS = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")
WORD = re.compile(r"^[^\W_]([\w.'&+-]{0,38}[^\W_])?$", re.UNICODE)

# Words that say nothing about a topic, or ask for everything.
WEAK = set("""
a an and are as at be but by for from has have i in is it its me my no not of
on or our so that the their them then there these they this to us was we were
what when where which who why will with you your
all any anything every everyone everything each entire whole
mail mails email emails message messages thread threads inbox inboxes
subject subjects sender senders contact contacts sent received
stuff things latest recent new old
""".split())

# A purpose that asks for everything is refused, whatever the lookups say.
BROAD = [
    re.compile(r"\b(all|every|each|entire|whole|any)\b[^.]{0,40}\b(mail|mails|email|emails|"
               r"messages?|threads?|inbox|subjects?|senders?|contacts?|correspondence|history)\b", re.I),
    re.compile(r"\b(everything|dump|export|back ?up|archive|scrape|crawl|harvest|bulk)\b", re.I),
    re.compile(r"\b(list|show|read|get|fetch)\b[^.]{0,20}\b(my|the)\s+(inbox|mailbox|mail|email)\b", re.I),
    re.compile(r"\bever\b", re.I),
]


class Refused(Exception):
    pass


def limits_from(cfg_path):
    out = dict(DEFAULTS)
    try:
        with open(cfg_path) as f:
            for line in f:
                key, sep, val = line.partition("=")
                key, val = key.strip(), val.strip()
                if sep and key in CEILING and val.isdigit():
                    out[key] = max(1, min(int(val), CEILING[key]))
    except OSError:
        pass
    return out


# ---------------------------------------------------------------- parsing

def from_args(argv):
    """The flag form of a request. --then starts the next lookup."""
    req = {"purpose": None, "lookups": []}
    cur = {}
    i = 0

    def value(flag):
        nonlocal i
        if i + 1 >= len(argv):
            raise Refused("%s needs a value" % flag)
        i += 1
        return argv[i]

    while i < len(argv):
        a = argv[i]
        if a == "--purpose":
            if req["purpose"] is not None:
                raise Refused("give --purpose once")
            req["purpose"] = value(a)
        elif a in ("--from", "--to"):
            key = a[2:]
            if key in cur:
                raise Refused("one %s per lookup (use --then for another lookup)" % a)
            cur[key] = value(a)
        elif a == "--about":
            cur.setdefault("about", []).extend(value(a).split())
        elif a == "--days":
            cur["days"] = value(a)
        elif a == "--max":
            cur["max"] = value(a)
        elif a == "--read":
            cur["want"] = "read"
        elif a == "--list":
            cur["want"] = "list"
        elif a == "--then":
            req["lookups"].append(cur)
            cur = {}
        else:
            raise Refused("unknown flag %r (fingeronit ask --help lists them)" % a)
        i += 1
    req["lookups"].append(cur)
    return req


def _int(v, name):
    if isinstance(v, bool):
        raise Refused("%s must be a whole number" % name)
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().isdigit():
        return int(v.strip())
    raise Refused("%s must be a whole number" % name)


def check_purpose(p):
    if not isinstance(p, str):
        raise Refused("say why, in --purpose: one sentence the human reads before approving")
    p = " ".join(p.split())
    if len(p) < 12:
        raise Refused("--purpose is too short: say what you need and why, in one sentence")
    if len(p) > 240:
        raise Refused("--purpose is too long: one sentence, 240 characters at most")
    if any(not ch.isprintable() for ch in p):
        raise Refused("--purpose must be plain text")
    for pat in BROAD:
        hit = pat.search(p)
        if hit:
            raise Refused("--purpose asks for too much (%r). Ask for one specific thing: "
                          "one person, one topic, a short time window" % hit.group(0))
    return p


def check_lookup(lk, n, lim):
    where = "lookup %d: " % n
    if not isinstance(lk, dict):
        raise Refused(where + "must be an object")
    extra = set(lk) - {"from", "to", "about", "days", "max", "want"}
    if extra:
        raise Refused(where + "unknown field %s" % ", ".join(sorted(extra)))
    have = [k for k in ("from", "to") if lk.get(k)]
    if len(have) != 1:
        raise Refused(where + "name exactly one person: --from ADDRESS (mail they sent) "
                      "or --to ADDRESS (mail sent to them)")
    direction = have[0]
    addr = lk[direction]
    if not isinstance(addr, str) or len(addr) > 254 or not ADDRESS.match(addr.strip()):
        raise Refused(where + "--%s must be one full email address, like name@example.com "
                      "(no wildcards, no bare domains)" % direction)
    addr = addr.strip().lower()

    about = lk.get("about")
    if isinstance(about, str):
        about = about.split()
    if not isinstance(about, list) or not about:
        raise Refused(where + "say what it is about: --about \"one to six words\" "
                      "(a person alone is too broad)")
    words = []
    for w in about:
        if not isinstance(w, str):
            raise Refused(where + "--about must be words")
        w = w.strip()
        low = w.lower()
        if not WORD.match(w) or len(w) < 3 or ":" in w:
            raise Refused(where + "%r is not a plain word of 3 to 40 letters or digits "
                          "(no search operators or symbols)" % w)
        if low in ("or", "and", "not", "around", "near"):
            raise Refused(where + "no search operators in --about")
        if low in WEAK:
            raise Refused(where + "%r says nothing about the topic. Use words the mail itself "
                          "would contain, like an order number or a product name" % w)
        if low not in [x.lower() for x in words]:
            words.append(w)
    if len(words) > MAX_WORDS:
        raise Refused(where + "--about takes %d words at most" % MAX_WORDS)

    if "days" not in lk:
        raise Refused(where + "--days N is required (1 to %d)" % lim["agent_max_days"])
    days = _int(lk["days"], "--days")
    if not 1 <= days <= lim["agent_max_days"]:
        raise Refused(where + "--days must be 1 to %d" % lim["agent_max_days"])

    cap = _int(lk.get("max", min(DEFAULT_MAX, lim["agent_max_threads"])), "--max")
    if not 1 <= cap <= lim["agent_max_threads"]:
        raise Refused(where + "--max must be 1 to %d threads" % lim["agent_max_threads"])

    want = lk.get("want", "list")
    if want not in ("list", "read"):
        raise Refused(where + "want is list (date, sender, subject) or read (also the text)")
    return {"dir": direction, "address": addr, "about": words,
            "days": days, "max": cap, "want": want}


def check(req, lim):
    if not isinstance(req, dict):
        raise Refused("a request is an object with purpose and lookups")
    extra = set(req) - {"purpose", "lookups"}
    if extra:
        raise Refused("unknown field %s" % ", ".join(sorted(extra)))
    purpose = check_purpose(req.get("purpose"))
    lookups = req.get("lookups")
    if not isinstance(lookups, list) or not lookups:
        raise Refused("ask for at least one lookup")
    if len(lookups) > lim["agent_max_lookups"]:
        raise Refused("%d lookups at most in one request" % lim["agent_max_lookups"])
    out = [check_lookup(lk, n, lim) for n, lk in enumerate(lookups, 1)]
    keys = [json.dumps(x, sort_keys=True) for x in out]
    if len(set(keys)) != len(keys):
        raise Refused("the same lookup twice")
    return {"purpose": purpose, "lookups": out}


# ---------------------------------------------------------------- telling the human

def one_line(lk):
    who = ("from " if lk["dir"] == "from" else "to ") + lk["address"]
    what = "date, sender, subject" if lk["want"] == "list" else "date, sender, subject, and text"
    return 'mail %s about "%s", last %d days, up to %d thread%s: %s' % (
        who, " ".join(lk["about"]), lk["days"], lk["max"], "" if lk["max"] == 1 else "s", what)


def describe(job, lim):
    lines = ["Purpose:  " + job["purpose"]]
    for n, lk in enumerate(job["lookups"], 1):
        lines.append("  %d. %s" % (n, one_line(lk)))
    if any(lk["want"] == "read" for lk in job["lookups"]):
        lines.append("  Text is cut to %d characters in all. Attachments never go to agents."
                     % lim["agent_max_chars"])
    return "\n".join(lines)


def reason(job, code):
    first = job["lookups"][0]
    s = "[%s] agent lookup: %s %s about %s, %dd, %d max" % (
        code, first["dir"], first["address"], " ".join(first["about"]),
        first["days"], first["max"])
    if len(job["lookups"]) > 1:
        s += ", +%d more" % (len(job["lookups"]) - 1)
    return s[:200]


# ---------------------------------------------------------------- provider side

def bucket(days):
    if days <= 7:
        return "last_7_days"
    if days <= 30:
        return "last_30_days"
    if days <= 90:
        return "last_90_days"
    return None


def search_args(job, provider, i):
    lk = job["lookups"][i]
    if provider == "gmail":
        out = []
        for w in lk["about"]:
            out += ["--word", w]
    else:
        out = [" ".join(lk["about"])]
    out += ["--" + lk["dir"], lk["address"]]
    b = bucket(lk["days"])
    if b:
        out += ["--date", b]
    return out


def blobs_of(text):
    dec = json.JSONDecoder()
    out, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError:
            break
        out.append(obj)
    return out


STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$")


def stamp_of(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, timezone.utc)
    if not isinstance(value, str):
        return None
    m = STAMP.match(value.strip())
    if not m:
        return None
    clock = m.group(2) if m.group(2).count(":") == 2 else m.group(2) + ":00"
    frac = (m.group(3) or "0")[:6].ljust(6, "0")
    tz = m.group(4) or "+00:00"
    if tz == "Z":
        tz = "+00:00"
    elif ":" not in tz:
        tz = tz[:3] + ":" + tz[3:]
    try:
        return datetime.fromisoformat("%sT%s.%s%s" % (m.group(1), clock, frac, tz))
    except ValueError:
        return None


def clean(value, cap=200):
    s = "".join(" " if (ch in "\t\r\n" or not ch.isprintable()) else ch for ch in str(value))
    return s[:cap]


THREAD_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def pick(job, i, text, now=None):
    """Threads from a search that really match the lookup, newest first."""
    lk = job["lookups"][i]
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=lk["days"])
    rows = []

    def walk(obj):
        if isinstance(obj, list):
            for x in obj:
                walk(x)
        elif isinstance(obj, dict):
            if "topic_id" in obj:
                rows.append(obj)
            else:
                for key in ("data", "results", "matches"):
                    if key in obj:
                        walk(obj[key])

    for blob in blobs_of(text):
        walk(blob)
    keep, seen = [], set()
    for row in rows:
        tid = str(row.get("topic_id") or "")
        if not THREAD_ID.match(tid) or tid in seen:
            continue
        msgs = [m for m in (row.get("messages") or []) if isinstance(m, dict)]
        senders = []
        for m in msgs:
            c = m.get("creator")
            if isinstance(c, dict):
                senders.append(str(c.get("email_address") or "").strip().lower())
        if lk["dir"] == "from" and lk["address"] not in senders:
            # The provider said it matched; fingeronit checks it did.
            continue
        when = None
        for m in msgs:
            s = stamp_of(m.get("created_at"))
            if s and (when is None or s > when):
                when = s
        if when is None:
            when = stamp_of(row.get("updated_at")) or stamp_of(row.get("active_at"))
        if when is None or when < cutoff:
            continue
        seen.add(tid)
        # Mail headers are written by strangers: no control characters reach a terminal.
        sender = clean(next((s for s in reversed(senders) if s), ""), 254)
        keep.append((when, tid, sender, clean(row.get("subject") or "(no subject)")))
    keep.sort(key=lambda r: r[0], reverse=True)
    more = len(keep) > lk["max"]
    return keep[:lk["max"]], more


def answer(job, work, lim):
    out = {"ok": True, "purpose": job["purpose"], "lookups": []}
    reads = []
    for i, lk in enumerate(job["lookups"]):
        entry = {"asked": one_line(lk), "threads": [], "more_matched": False}
        try:
            with open("%s/l%d.tsv" % (work, i)) as f:
                lines = f.read().splitlines()
        except OSError:
            lines = ["ERROR"]
        if lines and lines[0] == "ERROR":
            entry["error"] = "the mail service did not answer this lookup"
            lines = []
        for line in lines:
            if line == "MORE":
                entry["more_matched"] = True
                continue
            parts = line.split("\t")
            if len(parts) != 4:
                continue
            t = {"id": parts[0], "date": parts[1], "from": parts[2], "subject": parts[3]}
            if lk["want"] == "read":
                reads.append((t, "%s/t%d_%s.md" % (work, i, parts[0])))
            entry["threads"].append(t)
        out["lookups"].append(entry)
    if reads:
        each = max(200, lim["agent_max_chars"] // len(reads))
        for t, path in reads:
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    body = f.read(each + 1)
            except OSError:
                t["text"] = None
                t["error"] = "could not read this thread"
                continue
            if len(body) > each:
                body = body[:each] + "\n[cut at %d characters]" % each
            t["text"] = body
    out["note"] = "Approved once, for this purpose only. Attachments are never sent to agents."
    return out


def review(ans):
    lines = []
    for n, lk in enumerate(ans.get("lookups", []), 1):
        lines.append("  %d. %s" % (n, lk.get("asked", "")))
        if lk.get("error"):
            lines.append("     (%s)" % lk["error"])
        if not lk.get("threads"):
            lines.append("     nothing matched")
        for t in lk.get("threads", []):
            size = ""
            if t.get("text") is not None and "text" in t:
                size = "  (%d characters of text)" % len(t["text"])
            lines.append("     %s  %s  %s%s" % (t["date"], t["from"] or "?", t["subject"], size))
        if lk.get("more_matched"):
            lines.append("     (more matched; only these are sent)")
    return "\n".join(lines)


# ---------------------------------------------------------------- command line

def main(argv):
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "from-args":
            json.dump(from_args(rest), sys.stdout)
            return 0
        if cmd == "check":
            lim = limits_from(rest[0])
            raw = sys.stdin.read(65537)
            if len(raw) > 65536:
                raise Refused("request too large")
            try:
                req = json.loads(raw)
            except ValueError:
                raise Refused("the request is not JSON")
            json.dump(check(req, lim), sys.stdout)
            return 0
        job = None
        if cmd in ("describe", "reason", "count", "args", "want"):
            job = json.load(sys.stdin)
        if cmd == "describe":
            print(describe(job, limits_from(rest[0])))
        elif cmd == "reason":
            print(reason(job, rest[0]))
        elif cmd == "count":
            print(len(job["lookups"]))
        elif cmd == "want":
            print(job["lookups"][int(rest[0])]["want"])
        elif cmd == "args":
            for a in search_args(job, rest[0], int(rest[1])):
                print(a)
        elif cmd == "pick":
            with open(rest[0]) as f:
                job = json.load(f)
            rows, more = pick(job, int(rest[1]), sys.stdin.read())
            for when, tid, sender, subject in rows:
                sys.stdout.write("%s\t%s\t%s\t%s\n" % (
                    tid, when.astimezone().strftime("%Y-%m-%d %H:%M"), sender, subject))
            if more:
                sys.stdout.write("MORE\n")
        elif cmd == "answer":
            with open(rest[0]) as f:
                job = json.load(f)
            json.dump(answer(job, rest[1], limits_from(rest[2])), sys.stdout, indent=1)
            sys.stdout.write("\n")
        elif cmd == "review":
            print(review(json.load(sys.stdin)))
        else:
            sys.stderr.write("job.py: unknown command %s\n" % cmd)
            return 2
    except Refused as e:
        json.dump({"ok": False, "refused": str(e)}, sys.stdout)
        sys.stdout.write("\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
