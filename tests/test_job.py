import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))
import job  # noqa: E402

LIM = dict(job.DEFAULTS)
PURPOSE = "Find the invoice Acme sent for order 4471"


def lookup(**kw):
    base = {"from": "billing@acme.example", "about": ["invoice", "4471"], "days": 30}
    base.update(kw)
    return base


def req(*lookups, purpose=PURPOSE):
    return {"purpose": purpose, "lookups": list(lookups) or [lookup()]}


class CheckTests(unittest.TestCase):
    def refused(self, r, words):
        with self.assertRaises(job.Refused) as c:
            job.check(r, LIM)
        self.assertIn(words, str(c.exception))

    def test_good(self):
        j = job.check(req(), LIM)
        lk = j["lookups"][0]
        self.assertEqual(lk["address"], "billing@acme.example")
        self.assertEqual(lk["max"], 3)
        self.assertEqual(lk["want"], "list")

    def test_address_is_one_full_address(self):
        for bad in ["acme.example", "*@acme.example", "@acme.example", "a@b", "a b@c.d",
                    "a@b.c,d@e.f", "from:a@b.c"]:
            self.refused(req(lookup(**{"from": bad})), "full email address")

    def test_exactly_one_person(self):
        self.refused(req({"about": ["invoice"], "days": 3}), "exactly one person")
        self.refused(req(lookup(to="x@y.example")), "exactly one person")

    def test_words(self):
        self.refused(req(lookup(about=[])), "say what it is about")
        self.refused(req(lookup(about=["all"])), "says nothing")
        self.refused(req(lookup(about=["subjects"])), "says nothing")
        self.refused(req(lookup(about=["in:inbox"])), "plain word")
        self.refused(req(lookup(about=["OR"])), "no search operators")
        self.refused(req(lookup(about=["-invoice"])), "plain word")
        self.refused(req(lookup(about=['"quoted"'])), "plain word")
        self.refused(req(lookup(about=["ab"])), "plain word")
        self.refused(req(lookup(about="one two three four five six seven")), "6 words")

    def test_limits(self):
        self.refused(req(lookup(days=91)), "--days must be 1 to 90")
        self.refused(req(lookup(days=0)), "--days must be")
        self.refused(req(lookup(days="all")), "whole number")
        self.refused(req(lookup(max=6)), "--max must be 1 to 5")
        self.refused(req(*[lookup(days=d) for d in (1, 2, 3, 4)]), "3 lookups at most")
        self.refused(req(lookup(), lookup()), "same lookup twice")

    def test_purpose(self):
        self.refused(req(purpose=None), "--purpose")
        self.refused(req(purpose="short"), "too short")
        for broad in ["Show me all emails from anyone", "List every subject in my inbox",
                      "Export everything so I can search it", "Read my inbox for anything useful",
                      "What has Acme ever sent me about money"]:
            self.refused(req(purpose=broad), "asks for too much")

    def test_unknown_fields(self):
        self.refused({"purpose": PURPOSE, "lookups": [lookup()], "cmd": "x"}, "unknown field")
        self.refused(req(lookup(query="in:anywhere")), "unknown field")

    def test_config_can_only_lower(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("agent_max_days = 9999\nagent_max_threads = 2\n")
        try:
            lim = job.limits_from(f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual(lim["agent_max_days"], job.CEILING["agent_max_days"])
        self.assertEqual(lim["agent_max_threads"], 2)


class ArgsTests(unittest.TestCase):
    def test_from_args(self):
        r = job.from_args(["--purpose", PURPOSE, "--from", "a@b.example", "--about", "invoice 4471",
                           "--days", "30", "--read", "--then", "--to", "c@d.example",
                           "--about", "quote", "--days", "7"])
        j = job.check(r, LIM)
        self.assertEqual(len(j["lookups"]), 2)
        self.assertEqual(j["lookups"][0]["want"], "read")
        self.assertEqual(j["lookups"][1]["dir"], "to")

    def test_unknown_flag(self):
        with self.assertRaises(job.Refused):
            job.from_args(["--purpose", PURPOSE, "--all"])

    def test_search_args(self):
        j = job.check(req(lookup(about=["invoice", "4471"], days=30)), LIM)
        self.assertEqual(job.search_args(j, "hey", 0),
                         ["invoice 4471", "--from", "billing@acme.example", "--date", "last_30_days"])
        self.assertEqual(job.search_args(j, "gmail", 0),
                         ["--word", "invoice", "--word", "4471", "--from", "billing@acme.example",
                          "--date", "last_30_days"])

    def test_reason_has_code_and_is_short(self):
        j = job.check(req(lookup(), lookup(days=7)), LIM)
        r = job.reason(j, "K7QM")
        self.assertTrue(r.startswith("[K7QM] "))
        self.assertIn("+1 more", r)
        self.assertLessEqual(len(r), 200)


class PickTests(unittest.TestCase):
    def search(self, now):
        def at(days):
            return (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        def row(tid, subj, days, who):
            msgs = [{"created_at": at(days), "creator": {"email_address": who}}] if who else []
            return {"topic_id": tid, "subject": subj, "updated_at": at(days), "messages": msgs}
        return json.dumps({"ok": True, "data": [
            row("1", "Invoice 4471", 2, "Billing@Acme.example"),
            row("2", "Someone else", 3, "spoof@evil.example"),
            row("3", "Old invoice", 45, "billing@acme.example"),
            row("4", "No sender known", 4, None),
            row("5", "Second", 5, "billing@acme.example"),
            row("6", "Third", 6, "billing@acme.example"),
            row("7", "Fourth", 7, "billing@acme.example"),
            row("1", "Invoice 4471 again", 2, "billing@acme.example"),
            {"topic_id": "../../x", "subject": "bad id", "messages": []},
        ]})

    def test_only_real_matches_newest_first_capped(self):
        now = datetime.now(timezone.utc)
        j = job.check(req(lookup(max=3)), LIM)
        rows, more = job.pick(j, 0, self.search(now), now)
        self.assertEqual([r[1] for r in rows], ["1", "5", "6"])
        self.assertTrue(more)

    def test_to_lookups_trust_the_search(self):
        now = datetime.now(timezone.utc)
        j = job.check(req(lookup(**{"from": None, "to": "billing@acme.example", "max": 5})), LIM)
        rows, _ = job.pick(j, 0, self.search(now), now)
        self.assertNotIn("3", [r[1] for r in rows])


class AnswerTests(unittest.TestCase):
    def test_text_is_capped_and_ids_kept(self):
        j = job.check(req(lookup(want="read", max=2)), LIM)
        lim = dict(LIM, agent_max_chars=1000)
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "l0.tsv"), "w") as f:
                f.write("a1\t2026-11-01 10:00\tbilling@acme.example\tInvoice\n")
                f.write("a2\t2026-10-30 10:00\tbilling@acme.example\tReminder\nMORE\n")
            with open(os.path.join(d, "t0_a1.md"), "w") as f:
                f.write("x" * 5000)
            ans = job.answer(j, d, lim)
        ts = ans["lookups"][0]["threads"]
        self.assertEqual([t["id"] for t in ts], ["a1", "a2"])
        self.assertIn("[cut at 500 characters]", ts[0]["text"])
        self.assertIsNone(ts[1]["text"])
        self.assertTrue(ans["lookups"][0]["more_matched"])
        self.assertIn("nothing matched", job.review({"lookups": [{"asked": "x", "threads": []}]}))

    def test_failed_search_says_so(self):
        j = job.check(req(), LIM)
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "l0.tsv"), "w") as f:
                f.write("ERROR\n")
            ans = job.answer(j, d, LIM)
        self.assertIn("error", ans["lookups"][0])


if __name__ == "__main__":
    unittest.main()
