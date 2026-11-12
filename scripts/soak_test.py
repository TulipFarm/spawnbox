#!/usr/bin/env python3
"""Tests of soak.py's own logic, with the API and hosts stubbed out.
Run: python3 scripts/soak_test.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soak  # noqa: E402


class Clock:
    """Time that moves only when the script sleeps."""

    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def make(argv=()):
    clock = Clock()
    soak.time.time, soak.time.sleep = clock.time, clock.sleep
    s = soak.Soak(soak.parse_args(["--api", "http://127.0.0.1:1", "--key", "k", *argv]))
    s.log = lambda msg: None
    s.clock = clock
    return s


class Fleet:
    """A fake API and hosts: where each sandbox runs, and where its next
    cold start lands."""

    def __init__(self, s, lands):
        self.s, self.lands, self.where, self.state = s, list(lands), {}, {}
        self.commands, self.deleted = [], []
        s.call = self.call
        s.host_of = lambda view: self.where.get(view["id"])
        s.hosts.run = lambda host, script, timeout=60: self.kill(host, script)

    def kill(self, host, script):
        for sid, h in self.where.items():
            if h == host and soak.host_name(sid) in script:
                self.state[sid] = "cold"

    def call(self, method, path, body=None, **kw):
        if path == "/v1/volumes":
            return 201, {}
        if path == "/v1/sandboxes" and method == "POST":
            sid = f"sbx_{len(self.where):012d}"
            self.where[sid], self.state[sid] = "primary", "running"
            return 201, {"id": sid, "generation": 1}
        sid = path.split("/")[3].split("?")[0]
        if method == "DELETE":
            self.deleted.append(sid)
            return 204, None
        if path.endswith("/exec"):
            self.commands.append(body["cmd"])
            if self.state[sid] == "cold":
                self.where[sid] = self.lands.pop(0)
                self.state[sid] = "running"
            if "Permission" in self.lands[:1]:
                return 200, {"stdout": "", "exit_code": 1, "stderr": "Permission denied"}
            if body["cmd"].startswith("printf"):
                rec = self.s.mine[sid]
                return 200, {"stdout": f"{rec['token']}|{rec['token']}|{rec['token']}", "exit_code": 0}
            return 200, {"stdout": "ok\n", "exit_code": 0}
        return 200, {"id": sid, "state": self.state[sid], "generation": 1}


class Markers(unittest.TestCase):
    def test_markers_go_to_the_default_users_home(self):
        s = make()
        fleet = Fleet(s, [])
        s.create(True, volume=False)
        self.assertIn('"$HOME/soak-marker"', fleet.commands[0])
        self.assertNotIn("/root", " ".join(fleet.commands))

    def test_a_failed_marker_write_is_a_setup_error_not_a_loss(self):
        s = make()
        fleet = Fleet(s, ["Permission"])
        self.assertIsNone(s.create(True, volume=False))
        self.assertEqual(s.summary["violations"], [])
        self.assertEqual(len(s.summary["setup_errors"]), 1)
        self.assertEqual(fleet.deleted, ["sbx_000000000000"])
        s.create(True, volume=False)
        with self.assertRaises(soak.SetupError):
            s.create(True, volume=False)


class Placement(unittest.TestCase):
    def test_cold_starts_until_the_sandbox_lands_on_the_worker(self):
        s = make()
        # The first lands at its third cold start, the second at its first.
        fleet = Fleet(s, ["primary", "primary", "nod_a", "nod_a"])
        ids = s.place(2, "nod_a", volume=False)
        self.assertEqual(len(ids), 2)
        self.assertEqual([fleet.where[i] for i in ids], ["nod_a", "nod_a"])
        self.assertEqual(s.summary["violations"], [])

    def test_a_sandbox_that_never_lands_fails_the_setup_and_is_cleaned_up(self):
        s = make(["--place-tries", "3"])
        fleet = Fleet(s, ["primary"] * 3)
        with self.assertRaisesRegex(soak.SetupError, "after 3 cold starts, not on nod_a"):
            s.place(1, "nod_a", volume=False)
        self.assertEqual(fleet.deleted, ["sbx_000000000000"])
        self.assertEqual(s.summary["violations"], [])


class Retries(unittest.TestCase):
    NO_ROOM = (503, {"error": {"code": "no_capacity", "retryable": True,
                               "message": "the memory of this host is reserved by other sandboxes"}})

    def sandbox(self, answers):
        """A persistent sandbox whose next checks get `answers`, then work."""
        s = make()
        Fleet(s, [])
        sid = s.create(True, volume=False)
        answers = list(answers)
        works = s.exec

        def exec_(sandbox, cmd, timeout=300):
            if answers:
                status, body = answers.pop(0)
                return None, status, body
            return works(sandbox, cmd, timeout)

        s.exec = exec_
        return s, sid

    def test_a_wake_with_no_room_is_asked_again_with_backoff(self):
        s, sid = self.sandbox([self.NO_ROOM] * 4)
        start = s.clock.now
        self.assertTrue(s.verify(sid, "wake"))
        self.assertEqual(s.summary["violations"], [])
        self.assertEqual(s.summary["errors"]["retried_no_capacity"], 4)
        # 2 + 4 + 8 + 16 seconds of backoff.
        self.assertEqual(s.clock.now - start, 30)

    def test_a_wake_that_has_no_room_for_too_long_is_lost(self):
        s, sid = self.sandbox([self.NO_ROOM] * 100)
        start = s.clock.now
        self.assertFalse(s.verify(sid, "wake"))
        self.assertEqual([v["kind"] for v in s.summary["violations"]], ["lost"])
        self.assertLessEqual(s.clock.now - start, 90)
        self.assertGreater(s.summary["errors"]["retried_no_capacity"], 3)

    def test_an_error_that_is_not_retryable_is_lost_at_once(self):
        s, sid = self.sandbox([(404, {"error": {"code": "not_found", "retryable": False}})])
        start = s.clock.now
        self.assertFalse(s.verify(sid, "wake"))
        self.assertEqual([v["kind"] for v in s.summary["violations"]], ["lost"])
        self.assertEqual(s.clock.now, start)
        self.assertNotIn("retried_not_found", s.summary["errors"])


if __name__ == "__main__":
    unittest.main()
