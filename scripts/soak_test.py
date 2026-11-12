#!/usr/bin/env python3
"""Tests of soak.py's own logic, with the API and hosts stubbed out.
Run: python3 scripts/soak_test.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soak  # noqa: E402


def make(argv=()):
    s = soak.Soak(soak.parse_args(["--api", "http://127.0.0.1:1", "--key", "k", *argv]))
    s.log = lambda msg: None
    soak.time.sleep = lambda _: None
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


if __name__ == "__main__":
    unittest.main()
