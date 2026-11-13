#!/usr/bin/env python3
"""Tests of wake_bench.py's own logic, without a server.
Run: python3 scripts/wake_bench_test.py"""

import base64
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wake_bench  # noqa: E402


class Stats(unittest.TestCase):
    def test_percentile_is_nearest_rank_on_unsorted_input(self):
        samples = [float(n) for n in range(20, 0, -1)]
        self.assertEqual(wake_bench.percentile(samples, 50), 10.0)
        self.assertEqual(wake_bench.percentile(samples, 95), 19.0)
        self.assertEqual(wake_bench.percentile(samples, 100), 20.0)
        self.assertEqual(wake_bench.percentile(samples, 0), 1.0)
        self.assertIsNone(wake_bench.percentile([], 50))
        self.assertIsNone(wake_bench.percentile([1.0], 101))

    def test_summary_counts_failures_and_leaves_them_out_of_latency(self):
        samples = [{"ok": True, "ms": float(n)} for n in range(1, 11)] + [{"ok": False, "ms": 99999.0}]
        self.assertEqual(
            wake_bench.summarize(samples),
            {"n": 11, "failures": 1, "p50": 5.0, "p95": 10.0, "p99": 10.0, "min": 1.0, "max": 10.0, "mean": 5.5},
        )
        self.assertEqual(wake_bench.summarize([{"ok": False, "ms": None}]), {"n": 1, "failures": 1})


class Memory(unittest.TestCase):
    MEMINFO = "MemTotal:        3903488 kB\nMemFree:          451584 kB\nMemAvailable:    3288064 kB\n"

    def test_meminfo_is_in_mib(self):
        mem = wake_bench.meminfo(self.MEMINFO)
        self.assertEqual((mem["MemTotal"], mem["MemAvailable"]), (3812.0, 3211.0))
        self.assertAlmostEqual(wake_bench.used_pct(mem), 15.766, places=3)

    def test_density_stops_before_the_next_sandbox_crosses_the_limit(self):
        mem = {"MemTotal": 1000.0, "MemAvailable": 300.0}
        self.assertFalse(wake_bench.next_would_cross(mem, 99, 80))
        self.assertTrue(wake_bench.next_would_cross(mem, 100, 80))

    def test_disk_size_counts_written_blocks_and_skips_shared_links(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "sbx", "mem"))
            with open(os.path.join(d, "sbx", "mem", "memory"), "wb") as f:
                f.write(b"x" * 2**20)
                f.truncate(100 * 2**20)
            with open(os.path.join(d, "base.ext4"), "wb") as f:
                f.write(b"x" * 4 * 2**20)
            os.link(os.path.join(d, "base.ext4"), os.path.join(d, "sbx", "base.ext4"))
            self.assertGreaterEqual(wake_bench.disk_mib(os.path.join(d, "sbx")), 1.0)
            self.assertLess(wake_bench.disk_mib(os.path.join(d, "sbx")), 2.0)
            self.assertEqual(wake_bench.disk_mib(os.path.join(d, "missing")), 0.0)


class Template(unittest.TestCase):
    def test_setup_writes_the_app_unchanged(self):
        spec = wake_bench.app_template("t", 1, 256)
        encoded = spec["setup"][0].split("echo ", 1)[1].split(" |", 1)[0]
        self.assertEqual(base64.b64decode(encoded).decode(), wake_bench.APP)
        self.assertEqual(spec["resources"], {"vcpus": 1, "memory_mib": 256, "disk_gib": 4})


if __name__ == "__main__":
    unittest.main()
