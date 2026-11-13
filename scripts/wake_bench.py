#!/usr/bin/env python3
"""Wake benchmark for a web app in Spawnbox sandboxes on a real KVM host.
Uses only the standard library. Measures, through the preview listener:

  cold     create a sandbox with the app as a service, then GET until the
           first 200
  resume   pause that sandbox, wait --settle-s, then GET until the first 200
           (the preview request resumes it)
  density  start idle app sandboxes one at a time until host memory use
           reaches --mem-stop-pct, the server refuses, or --density-max
  burst    create --burst sandboxes at once, each timed to its first 200,
           --wake-rounds times
  wake     pause every density sandbox, then wake them all at once,
           --wake-rounds times
  wake_requests
           --wake-requests concurrent requests spread over the paused
           density sandboxes, when there are fewer sandboxes than requests

Cold and resume samples alternate, so drift and warm pools touch both.
Host memory comes from --proc, so run the script on the host for the
density phase. It deletes every sandbox it made, and checks the listing.
"""

import argparse
import base64
import http.client
import json
import math
import os
import platform
import sys
import threading
import time
import urllib.parse

APP = """const http = require("http");
http.createServer((req, res) => {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("ok\\n");
}).listen(Number(process.env.PORT || 3000), "127.0.0.1");
"""
PORT = 3000


def percentile(samples, p):
    """Nearest rank, as in spawn-bench. `p` is 0..=100."""
    if not samples or not 0 <= p <= 100:
        return None
    ordered = sorted(samples)
    return ordered[max(math.ceil(p / 100 * len(ordered)), 1) - 1]


def summarize(samples):
    ok = [s["ms"] for s in samples if s["ok"]]
    out = {"n": len(samples), "failures": len(samples) - len(ok)}
    if ok:
        out.update({f"p{p}": round(percentile(ok, p), 1) for p in (50, 95, 99)})
        out.update(min=round(min(ok), 1), max=round(max(ok), 1), mean=round(sum(ok) / len(ok), 1))
    return out


def meminfo(text):
    """MiB values of /proc/meminfo."""
    out = {}
    for line in text.splitlines():
        name, _, rest = line.partition(":")
        parts = rest.split()
        if parts:
            out[name] = int(parts[0]) / 1024
    return out


def used_pct(mem):
    return 100 * (mem["MemTotal"] - mem["MemAvailable"]) / mem["MemTotal"]


def next_would_cross(mem, per_sandbox_mib, stop_pct):
    """Whether one more sandbox of `per_sandbox_mib` takes used memory to
    `stop_pct` or more."""
    used = mem["MemTotal"] - mem["MemAvailable"] + per_sandbox_mib
    return 100 * used / mem["MemTotal"] >= stop_pct


def disk_mib(path):
    """Allocated MiB under `path` that belong to it alone. Sparse files count
    only written blocks. Hard links, such as the base disks that every paused
    sandbox of a build shares, are left out."""
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                st = os.lstat(os.path.join(root, name))
            except OSError:
                continue
            if st.st_nlink == 1:
                total += st.st_blocks * 512
    return round(total / 2**20, 1)


def app_template(name, vcpus, memory_mib):
    code = base64.b64encode(APP.encode()).decode()
    return {
        "name": name,
        "setup": [f"mkdir -p /opt/app && echo {code} | base64 -d > /opt/app/server.js && node --check /opt/app/server.js"],
        "resources": {"vcpus": vcpus, "memory_mib": memory_mib, "disk_gib": 4},
    }


class Http:
    def __init__(self, url, key):
        u = urllib.parse.urlsplit(url)
        self.host, self.port, self.key = u.hostname, u.port or 80, key

    def call(self, method, path, body=None, timeout=180):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        headers = {"Authorization": "Bearer " + self.key}
        data = None
        if body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        try:
            conn.request(method, "/v1" + path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        finally:
            conn.close()
        try:
            return resp.status, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return resp.status, raw.decode(errors="replace")


class Bench:
    def __init__(self, args):
        self.args = args
        self.api = Http(args.api, args.key)
        addr = urllib.parse.urlsplit("//" + args.preview_addr)
        self.preview = (addr.hostname, addr.port)
        self.host_pattern = None
        self.made = []
        self.result = {"args": {k: v for k, v in vars(args).items() if k != "key"}, "samples": []}

    def log(self, msg):
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)

    def mem(self):
        with open(os.path.join(self.args.proc, "meminfo")) as f:
            return meminfo(f.read())

    def rss_mib(self, comm):
        total = 0.0
        for pid in filter(str.isdigit, os.listdir(self.args.proc)):
            try:
                with open(os.path.join(self.args.proc, pid, "status")) as f:
                    status = f.read()
            except OSError:
                continue
            fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
            if fields.get("Name", "").strip() == comm and "VmRSS" in fields:
                total += int(fields["VmRSS"].split()[0]) / 1024
        return round(total, 1)

    def environment(self):
        env = {"client": platform.platform(), "python": platform.python_version()}
        try:
            mem = self.mem()
            env["mem_total_mib"] = round(mem["MemTotal"])
            with open(os.path.join(self.args.proc, "cpuinfo")) as f:
                cpu = [line.split(":", 1)[1].strip() for line in f if line.startswith("model name")]
            env.update(cpus=len(cpu), cpu=cpu[0] if cpu else None)
            with open(os.path.join(self.args.proc, "loadavg")) as f:
                env["loadavg"] = f.read().split()[:3]
        except OSError:
            pass
        status, tenant = self.api.call("GET", "/sandboxes")
        env["sandboxes_visible_at_start"] = len(tenant.get("sandboxes", [])) if status == 200 else None
        return env

    def ensure_template(self):
        a = self.args
        spec = app_template(a.template, a.vcpus, a.memory_mib)
        status, got = self.api.call("GET", f"/templates/{a.template}")
        if status != 200 or got.get("setup") != spec["setup"] or got.get("resources") != spec["resources"]:
            status, got = self.api.call("POST", "/templates", spec)
            if status not in (200, 201, 202):
                raise SystemExit(f"template create failed: {status} {got}")
        while True:
            status, got = self.api.call("GET", f"/templates/{a.template}")
            build = got["latest_build"]
            if build["state"] == "ready":
                self.log(f"template {a.template} build {build['id']} ready")
                return build
            if build["state"] == "failed":
                raise SystemExit(f"template build failed: {build.get('error')}")
            time.sleep(2)

    def create(self):
        service = {"name": "web", "command": ["node", "/opt/app/server.js"], "port": PORT, "access": "public"}
        if self.args.health:
            service["health"] = {"http": "/", "interval_s": 1, "failures": 30}
        body = {"template": self.args.template, "timeout_s": self.args.timeout_s, "services": [service]}
        status, got = self.api.call("POST", "/sandboxes", body)
        if status not in (200, 201):
            return None, status, got
        self.made.append(got["id"])
        return got, status, None

    def host_of(self, sid):
        if self.host_pattern is None:
            _, ports = self.api.call("GET", f"/sandboxes/{sid}/ports")
            url = urllib.parse.urlsplit(ports["ports"][0]["url"])
            # The host label spells the ID with a dash: 3000-sbx-abc.
            self.host_pattern = url.netloc.replace(sid.replace("_", "-"), "{id}")
            if "{id}" not in self.host_pattern:
                raise SystemExit(f"cannot find the sandbox ID in preview URL {url.netloc}")
        return self.host_pattern.format(id=sid.replace("_", "-"))

    def get_until_200(self, sid, deadline_s=60):
        """GETs the app until it answers 200. Returns (ok, attempts, last)."""
        host = self.host_of(sid)
        end = time.perf_counter() + deadline_s
        attempts, last = 0, None
        while time.perf_counter() < end:
            attempts += 1
            conn = http.client.HTTPConnection(*self.preview, timeout=deadline_s)
            try:
                conn.request("GET", "/", headers={"Host": host})
                resp = conn.getresponse()
                body = resp.read()
                if resp.status == 200 and body.startswith(b"ok"):
                    return True, attempts, 200
                last = resp.status
            except (OSError, http.client.HTTPException) as e:
                last = type(e).__name__
            finally:
                conn.close()
            time.sleep(self.args.poll_ms / 1000)
        return False, attempts, last

    def sample(self, kind, **fields):
        s = {"kind": kind, **fields}
        self.result["samples"].append(s)
        return s

    def cold(self, i):
        t0 = time.perf_counter()
        got, status, err = self.create()
        if got is None:
            return self.sample("cold", i=i, ok=False, ms=None, error=f"{status} {err}"), None
        create_ms = (time.perf_counter() - t0) * 1000
        ok, attempts, last = self.get_until_200(got["id"])
        ms = (time.perf_counter() - t0) * 1000
        s = self.sample("cold", i=i, ok=ok, ms=ms, create_ms=round(create_ms, 1), attempts=attempts,
                        last=last, started_from=got.get("started_from"), timings_ms=got.get("timings_ms"))
        return s, got["id"]

    def pause(self, sid):
        t0 = time.perf_counter()
        status, got = self.api.call("POST", f"/sandboxes/{sid}:pause")
        return status, (time.perf_counter() - t0) * 1000

    def resume(self, i, sid, kind="resume"):
        t0 = time.perf_counter()
        ok, attempts, last = self.get_until_200(sid)
        return self.sample(kind, i=i, sandbox=sid, ok=ok, ms=(time.perf_counter() - t0) * 1000,
                           attempts=attempts, last=last)

    def delete(self, sid):
        self.api.call("DELETE", f"/sandboxes/{sid}")

    def cold_and_resume(self):
        a = self.args
        for i in range(-a.warmup, a.samples):
            s, sid = self.cold(i)
            if sid:
                status, pause_ms = self.pause(sid)
                time.sleep(a.settle_s)
                r = self.resume(i, sid)
                r["pause_ms"], r["pause_status"] = round(pause_ms, 1), status
                self.delete(sid)
                self.log(f"{i:>3} cold {s['ms']:.0f} ms ({s['started_from']}) resume {r['ms']:.0f} ms")
            else:
                self.log(f"{i:>3} cold failed: {s['error']}")
            time.sleep(a.cold_gap_s)

    def density(self):
        a = self.args
        mem0 = self.mem()
        steps = [{"count": 0, "used_mib": round(mem0["MemTotal"] - mem0["MemAvailable"]),
                  "used_pct": round(used_pct(mem0), 1), "firecracker_rss_mib": self.rss_mib("firecracker")}]
        ids, measured, stop = [], None, "density_max"
        while len(ids) < a.density_max:
            mem = self.mem()
            # Until a step is measured, assume the full reservation is used.
            if next_would_cross(mem, measured or a.memory_mib, a.mem_stop_pct):
                stop = f"next sandbox would cross {a.mem_stop_pct}% host memory"
                break
            got, status, err = self.create()
            if got is None:
                stop = f"create refused: {status} {err}"
                break
            ids.append(got["id"])
            ok, _, last = self.get_until_200(got["id"])
            if not ok:
                stop = f"app did not answer: {last}"
                break
            time.sleep(a.idle_s)
            mem = self.mem()
            step = {"count": len(ids), "used_mib": round(mem["MemTotal"] - mem["MemAvailable"]),
                    "used_pct": round(used_pct(mem), 1), "firecracker_rss_mib": self.rss_mib("firecracker")}
            steps.append(step)
            measured = max(1.0, (step["used_mib"] - steps[0]["used_mib"]) / len(ids))
            self.log(f"density {len(ids)}: host used {step['used_pct']}%, firecracker RSS {step['firecracker_rss_mib']} MiB")
        self.result["density"] = {"steps": steps, "stopped_by": stop, "sandboxes": len(ids),
                                  "used_mib_per_sandbox": measured and round(measured, 1)}
        return ids

    def concurrent(self, kind, targets, round_no):
        barrier = threading.Barrier(len(targets))
        out = [None] * len(targets)

        def one(n, sid):
            barrier.wait()
            out[n] = self.resume(round_no, sid, kind)

        threads = [threading.Thread(target=one, args=(n, sid)) for n, sid in enumerate(targets)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return out

    def cold_burst(self):
        """Starts `--burst` sandboxes at once from the template, each timed to
        its first 200, then deletes them. Compares with concurrent wakes."""
        a = self.args
        for r in range(a.wake_rounds):
            barrier = threading.Barrier(a.burst)
            out, ids = [None] * a.burst, [None] * a.burst

            def one(n):
                barrier.wait()
                out[n], ids[n] = self.cold(r)
                out[n]["kind"] = "cold_burst"

            threads = [threading.Thread(target=one, args=(n,)) for n in range(a.burst)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.log(f"cold burst round {r}: {summarize(out)}")
            for sid in ids:
                if sid:
                    self.delete(sid)
            time.sleep(a.settle_s)

    def pause_all(self, ids):
        for sid in ids:
            self.pause(sid)
        time.sleep(self.args.settle_s)
        if self.args.data_dir:
            sizes = [disk_mib(os.path.join(self.args.data_dir, "paused", sid)) for sid in ids]
            self.result.setdefault("paused_disk_mib", []).append(
                {"sandboxes": len(ids), "p50": percentile(sizes, 50), "max": max(sizes)})

    def wakes(self, ids):
        a = self.args
        for r in range(a.wake_rounds):
            self.pause_all(ids)
            got = self.concurrent("wake", ids, r)
            self.log(f"wake round {r}: {summarize(got)}")
        if a.wake_requests > len(ids):
            self.pause_all(ids)
            targets = [ids[n % len(ids)] for n in range(a.wake_requests)]
            got = self.concurrent("wake_requests", targets, 0)
            self.log(f"{a.wake_requests} requests over {len(ids)} sandboxes: {summarize(got)}")

    def cleanup(self):
        for sid in self.made:
            self.delete(sid)
        time.sleep(2)
        status, got = self.api.call("GET", "/sandboxes")
        live = [s["id"] for s in got.get("sandboxes", []) if s["id"] in set(self.made)
                and s["state"] not in ("deleted", "failed")]
        self.result["cleanup"] = {"made": len(self.made), "still_listed": live}
        if self.args.delete_template:
            self.api.call("DELETE", f"/templates/{self.args.template}")
        self.log(f"cleanup: deleted {len(self.made)} sandboxes, still listed: {live}")

    def run(self):
        a = self.args
        self.result["environment"] = self.environment()
        self.result["template_build"] = self.ensure_template()
        started = time.time()
        try:
            if "cold" in a.phases:
                self.cold_and_resume()
            if "burst" in a.phases:
                self.cold_burst()
            if "density" in a.phases:
                ids = self.density()
                if "wake" in a.phases and ids:
                    self.wakes(ids)
        finally:
            self.cleanup()
        self.result["duration_s"] = round(time.time() - started)
        kinds = sorted({s["kind"] for s in self.result["samples"]})
        timed = lambda k: [s for s in self.result["samples"] if s["kind"] == k and s.get("i", 0) >= 0]
        self.result["summary"] = {k: summarize(timed(k)) for k in kinds}
        cold = timed("cold")
        for source in sorted({s.get("started_from") for s in cold if s.get("started_from")}):
            self.result["summary"][f"cold_from_{source}"] = summarize([s for s in cold if s.get("started_from") == source])
        with open(a.summary, "w") as f:
            json.dump(self.result, f, indent=1)
        print(json.dumps({"summary": self.result["summary"], "density": self.result.get("density", {}).get("stopped_by"),
                          "cleanup": self.result["cleanup"]}, indent=1))
        return 1 if self.result["cleanup"]["still_listed"] else 0


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--api", required=True, help="API base URL, for example http://10.0.0.5:8080")
    p.add_argument("--key", default=os.environ.get("SPAWNBOX_API_KEY"), help="tenant key (default $SPAWNBOX_API_KEY)")
    p.add_argument("--preview-addr", required=True, help="host:port of the preview listener")
    p.add_argument("--template", default="bench-node")
    p.add_argument("--vcpus", type=int, default=1)
    p.add_argument("--memory-mib", type=int, default=256)
    p.add_argument("--timeout-s", type=int, default=3600)
    p.add_argument("--phases", default="cold,density,wake", help="comma list of cold, burst, density, wake")
    p.add_argument("--health", action="store_true", help="give the service an HTTP health check (1 s interval)")
    p.add_argument("--samples", type=int, default=30)
    p.add_argument("--warmup", type=int, default=3, help="untimed iterations before the samples")
    p.add_argument("--settle-s", type=float, default=10, help="wait after a pause before the wake")
    p.add_argument("--cold-gap-s", type=float, default=0, help="wait between iterations")
    p.add_argument("--density-max", type=int, default=50)
    p.add_argument("--mem-stop-pct", type=float, default=80)
    p.add_argument("--idle-s", type=float, default=5, help="idle time before reading memory per density step")
    p.add_argument("--poll-ms", type=float, default=10, help="wait between GETs while the app is not up")
    p.add_argument("--burst", type=int, default=22, help="sandboxes started at once in the burst phase")
    p.add_argument("--wake-rounds", type=int, default=3)
    p.add_argument("--wake-requests", type=int, default=50)
    p.add_argument("--proc", default="/proc")
    p.add_argument("--data-dir", help="the server's --data-dir, to size paused sandboxes (run on the host)")
    p.add_argument("--delete-template", action="store_true")
    p.add_argument("--summary", default="wake-bench.json")
    args = p.parse_args(argv)
    if not args.key:
        p.error("--key or SPAWNBOX_API_KEY is required")
    args.phases = args.phases.split(",")
    return args


if __name__ == "__main__":
    sys.exit(Bench(parse_args(sys.argv[1:])).run())
