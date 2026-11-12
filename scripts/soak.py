#!/usr/bin/env python3
"""Soak and failover checks for a Spawnbox server or fleet on real KVM hosts.
Uses only the standard library. Writes a JSON summary and exits 1 if any
invariant is broken, 2 on a usage error, and 3 if the soak could not set up
what it tests (for example it cannot write its markers, or cannot get a
failover sandbox onto its host).

Modes:
  soak      For --duration (default 72h), keeps about --density sandboxes
            of the soak tenant alive and does random actions on them:
            creates (ephemeral and persistent, with a volume, a service
            and env), pauses, wakes, cold starts (kills the VM's
            firecracker process), service crashes (kills the service
            inside the guest), deletes and, with --chaos-every, kill -9
            of a server followed by a restart. Every --check-every it
            checks the invariants below. At the end it wakes every
            persistent sandbox, checks its data and deletes what it made.
  failover  Runs the scenarios in --scenarios once, each against
            persistent sandboxes on one host. New persistent sandboxes
            start on the primary, so each is moved to a worker by cold
            starts (kill its VM, wake it) until placement picks that
            worker, up to --place-tries times. Sandboxes without a volume
            are woken while the host is still cut off, so they start
            again elsewhere before it returns. A cold start prefers the
            host that holds a sandbox's volume, so sandboxes with one
            (--failover-volume-sandboxes, default 0) reach a worker only
            when the primary has no room; the leader scenario always has
            some. Scenarios:
              worker     kill -9 a worker's server, then start it again
              partition  cut a worker off from the primary with iptables,
                         then heal it
              leader     kill -9 the leader (needs a standby host)

Invariants:
  lost       every persistent sandbox answers (within --verify-wait while
             its host restarts or its volume's host is away, and within
             --retry-wait, with backoff, while a wake or check fails with a
             retryable error such as no_capacity), with its volume marker
             intact, and its disk marker ($HOME of the guest's default
             user) intact unless it was cold started
             since the marker was written; its env value is still there
  duplicate  a sandbox's VM never runs on two hosts at once, nor twice on
             one host, and runs only on the host the API names
  leak       no jail dir, network namespace, cgroup or host link stays
             behind for a sandbox that was deleted, is cold or moved;
             names of no known sandbox (warm pools, builds, other
             tenants) stay under --leak-slack per host; nftables and
             iptables rule counts come back to their first values
  service    a killed service runs again with a higher restart count
  growth     spawn-api's resident memory and open files on each host grow
             by less than --max-rss-growth-mib and --max-fd-growth from
             their values after --warmup
  fencing    (failover) no sample taken on a cut-off host after the API
             made a sandbox cold shows its VM, during the cut, the 15 s
             after, and after the host returns
  api        no request fails with 500 internal

Hosts are reached with ssh as a user that can run ps, ip, nft, iptables and
kill (root, or set --sudo). Name each host with --host NAME=TARGET, where
NAME is a worker's node ID, `primary` or `standby`, and TARGET is what ssh
takes, such as root@10.0.0.5. Pass ssh options with --ssh-opt, for example
--ssh-opt=-i --ssh-opt=/path/to/key. Without --host the host checks are
skipped and only API checks run.

Examples:
  soak.py --api http://10.0.0.5:8080 --key "$KEY" --host primary=root@10.0.0.5 \\
      --host node_abc=root@10.0.0.6 --density 30 --duration 72h --chaos-every 6h
  soak.py --mode failover --api http://10.0.0.5:8080 --api http://10.0.0.7:8080 \\
      --key "$KEY" --host primary=root@10.0.0.5 --host standby=root@10.0.0.7 \\
      --host node_abc=root@10.0.0.6 --primary-ip 10.0.0.5 --fence-after-s 60
  soak.py --dry-run --api http://127.0.0.1:8080 --key "$KEY"
"""

import argparse
import http.client
import json
import os
import random
import re
import shlex
import ssl
import subprocess
import sys
import time
import urllib.parse

LIVE = ("starting", "running", "paused")
# 503 codes that mean "not yet": the sandbox's host is restarting or cut
# off, a wake is under way, or a volume's host is away.
# Setup errors in a row that stop the run.
SETUP_ERRORS_IN_A_ROW = 3


class SetupError(Exception):
    """The soak cannot set up what it tests; not a fault of the server."""


NOT_YET = ("node_unreachable", "sandbox_cold", "rebuilding", "volume_unavailable")
VM_NAME = re.compile(r"sbx-[a-z0-9]{8,}")
SOAK_NAME = re.compile(r"^soak-")


def duration(text):
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", text.strip())
    if not m:
        raise argparse.ArgumentTypeError(f"not a duration: {text!r} (use 90s, 30m, 72h or 3d)")
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def parse_args(argv):
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        epilog=__doc__.split("\n\n", 1)[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--mode", choices=["soak", "failover"], default="soak")
    p.add_argument("--api", action="append", default=[], help="API base URL; repeat for a standby (default $SPAWNBOX_URL)")
    p.add_argument("--key", default=os.environ.get("SPAWNBOX_API_KEY"), help="org API key (default $SPAWNBOX_API_KEY)")
    p.add_argument("--insecure", action="store_true", help="do not check the API's TLS certificate")
    p.add_argument("--tenant", default="soak", help="tenant the sandboxes and volumes are made in (created if missing)")
    p.add_argument("--template", help="template for new sandboxes (default: the server's default)")
    p.add_argument("--duration", type=duration, default=duration("72h"))
    p.add_argument("--density", type=int, default=20, help="target number of live soak sandboxes")
    p.add_argument("--persistent-ratio", type=float, default=0.5)
    p.add_argument("--interval", type=duration, default=duration("5s"), help="pause between actions")
    p.add_argument("--check-every", type=duration, default=duration("5m"))
    p.add_argument("--warmup", type=duration, default=duration("30m"), help="time before memory and fd baselines are taken")
    p.add_argument("--chaos-every", type=duration, default=0, help="kill -9 a random server this often (0: never)")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--volume-gib", type=int, default=1)
    p.add_argument("--service-command", default="while :; do sleep 1; done", help="shell command of the soak service")
    p.add_argument("--host", action="append", default=[], metavar="NAME=TARGET")
    p.add_argument("--ssh-opt", action="append", default=[], help="option passed to ssh; repeat")
    p.add_argument("--sudo", action="store_true", help="run host commands with sudo")
    p.add_argument("--data-dir", default="/var/lib/spawnbox", help="--data-dir of spawn-api on the hosts")
    p.add_argument("--server-kill-cmd", default="systemctl kill -s KILL spawnbox", help="kills the server on a host")
    p.add_argument("--server-start-cmd", default="systemctl start spawnbox", help="starts it again")
    p.add_argument("--leak-slack", type=int, default=8, help="resources of unknown sandboxes allowed per host and kind")
    p.add_argument("--leak-grace", type=duration, default=duration("3m"), help="time a stale resource may take to go")
    p.add_argument("--max-rss-growth-mib", type=int, default=512)
    p.add_argument("--max-fd-growth", type=int, default=2000)
    p.add_argument("--scenarios", default="worker,partition,leader", help="failover scenarios, comma separated")
    p.add_argument("--failover-sandboxes", type=int, default=4,
                   help="persistent sandboxes without a volume per failover scenario")
    p.add_argument("--failover-volume-sandboxes", type=int, default=0,
                   help="persistent sandboxes with a volume per worker or partition scenario; they reach a worker"
                        " only when the primary has no room (the leader scenario always uses some)")
    p.add_argument("--place-tries", type=int, default=12,
                   help="cold starts tried to move a failover sandbox onto its host")
    p.add_argument("--primary-ip", help="primary's address as workers reach it (partition)")
    p.add_argument("--fleet-port", type=int, default=7443)
    p.add_argument("--node-port", type=int, default=7444)
    p.add_argument("--fence-after-s", type=int, default=60)
    p.add_argument("--fence-margin-s", type=int, default=30)
    p.add_argument("--verify-wait", type=duration, default=duration("3m"),
                   help="time a restarting host or an away volume may take before a sandbox counts as lost")
    p.add_argument("--retry-wait", type=duration, default=duration("90s"),
                   help="time a wake or check that fails with a retryable error, such as no_capacity, is asked again")
    p.add_argument("--summary", default="soak-summary.json")
    p.add_argument("--keep", action="store_true", help="do not delete the soak's sandboxes and volumes at the end")
    p.add_argument("--dry-run", action="store_true", help="print the plan and run read-only probes only")
    args = p.parse_args(argv)
    if not args.api and os.environ.get("SPAWNBOX_URL"):
        args.api = [os.environ["SPAWNBOX_URL"]]
    if not args.api:
        p.error("--api is required")
    if not args.key and not args.dry_run:
        p.error("--key or SPAWNBOX_API_KEY is required")
    hosts = {}
    for item in args.host:
        name, sep, target = item.partition("=")
        if not sep or not name or not target:
            p.error(f"--host takes NAME=TARGET, not {item!r}")
        hosts[name] = target
    args.hosts = hosts
    args.scenarios = [s for s in args.scenarios.split(",") if s]
    for s in args.scenarios:
        if s not in ("worker", "partition", "leader"):
            p.error(f"unknown scenario {s!r}")
    if not 0 <= args.persistent_ratio <= 1:
        p.error("--persistent-ratio must be 0 to 1")
    return args


class Api:
    """Requests to whichever --api URL answers; a standby answers only after
    it takes over."""

    def __init__(self, urls, key, insecure, log):
        self.urls = [urllib.parse.urlsplit(u) for u in urls]
        self.key = key
        self.log = log
        self.current = 0
        self.ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()

    def _once(self, url, method, path, body, timeout):
        cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        kw = {"context": self.ctx} if url.scheme == "https" else {}
        conn = cls(url.hostname, url.port, timeout=timeout, **kw)
        headers = {"Accept": "application/json"}
        if self.key:
            headers["Authorization"] = "Bearer " + self.key
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, (url.path.rstrip("/") or "") + path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        finally:
            conn.close()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = raw.decode(errors="replace")
        return resp.status, parsed

    def request(self, method, path, body=None, timeout=300, wait=180):
        """Retries connection failures on every URL for up to `wait` seconds,
        since a server may be restarting. Never resends a request that got
        an answer."""
        deadline = time.time() + wait
        while True:
            for i in range(len(self.urls)):
                n = (self.current + i) % len(self.urls)
                try:
                    status, body_out = self._once(self.urls[n], method, path, body, timeout)
                except (OSError, http.client.HTTPException):
                    continue
                if status == 503 and len(self.urls) > 1 and code(body_out) in ("not_leader", "standby"):
                    continue
                self.current = n
                return status, body_out
            if time.time() > deadline:
                return 0, {"error": {"code": "unreachable", "message": f"no API answered {method} {path}"}}
            time.sleep(2)

    def healthy(self):
        for url in self.urls:
            try:
                status, _ = self._once(url, "GET", "/healthz", None, 5)
                if status == 200:
                    return url.geturl()
            except (OSError, http.client.HTTPException):
                pass
        return None


def retryable(status, body):
    """Whether a failed call may work if asked again soon."""
    if status == 503:
        return True
    if isinstance(body, dict) and isinstance(body.get("error"), dict) and body["error"].get("retryable") is True:
        return True
    return code(body) in ("no_capacity", "conflict")


def code(body):
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        return body["error"].get("code")
    return None


class Hosts:
    def __init__(self, args, log):
        self.args = args
        self.log = log

    def names(self):
        return list(self.args.hosts)

    def run(self, name, script, timeout=60):
        target = self.args.hosts[name]
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", *self.args.ssh_opt, target]
        remote = ("sudo " if self.args.sudo else "") + "sh -c " + shlex.quote(script)
        try:
            out = subprocess.run(cmd + [remote], capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, ""
        return out.returncode, out.stdout

    def sample(self, name):
        """Processes, host resources and spawn-api's memory and fds."""
        d = shlex.quote(self.args.data_dir)
        script = f"""
echo @@PS; ps -eo pid=,comm=,args= 2>/dev/null
echo @@NETNS; ip netns list 2>/dev/null | awk '{{print $1}}'
echo @@LINKS; ip -o link show 2>/dev/null | awk -F': ' '{{print $2}}' | cut -d@ -f1
echo @@JAILS; ls -1 {d}/jails/firecracker 2>/dev/null
echo @@CGROUPS; find /sys/fs/cgroup/spawnbox -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' 2>/dev/null
echo @@NFT; nft list ruleset 2>/dev/null | wc -l
echo @@IPT; iptables-save 2>/dev/null | grep -c '^-A'
echo @@API; pid=$(pgrep -xo spawn-api); if [ -n "$pid" ]; then
  echo "pid $pid"; awk '/^VmRSS/ {{print "rss_kib", $2}}' /proc/$pid/status; echo "fds $(ls /proc/$pid/fd | wc -l)"; fi
"""
        rc, out = self.run(name, script)
        if rc not in (0, 1) or "@@PS" not in out:
            return None
        parts, cur = {}, None
        for line in out.splitlines():
            if line.startswith("@@"):
                cur = line[2:]
                parts[cur] = []
            elif cur:
                parts[cur].append(line)
        vms = {}
        for line in parts.get("PS", []):
            fields = line.split(None, 2)
            if len(fields) < 3:
                continue
            comm, cmdline = fields[1], fields[2]
            if comm == "firecracker":
                m = re.search(r"--id (\S+)", cmdline)
                if m:
                    vms[m.group(1)] = vms.get(m.group(1), 0) + 1
            elif comm.startswith("runsc"):
                for name_ in set(VM_NAME.findall(cmdline)):
                    vms.setdefault(name_, 1)
        netns = {re.sub(r"-guest$", "", n.removeprefix("spawnbox-")) for n in parts.get("NETNS", []) if n.startswith("spawnbox-")}
        links = [n for n in parts.get("LINKS", []) if re.fullmatch(r"sbx\d+", n)]
        api = dict(line.split(None, 1) for line in parts.get("API", []) if " " in line)
        return {
            "vms": vms,
            "netns": netns,
            "links": len(links),
            "jails": {n for n in parts.get("JAILS", []) if n},
            "cgroups": {n for n in parts.get("CGROUPS", []) if VM_NAME.fullmatch(n)},
            "nft": int((parts.get("NFT") or ["0"])[0] or 0),
            "ipt": int((parts.get("IPT") or ["0"])[0] or 0),
            "pid": api.get("pid"),
            "rss_kib": int(api["rss_kib"]) if "rss_kib" in api else None,
            "fds": int(api["fds"]) if "fds" in api else None,
        }


def host_name(sid):
    return sid.replace("_", "-")


class Soak:
    def __init__(self, args):
        self.args = args
        self.rng = random.Random(args.seed)
        self.started = time.time()
        self.summary = {
            "mode": args.mode,
            "seed": args.seed,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "actions": {},
            "errors": {},
            "violations": [],
            "setup_errors": [],
            "checks": 0,
            "growth": {},
            "scenarios": [],
        }
        self.api = Api(args.api, args.key, args.insecure, self.log)
        self.hosts = Hosts(args, self.log)
        # id -> {persistent, token, volume, disk_gen, generation, state}
        self.mine = {}
        self.suspects = {}
        self.baselines = {}
        self.first_rules = {}
        self.seq = 0
        self.setup_streak = 0

    # --- reporting -------------------------------------------------------

    def log(self, msg):
        t = time.time() - self.started
        print(f"[{int(t // 3600):02d}:{int(t % 3600 // 60):02d}:{int(t % 60):02d}] {msg}", flush=True)

    def setup_error(self, detail):
        """Records a fault of the soak's own setup, not of the server. A few
        in a row stop the run: it would only repeat them."""
        self.log(f"SETUP ERROR: {detail}")
        self.summary["setup_errors"].append({"at_s": round(time.time() - self.started), "detail": detail})
        self.setup_streak += 1
        if self.setup_streak >= SETUP_ERRORS_IN_A_ROW:
            raise SetupError(f"{SETUP_ERRORS_IN_A_ROW} setup errors in a row; the last: {detail}")

    def violate(self, kind, detail):
        self.summary["violations"].append({"at_s": round(time.time() - self.started), "kind": kind, "detail": detail})
        self.log(f"VIOLATION {kind}: {detail}")

    def count(self, action, result="ok"):
        a = self.summary["actions"].setdefault(action, {})
        a[result] = a.get(result, 0) + 1

    def call(self, method, path, body=None, **kw):
        status, out = self.api.request(method, path, body, **kw)
        c = code(out)
        if status >= 400 or status == 0:
            self.summary["errors"][c or str(status)] = self.summary["errors"].get(c or str(status), 0) + 1
            if status == 500 or c == "internal":
                self.violate("api", f"{method} {path}: {status} {json.dumps(out)[:300]}")
        return status, out

    def write_summary(self):
        self.summary["elapsed_s"] = round(time.time() - self.started)
        self.summary["ok"] = not self.summary["violations"] and not self.summary["setup_errors"]
        with open(self.args.summary, "w") as f:
            json.dump(self.summary, f, indent=2, sort_keys=True)
        self.log(f"summary in {self.args.summary}: {len(self.summary['violations'])} violation(s)")

    # --- sandboxes -------------------------------------------------------

    def tq(self):
        return "tenant=" + urllib.parse.quote(self.args.tenant)

    def setup(self):
        status, out = self.call("POST", "/v1/tenants", {"id": self.args.tenant, "quotas": {
            "persistent_sandboxes": max(self.args.density * 2, self.args.failover_sandboxes * 2)}})
        if status not in (200, 201, 409):
            raise SystemExit(f"cannot create tenant {self.args.tenant}: {status} {out}")

    def exec(self, sid, cmd, timeout=300):
        status, out = self.call("POST", f"/v1/sandboxes/{sid}/exec", {"cmd": cmd}, timeout=timeout)
        if status != 200 or not isinstance(out, dict):
            return None, status, out
        return out.get("stdout", ""), out.get("exit_code"), out

    def get(self, sid):
        status, out = self.call("GET", f"/v1/sandboxes/{sid}")
        return out if status == 200 and isinstance(out, dict) else None

    def listing(self):
        """Every sandbox of the soak tenant, as the API sees them."""
        seen, cursor = {}, None
        while True:
            q = f"/v1/sandboxes?{self.tq()}&limit=200" + (f"&cursor={cursor}" if cursor else "")
            status, out = self.call("GET", q)
            if status != 200:
                return None
            for s in out.get("sandboxes", []):
                seen[s["id"]] = s
            cursor = out.get("next_cursor")
            if not cursor:
                return seen

    def create(self, persistent, volume=True):
        self.seq += 1
        token = f"{int(time.time())}-{self.seq}-{self.rng.getrandbits(32):08x}"
        spec = {
            "tenant": self.args.tenant,
            "env": {"SOAK_TOKEN": token},
            "services": [{"name": "soak", "command": ["sh", "-c", self.args.service_command]}],
        }
        if self.args.template:
            spec["template"] = self.args.template
        if not persistent or not volume:
            volume = None
        if volume:
            volume = f"soak-{self.seq}-{self.rng.getrandbits(16):04x}"
            status, out = self.call("POST", "/v1/volumes", {"name": volume, "size_gib": self.args.volume_gib, "tenant": self.args.tenant})
            if status not in (200, 201):
                self.count("create_persistent", f"volume_{code(out) or status}")
                return None
            spec["volumes"] = [{"volume": volume, "path": "/data"}]
        if persistent:
            spec["persistent"] = True
        else:
            spec["timeout_s"] = 3600
        status, out = self.call("POST", "/v1/sandboxes", spec)
        kind = "create_persistent" if persistent else "create_ephemeral"
        if status not in (200, 201):
            self.count(kind, code(out) or str(status))
            if volume:
                self.call("DELETE", f"/v1/volumes/{volume}?{self.tq()}")
            return None
        sid = out["id"]
        rec = {"persistent": persistent, "token": token, "volume": volume, "disk_gen": None, "generation": out.get("generation", 1)}
        self.mine[sid] = rec
        if persistent:
            data = f"echo {token} > /data/soak-marker && " if volume else ""
            stdout, exit_code, raw = self.exec(sid, f'{data}echo {token} > "$HOME/soak-marker" && sync && echo ok')
            if exit_code != 0 or (stdout or "").strip() != "ok":
                # Nothing was stored yet, so nothing is lost: the soak
                # itself cannot do its work.
                self.count(kind, "marker_write_failed")
                self.delete(sid)
                self.setup_error(f"{sid}: cannot write the markers: {json.dumps(raw)[:300]}")
                return None
            self.setup_streak = 0
            rec["disk_gen"] = self.generation(sid)
        self.count(kind)
        self.log(f"created {'persistent' if persistent else 'ephemeral'} {sid}")
        return sid

    def generation(self, sid):
        s = self.get(sid)
        return s.get("generation") if s else None

    def verify(self, sid, why, wait=None):
        """The sandbox answers and still has its data. Answers that only mean
        "not yet", such as a host that is restarting or a volume whose host
        is away, are asked again for up to `wait` seconds. Other retryable
        answers, such as no room to wake it now, are asked again with
        backoff for up to --retry-wait. A persistent sandbox that still does
        not answer then, or answers with an error that is not retryable,
        is lost."""
        rec = self.mine[sid]
        now = time.time()
        deadline = now + (self.args.verify_wait if wait is None else wait)
        busy_deadline = now + self.args.retry_wait
        backoff = 2
        while True:
            stdout, exit_code, raw = self.exec(
                sid, 'printf "%s|%s|%s" "$(cat /data/soak-marker 2>/dev/null)" "$(cat "$HOME/soak-marker" 2>/dev/null)" "$SOAK_TOKEN"'
            )
            if stdout is not None:
                break
            c = code(raw) or str(exit_code)
            if exit_code == 503 and c in NOT_YET and time.time() < deadline:
                self.count("verify_wait", c)
                time.sleep(5)
                continue
            if retryable(exit_code, raw) and time.time() < busy_deadline:
                key = "retried_" + c
                self.summary["errors"][key] = self.summary["errors"].get(key, 0) + 1
                time.sleep(min(backoff, max(0.0, busy_deadline - time.time())))
                backoff = min(backoff * 2, 20)
                continue
            break
        if stdout is None:
            if rec["persistent"]:
                self.violate("lost", f"{sid} ({why}) does not answer: {exit_code} {json.dumps(raw)[:300]}")
            return False
        vol, disk, env = (stdout.split("|") + ["", "", ""])[:3]
        gen = self.generation(sid)
        if env != rec["token"]:
            self.violate("lost", f"{sid} ({why}): env SOAK_TOKEN is {env!r}")
        if rec["persistent"]:
            if rec["volume"] and vol != rec["token"]:
                self.violate("lost", f"{sid} ({why}): volume marker is {vol!r}, wanted {rec['token']!r}")
            if rec["disk_gen"] == gen and disk != rec["token"]:
                self.violate("lost", f"{sid} ({why}): disk marker is {disk!r} at the same generation {gen}")
            if rec["disk_gen"] != gen:
                # A cold start keeps volumes only; write the disk marker again.
                self.exec(sid, f"echo {rec['token']} > \"$HOME/soak-marker\" && sync")
                rec["disk_gen"] = gen
        if gen is not None and rec["generation"] is not None and gen < rec["generation"]:
            self.violate("duplicate", f"{sid}: generation went back from {rec['generation']} to {gen}")
        rec["generation"] = gen
        self.count("verify")
        return True

    def delete(self, sid):
        rec = self.mine.pop(sid)
        status, out = self.call("DELETE", f"/v1/sandboxes/{sid}")
        self.count("delete", "ok" if status in (200, 204, 404) else code(out) or str(status))
        if rec["volume"]:
            for _ in range(30):
                status, out = self.call("DELETE", f"/v1/volumes/{rec['volume']}?{self.tq()}")
                if status in (200, 204, 404):
                    break
                time.sleep(2)
            else:
                self.violate("leak", f"volume {rec['volume']} of deleted {sid} cannot be deleted: {status} {out}")

    def pick(self, persistent=None, states=None):
        ids = [s for s, r in self.mine.items() if persistent is None or r["persistent"] == persistent]
        if states is not None:
            listing = self.listing() or {}
            ids = [s for s in ids if listing.get(s, {}).get("state") in states]
        return self.rng.choice(ids) if ids else None

    def host_of(self, view):
        node = view.get("node")
        if node and node in self.args.hosts:
            return node
        if not node:
            for name in ("primary", "standby"):
                if name in self.args.hosts:
                    sample = self.hosts.sample(name)
                    if sample and host_name(view["id"]) in sample["vms"]:
                        return name
        return None

    # --- actions ---------------------------------------------------------

    def act_pause(self):
        sid = self.pick(states=("running",))
        if sid:
            status, out = self.call("POST", f"/v1/sandboxes/{sid}:pause")
            self.count("pause", "ok" if status in (200, 204) else code(out) or str(status))

    def act_wake(self):
        sid = self.pick(states=("paused", "cold"))
        if sid:
            self.verify(sid, "wake")

    def act_cold_start(self):
        sid = self.pick(persistent=True, states=("running",))
        if not sid or not self.args.hosts:
            return
        view = self.get(sid)
        host = view and self.host_of(view)
        if not host:
            self.count("cold_start", "no_host")
            return
        gen = view.get("generation")
        if not self.kill_vm(sid, host):
            return
        if self.verify(sid, "cold start"):
            if (self.mine[sid]["generation"] or 0) <= (gen or 0):
                self.violate("duplicate", f"{sid}: cold start kept generation {gen}")
            self.count("cold_start")

    def kill_vm(self, sid, host):
        """Kills the VM of `sid` on `host` and waits until the API says cold."""
        self.hosts.run(host, f"pkill -9 -f -- '--id {host_name(sid)}( |$)'")
        for _ in range(90):
            s = self.get(sid)
            if s and s.get("state") == "cold":
                return True
            time.sleep(1)
        self.violate("lost", f"{sid}: did not become cold after its VM was killed on {host}")
        return False

    def act_service_crash(self):
        sid = self.pick(states=("running",))
        if not sid:
            return
        status, out = self.call("GET", f"/v1/sandboxes/{sid}/services")
        svc = next((s for s in (out or {}).get("services", []) if s.get("name") == "soak"), None) if status == 200 else None
        if not svc or not svc.get("pid"):
            self.count("service_crash", "no_pid")
            return
        before = svc.get("restarts", 0)
        self.exec(sid, f"kill -9 {svc['pid']}")
        for _ in range(60):
            time.sleep(1)
            status, out = self.call("GET", f"/v1/sandboxes/{sid}/services")
            svc = next((s for s in (out or {}).get("services", []) if s.get("name") == "soak"), None)
            if svc and svc.get("restarts", 0) > before and svc.get("state") in ("starting", "healthy") and svc.get("pid"):
                self.count("service_crash")
                return
        self.violate("service", f"{sid}: service did not come back after kill -9: {svc}")

    def act_chaos(self):
        if not self.args.hosts:
            return
        host = self.rng.choice(self.hosts.names())
        self.log(f"chaos: kill -9 the server on {host}")
        self.hosts.run(host, self.args.server_kill_cmd)
        time.sleep(3)
        self.hosts.run(host, self.args.server_start_cmd)
        self.baselines = {k: v for k, v in self.baselines.items() if k[0] != host}
        if not self.wait_ready(host):
            self.violate("api", f"{host} is not ready {self.args.verify_wait}s after a restart")
        # Ephemeral sandboxes on that host are gone by design.
        listing = self.listing() or {}
        for sid, rec in list(self.mine.items()):
            if not rec["persistent"] and listing.get(sid, {}).get("state") not in LIVE:
                self.mine.pop(sid)
                self.count("chaos_ephemeral_lost")
        self.count("chaos")

    # --- invariants ------------------------------------------------------

    def check(self, final=False):
        self.summary["checks"] += 1
        listing = self.listing()
        if listing is None:
            self.violate("api", "cannot list sandboxes")
            return
        for sid, rec in self.mine.items():
            view = listing.get(sid)
            if rec["persistent"] and (not view or view.get("state") in ("deleted", "failed")):
                self.violate("lost", f"{sid}: persistent sandbox is {view and view.get('state')}")
        if self.args.hosts:
            self.check_hosts(listing, final)
        persistent = [s for s, r in self.mine.items() if r["persistent"]]
        sample = persistent if final else self.rng.sample(persistent, min(3, len(persistent)))
        for sid in sample:
            self.verify(sid, "final check" if final else "check")

    def check_hosts(self, listing, final):
        samples = {h: self.hosts.sample(h) for h in self.hosts.names()}
        now = time.time()
        where = {}
        for host, s in samples.items():
            if s is None:
                self.log(f"host {host}: no sample (ssh failed)")
                continue
            for name, n in s["vms"].items():
                where.setdefault(name, []).append(host)
                if n > 1:
                    self.violate("duplicate", f"{name}: {n} firecracker processes on {host}")
        by_name = {host_name(sid): v for sid, v in listing.items()}
        seen = set()
        for name, hosts in where.items():
            view = by_name.get(name)
            if len(hosts) > 1:
                self.violate("duplicate", f"{name} runs on {hosts}")
            if view and view.get("node") and view["node"] in self.args.hosts and hosts[0] != view["node"]:
                key = (hosts[0], "vm", name)
                seen.add(key)
                self.suspects.setdefault(key, now)
                if now - self.suspects[key] > self.args.leak_grace:
                    self.violate("duplicate", f"{name} runs on {hosts[0]} but the API says {view['node']}")
        live_here = {h: set() for h in samples}
        for name, view in by_name.items():
            if view.get("state") in LIVE:
                node = view.get("node")
                for h in samples:
                    if (node and h == node) or (not node and h in ("primary", "standby")):
                        live_here[h].add(name)
        for host, s in samples.items():
            if s is None:
                continue
            for kind in ("netns", "jails", "cgroups"):
                unknown = 0
                for name in s[kind]:
                    view = by_name.get(name)
                    if view is None:
                        unknown += 1
                        continue
                    if name in live_here[host]:
                        continue
                    key = (host, kind, name)
                    seen.add(key)
                    self.suspects.setdefault(key, now)
                    if now - self.suspects[key] > self.args.leak_grace:
                        self.violate("leak", f"{kind} {name} on {host}; the sandbox is {view.get('state')} on {view.get('node') or 'a primary'}")
                        self.suspects[key] = now
                if unknown > self.args.leak_slack:
                    self.violate("leak", f"{unknown} {kind} on {host} belong to no sandbox of the tenant (slack {self.args.leak_slack})")
            if s["links"] > len(s["netns"]) + self.args.leak_slack:
                self.violate("leak", f"{s['links']} host links but {len(s['netns'])} namespaces on {host}")
            first = self.first_rules.setdefault(host, (s["nft"], s["ipt"]))
            if final and not self.mine and (s["nft"] > first[0] + self.args.leak_slack or s["ipt"] > first[1]):
                self.violate("leak", f"rules on {host}: nft {first[0]} -> {s['nft']} lines, iptables {first[1]} -> {s['ipt']}")
            self.check_growth(host, s)
        self.suspects = {k: v for k, v in self.suspects.items() if k in seen}

    def check_growth(self, host, s):
        if s["pid"] is None or s["rss_kib"] is None:
            return
        key = (host, s["pid"])
        g = self.summary["growth"].setdefault(host, {})
        g["rss_mib_max"] = max(g.get("rss_mib_max", 0), s["rss_kib"] // 1024)
        g["fds_max"] = max(g.get("fds_max", 0), s["fds"] or 0)
        if time.time() - self.started < min(self.args.warmup, self.args.duration / 4):
            return
        base = self.baselines.setdefault(key, (s["rss_kib"], s["fds"]))
        g["baseline"] = {"pid": s["pid"], "rss_mib": base[0] // 1024, "fds": base[1]}
        if s["rss_kib"] - base[0] > self.args.max_rss_growth_mib * 1024:
            self.violate("growth", f"spawn-api on {host} grew from {base[0] // 1024} to {s['rss_kib'] // 1024} MiB")
            self.baselines[key] = (s["rss_kib"], s["fds"])
        if s["fds"] is not None and base[1] is not None and s["fds"] - base[1] > self.args.max_fd_growth:
            self.violate("growth", f"spawn-api on {host} went from {base[1]} to {s['fds']} open files")
            self.baselines[key] = (s["rss_kib"], s["fds"])

    # --- soak ------------------------------------------------------------

    def soak(self):
        self.setup()
        end = self.started + self.args.duration
        next_check = time.time() + self.args.check_every
        next_chaos = time.time() + self.args.chaos_every if self.args.chaos_every else None
        self.check()
        while time.time() < end:
            live = len(self.mine)
            weights = {
                "create": 6 if live < self.args.density else 1 if live < self.args.density * 1.2 else 0,
                "delete": 1 if live < self.args.density else 4,
                "pause": 3,
                "wake": 3,
                "cold_start": 1,
                "service_crash": 1,
            }
            action = self.rng.choices(list(weights), list(weights.values()))[0]
            try:
                if action == "create":
                    self.create(self.rng.random() < self.args.persistent_ratio)
                elif action == "delete":
                    sid = self.pick()
                    if sid:
                        self.delete(sid)
                else:
                    getattr(self, "act_" + action)()
            except Exception as e:  # keep soaking; a crash of the script is not a server fault
                self.log(f"{action} raised {e!r}")
                self.count(action, "script_error")
            if next_chaos and time.time() >= next_chaos:
                self.act_chaos()
                next_chaos = time.time() + self.args.chaos_every
            if time.time() >= next_check:
                self.check()
                self.write_summary()
                next_check = time.time() + self.args.check_every
            time.sleep(self.args.interval)
        self.check(final=True)
        self.teardown()

    def teardown(self):
        if self.args.keep:
            return
        for sid in list(self.mine):
            self.delete(sid)
        if self.args.hosts:
            self.log(f"waiting {int(self.args.leak_grace)}s, then checking that nothing stayed behind")
            time.sleep(self.args.leak_grace + 5)
            listing = self.listing()
            if listing is not None:
                self.check_hosts(listing, final=True)
                time.sleep(self.args.leak_grace + 5)
                self.check_hosts(self.listing() or listing, final=True)

    # --- failover --------------------------------------------------------

    def watch_copies(self, ids, seconds, cut_host, cold_at=None, until_cold=False, grace=15):
        """Polls every host's processes and the API for `seconds`, or, with
        `until_cold`, until every sandbox is cold and then `grace` more
        seconds. Flags a sandbox running on two hosts, and any VM seen on
        `cut_host` in a sample taken after the API said it was cold.
        Returns per id when its VM was last seen on each host, and when the
        API first said cold."""
        names = {host_name(s): s for s in ids}
        last_seen = {}
        cold_at = {} if cold_at is None else cold_at
        end = time.time() + seconds
        while time.time() < end:
            where = {}
            for host in self.hosts.names():
                t = time.time()
                s = self.hosts.sample(host)
                if s is None:
                    continue
                for name in s["vms"]:
                    if name not in names:
                        continue
                    sid = names[name]
                    where.setdefault(sid, []).append(host)
                    last_seen[(sid, host)] = t
                    if host == cut_host and sid in cold_at and t > cold_at[sid]:
                        self.violate("fencing", f"{sid} still runs on {host} {round(t - cold_at[sid], 1)}s after it went cold")
            for sid, hosts in where.items():
                if len(hosts) > 1:
                    self.violate("duplicate", f"{sid} runs on {hosts} at once")
            for sid in ids:
                if sid not in cold_at:
                    v = self.get(sid)
                    if v and v.get("state") == "cold":
                        cold_at[sid] = time.time()
            if until_cold and len(cold_at) == len(ids):
                end = min(end, time.time() + grace)
                until_cold = False
            time.sleep(2)
        return last_seen, cold_at

    def place(self, n, want_host, volume=True):
        """Creates `n` persistent sandboxes running on `want_host`. They are
        made on the primary, so each one is moved by cold starts: kill its
        VM and wake it, until placement picks `want_host`. Raises
        SetupError if one does not get there."""
        ids = []
        try:
            for _ in range(n):
                sid = None
                for _ in range(3):
                    sid = self.create(True, volume)
                    if sid:
                        break
                if not sid:
                    raise SetupError(f"cannot create a persistent sandbox to place on {want_host}; see the errors in the summary")
                ids.append(sid)
                where = self.move_to(sid, want_host)
                if where != want_host:
                    why = (" A cold start prefers the host that holds the sandbox's volume, which is the primary"
                           " where it was made, so one with a volume reaches a worker only when the primary has"
                           " no room.") if volume else ""
                    raise SetupError(f"{sid} still runs on {where} after {self.args.place_tries} cold starts,"
                                     f" not on {want_host}.{why}")
        except SetupError:
            for sid in ids:
                self.delete(sid)
            raise
        return ids

    def move_to(self, sid, want_host):
        """Cold starts `sid` until it runs on `want_host`, at most
        --place-tries times. Returns the host it runs on at the end."""
        where = None
        for attempt in range(self.args.place_tries + 1):
            view = self.get(sid)
            where = view and self.host_of(view)
            if where == want_host and view.get("state") == "running":
                if attempt:
                    self.log(f"placed {sid} on {want_host} after {attempt} cold start(s)")
                return where
            if attempt == self.args.place_tries:
                break
            if view and view.get("state") == "running" and where:
                if not self.kill_vm(sid, where):
                    return where
            self.verify(sid, f"placing on {want_host}")
            self.count("place_cold_start")
        return where

    def scenario(self, name, host, ids, cut, heal):
        """Runs one failover: `cut` breaks the host, then checks the design's
        fencing order, cold starts elsewhere and the data, then `heal`.
        Sandboxes without a volume are woken while the host is still cut, so
        a second copy starts elsewhere before the old one could return."""
        result = {"scenario": name, "host": host, "sandboxes": ids}
        gens = {s: self.mine[s]["generation"] for s in ids}
        bare = [s for s in ids if not self.mine[s]["volume"]]
        t0 = time.time()
        cut()
        fence = self.args.fence_after_s + self.args.fence_margin_s
        last_seen, cold_at = self.watch_copies(ids, fence + 90, host, until_cold=True)
        gone = {s: round(last_seen.get((s, host), t0) - t0, 1) for s in ids}
        cold = {s: round(cold_at[s] - t0, 1) if s in cold_at else None for s in ids}
        result.update(vm_gone_s=gone, cold_s=cold)
        self.log(f"{name}: VMs last seen on {host} after {gone}, cold after {cold}")
        for s in ids:
            if cold[s] is None:
                self.violate("fencing", f"{name}: {s} never became cold")

        def moved(s, when):
            if self.verify(s, f"{name} {when}") and (self.mine[s]["generation"] or 0) <= (gens[s] or 0):
                self.violate("duplicate", f"{name}: {s} restarted at generation {self.mine[s]['generation']}")

        for s in bare:
            moved(s, "while cut")
        if bare:
            self.watch_copies(ids, 20, host, cold_at)
        heal()
        if not self.wait_ready(host):
            self.violate("lost", f"{name}: {host} is not ready again, so its volumes cannot be checked")
        # A returning host must not start its stale copies again.
        self.watch_copies(ids, 30, host, cold_at)
        for s in ids:
            if s in bare:
                self.verify(s, f"{name} after heal")
            else:
                moved(s, "after heal")
        result["violations"] = len(self.summary["violations"])
        self.summary["scenarios"].append(result)

    def failover(self):
        self.setup()
        workers = [h for h in self.hosts.names() if h not in ("primary", "standby")]
        n = self.args.failover_sandboxes
        for name in self.args.scenarios:
            if name in ("worker", "partition") and not workers:
                self.log(f"{name}: skipped, no worker --host")
                continue
            if name == "leader" and ("standby" not in self.args.hosts or len(self.args.api) < 2):
                self.log("leader: skipped, needs --host standby=... and its --api URL")
                continue
            host = self.rng.choice(workers) if name != "leader" else self.leader()
            if host is None:
                self.violate("api", "cannot tell which primary is the leader")
                continue
            self.log(f"== {name} on {host}")
            # Those with a volume reach a worker only when the primary is full;
            # see place().
            volumes = max(1, n // 2) if name == "leader" else self.args.failover_volume_sandboxes
            ids = self.place(n, host, volume=False) + self.place(volumes, host)
            if name == "worker" or name == "leader":
                def cut(h=host):
                    self.hosts.run(h, self.args.server_kill_cmd)

                def heal(h=host):
                    self.hosts.run(h, self.args.server_start_cmd)
            else:
                if not self.args.primary_ip:
                    self.log("partition: skipped, needs --primary-ip")
                    continue
                ip, fp, np_ = self.args.primary_ip, self.args.fleet_port, self.args.node_port
                rules = [f"OUTPUT -d {ip} -p tcp --dport {fp} -j DROP", f"INPUT -s {ip} -p tcp --dport {np_} -j DROP"]

                def cut(h=host, rules=rules, ip=ip, np_=np_):
                    self.hosts.run(h, "; ".join(f"iptables -I {r}" for r in rules)
                                   + f"; conntrack -D -s {ip} -p tcp --dport {np_} >/dev/null 2>&1; true")

                def heal(h=host, rules=rules):
                    self.hosts.run(h, "; ".join(f"iptables -D {r}" for r in rules) + "; true")
            try:
                self.scenario(name, host, ids, cut, heal)
            finally:
                heal()
            self.wait_ready(host)
            for sid in ids:
                self.delete(sid)
        self.teardown()

    def leader(self):
        url = self.api.healthy()
        if not url:
            return None
        hostname = urllib.parse.urlsplit(url).hostname
        for name in ("primary", "standby"):
            if hostname and hostname in self.args.hosts.get(name, ""):
                return name
        return "primary"

    def wait_ready(self, host):
        deadline = time.time() + self.args.verify_wait
        while time.time() < deadline:
            if host in ("primary", "standby"):
                if self.api.healthy():
                    return True
            else:
                status, out = self.call("GET", f"/v1/nodes/{host}")
                if status == 200 and out.get("state") == "ready":
                    return True
            time.sleep(2)
        self.log(f"{host} is not ready again")
        return False

    # --- dry run ---------------------------------------------------------

    def dry_run(self):
        a = self.args
        plan = {
            "mode": a.mode,
            "api": a.api,
            "tenant": a.tenant,
            "hosts": a.hosts,
            "duration_s": a.duration,
            "density": a.density,
            "persistent_ratio": a.persistent_ratio,
            "chaos_every_s": a.chaos_every,
            "check_every_s": a.check_every,
            "scenarios": a.scenarios if a.mode == "failover" else [],
            "summary": a.summary,
        }
        print(json.dumps({"plan": plan}, indent=2))
        url = self.api.healthy()
        print(f"api: {url or 'no URL answered /healthz'}")
        if url and a.key:
            status, out = self.api.request("GET", "/v1/nodes", wait=0)
            print(f"nodes: {status} {json.dumps(out)[:400]}")
            status, out = self.api.request("GET", f"/v1/sandboxes?{self.tq()}&limit=1", wait=0)
            print(f"sandboxes: {status}")
        for host in self.hosts.names():
            s = self.hosts.sample(host)
            if s is None:
                print(f"host {host}: ssh failed")
                continue
            print(f"host {host}: {len(s['vms'])} VMs, {len(s['netns'])} namespaces, {len(s['jails'])} jails, "
                  f"{len(s['cgroups'])} cgroups, {s['links']} links, nft {s['nft']} lines, iptables {s['ipt']} rules, "
                  f"spawn-api pid {s['pid']} rss {s['rss_kib']} KiB fds {s['fds']}")


def main(argv):
    args = parse_args(argv)
    soak = Soak(args)
    if args.dry_run:
        soak.dry_run()
        return 0
    try:
        if args.mode == "soak":
            soak.soak()
        else:
            soak.failover()
    except KeyboardInterrupt:
        soak.log("interrupted")
        soak.summary["interrupted"] = True
    except SetupError as e:
        soak.log(f"SETUP ERROR, stopping: {e}")
        soak.summary["setup_failed"] = str(e)
        try:
            soak.teardown()
        except Exception as cleanup:  # the summary matters more
            soak.log(f"teardown raised {cleanup!r}")
    finally:
        soak.write_summary()
    if soak.summary["violations"]:
        return 1
    return 3 if soak.summary["setup_errors"] or "setup_failed" in soak.summary else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
