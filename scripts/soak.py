#!/usr/bin/env python3
"""Soak and failover checks for a Spawnbox server or fleet on real KVM hosts.
Uses only the standard library. Writes a JSON summary and exits 1 if any
invariant is broken, 2 on a usage error.

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
            persistent sandboxes with volumes:
              worker     kill -9 a worker's server, then start it again
              partition  cut a worker off from the primary with iptables,
                         then heal it
              leader     kill -9 the leader (needs a standby host)

Invariants:
  lost       every persistent sandbox answers, with its volume marker
             intact, and its disk marker intact unless it was cold started
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
  fencing    (failover) a cut-off worker stops its VMs before the primary
             makes them cold, and a stale copy never runs again
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
    p.add_argument("--failover-sandboxes", type=int, default=4, help="persistent sandboxes per failover scenario")
    p.add_argument("--primary-ip", help="primary's address as workers reach it (partition)")
    p.add_argument("--fleet-port", type=int, default=7443)
    p.add_argument("--node-port", type=int, default=7444)
    p.add_argument("--fence-after-s", type=int, default=60)
    p.add_argument("--fence-margin-s", type=int, default=30)
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

    # --- reporting -------------------------------------------------------

    def log(self, msg):
        t = time.time() - self.started
        print(f"[{int(t // 3600):02d}:{int(t % 3600 // 60):02d}:{int(t % 60):02d}] {msg}", flush=True)

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
        self.summary["ok"] = not self.summary["violations"]
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

    def create(self, persistent):
        self.seq += 1
        token = f"{int(time.time())}-{self.seq}-{self.rng.getrandbits(32):08x}"
        spec = {
            "tenant": self.args.tenant,
            "env": {"SOAK_TOKEN": token},
            "services": [{"name": "soak", "command": ["sh", "-c", self.args.service_command]}],
        }
        if self.args.template:
            spec["template"] = self.args.template
        volume = None
        if persistent:
            volume = f"soak-{self.seq}-{self.rng.getrandbits(16):04x}"
            status, out = self.call("POST", "/v1/volumes", {"name": volume, "size_gib": self.args.volume_gib, "tenant": self.args.tenant})
            if status not in (200, 201):
                self.count("create_persistent", f"volume_{code(out) or status}")
                return None
            spec.update(persistent=True, volumes=[{"volume": volume, "path": "/data"}])
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
            stdout, exit_code, raw = self.exec(sid, f"echo {token} > /data/soak-marker && echo {token} > /root/soak-marker && sync && echo ok")
            if exit_code != 0 or (stdout or "").strip() != "ok":
                self.violate("lost", f"{sid}: cannot write markers: {json.dumps(raw)[:300]}")
            else:
                rec["disk_gen"] = self.generation(sid)
        self.count(kind)
        self.log(f"created {'persistent' if persistent else 'ephemeral'} {sid}")
        return sid

    def generation(self, sid):
        s = self.get(sid)
        return s.get("generation") if s else None

    def verify(self, sid, why):
        """The sandbox answers and still has its data."""
        rec = self.mine[sid]
        stdout, exit_code, raw = self.exec(
            sid, 'printf "%s|%s|%s" "$(cat /data/soak-marker 2>/dev/null)" "$(cat /root/soak-marker 2>/dev/null)" "$SOAK_TOKEN"'
        )
        if stdout is None:
            if rec["persistent"]:
                c = code(raw)
                # A volume whose host is away cannot be mounted until it
                # returns; that is a wait, not a loss.
                if c == "volume_unavailable":
                    self.count("verify", c)
                    return False
                self.violate("lost", f"{sid} ({why}) does not answer: {exit_code} {json.dumps(raw)[:300]}")
            return False
        vol, disk, env = (stdout.split("|") + ["", "", ""])[:3]
        gen = self.generation(sid)
        if env != rec["token"]:
            self.violate("lost", f"{sid} ({why}): env SOAK_TOKEN is {env!r}")
        if rec["persistent"]:
            if vol != rec["token"]:
                self.violate("lost", f"{sid} ({why}): volume marker is {vol!r}, wanted {rec['token']!r}")
            if rec["disk_gen"] == gen and disk != rec["token"]:
                self.violate("lost", f"{sid} ({why}): disk marker is {disk!r} at the same generation {gen}")
            if rec["disk_gen"] != gen:
                # A cold start keeps volumes only; write the disk marker again.
                self.exec(sid, f"echo {rec['token']} > /root/soak-marker && sync")
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
        self.hosts.run(host, f"pkill -9 -f -- '--id {host_name(sid)}( |$)'")
        for _ in range(90):
            s = self.get(sid)
            if s and s.get("state") == "cold":
                break
            time.sleep(1)
        else:
            self.violate("lost", f"{sid}: did not become cold after its VM was killed on {host}")
            return
        if self.verify(sid, "cold start"):
            if (self.mine[sid]["generation"] or 0) <= (gen or 0):
                self.violate("duplicate", f"{sid}: cold start kept generation {gen}")
            self.count("cold_start")

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
        for _ in range(120):
            if self.api.healthy():
                break
            time.sleep(2)
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

    def watch_copies(self, ids, seconds, stop=None):
        """Polls every host's processes and the API; returns per id when its
        VM was last seen on each host, and when the API first said cold."""
        names = {host_name(s): s for s in ids}
        last_seen, cold_at = {}, {}
        end = time.time() + seconds
        while time.time() < end:
            t = time.time()
            where = {}
            for host in self.hosts.names():
                s = self.hosts.sample(host)
                if s is None:
                    continue
                for name in s["vms"]:
                    if name in names:
                        where.setdefault(name, []).append(host)
                        last_seen[(names[name], host)] = t
            for name, hosts in where.items():
                if len(hosts) > 1:
                    self.violate("duplicate", f"{names[name]} runs on {hosts} during failover")
            for sid in ids:
                if sid not in cold_at:
                    v = self.get(sid)
                    if v and v.get("state") == "cold":
                        cold_at[sid] = t
            if stop and stop(last_seen, cold_at):
                break
            time.sleep(2)
        return last_seen, cold_at

    def place(self, n, want_host):
        """Creates persistent sandboxes until `n` run on `want_host`."""
        ids = []
        for _ in range(n * 6):
            sid = self.create(True)
            if not sid:
                continue
            view = self.get(sid)
            if view and self.host_of(view) == want_host:
                ids.append(sid)
                if len(ids) == n:
                    break
            else:
                self.delete(sid)
        return ids

    def scenario(self, name, host, ids, cut, heal):
        """Runs one failover: `cut` breaks the host, then checks the design's
        fencing order, cold starts elsewhere and the data, then `heal`."""
        result = {"scenario": name, "host": host, "sandboxes": ids}
        gens = {s: self.mine[s]["generation"] for s in ids}
        t0 = time.time()
        cut()
        fence = self.args.fence_after_s + self.args.fence_margin_s
        last_seen, cold_at = self.watch_copies(ids, fence + 90, stop=lambda _, c: len(c) == len(ids))
        gone = {s: round(last_seen.get((s, host), t0) - t0, 1) for s in ids}
        cold = {s: round(cold_at[s] - t0, 1) if s in cold_at else None for s in ids}
        result.update(vm_gone_s=gone, cold_s=cold)
        self.log(f"{name}: VMs gone after {gone}, cold after {cold}")
        for s in ids:
            if cold[s] is None:
                self.violate("fencing", f"{name}: {s} never became cold")
            elif cold[s] + 2 < gone[s]:
                self.violate("fencing", f"{name}: {s} was cold at {cold[s]}s while its VM still ran on {host} until {gone[s]}s")
        heal()
        for s in ids:
            if self.verify(s, name) and (self.mine[s]["generation"] or 0) <= (gens[s] or 0):
                self.violate("duplicate", f"{name}: {s} restarted at generation {self.mine[s]['generation']}")
        # A returning host must not start its stale copies again.
        self.watch_copies(ids, 30)
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
            ids = self.place(n, host)
            if not ids:
                self.log(f"{name}: no sandbox landed on {host}; skipped")
                continue
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
        for _ in range(90):
            if host in ("primary", "standby"):
                if self.api.healthy():
                    return
            else:
                status, out = self.call("GET", f"/v1/nodes/{host}")
                if status == 200 and out.get("state") == "ready":
                    return
            time.sleep(2)
        self.log(f"{host} is not ready again")

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
    finally:
        soak.write_summary()
    return 1 if soak.summary["violations"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
