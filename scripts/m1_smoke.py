#!/usr/bin/env python3
"""End-to-end checks for the spawn-api HTTP API. Uses only the standard
library. Prints a JSON report and exits non-zero on the first failed check.

Usage: m1_smoke.py <base-url> <api-key> [api|templates|interactive|pause|egress|tenants|events|restart <build-id> <paused-id>]
  api          sandboxes, exec and limits (the default)
  templates    custom template builds and file access
  interactive  terminals, git clone and preview URLs (needs internet and
               the template from `templates`; SPAWNBOX_PREVIEW is the
               preview listener's base URL)
  pause      pause, resume, idle pause and waking on calls (needs the
             template from `templates`); leaves one paused sandbox for
             `restart`, its id in the report as `paused_id`
  egress     secrets, injection and egress policies (needs internet)
  tenants    tenants, tenant keys, scopes, quotas and namespaced templates
             and secrets (needs internet and an org key)
  events     the event log: step IDs, exec, network, secret and file
             events, filters, paging, live follow and tenant isolation
             (needs internet; SPAWNBOX_OTLP_LOG is a file the test OTLP
             receiver appends request bodies to)
  volumes    persistent volumes: create, mount, one writer or many
             readers, read-only mounts, pause and resume, and delete
             (uses the template from `templates` if it exists)
  restart    after a server restart: the template build from `templates`
             is still current and works, and the paused sandbox resumes"""

import base64
import concurrent.futures
import datetime
import hashlib
import http.client
import json
import os
import re
import socket
import statistics
import struct
import sys
import time
import urllib.parse

BASE, KEY = sys.argv[1], sys.argv[2]
MODE = sys.argv[3] if len(sys.argv) > 3 else "api"
URL = urllib.parse.urlsplit(BASE)
report = {"checks": []}


def request(method, path, body=None, key=KEY, accept="application/json", timeout=120, headers=None):
    conn = http.client.HTTPConnection(URL.hostname, URL.port, timeout=timeout)
    headers = {"Accept": accept, **(headers or {})}
    if key:
        headers["Authorization"] = "Bearer " + key
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = raw.decode(errors="replace")
    return resp.status, parsed


def check(name, ok, detail=None):
    report["checks"].append(name)
    if not ok:
        print(json.dumps(report, indent=2))
        sys.exit(f"FAILED: {name}: {detail!r}")


def expect_error(name, status, body, want_status, want_code):
    ok = (
        status == want_status
        and isinstance(body, dict)
        and body.get("error", {}).get("code") == want_code
        and body["error"].get("request_id", "").startswith("req_")
    )
    check(name, ok, (status, body))


def create(body=None):
    status, sandbox = request("POST", "/v1/sandboxes", body or {})
    check("create returns 201", status == 201, (status, sandbox))
    check("create is running", sandbox["state"] == "running", sandbox)
    return sandbox


def run(sandbox_id, cmd, **fields):
    status, body = request("POST", f"/v1/sandboxes/{sandbox_id}/exec", {"cmd": cmd, **fields})
    check(f"exec {cmd[:40]!r} returns 200", status == 200, (status, body))
    return body


def sse(sandbox_id, cmd, read_events=None):
    """Returns [(seconds since request, event, data)]. Stops after
    `read_events` events when given, closing the connection."""
    conn = http.client.HTTPConnection(URL.hostname, URL.port, timeout=60)
    start = time.monotonic()
    conn.request(
        "POST",
        f"/v1/sandboxes/{sandbox_id}/exec",
        body=json.dumps({"cmd": cmd}).encode(),
        headers={
            "Authorization": "Bearer " + KEY,
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
        },
    )
    resp = conn.getresponse()
    check("sse returns 200", resp.status == 200, resp.status)
    check(
        "sse content type",
        resp.getheader("Content-Type", "").startswith("text/event-stream"),
        resp.getheader("Content-Type"),
    )
    events, name, data = [], None, []
    while True:
        line = resp.fp.readline()
        if not line:
            break
        line = line.decode().rstrip("\r\n")
        if line.startswith("event:"):
            name = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        elif line == "" and name:
            events.append((time.monotonic() - start, name, json.loads("\n".join(data))))
            name, data = None, []
            if read_events and len(events) >= read_events:
                break
            if events[-1][1] in ("exit", "error"):
                break
    conn.close()
    return events


def api_checks():
    # Health and auth.
    conn = http.client.HTTPConnection(URL.hostname, URL.port, timeout=10)
    conn.request("GET", "/healthz")
    check("healthz", conn.getresponse().status == 200)
    conn.close()
    expect_error("no key is rejected", *request("GET", "/v1/sandboxes", key=None), 401, "unauthorized")
    expect_error(
        "unknown key is rejected",
        *request("GET", "/v1/sandboxes", key="sbk_" + "a" * 52),
        401,
        "unauthorized",
    )
    expect_error("unknown endpoint", *request("GET", "/v1/nope"), 404, "not_found")

    # Bad create requests fail before a VM starts.
    expect_error(
        "unknown template",
        *request("POST", "/v1/sandboxes", {"template": "node22"}),
        400,
        "invalid_request",
    )
    expect_error(
        "unsupported field",
        *request("POST", "/v1/sandboxes", {"ports": [3000]}),
        400,
        "invalid_request",
    )
    expect_error("bad json", *request("POST", "/v1/sandboxes", b"{"), 400, "invalid_request")

    # Create, get, exec.
    a = create({"labels": {"suite": "m1"}, "env": {"GREETING": "hi"}, "timeout_s": 600})
    check("timings are returned", set(a["timings_ms"]) == {"prepare", "restore", "fixups", "total"}, a)
    check("created_at format", a["created_at"].endswith("Z") and len(a["created_at"]) == 24, a)
    status, got = request("GET", f"/v1/sandboxes/{a['id']}")
    check("get", status == 200 and got["labels"] == {"suite": "m1"} and "timings_ms" not in got, got)

    out = run(a["id"], "echo $GREETING; id -un; pwd; hostname")
    check(
        "default user, cwd, sandbox env and hostname",
        out["stdout"] == f"hi\nuser\n/workspace\n{a['id'].replace('_', '-')}\n" and out["exit_code"] == 0,
        out,
    )
    out = run(a["id"], "echo $GREETING; id -un; pwd", user="root", cwd="/tmp", env={"GREETING": "yo"})
    check("exec user, cwd and env override", out["stdout"] == "yo\nroot\n/tmp\n", out)
    out = run(a["id"], "echo oops >&2; exit 3")
    check("exit code and stderr", out["exit_code"] == 3 and out["stderr"] == "oops\n", out)
    out = run(a["id"], "tr a-z A-Z; echo done", stdin="hello\nworld\n")
    check("exec stdin", out["stdout"] == "HELLO\nWORLD\ndone\n", out)
    out = run(a["id"], "cat; echo end")
    check("exec without stdin reads nothing", out["stdout"] == "end\n", out)
    started = time.monotonic()
    out = run(a["id"], "sleep 30 & echo bg")
    check(
        "background job does not hold exec open",
        out["stdout"] == "bg\n" and time.monotonic() - started < 5,
        (out, time.monotonic() - started),
    )
    run(a["id"], "pkill -x sleep; true")
    out = run(a["id"], "sleep 10", timeout_s=1)
    check("exec timeout", out["timed_out"] is True and out["duration_ms"] < 3000, out)
    out = run(a["id"], "head -c 2000000 /dev/zero | tr '\\0' a")
    check(
        "json output is capped",
        len(out["stdout"]) == 1024 * 1024 and out["stdout_truncated"] is True,
        {k: v for k, v in out.items() if k != "stdout"},
    )
    expect_error(
        "missing cwd",
        *request("POST", f"/v1/sandboxes/{a['id']}/exec", {"cmd": "true", "cwd": "/nope"}),
        400,
        "invalid_request",
    )
    expect_error(
        "unknown user",
        *request("POST", f"/v1/sandboxes/{a['id']}/exec", {"cmd": "true", "user": "nobody2"}),
        400,
        "invalid_request",
    )
    out = run(
        a["id"],
        "curl -sS -o /dev/null -w '%{http_code}' --max-time 10 https://deb.debian.org/debian/",
    )
    check("internet works", out["stdout"][:1] in "23" and out["stdout"] != "", out)
    out = run(
        a["id"],
        "curl -s --max-time 3 -o /dev/null http://169.254.169.254/ && echo reachable || echo blocked",
    )
    check("metadata blocked", out["stdout"] == "blocked\n", out)

    # SSE streams output as it happens and keeps split characters whole.
    events = sse(a["id"], "for i in 1 2 3; do echo line$i; sleep 0.3; done; printf '\\xe2'; sleep 0.2; printf '\\x82\\xac'")
    stdout = "".join(d["text"] for _, e, d in events if e == "stdout")
    exits = [d for _, e, d in events if e == "exit"]
    check("sse output", stdout == "line1\nline2\nline3\n€", events)
    check("sse exit", exits and exits[0]["exit_code"] == 0, events)
    check("sse streams before exit", events[0][0] + 0.5 < events[-1][0], events)

    # Closing an SSE stream kills the command.
    events = sse(a["id"], "echo started; sleep 30; touch /workspace/not-killed", read_events=1)
    check("sse first event", events and events[0][2]["text"] == "started\n", events)
    time.sleep(1)
    out = run(a["id"], "pgrep -x sleep || echo none")
    check("disconnect kills the command", out["stdout"] == "none\n", out)

    # Two sandboxes do not share files.
    b = create()
    run(a["id"], "echo secret > /workspace/a.txt")
    out = run(b["id"], "test -e /workspace/a.txt && echo shared || echo isolated")
    check("sandboxes are isolated", out["stdout"] == "isolated\n", out)

    # Listing pages through sandboxes.
    status, page = request("GET", "/v1/sandboxes?limit=1")
    check("list first page", status == 200 and len(page["sandboxes"]) == 1 and page["next_cursor"], page)
    status, page2 = request("GET", f"/v1/sandboxes?limit=1&cursor={page['next_cursor']}")
    check(
        "list next page",
        status == 200 and page2["sandboxes"][0]["id"] != page["sandboxes"][0]["id"],
        page2,
    )
    expect_error("bad list state", *request("GET", "/v1/sandboxes?state=nope"), 400, "invalid_request")

    # Parallel creates.
    with concurrent.futures.ThreadPoolExecutor(5) as pool:
        parallel = list(pool.map(lambda _: create(), range(5)))
    check("parallel ids differ", len({s["id"] for s in parallel}) == 5)
    timings = [s["timings_ms"]["total"] for s in [a, b, *parallel]]
    report["create_total_ms"] = {
        "single": [a["timings_ms"], b["timings_ms"]],
        "parallel_5": [s["timings_ms"]["total"] for s in parallel],
        "median_all": statistics.median(timings),
    }
    for s in parallel:
        status, _ = request("DELETE", f"/v1/sandboxes/{s['id']}")
        check("delete parallel", status == 204, status)

    # Sequential creates for a latency sample.
    sequential = []
    for _ in range(10):
        s = create()
        sequential.append(s["timings_ms"])
        out = run(s["id"], "echo ok")
        check("exec after create", out["stdout"] == "ok\n", out)
        request("DELETE", f"/v1/sandboxes/{s['id']}")
    report["create_sequential_ms"] = {
        key: {
            "p50": statistics.median(t[key] for t in sequential),
            "max": max(t[key] for t in sequential),
        }
        for key in ("prepare", "restore", "fixups", "total")
    }

    # Expiry.
    c = create({"timeout_s": 2})
    time.sleep(4)
    status, got = request("GET", f"/v1/sandboxes/{c['id']}")
    check("expired sandbox is deleted", got["state"] == "deleted", got)
    expect_error(
        "exec on deleted sandbox",
        *request("POST", f"/v1/sandboxes/{c['id']}/exec", {"cmd": "true"}),
        409,
        "conflict",
    )

    # Delete.
    for s in (a, b):
        status, _ = request("DELETE", f"/v1/sandboxes/{s['id']}")
        check("delete returns 204", status == 204, status)
    status, got = request("GET", f"/v1/sandboxes/{a['id']}")
    check("deleted state", got["state"] == "deleted", got)
    status, _ = request("DELETE", f"/v1/sandboxes/{a['id']}")
    check("delete is repeatable", status == 204, status)
    expect_error("unknown id", *request("GET", "/v1/sandboxes/sbx_0000000000000000"), 404, "not_found")
    expect_error("malformed id", *request("GET", "/v1/sandboxes/..%2f..%2fetc"), 404, "not_found")
    status, page = request("GET", "/v1/sandboxes")
    check("nothing left running", page["sandboxes"] == [], page)


def raw(method, path, body=None, timeout=300):
    """Like `request`, but sends and returns bytes."""
    conn = http.client.HTTPConnection(URL.hostname, URL.port, timeout=timeout)
    headers = {"Authorization": "Bearer " + KEY}
    if body is not None:
        headers["Content-Type"] = "application/octet-stream"
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def files_path(sandbox_id, path, **params):
    query = urllib.parse.urlencode({"path": path, **params})
    return f"/v1/sandboxes/{sandbox_id}/files?{query}"


def wait_build(name, build_id, limit_s=1200):
    deadline = time.monotonic() + limit_s
    while True:
        status, build = request("GET", f"/v1/templates/{name}/builds/{build_id}")
        check("get build", status == 200, (status, build))
        if build["state"] not in ("queued", "building"):
            return build
        if time.monotonic() > deadline:
            check(f"build {name} finishes in time", False, build)
        time.sleep(2)


def template_checks():
    status, page = request("GET", "/v1/templates")
    names = [t["name"] for t in page["templates"]]
    check("base template is listed", status == 200 and "base" in names, page)
    status, base = request("GET", "/v1/templates/base")
    check("base is ready", status == 200 and base["current_build"], base)
    expect_error("base is reserved", *request("POST", "/v1/templates", {"name": "base"}), 400, "invalid_request")
    expect_error("base cannot be deleted", *request("DELETE", "/v1/templates/base"), 400, "invalid_request")
    expect_error("bad template name", *request("POST", "/v1/templates", {"name": "Bad Name"}), 400, "invalid_request")
    expect_error(
        "unknown template field",
        *request("POST", "/v1/templates", {"name": "x", "image": "node"}),
        400,
        "invalid_request",
    )
    expect_error(
        "too much memory",
        *request("POST", "/v1/templates", {"name": "x", "resources": {"memory_mib": 999999}}),
        400,
        "invalid_request",
    )
    expect_error("unknown template get", *request("GET", "/v1/templates/nope"), 404, "not_found")

    # A template with setup (as root, with network) and warmup (as user).
    spec = {
        "name": "smoke-jq",
        "setup": [
            "apt-get update -qq && apt-get install -y -qq --no-install-recommends jq python3",
            "echo from-setup > /opt/marker && echo setup env: $TPL",
        ],
        "warmup": [
            "id -un > /workspace/warm",
            "sh -c 'while true; do echo tick; date +%s%N > /workspace/tick; sleep 0.5; done' &",
        ],
        "env": {"TPL": "template", "GREETING": "from-template"},
        "resources": {"memory_mib": 1536},
    }
    started = time.monotonic()
    status, put = request("POST", "/v1/templates", spec)
    check("put template returns 202", status == 202 and put["build"]["state"] in ("queued", "building"), (status, put))
    build_id = put["build"]["id"]
    check("template view", put["template"]["env"] == spec["env"] and put["template"]["resources"]["memory_mib"] == 1536, put)
    expect_error(
        "create while building",
        *request("POST", "/v1/sandboxes", {"template": "smoke-jq"}),
        409,
        "conflict",
    )
    build = wait_build("smoke-jq", build_id)
    report["template_build_s"] = round(time.monotonic() - started, 1)
    check("template build is ready", build["state"] == "ready", build)
    check("build log", "== ready" in build["log"] and "setup env: template" in build["log"], build["log"][-2000:])
    status, got = request("GET", "/v1/templates/smoke-jq")
    check("current build", got["current_build"] == build_id and got["latest_build"]["id"] == build_id, got)

    t = create({"template": "smoke-jq", "env": {"GREETING": "from-sandbox"}})
    check("sandbox records template and build", t["template"] == "smoke-jq" and t["build"] == build_id, t)
    out = run(t["id"], "jq -n '1+1'; cat /opt/marker /workspace/warm; echo $TPL $GREETING; nproc; id -un")
    check(
        "setup, warmup and env reach the sandbox",
        out["stdout"] == "2\nfrom-setup\nuser\ntemplate from-sandbox\n2\nuser\n" and out["exit_code"] == 0,
        out,
    )
    out = run(t["id"], "a=$(cat /workspace/tick); sleep 2; b=$(cat /workspace/tick); [ \"$a\" != \"$b\" ] && echo alive")
    check("warmup daemon keeps running", out["stdout"] == "alive\n", out)
    out = run(t["id"], "free -m | awk '/Mem:/ {print $2}'")
    check("template memory", 1200 < int(out["stdout"]) <= 1536, out)
    out = run(t["id"], "echo changed > /opt/marker", user="root")
    out = run(t["id"], "cat /opt/marker")
    check("layer files can be changed", out["stdout"] == "changed\n", out)
    t2 = create({"template": "smoke-jq"})
    out = run(t2["id"], "cat /opt/marker")
    check("changes stay in their sandbox", out["stdout"] == "from-setup\n", out)
    report["template_create_ms"] = [t["timings_ms"], t2["timings_ms"]]

    file_checks(t["id"])

    for s in (t, t2):
        request("DELETE", f"/v1/sandboxes/{s['id']}")

    # A failing setup step.
    status, put = request("POST", "/v1/templates", {"name": "smoke-broken", "setup": ["echo before-fail; exit 7"]})
    check("put broken template", status == 202, (status, put))
    build = wait_build("smoke-broken", put["build"]["id"])
    check("failed build", build["state"] == "failed" and build["error"], build)
    check("failed build log", "before-fail" in build["log"], build)
    expect_error(
        "create from failed template",
        *request("POST", "/v1/sandboxes", {"template": "smoke-broken"}),
        409,
        "conflict",
    )
    status, _ = request("DELETE", "/v1/templates/smoke-broken")
    check("delete template", status == 204, status)
    expect_error("deleted template", *request("GET", "/v1/templates/smoke-broken"), 404, "not_found")
    expect_error(
        "create from deleted template",
        *request("POST", "/v1/sandboxes", {"template": "smoke-broken"}),
        400,
        "invalid_request",
    )
    report["template_build_id"] = build_id


def file_checks(sid):
    # Small binary round trip; relative paths go under /workspace.
    blob = bytes(range(256)) * 4
    status, info = request("PUT", files_path(sid, "bin/data.bin"), blob)
    check("write file", status == 200 and info["size"] == len(blob) and info["kind"] == "file", (status, info))
    check("relative path", info["path"] == "/workspace/bin/data.bin" and info["mode"] == "0644", info)
    status, data = raw("GET", files_path(sid, "/workspace/bin/data.bin"))
    check("read file", status == 200 and data == blob, (status, len(data)))
    out = run(sid, "stat -c '%U %s' /workspace/bin/data.bin")
    check("file belongs to user", out["stdout"] == f"user {len(blob)}\n", out)

    # 50 MB streams both ways.
    big = os.urandom(50 * 1024 * 1024)
    started = time.monotonic()
    status, info = request("PUT", files_path(sid, "/tmp/big.bin"), big)
    up = time.monotonic() - started
    check("write 50 MB", status == 200 and info["size"] == len(big), (status, info))
    started = time.monotonic()
    status, data = raw("GET", files_path(sid, "/tmp/big.bin"))
    down = time.monotonic() - started
    check("read 50 MB", status == 200 and hashlib.sha256(data).digest() == hashlib.sha256(big).digest(), len(data))
    out = run(sid, "sha256sum /tmp/big.bin | cut -d' ' -f1")
    check("guest sees the same bytes", out["stdout"].strip() == hashlib.sha256(big).hexdigest(), out)
    report["files_50mb_s"] = {"upload": round(up, 2), "download": round(down, 2)}

    # Overwrite keeps the mode.
    run(sid, "printf old > /workspace/script.sh && chmod 755 /workspace/script.sh")
    status, info = request("PUT", files_path(sid, "script.sh"), b"#!/bin/sh\necho new\n")
    check("overwrite keeps mode", status == 200 and info["mode"] == "0755", info)
    out = run(sid, "./script.sh")
    check("overwritten file runs", out["stdout"] == "new\n", out)

    # Empty files and listings.
    status, info = request("PUT", files_path(sid, "empty"), b"")
    check("write empty file", status == 200 and info["size"] == 0, (status, info))
    status, listing = request("GET", files_path(sid, "/workspace"))
    names = {e["name"]: e["kind"] for e in listing["entries"]}
    check(
        "list directory",
        status == 200 and listing["path"] == "/workspace" and names.get("bin") == "dir" and names.get("script.sh") == "file",
        listing,
    )

    # Users and permissions.
    expect_error("read root-only file", *request("GET", files_path(sid, "/etc/shadow")), 403, "forbidden")
    status, data = raw("GET", files_path(sid, "/etc/shadow", user="root"))
    check("root reads root-only file", status == 200 and b"root:" in data, status)
    expect_error("write as user into /etc", *request("PUT", files_path(sid, "/etc/x"), b"x"), 403, "forbidden")
    status, info = request("PUT", files_path(sid, "/etc/spawn-smoke", user="root"), b"x")
    check("write as root", status == 200, (status, info))
    out = run(sid, "stat -c %U /etc/spawn-smoke")
    check("root file owner", out["stdout"] == "root\n", out)

    # Errors.
    expect_error("missing file", *request("GET", files_path(sid, "/nope")), 404, "not_found")
    expect_error("missing path", *request("GET", f"/v1/sandboxes/{sid}/files"), 400, "invalid_request")
    expect_error("unknown file user", *request("GET", files_path(sid, "x", user="nobody2")), 400, "invalid_request")
    expect_error("read a device", *request("GET", files_path(sid, "/dev/zero")), 400, "invalid_request")
    expect_error(
        "files on unknown sandbox",
        *request("GET", files_path("sbx_0000000000000000", "x")),
        404,
        "not_found",
    )

    # Delete.
    status, _ = request("DELETE", files_path(sid, "empty"))
    check("delete file", status == 204, status)
    expect_error("delete non-empty dir", *request("DELETE", files_path(sid, "bin")), 409, "conflict")
    status, _ = request("DELETE", files_path(sid, "bin", recursive="true"))
    check("delete dir recursively", status == 204, status)
    expect_error("deleted dir", *request("GET", files_path(sid, "bin")), 404, "not_found")


def curl(sandbox_id, args, timeout_s=20):
    """Runs curl in the sandbox. Returns (exit code, stdout)."""
    out = run(sandbox_id, f"curl -sS -m {timeout_s} {args}")
    return out["exit_code"], out["stdout"]


# A DNS query for example.com sent straight to 8.8.8.8 over UDP. Prints the
# number of reply bytes.
UDP_DNS = (
    "exec 3<>/dev/udp/8.8.8.8/53; "
    "printf '\\022\\064\\001\\000\\000\\001\\000\\000\\000\\000\\000\\000\\007\\145\\170\\141\\155\\160\\154\\145\\003\\143\\157\\155\\000\\000\\001\\000\\001' >&3; "
    "timeout 3 head -c 12 <&3 | wc -c"
)


def egress_checks():
    # Secrets API. Values are write-only.
    value = "s3cret-" + os.urandom(8).hex()
    spec = {
        "name": "echo_token",
        "type": "http_header",
        "allowed_hosts": ["postman-echo.com"],
        "env": "ECHO_TOKEN",
        "value": value,
    }
    status, made = request("POST", "/v1/secrets", spec)
    check("create secret", status == 201 and made["version"] == 1, (status, made))
    check("created secret hides value", value not in json.dumps(made), made)
    check(
        "secret defaults",
        made["header"] == "Authorization" and made["format"] == "Bearer {value}",
        made,
    )
    status, got = request("GET", "/v1/secrets/echo_token")
    check("get secret hides value", status == 200 and value not in json.dumps(got), got)
    status, page = request("GET", "/v1/secrets")
    check("list secrets", status == 200 and [x["name"] for x in page["secrets"]] == ["echo_token"], page)
    expect_error("duplicate secret", *request("POST", "/v1/secrets", spec), 409, "conflict")
    expect_error(
        "bad secret name",
        *request("POST", "/v1/secrets", {**spec, "name": "Bad Name"}),
        400,
        "invalid_request",
    )
    expect_error(
        "secret without hosts",
        *request("POST", "/v1/secrets", {**spec, "name": "x", "allowed_hosts": []}),
        400,
        "invalid_request",
    )
    expect_error("unknown secret get", *request("GET", "/v1/secrets/nope"), 404, "not_found")
    expect_error(
        "unknown secret on create",
        *request("POST", "/v1/sandboxes", {"secrets": ["nope"]}),
        400,
        "invalid_request",
    )
    expect_error(
        "env clashes with secret",
        *request("POST", "/v1/sandboxes", {"secrets": ["echo_token"], "env": {"ECHO_TOKEN": "x"}}),
        400,
        "invalid_request",
    )
    expect_error(
        "bad egress policy",
        *request("POST", "/v1/sandboxes", {"egress": {"mode": "allowlist"}}),
        400,
        "invalid_request",
    )
    git_value = "ghp_" + os.urandom(8).hex()
    status, made = request(
        "POST",
        "/v1/secrets",
        {
            "name": "git_token",
            "type": "git_https",
            "allowed_hosts": ["postman-echo.com"],
            "env": "GIT_TOKEN",
            "value": git_value,
        },
    )
    check("create git secret", status == 201 and made["username"] == "x-access-token", (status, made))

    # The sandbox only sees placeholders; the proxy swaps in the value.
    s = create({"secrets": ["echo_token", "git_token"]})
    sid = s["id"]
    check("view lists secrets", s["secrets"] == ["echo_token", "git_token"], s)
    check("view has default egress", s["egress"]["mode"] == "allow_all", s)
    out = run(sid, "echo $ECHO_TOKEN; echo $GIT_TOKEN; echo $SSL_CERT_FILE")
    lines = out["stdout"].split()
    check("env has placeholders", len(lines) == 3 and all(x.startswith("sbx_ph_") for x in lines[:2]), out)
    check("env points at the CA bundle", lines[2] == "/etc/ssl/certs/ca-certificates.crt", out)
    # The pattern goes on stdin: sudo copies its command line into the
    # environment of what it runs.
    out = run(sid, f"echo {value} | sudo grep -rqsF -f - /proc/*/environ /etc /workspace; echo $?")
    # With -q, grep exits 0 on any match, even if some files were unreadable.
    check("value is not in the sandbox", out["stdout"] in ("1\n", "2\n"), out)

    code, body = curl(sid, "https://postman-echo.com/headers")
    check("secret added for allowed host", code == 0 and f"Bearer {value}" in body, (code, body))
    code, body = curl(sid, '-H "Authorization: token $ECHO_TOKEN" -H "X-Token: $ECHO_TOKEN" https://postman-echo.com/headers')
    sent = json.loads(body)["headers"] if code == 0 else {}
    check("placeholder replaced in its header", sent.get("authorization") == f"token {value}", body)
    check("placeholder kept in other headers", sent.get("x-token") == lines[0], body)
    code, _ = curl(sid, '-H "Host: httpbin.org" https://postman-echo.com/headers')
    check("Host must match the TLS name", code != 0, code)
    code, body = curl(sid, '-H "X-Token: $ECHO_TOKEN" https://httpbin.org/headers')
    check(
        "placeholder kept for other hosts",
        code == 0 and value not in body and lines[0] in body,
        (code, body),
    )
    code, body = curl(sid, '-u "x-access-token:$GIT_TOKEN" https://postman-echo.com/headers')
    basic = base64.b64encode(f"x-access-token:{git_value}".encode()).decode()
    # git_https and http_header both target Authorization; the header sent wins.
    check("git secret in basic auth", code == 0 and f"Basic {basic}" in body, (code, body))
    out = run(sid, UDP_DNS)
    check("allow_all relays UDP", out["stdout"].strip() == "12", out)
    host_ip = os.environ.get("SPAWNBOX_HOST_IP")
    if host_ip:
        code, _ = curl(sid, f"http://{host_ip}:18999/", 5)
        check("sandbox cannot reach the host's own addresses", code != 0, code)
    code, body = curl(sid, "-v https://example.com -o /dev/null 2>&1 | grep -i 'issuer:'")
    check("hosts without secrets are not intercepted", "spawnbox" not in body.lower(), body)

    status, rotated = request("PATCH", "/v1/secrets/echo_token", {"value": value + "-v2"})
    check("rotate secret", status == 200 and rotated["version"] == 2, (status, rotated))
    code, body = curl(sid, "https://postman-echo.com/headers")
    check("running sandbox gets rotated value", f"Bearer {value}-v2" in body, (code, body))
    request("DELETE", f"/v1/sandboxes/{sid}")

    # Allowlist: only listed names on 80 and 443.
    s = create({"egress": {"mode": "allowlist", "allow": ["example.com"]}})
    sid = s["id"]
    check("view shows allowlist", s["egress"] == {"mode": "allowlist", "allow": ["example.com"]}, s)
    code, body = curl(sid, "https://example.com")
    check("allowlist allows listed https", code == 0 and "Example Domain" in body, (code, body))
    code, body = curl(sid, "http://example.com")
    check("allowlist allows listed http", code == 0 and "Example Domain" in body, (code, body))
    code, _ = curl(sid, "https://www.google.com", 10)
    check("allowlist denies other https", code != 0, code)
    code, _ = curl(sid, "http://www.google.com", 10)
    check("allowlist denies other http", code != 0, code)
    code, _ = curl(sid, "http://example.com:8080", 5)
    check("allowlist denies other ports", code != 0, code)
    out = run(sid, "getent ahostsv4 www.google.com")
    check("allowlist refuses other names", out["stdout"].strip() == "", out)
    out = run(sid, "getent ahostsv4 example.com | awk '{print $1; exit}'")
    check("allowlist resolves listed names", out["stdout"].strip() != "", out)
    # An address that is not example.com's: the proxy goes by the name.
    ip = "1.1.1.1"
    code, body = curl(sid, f"-k --resolve example.com:443:{ip} https://example.com")
    check("fake address goes to the named host", code == 0 and "Example Domain" in body, (code, body))
    code, _ = curl(sid, f"-k https://{ip}", 10)
    check("allowlist denies TLS without a name", code != 0, code)
    code, _ = curl(sid, f'-H "Host: example.com" http://{ip}', 10)
    check("allowlist ignores the address for http", code == 0, code)
    out = run(sid, UDP_DNS)
    check("allowlist drops UDP", out["stdout"].strip() == "0", out)
    request("DELETE", f"/v1/sandboxes/{sid}")

    # deny_all: nothing leaves, not even DNS.
    s = create({"egress": {"mode": "deny_all"}})
    sid = s["id"]
    code, _ = curl(sid, "https://example.com", 5)
    check("deny_all denies https", code != 0, code)
    out = run(sid, "timeout 5 getent hosts example.com")
    check("deny_all denies DNS", out["exit_code"] != 0, out)
    request("DELETE", f"/v1/sandboxes/{sid}")

    status, _ = request("DELETE", "/v1/secrets/echo_token")
    check("delete secret", status == 204, status)
    request("DELETE", "/v1/secrets/git_token")
    expect_error("deleted secret", *request("GET", "/v1/secrets/echo_token"), 404, "not_found")


class WebSocket:
    """A minimal WebSocket client: enough for the terminal and previews."""

    def __init__(self, host, port, path, headers):
        self.sock = socket.create_connection((host, port), timeout=30)
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            *[f"{k}: {v}" for k, v in headers.items()],
        ]
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(1)
            if not chunk:
                break
            head += chunk
        self.status = int(head.split(b" ", 2)[1]) if head else 0
        self.head = head.decode(errors="replace")
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        self.accepted = self.status == 101 and accept in self.head

    def send(self, payload, opcode=2):
        if isinstance(payload, str):
            payload = payload.encode()
        header = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        self.sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def text(self, value):
        self.send(json.dumps(value), opcode=1)

    def _read(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def recv(self):
        """Returns (opcode, payload), or (None, b"") once closed."""
        try:
            first, second = self._read(2)
            n = second & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            mask = self._read(4) if second & 0x80 else None
            payload = self._read(n)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            return first & 0x0F, payload
        except (EOFError, ConnectionError, socket.timeout):
            return None, b""

    def close(self):
        try:
            self.send(b"\x03\xe8", opcode=8)
        except OSError:
            pass
        self.sock.close()


class Terminal:
    """A terminal session: collects output and the final text frames."""

    def __init__(self, sandbox_id, **params):
        query = urllib.parse.urlencode(params)
        self.ws = WebSocket(
            URL.hostname, URL.port, f"/v1/sandboxes/{sandbox_id}/pty?{query}", {"Authorization": "Bearer " + KEY}
        )
        self.output = b""
        self.messages = []

    def until(self, pattern, timeout_s=20):
        """Reads until the output matches `pattern` or the session ends."""
        deadline = time.monotonic() + timeout_s
        while not re.search(pattern, self.output.decode(errors="replace")):
            if time.monotonic() > deadline:
                return False
            self.ws.sock.settimeout(max(0.1, deadline - time.monotonic()))
            opcode, payload = self.ws.recv()
            if opcode is None or opcode == 8:
                return bool(re.search(pattern, self.output.decode(errors="replace")))
            if opcode == 2:
                self.output += payload
            elif opcode == 1:
                self.messages.append(json.loads(payload))
        return True

    def finish(self, timeout_s=20):
        """Reads to the end. Returns the last text message."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            self.ws.sock.settimeout(max(0.1, deadline - time.monotonic()))
            opcode, payload = self.ws.recv()
            if opcode is None or opcode == 8:
                break
            if opcode == 2:
                self.output += payload
            elif opcode == 1:
                self.messages.append(json.loads(payload))
        self.ws.sock.close()
        return self.messages[-1] if self.messages else None


def terminal_checks(sid):
    t = Terminal(sid, cols=100, rows=30)
    check("terminal upgrades", t.ws.accepted, t.ws.head)
    t.ws.send(b"tty; stty size; echo T=$TERM U=$(id -un) D=$PWD\n")
    check(
        "terminal is a tty with the asked size",
        t.until(r"/dev/pts/\d+\s+30 100\s+T=xterm-256color U=user D=/workspace"),
        t.output[-500:],
    )
    t.ws.text({"type": "resize", "cols": 120, "rows": 40})
    t.ws.text({"type": "input", "data": "stty size\n"})
    check("terminal resizes", t.until(r"40 120"), t.output[-300:])
    out = run(sid, "ls -l /proc/self/fd | grep -c -e ptmx -e /pts/ || true")
    check("other processes do not inherit open terminals", out["stdout"] == "0\n", out)
    t.ws.send(b"sleep 100\n")
    time.sleep(0.5)
    t.ws.send(b"\x03")
    t.ws.send(b"echo after-$((40+2))\n")
    check("ctrl-c stops the foreground job", t.until(r"after-42"), t.output[-300:])
    t.ws.send(b"exit 3\n")
    last = t.finish()
    check("shell exit is reported", last == {"type": "exit", "exit_code": 3, "signal": None, "duration_ms": last and last.get("duration_ms")}, t.messages)

    t = Terminal(sid, cmd="echo hi from $(id -un)", user="root", cwd="/tmp")
    last = t.finish()
    check("terminal runs a command", b"hi from root" in t.output and last["type"] == "exit" and last["exit_code"] == 0, (t.output, last))

    # Leaving hangs up the terminal and its processes.
    t = Terminal(sid, cmd="echo $$ > /tmp/pty.pid; echo started; sleep 1000")
    check("long command starts", t.until("started"), t.output)
    t.ws.close()
    out = run(sid, "sleep 3; kill -0 $(cat /tmp/pty.pid) 2>/dev/null && echo alive || echo gone")
    check("closing the socket ends the session", out["stdout"] == "gone\n", out)

    ws = WebSocket(URL.hostname, URL.port, f"/v1/sandboxes/{sid}/pty", {})
    check("terminal needs an API key", ws.status == 401, ws.head)
    ws.sock.close()
    ws = WebSocket(URL.hostname, URL.port, f"/v1/sandboxes/{sid}/pty?cols=0", {"Authorization": "Bearer " + KEY})
    check("terminal checks its size", ws.status == 400, ws.head)
    ws.sock.close()
    ws = WebSocket(URL.hostname, URL.port, f"/v1/sandboxes/{sid}/pty?user=nobody2", {"Authorization": "Bearer " + KEY})
    check("terminal checks the user", ws.status == 400, ws.head)
    ws.sock.close()


def git_checks(sid):
    status, got = request("POST", f"/v1/sandboxes/{sid}/git:clone", {"url": "https://github.com/octocat/Hello-World"})
    check("clone returns 200", status == 200, (status, got))
    check(
        "clone reports path, commit and branch",
        got["path"] == "/workspace/Hello-World" and re.fullmatch(r"[0-9a-f]{40}", got["commit"]) and got["branch"] == "master",
        got,
    )
    out = run(sid, "cd /workspace/Hello-World && cat README && stat -c %U .")
    check("clone is owned by user", out["stdout"].startswith("Hello World!") and out["stdout"].endswith("user\n"), out)
    status, got = request(
        "POST",
        f"/v1/sandboxes/{sid}/git:clone",
        {"url": "https://github.com/octocat/Hello-World.git", "path": "/tmp/hw shallow", "branch": "test", "depth": 1},
    )
    check("shallow branch clone", status == 200 and got["branch"] == "test" and got["path"] == "/tmp/hw shallow", (status, got))
    out = run(sid, "git -C '/tmp/hw shallow' rev-list --count HEAD")
    check("clone is shallow", out["stdout"] == "1\n", out)
    status, got = request("POST", f"/v1/sandboxes/{sid}/git:clone", {"url": "https://github.com/octocat/Hello-World"})
    check("clone into an existing path fails", status == 400 and "already exists" in got["error"]["message"], (status, got))
    status, got = request(
        "POST", f"/v1/sandboxes/{sid}/git:clone", {"url": "https://github.com/octocat/no-such-repo-spawnbox", "timeout_s": 60}
    )
    check("clone of a missing repo fails fast", status == 400 and "git clone failed" in got["error"]["message"], (status, got))
    expect_error(
        "clone with credentials in the url",
        *request("POST", f"/v1/sandboxes/{sid}/git:clone", {"url": "https://x:y@github.com/octocat/Hello-World"}),
        400,
        "invalid_request",
    )
    expect_error(
        "clone over ssh",
        *request("POST", f"/v1/sandboxes/{sid}/git:clone", {"url": "git@github.com:octocat/Hello-World.git"}),
        400,
        "invalid_request",
    )

    s = create({"egress": {"mode": "allowlist", "allow": ["github.com"]}})
    status, got = request("POST", f"/v1/sandboxes/{s['id']}/git:clone", {"url": "https://github.com/octocat/Hello-World"})
    check("clone in an allowlist sandbox", status == 200 and got["branch"] == "master", (status, got))
    status, got = request(
        "POST", f"/v1/sandboxes/{s['id']}/git:clone", {"url": "https://gitlab.com/gitlab-org/gitlab-foss.git", "timeout_s": 30}
    )
    check("clone from a host outside the allowlist fails", status == 400, (status, got))
    request("DELETE", f"/v1/sandboxes/{s['id']}")


# Serves on 127.0.0.1:3000 and 3001. GET returns the headers it saw;
# /sse streams two events; an Upgrade request switches to echoing bytes.
PREVIEW_APP = r"""
import json, socket, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        if self.headers.get("Upgrade"):
            self.send_response(101)
            self.send_header("Upgrade", self.headers["Upgrade"])
            self.send_header("Connection", "Upgrade")
            self.end_headers()
            self.wfile.flush()
            while True:
                data = self.connection.recv(65536)
                if not data:
                    return
                self.connection.sendall(data[::-1])
        if self.path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for n in (1, 2):
                chunk = f"data: {n}\n\n".encode()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
                time.sleep(1)
            self.wfile.write(b"0\r\n\r\n")
            return
        body = json.dumps({"path": self.path, "port": self.server.server_address[1],
                           "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.upper())

servers = [ThreadingHTTPServer(("127.0.0.1", port), H) for port in (3000, 3001)]
for s in servers[1:]:
    threading.Thread(target=s.serve_forever, daemon=True).start()
servers[0].serve_forever()
"""


def preview_request(url, method="GET", path=None, headers=None, body=None):
    """Sends a request to the preview listener with the URL's host name."""
    preview = urllib.parse.urlsplit(os.environ["SPAWNBOX_PREVIEW"])
    target = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(preview.hostname, preview.port, timeout=30)
    if path is None:
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
    conn.request(method, path, body=body, headers={"Host": target.netloc, **(headers or {})})
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = raw.decode(errors="replace")
    return resp.status, dict(resp.getheaders()), parsed


def preview_checks(sid):
    run(sid, f"cat > /tmp/app.py <<'EOF'\n{PREVIEW_APP}\nEOF")
    run(sid, "setsid python3 /tmp/app.py >/tmp/app.log 2>&1 < /dev/null &")
    out = run(sid, "for i in $(seq 50); do curl -s -o /dev/null localhost:3000 && curl -s -o /dev/null localhost:3001 && break; sleep 0.2; done; curl -s localhost:3000/x")
    check("preview app runs", '"port": 3000' in out["stdout"], (out, run(sid, "cat /tmp/app.log")))

    status, pub = request("POST", f"/v1/sandboxes/{sid}/ports", {"port": 3000, "access": "public"})
    check("publish a public port", status == 200 and pub["access"] == "public" and "3000-sbx-" in pub["url"], (status, pub))
    status, headers, got = preview_request(pub["url"] + "/hello?x=1")
    check("public preview", status == 200 and got["path"] == "/hello?x=1", (status, got))
    check(
        "preview forwards host headers",
        got["headers"]["host"] == urllib.parse.urlsplit(pub["url"]).netloc
        and got["headers"]["x-forwarded-host"] == got["headers"]["host"]
        and got["headers"]["x-forwarded-proto"] == "http",
        got,
    )
    status, _, got = preview_request(pub["url"], method="POST", path="/echo", body=b"shout", headers={"Content-Type": "text/plain"})
    check("preview POST body", status == 200 and got == "SHOUT", (status, got))

    # Server-sent events arrive as they are written.
    preview = urllib.parse.urlsplit(os.environ["SPAWNBOX_PREVIEW"])
    conn = http.client.HTTPConnection(preview.hostname, preview.port, timeout=30)
    started = time.monotonic()
    conn.request("GET", "/sse", headers={"Host": urllib.parse.urlsplit(pub["url"]).netloc})
    resp = conn.getresponse()
    first = resp.read1(64)
    first_s = time.monotonic() - started
    rest = resp.read()
    conn.close()
    check("preview streams SSE", first.startswith(b"data: 1") and first_s < 0.9 and b"data: 2" in rest, (first, first_s, rest))

    # Any upgrade (here: a byte reverser) is spliced through.
    sock = socket.create_connection((preview.hostname, preview.port), timeout=30)
    host = urllib.parse.urlsplit(pub["url"]).netloc
    sock.sendall(f"GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: reverse\r\nConnection: Upgrade\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += sock.recv(1)
    sock.sendall(b"spawnbox")
    echoed = b""
    while len(echoed) < 8:
        echoed += sock.recv(64)
    sock.close()
    check("preview upgrades connections", head.startswith(b"HTTP/1.1 101") and echoed == b"xobnwaps", (head, echoed))

    status, pub6 = request("POST", f"/v1/sandboxes/{sid}/ports", {"port": 3001, "access": "public"})
    status, _, got = preview_request(pub6["url"])
    check("preview reaches a second port", status == 200 and got["port"] == 3001, (status, got))

    status, priv = request("POST", f"/v1/sandboxes/{sid}/ports", {"port": 3000, "access": "private"})
    check("republish as private", status == 200 and priv["access"] == "private" and "?" not in priv["url"], priv)
    status, _, got = preview_request(priv["url"])
    check("private preview needs a key", status == 401, (status, got))
    status, _, got = preview_request(priv["url"], headers={"Authorization": "Bearer sbk_wrong"})
    check("private preview rejects a wrong key", status == 401, (status, got))
    status, _, got = preview_request(priv["url"], headers={"Authorization": "Bearer " + KEY})
    check("private preview with a key", status == 200 and "authorization" not in got["headers"], (status, got))

    status, tok = request("POST", f"/v1/sandboxes/{sid}/ports", {"port": 3000, "access": "token", "ttl_s": 600})
    check("publish with a token", status == 200 and "spawnbox_token=spt_" in tok["url"] and tok["token_expires_at"], tok)
    bare = tok["url"].split("/?")[0]
    status, _, got = preview_request(bare)
    check("token preview needs the link", status == 401, (status, got))
    status, _, got = preview_request(bare + "/?spawnbox_token=spt_wrong")
    check("token preview rejects a wrong token", status == 401, (status, got))
    token = tok["url"].split("spawnbox_token=")[1]
    status, headers, _ = preview_request(f"{bare}/page?a=1&spawnbox_token={token}&b=2")
    cookie = headers.get("set-cookie", "")
    check(
        "token link sets a cookie and redirects",
        status == 302 and headers.get("location") == "/page?a=1&b=2" and cookie.startswith("spawnbox_preview=" + token) and "HttpOnly" in cookie,
        (status, headers),
    )
    status, _, got = preview_request(bare + "/page", headers={"Cookie": f"theme=dark; spawnbox_preview={token}"})
    check(
        "token cookie opens the preview and is not forwarded",
        status == 200 and got["headers"].get("cookie") == "theme=dark",
        (status, got),
    )
    status, page = request("GET", f"/v1/sandboxes/{sid}/ports")
    check("list ports", status == 200 and sorted(p["port"] for p in page["ports"]) == [3000, 3001], page)

    status, _ = request("DELETE", f"/v1/sandboxes/{sid}/ports/3001")
    check("unpublish", status == 204, status)
    status, _, got = preview_request(pub6["url"])
    check("unpublished port is gone", status == 404, (status, got))
    expect_error("unpublish twice", *request("DELETE", f"/v1/sandboxes/{sid}/ports/3001"), 404, "not_found")

    status, idle = request("POST", f"/v1/sandboxes/{sid}/ports", {"port": 4000, "access": "public"})
    status, _, got = preview_request(idle["url"])
    check("nothing listening is a 502", status == 502, (status, got))
    status, _, got = preview_request("http://3000-sbx-0000000000000000.localhost")
    check("unknown sandbox is a 404", status == 404, (status, got))
    expect_error("bad port", *request("POST", f"/v1/sandboxes/{sid}/ports", {"port": 0}), 400, "invalid_request")
    expect_error(
        "ttl only for token",
        *request("POST", f"/v1/sandboxes/{sid}/ports", {"port": 80, "access": "public", "ttl_s": 5}),
        400,
        "invalid_request",
    )
    request("DELETE", f"/v1/sandboxes/{sid}")
    status, _, got = preview_request(pub["url"])
    check("deleted sandbox has no previews", status == 404, (status, got))


def interactive_checks():
    s = create({"template": "smoke-jq"})
    terminal_checks(s["id"])
    git_checks(s["id"])
    preview_checks(s["id"])


def stamp(text):
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def get_sandbox(sid):
    status, got = request("GET", f"/v1/sandboxes/{sid}")
    check("get sandbox", status == 200, (status, got))
    return got


def pause(sid, name="pause"):
    started = time.monotonic()
    status, got = request("POST", f"/v1/sandboxes/{sid}:pause")
    elapsed = time.monotonic() - started
    check(
        name,
        status == 200 and got["state"] == "paused" and got["expires_at"] is None and got["paused_at"],
        (status, got),
    )
    return got, elapsed


def pause_checks():
    s = create({"template": "smoke-jq", "timeout_s": 900})
    sid = s["id"]
    check("view has idle_pause_s", s["idle_pause_s"] == 600 and s["paused_at"] is None, s)
    run(sid, "echo kept > /workspace/note; setsid sh -c 'i=0; while :; do i=$((i+1)); echo $i > /tmp/count; sleep 0.2; done' >/dev/null 2>&1 < /dev/null &")
    run(sid, f"cat > /tmp/app.py <<'EOF'\n{PREVIEW_APP}\nEOF")
    run(sid, "setsid python3 /tmp/app.py >/tmp/app.log 2>&1 < /dev/null &")
    run(sid, "for i in $(seq 50); do curl -s -o /dev/null localhost:3000 && break; sleep 0.2; done")
    status, pub = request("POST", f"/v1/sandboxes/{sid}/ports", {"port": 3000, "access": "public"})
    check("publish before pause", status == 200, (status, pub))
    # Caches the gateway's MAC address in the guest before the pause.
    run(sid, "timeout 5 getent hosts example.com")
    before = get_sandbox(sid)

    paused, pause_s = pause(sid)
    report["pause_s"] = round(pause_s, 3)
    paused_again, _ = pause(sid, "pause is idempotent")
    check("second pause keeps paused_at", paused_again["paused_at"] == paused["paused_at"], paused_again)
    check("paused sandbox is listed as paused", get_sandbox(sid)["state"] == "paused")
    time.sleep(5)

    started = time.monotonic()
    out = run(sid, "cat /workspace/note; cat /tmp/count; sleep 1; cat /tmp/count")
    report["exec_resume_s"] = round(time.monotonic() - started, 3)
    lines = out["stdout"].split("\n")
    check("exec wakes the sandbox with its files", lines[0] == "kept", out)
    check("background processes survive a pause", int(lines[2]) > int(lines[1]), out)
    after = get_sandbox(sid)
    check("woken sandbox is running", after["state"] == "running" and after["paused_at"] is None, after)
    shift = stamp(after["expires_at"]) - stamp(before["expires_at"])
    check("paused time does not count toward the timeout", shift >= 4.5, (before, after))
    out = run(sid, "date +%s")
    check("guest clock is right after resume", abs(int(out["stdout"]) - time.time()) < 3, out)
    out = run(sid, "timeout 5 getent hosts example.com")
    check("network works after resume", out["exit_code"] == 0, out)

    pause(sid)
    started = time.monotonic()
    status, _, got = preview_request(pub["url"] + "/woken")
    report["preview_resume_s"] = round(time.monotonic() - started, 3)
    check("preview wakes the sandbox", status == 200 and got["path"] == "/woken", (status, got))

    pause(sid)
    status, body = raw("GET", files_path(sid, "/workspace/note"))
    check("file read wakes the sandbox", status == 200 and body == b"kept\n", (status, body))

    pause(sid)
    t = Terminal(sid, cmd="cat /workspace/note")
    last = t.finish()
    check("terminal wakes the sandbox", b"kept" in t.output and last and last["exit_code"] == 0, (t.output, last))

    pause(sid)
    status, pub2 = request("POST", f"/v1/sandboxes/{sid}/ports", {"port": 3001, "access": "public"})
    check("publish while paused", status == 200 and "3001-sbx-" in pub2["url"], (status, pub2))
    status, page = request("GET", f"/v1/sandboxes/{sid}/ports")
    check("list ports while paused", status == 200 and sorted(p["port"] for p in page["ports"]) == [3000, 3001], page)
    status, _ = request("DELETE", f"/v1/sandboxes/{sid}/ports/3001")
    check("unpublish while paused", status == 204, status)
    check("port changes do not wake the sandbox", get_sandbox(sid)["state"] == "paused")

    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        outs = list(pool.map(lambda i: request("POST", f"/v1/sandboxes/{sid}/exec", {"cmd": f"echo {i}"}), range(8)))
    check("concurrent calls share one resume", all(o[0] == 200 and o[1]["stdout"] == f"{i}\n" for i, o in enumerate(outs)), outs)

    status, got = request("POST", f"/v1/sandboxes/{sid}:resume")
    check("explicit resume of a running sandbox", status == 200 and got["state"] == "running", (status, got))
    out = run(sid, "head -c 600M /dev/urandom > /dev/shm/fill && md5sum < /dev/shm/fill")
    _, pause_s = pause(sid, "pause with most memory in use")
    report["pause_full_s"] = round(pause_s, 3)
    # Mostly disk speed: Firecracker flushes the disks, which waits for
    # earlier pauses' memory files on the same file system.
    check("pause with most memory in use finishes", pause_s < 60, pause_s)
    again = run(sid, "md5sum < /dev/shm/fill; rm /dev/shm/fill")
    check("memory survives a pause", again["stdout"] == out["stdout"], (out, again))

    pause(sid)
    started = time.monotonic()
    status, got = request("POST", f"/v1/sandboxes/{sid}:resume")
    report["resume_s"] = round(time.monotonic() - started, 3)
    check("explicit resume", status == 200 and got["state"] == "running" and got["expires_at"], (status, got))
    out = run(sid, "cat /workspace/note")
    check("resumed sandbox runs commands", out["stdout"] == "kept\n", out)

    expect_error("unknown action", *request("POST", f"/v1/sandboxes/{sid}:explode"), 404, "not_found")
    expect_error("pause an unknown sandbox", *request("POST", "/v1/sandboxes/sbx_0000000000000000:pause"), 404, "not_found")
    expect_error("idle_pause_s too large", *request("POST", "/v1/sandboxes", {"idle_pause_s": 10**9}), 400, "invalid_request")

    pause(sid)
    status, _ = request("DELETE", f"/v1/sandboxes/{sid}")
    check("delete a paused sandbox", status == 204, status)
    check("deleted paused sandbox", get_sandbox(sid)["state"] == "deleted")
    expect_error("resume a deleted sandbox", *request("POST", f"/v1/sandboxes/{sid}:resume"), 409, "conflict")

    idle = create({"idle_pause_s": 2})
    check("create sets idle_pause_s", idle["idle_pause_s"] == 2, idle)
    stream = sse(idle["id"], "sleep 4; echo done")
    check("a running command keeps the sandbox awake", any(e == "exit" for _, e, _ in stream) and get_sandbox(idle["id"])["state"] == "running", stream)
    deadline = time.monotonic() + 20
    while get_sandbox(idle["id"])["state"] != "paused" and time.monotonic() < deadline:
        time.sleep(0.5)
    check("idle sandbox pauses itself", get_sandbox(idle["id"])["state"] == "paused")
    out = run(idle["id"], "echo awake")
    check("idle-paused sandbox wakes", out["stdout"] == "awake\n", out)
    never = create({"idle_pause_s": 0})
    time.sleep(3)
    check("idle_pause_s 0 never pauses", get_sandbox(never["id"])["state"] == "running")
    for x in (idle, never):
        request("DELETE", f"/v1/sandboxes/{x['id']}")

    keep = create({"template": "smoke-jq", "timeout_s": 900})
    run(keep["id"], "echo survives > /workspace/restart")
    pause(keep["id"])
    report["paused_id"] = keep["id"]


def restart_checks(build_id, paused_id):
    got = get_sandbox(paused_id)
    check("paused sandbox survives a restart", got["state"] == "paused", got)
    out = run(paused_id, "cat /workspace/restart")
    check("paused sandbox resumes after a restart", out["stdout"] == "survives\n", out)
    request("DELETE", f"/v1/sandboxes/{paused_id}")
    status, got = request("GET", "/v1/templates/smoke-jq")
    check("template survives restart", status == 200 and got["current_build"] == build_id, got)
    t = create({"template": "smoke-jq"})
    out = run(t["id"], "jq -n '3'; cat /workspace/warm")
    check("restored build works", out["stdout"] == "3\nuser\n", out)
    request("DELETE", f"/v1/sandboxes/{t['id']}")
    status, _ = request("DELETE", "/v1/templates/smoke-jq")
    check("delete built template", status == 204, status)
    expect_error(
        "create from deleted template",
        *request("POST", "/v1/sandboxes", {"template": "smoke-jq"}),
        400,
        "invalid_request",
    )


def tenant_checks():
    def as_key(key):
        def call(method, path, body=None):
            return request(method, path, body, key=key)
        call.key = key
        return call

    def make(call, body=None, name="create"):
        status, got = call("POST", "/v1/sandboxes", body or {})
        check(name, status == 201 and got["state"] == "running", (status, got))
        return got

    def sh(call, sid, cmd):
        status, got = call("POST", f"/v1/sandboxes/{sid}/exec", {"cmd": cmd})
        check(f"exec {cmd[:40]!r}", status == 200, (status, got))
        return got

    org = as_key(KEY)
    suffix = str(int(time.time()))[-6:]
    acme_id, beta_id = f"acme-{suffix}", f"beta-{suffix}"

    status, got = org("GET", "/v1/tenants")
    default = next((t for t in got["tenants"] if t["id"] == "default"), None) if status == 200 else None
    check("default tenant exists", default is not None, (status, got))

    status, acme = org("POST", "/v1/tenants", {
        "id": acme_id,
        "name": "Acme",
        "quotas": {"running_sandboxes": 1, "max_session_s": 120, "max_paused_retention_s": 3600},
        "egress": {"mode": "allowlist", "allow": ["example.com"]},
    })
    check(
        "create tenant",
        status == 201 and acme["quotas"]["running_sandboxes"] == 1 and acme["quotas"]["running_vcpus"] == 40,
        (status, acme),
    )
    expect_error("duplicate tenant", *org("POST", "/v1/tenants", {"id": acme_id}), 409, "conflict")
    expect_error("bad tenant id", *org("POST", "/v1/tenants", {"id": "Acme!"}), 400, "invalid_request")
    expect_error("unknown tenant", *org("GET", "/v1/tenants/nope-nope"), 404, "not_found")
    status, beta = org("POST", "/v1/tenants", {"id": beta_id})
    check("create second tenant", status == 201, (status, beta))
    status, got = org("PATCH", f"/v1/tenants/{beta_id}", {"name": "Beta", "quotas": {"running_vcpus": None}})
    check("update tenant", status == 200 and got["name"] == "Beta" and got["quotas"]["running_vcpus"] is None, (status, got))

    status, key = org("POST", "/v1/keys", {"tenant": acme_id, "name": "acme-ci"})
    check("create tenant key", status == 201 and key["key"].startswith("sbx_tn_") and key["tenant"] == acme_id, (status, key))
    acme_key_id = key["id"]
    acme = as_key(key["key"])
    status, key = org("POST", "/v1/keys", {"tenant": acme_id, "scopes": ["sandboxes:read"]})
    check("create read-only key", status == 201 and key["scopes"] == ["sandboxes:read"], (status, key))
    reader = as_key(key["key"])
    status, key = org("POST", "/v1/keys", {"tenant": beta_id})
    beta = as_key(key["key"])
    status, key = org("POST", "/v1/keys", {})
    check("create org key", status == 201 and key["key"].startswith("sbx_org_") and key["tenant"] is None, (status, key))
    spare = as_key(key["key"])
    expect_error(
        "tenant keys cannot admin",
        *org("POST", "/v1/keys", {"tenant": acme_id, "scopes": ["tenants:admin"]}),
        400,
        "invalid_request",
    )
    expect_error("key for unknown tenant", *org("POST", "/v1/keys", {"tenant": "nope-nope"}), 400, "invalid_request")
    status, got = org("GET", "/v1/keys")
    check("list keys hides secrets", status == 200 and all("key" not in k for k in got["keys"]), (status, got))

    # Scopes.
    expect_error("tenant key cannot list tenants", *acme("GET", "/v1/tenants"), 403, "forbidden")
    expect_error("tenant key cannot make keys", *acme("POST", "/v1/keys", {}), 403, "forbidden")
    expect_error("read-only key cannot create", *reader("POST", "/v1/sandboxes", {}), 403, "forbidden")

    # Sandboxes belong to their tenant; the session cap applies.
    a = make(acme, name="tenant creates a sandbox")
    check("sandbox has its tenant", a["tenant"] == acme_id, a)
    lifetime = (
        datetime.datetime.fromisoformat(a["expires_at"].replace("Z", "+00:00"))
        - datetime.datetime.fromisoformat(a["created_at"].replace("Z", "+00:00"))
    ).total_seconds()
    check("default timeout fits max_session_s", 115 <= lifetime <= 120, a)
    expect_error("timeout over max_session_s", *acme("POST", "/v1/sandboxes", {"timeout_s": 121}), 400, "invalid_request")
    expect_error("running_sandboxes quota", *acme("POST", "/v1/sandboxes", {}), 429, "quota_exceeded")
    status, got = org("GET", f"/v1/tenants/{acme_id}")
    check("tenant shows usage", status == 200 and got["usage"]["running_sandboxes"] == 1, (status, got))
    status, got = reader("GET", f"/v1/sandboxes/{a['id']}")
    check("read-only key reads its tenant's sandbox", status == 200, (status, got))
    expect_error("read-only key cannot exec", *reader("POST", f"/v1/sandboxes/{a['id']}/exec", {"cmd": "true"}), 403, "forbidden")

    d = make(org, name="org key creates in default")
    check("org sandbox defaults to default tenant", d["tenant"] == "default", d)
    for name, method, path, body in [
        ("get", "GET", "", None),
        ("exec", "POST", "/exec", {"cmd": "true"}),
        ("files", "GET", "/files?path=/etc/hostname", None),
        ("pause", "POST", ":pause", None),
        ("delete", "DELETE", "", None),
    ]:
        expect_error(f"other tenant's sandbox: {name}", *acme(method, f"/v1/sandboxes/{d['id']}{path}", body), 404, "not_found")
    expect_error("other tenant's sandbox: pty", *beta("GET", f"/v1/sandboxes/{a['id']}/pty"), 404, "not_found")
    encoded = d["id"].replace("_", "%5F", 1)
    expect_error("encoded id cannot reach another tenant", *acme("GET", f"/v1/sandboxes/{encoded}"), 404, "not_found")
    expect_error("encoded verb cannot reach another tenant", *acme("POST", f"/v1/sandboxes/{d['id']}%3Apause"), 404, "not_found")
    expect_error("tenant key names another tenant", *acme("POST", "/v1/sandboxes", {"tenant": "default"}), 404, "not_found")
    status, got = acme("GET", "/v1/sandboxes")
    check("tenant lists only its own", status == 200 and [s["id"] for s in got["sandboxes"]] == [a["id"]], (status, got))
    status, got = org("GET", f"/v1/sandboxes?tenant={acme_id}")
    check("org lists one tenant", status == 200 and [s["id"] for s in got["sandboxes"]] == [a["id"]], (status, got))
    status, got = org("GET", "/v1/sandboxes")
    ids_all = {s["id"] for s in got["sandboxes"]}
    check("org lists every tenant", status == 200 and {a["id"], d["id"]} <= ids_all, (status, got))
    status, got = org("GET", f"/v1/sandboxes/{a['id']}")
    check("org sees tenant sandboxes", status == 200 and got["tenant"] == acme_id, (status, got))

    # Private previews only open for keys that see the sandbox.
    status, pub = acme("POST", f"/v1/sandboxes/{a['id']}/ports", {"port": 3000, "access": "private"})
    check("publish a private port", status == 200, (status, pub))
    status, _, got = preview_request(pub["url"], headers={"Authorization": "Bearer " + beta.key})
    check("other tenant's key cannot open a private preview", status == 404, (status, got))
    status, _, got = preview_request(pub["url"], headers={"Authorization": "Bearer " + acme.key})
    check("own key passes the preview check", status not in (401, 403, 404), (status, got))

    # The tenant's egress policy applies on top of the sandbox's.
    out = sh(acme, a["id"], "curl -s -o /dev/null -w '%{http_code}' -m 15 https://example.com/")
    check("tenant allowlist allows", out["stdout"] == "200", out)
    out = sh(acme, a["id"], "curl -s -o /dev/null -w '%{http_code}' -m 15 https://github.com/ || true")
    check("tenant allowlist blocks", out["stdout"] != "200", out)

    # Paused sandboxes do not count; resuming is admitted like a create.
    status, got = acme("POST", f"/v1/sandboxes/{a['id']}:pause")
    check("tenant pauses", status == 200 and got["state"] == "paused", (status, got))
    b = make(acme, name="paused sandboxes free the quota")
    expect_error("resume over quota", *acme("POST", f"/v1/sandboxes/{a['id']}:resume"), 429, "quota_exceeded")
    expect_error("exec wakes over quota", *acme("POST", f"/v1/sandboxes/{a['id']}/exec", {"cmd": "true"}), 429, "quota_exceeded")
    status, _ = acme("DELETE", f"/v1/sandboxes/{b['id']}")
    check("tenant deletes", status == 204, status)
    status, got = acme("POST", f"/v1/sandboxes/{a['id']}:resume")
    check("resume within quota", status == 200 and got["state"] == "running", (status, got))

    # Secrets: own ones, and org-wide ones read-only.
    secret = lambda name, value: {"name": name, "type": "http_header", "value": value, "allowed_hosts": ["example.com"]}
    status, got = org("POST", "/v1/secrets", secret(f"smoke-org-{suffix}", "org-value"))
    check("org-wide secret", status == 201 and got["tenant"] is None, (status, got))
    status, got = acme("POST", "/v1/secrets", secret(f"smoke-org-{suffix}", "acme-value"))
    check("tenant shadows an org-wide secret", status == 201 and got["tenant"] == acme_id and got["name"] == f"smoke-org-{suffix}", (status, got))
    status, got = org("POST", "/v1/secrets", secret(f"smoke-shared-{suffix}", "shared"))
    expect_error("org-wide secret is read-only", *acme("PATCH", f"/v1/secrets/smoke-shared-{suffix}", {"value": "x"}), 403, "forbidden")
    expect_error("tenant cannot delete org-wide", *acme("DELETE", f"/v1/secrets/smoke-shared-{suffix}"), 403, "forbidden")
    status, got = acme("GET", "/v1/secrets")
    names = sorted(
        ((s["name"], s["tenant"]) for s in got["secrets"] if suffix in s["name"]),
        key=lambda item: (item[0], item[1] or ""),
    )
    check(
        "tenant lists own and org-wide",
        names == [(f"smoke-org-{suffix}", None), (f"smoke-org-{suffix}", acme_id), (f"smoke-shared-{suffix}", None)],
        names,
    )
    status, got = beta("GET", "/v1/secrets")
    check("other tenant sees only org-wide", all(s["tenant"] is None for s in got["secrets"]), got)
    expect_error("other tenant cannot reach a private secret", *beta("GET", f"/v1/secrets/smoke-org-{suffix}?tenant={acme_id}"), 404, "not_found")
    status, got = org("GET", f"/v1/secrets/smoke-org-{suffix}?tenant={acme_id}")
    check("org reads in a tenant's namespace", status == 200 and got["tenant"] == acme_id, (status, got))

    # Templates: base is org-wide, a tenant's own are private.
    status, got = acme("GET", "/v1/templates/base")
    check("tenant reads base", status == 200 and got["tenant"] is None, (status, got))
    expect_error("tenant cannot delete base", *acme("DELETE", "/v1/templates/base"), 400, "invalid_request")
    status, _ = acme("DELETE", f"/v1/sandboxes/{a['id']}")
    tpl = f"smoke-tn-{suffix}"
    status, got = acme("POST", "/v1/templates", {"name": tpl, "setup": ["echo acme > /etc/acme"]})
    check("tenant creates a template", status == 202 and got["template"]["tenant"] == acme_id, (status, got))
    build_id = got["build"]["id"]
    deadline = time.monotonic() + 600
    while True:
        status, build = acme("GET", f"/v1/templates/{tpl}/builds/{build_id}")
        check("tenant reads its build", status == 200 and build["template"] == tpl, (status, build))
        if build["state"] not in ("queued", "building"):
            break
        check("tenant build finishes in time", time.monotonic() < deadline, build)
        time.sleep(2)
    check("tenant build is ready", build["state"] == "ready", build)
    expect_error("org-wide lookup misses a tenant's template", *org("GET", f"/v1/templates/{tpl}"), 404, "not_found")
    status, got = org("GET", "/v1/templates")
    check("org lists every template", any(t["name"] == tpl and t["tenant"] == acme_id for t in got["templates"]), got)
    expect_error("other tenant cannot use it", *beta("POST", "/v1/sandboxes", {"template": tpl}), 400, "invalid_request")
    t = make(acme, {"template": tpl, "secrets": [f"smoke-org-{suffix}"]}, name="create from own template")
    out = sh(acme, t["id"], "cat /etc/acme")
    check("own template content", out["stdout"] == "acme\n", out)
    out = sh(acme, t["id"], "curl -s -m 15 -H 'X-Probe: 1' https://example.com/ -o /dev/null -w '%{http_code}'")
    check("tenant secret attaches", out["stdout"] == "200", out)

    # A tenant with things left cannot be deleted.
    expect_error("delete default", *org("DELETE", "/v1/tenants/default"), 400, "invalid_request")
    expect_error("delete busy tenant", *org("DELETE", f"/v1/tenants/{acme_id}"), 409, "conflict")
    acme("DELETE", f"/v1/sandboxes/{t['id']}")
    expect_error("delete tenant with templates", *org("DELETE", f"/v1/tenants/{acme_id}"), 409, "conflict")
    status, _ = acme("DELETE", f"/v1/templates/{tpl}")
    check("tenant deletes its template", status == 204, status)
    expect_error("delete tenant with secrets", *org("DELETE", f"/v1/tenants/{acme_id}"), 409, "conflict")
    status, _ = acme("DELETE", f"/v1/secrets/smoke-org-{suffix}")
    check("tenant deletes its secret", status == 204, status)
    status, got = org("GET", f"/v1/secrets/smoke-org-{suffix}")
    check("org-wide secret stays", status == 200 and got["tenant"] is None, (status, got))
    status, _ = org("DELETE", f"/v1/tenants/{acme_id}")
    check("delete empty tenant", status == 204, status)
    expect_error("deleted tenant's keys stop working", *acme("GET", "/v1/sandboxes"), 401, "unauthorized")
    status, got = org("GET", "/v1/keys")
    revoked = next(k for k in got["keys"] if k["id"] == acme_key_id)
    check("deleted tenant's keys are revoked", revoked["revoked_at"] is not None, revoked)

    status, got = spare("GET", "/v1/tenants")
    check("new org key works", status == 200, (status, got))
    status, _ = org("DELETE", f"/v1/keys/{key['id']}")
    check("revoke key", status == 204, status)
    expect_error("revoked key", *spare("GET", "/v1/tenants"), 401, "unauthorized")
    expect_error("revoke unknown key", *org("DELETE", "/v1/keys/key_nope"), 404, "not_found")

    org("DELETE", f"/v1/sandboxes/{d['id']}")
    for name in (f"smoke-org-{suffix}", f"smoke-shared-{suffix}"):
        org("DELETE", f"/v1/secrets/{name}")
    status, _ = org("DELETE", f"/v1/tenants/{beta_id}")
    check("delete second tenant", status == 204, status)



def event_checks():
    suffix = str(int(time.time()))[-6:]

    def step(name):
        return {"X-Spawnbox-Step": name}

    def events(path, want=None, limit_s=15):
        """GETs `path` until `want(events)` holds, for events written in
        the background."""
        deadline = time.monotonic() + limit_s
        while True:
            status, got = request("GET", path)
            check(f"GET {path}", status == 200, (status, got))
            if want is None or want(got["events"]) or time.monotonic() > deadline:
                return got
            time.sleep(0.3)

    def of(evs, kind, **attrs):
        return [
            e for e in evs
            if e["type"] == kind and all(e["attrs"].get(k) == v for k, v in attrs.items())
        ]

    secret = f"ev-tok-{suffix}"
    status, got = request("POST", "/v1/secrets", {
        "name": secret, "type": "http_header", "value": f"s3cret-{suffix}",
        "allowed_hosts": ["postman-echo.com"],
    })
    check("create secret", status == 201, (status, got))

    status, sb = request("POST", "/v1/sandboxes", {
        "secrets": [secret],
        "egress": {"mode": "allowlist", "allow": ["example.com", "postman-echo.com"]},
    }, headers=step("step-create"))
    check("create with a step", status == 201, (status, sb))
    sid = sb["id"]
    base = f"/v1/sandboxes/{sid}/events"

    status, got = request("POST", f"/v1/sandboxes/{sid}/exec", {"cmd": "true"}, headers=step("bad step"))
    expect_error("step with a space", status, got, 400, "invalid_request")

    # The sleep lets the proxy report closed connections while the step runs.
    net_cmd = (
        "curl -s -o /dev/null -w '%{http_code}\\n' https://example.com; "
        # DNS refuses github.com; a fixed address lets the proxy block it.
        "curl -s -m 5 -o /dev/null --resolve github.com:443:1.1.1.1 https://github.com || echo blocked; "
        "curl -s https://postman-echo.com/headers >/dev/null; sleep 1"
    )
    status, got = request("POST", f"/v1/sandboxes/{sid}/exec", {"cmd": net_cmd}, headers=step("step-net"))
    check("network exec", status == 200 and "200" in got["stdout"] and "blocked" in got["stdout"], (status, got))

    status, out = request(
        "POST", f"/v1/sandboxes/{sid}/exec",
        {"cmd": "echo hello-out; echo err-out >&2; exit 3"},
        headers={**step("step-out"), "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
    )
    check("exec result has an exec_id", status == 200 and out["exec_id"].startswith("ex_"), (status, out))

    payload = b"abc"
    status, got = request("PUT", f"/v1/sandboxes/{sid}/files?path=ev.txt", payload, headers=step("step-file"))
    check("write file", status == 200, (status, got))

    got = events(base + "?limit=1000", lambda evs: of(evs, "exec.finished", exec_id=out["exec_id"])
                 and of(evs, "file.written") and of(evs, "secret.injected"))
    evs = got["events"]
    ids = [int(e["id"]) for e in evs]
    check("ids increase", ids == sorted(ids), ids)
    created = of(evs, "sandbox.created")
    check("sandbox.created has the step and the key", created and created[0]["step_id"] == "step-create"
          and created[0]["actor"].startswith("key_") and created[0]["tenant"] == "default", created)
    started = of(evs, "exec.started", exec_id=out["exec_id"])
    check("exec.started", started and started[0]["step_id"] == "step-out", started)
    finished = of(evs, "exec.finished", exec_id=out["exec_id"])
    f = finished[0] if finished else {}
    check("exec.finished has exit and output tails", f.get("step_id") == "step-out"
          and f["attrs"]["exit_code"] == 3 and f["attrs"]["stdout_tail"] == "hello-out\n"
          and f["attrs"]["stderr_tail"] == "err-out\n" and f["attrs"]["stdout_bytes"] == 10, f)
    check("exec.finished has the trace", f.get("trace_id") == "0af7651916cd43dd8448eb211c80319c", f)
    conn = of(evs, "net.connection", host="example.com")
    check("net.connection is tagged with the step", conn and conn[0]["step_id"] == "step-net"
          and conn[0]["attrs"]["bytes_down"] > 0, conn)
    blocked = of(evs, "net.blocked", host="github.com")
    check("net.blocked", blocked and blocked[0]["step_id"] == "step-net", blocked)
    injected = of(evs, "secret.injected", name=secret)
    tapped = of(evs, "net.connection", host="postman-echo.com", verdict="intercept")
    check("intercepted connections count bytes", tapped and tapped[0]["attrs"]["bytes_down"] > 0, tapped)
    check("secret.injected", injected and injected[0]["step_id"] == "step-net"
          and injected[0]["attrs"]["host"] == "postman-echo.com" and injected[0]["attrs"]["status"] == 200, injected)
    check("no secret value in events", f"s3cret-{suffix}" not in json.dumps(evs), "value leaked")
    written = of(evs, "file.written", path="/workspace/ev.txt")
    check("file.written has the hash", written and written[0]["attrs"]["sha256"] == hashlib.sha256(payload).hexdigest()
          and written[0]["step_id"] == "step-file", written)

    got = events(base + "?step_id=step-out")
    check("filter by step", got["events"] and all(e["step_id"] == "step-out" for e in got["events"]), got)
    got = events(base + "?type=exec.*,file.written")
    kinds = {e["type"] for e in got["events"]}
    check("filter by type group", kinds == {"exec.started", "exec.finished", "file.written"}, kinds)
    first = events(base + "?limit=2")
    check("paging has more", len(first["events"]) == 2 and first["has_more"], first)
    second = events(base + f"?limit=2&cursor={first['next_cursor']}")
    check("next page continues", int(second["events"][0]["id"]) > int(first["events"][-1]["id"]), second)
    got = events(f"/v1/events?sandbox={sid}&type=sandbox.*")
    check("global feed filters by sandbox", got["events"] and all(e["sandbox"] == sid for e in got["events"]), got)
    got = events(f"/v1/events?type=secret.created")
    check("admin events", of(got["events"], "secret.created", name=secret), got)
    future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()
    got = events(base + "?since=" + urllib.parse.quote(future))
    check("since filter", got["events"] == [], got)
    expect_error("bad since", *request("GET", base + "?since=yesterday"), 400, "invalid_request")
    expect_error("bad type", *request("GET", base + "?type=Exec!"), 400, "invalid_request")

    # Live follow: a feed opened now sees the next exec.
    conn = http.client.HTTPConnection(URL.hostname, URL.port, timeout=30)
    conn.request("GET", f"{base}?follow=true&type=exec.finished",
                 headers={"Authorization": "Bearer " + KEY, "Accept": "text/event-stream"})
    resp = conn.getresponse()
    check("follow returns sse", resp.status == 200
          and resp.getheader("Content-Type", "").startswith("text/event-stream"), resp.status)
    live = run(sid, "echo live")
    seen = None
    deadline = time.monotonic() + 20
    while seen is None and time.monotonic() < deadline:
        line = resp.fp.readline().decode().rstrip("\r\n")
        if line.startswith("data:"):
            seen = json.loads(line[5:])
    conn.close()
    check("follow gets the live event", seen and seen["attrs"]["exec_id"] == live["exec_id"], seen)

    # Tenants only see their own events.
    tenant = f"evt-{suffix}"
    status, got = request("POST", "/v1/tenants", {"id": tenant})
    check("create tenant", status == 201, (status, got))
    status, tk = request("POST", "/v1/keys", {"tenant": tenant})
    check("tenant key", status == 201, (status, tk))
    status, rk = request("POST", "/v1/keys", {"tenant": tenant, "scopes": ["sandboxes:read"]})
    check("read-only key", status == 201, (status, rk))
    status, got = request("GET", "/v1/events", key=tk["key"])
    check("tenant sees only its events", status == 200 and got["events"]
          and all(e["tenant"] == tenant for e in got["events"]), (status, got))
    expect_error("tenant cannot read other sandbox events", *request("GET", base, key=tk["key"]), 404, "not_found")
    expect_error("tenant cannot ask for another tenant",
                 *request("GET", "/v1/events?tenant=default", key=tk["key"]), 404, "not_found")
    expect_error("events need audit:read", *request("GET", "/v1/events", key=rk["key"]), 403, "forbidden")

    otlp_log = os.environ.get("SPAWNBOX_OTLP_LOG")
    if otlp_log:
        deadline, data = time.monotonic() + 20, b""
        while time.monotonic() < deadline:
            data = open(otlp_log, "rb").read() if os.path.exists(otlp_log) else b""
            if out["exec_id"].encode() in data:
                break
            time.sleep(0.5)
        check("events reach the OTLP collector", out["exec_id"].encode() in data
              and b"exec.finished" in data and b"step-out" in data, len(data))

    status, _ = request("DELETE", f"/v1/sandboxes/{sid}", headers=step("step-delete"))
    check("delete sandbox", status == 204, status)
    got = events(base + "?type=sandbox.killed", lambda evs: evs)
    check("sandbox.killed", got["events"] and got["events"][0]["step_id"] == "step-delete", got)
    got = events(base + "?type=exec.*", lambda evs: evs)
    check("deleted sandbox events stay readable", got["events"], got)
    request("DELETE", f"/v1/secrets/{secret}")
    request("DELETE", f"/v1/keys/{tk['id']}")
    request("DELETE", f"/v1/keys/{rk['id']}")
    status, _ = request("DELETE", f"/v1/tenants/{tenant}")
    check("delete tenant", status == 204, status)


def usage_checks():
    suffix = str(int(time.time()))[-6:]
    tenant = f"meter-{suffix}"
    status, got = request("POST", "/v1/tenants", {"id": tenant})
    check("create tenant", status == 201 and got["quotas"]["monthly_egress_bytes"] is None
          and got["quotas"]["snapshot_storage_gib"] is None, (status, got))
    status, tk = request("POST", "/v1/keys", {"tenant": tenant})
    check("tenant key", status == 201, (status, tk))
    status, rk = request("POST", "/v1/keys", {"tenant": tenant, "scopes": ["sandboxes:read"]})
    check("read-only key", status == 201, (status, rk))
    key = tk["key"]

    def usage(query="", as_key=key):
        status, got = request("GET", "/v1/usage" + query, key=as_key)
        check(f"GET /v1/usage{query}", status == 200, (status, got))
        return got

    def quotas(**fields):
        status, got = request("PATCH", f"/v1/tenants/{tenant}", {"quotas": fields})
        check(f"set quotas {fields}", status == 200, (status, got))

    expect_error("usage needs usage:read", *request("GET", "/v1/usage", key=rk["key"]), 403, "forbidden")
    expect_error("tenant key names another tenant",
                 *request("GET", "/v1/usage?tenant=default", key=key), 404, "not_found")
    expect_error("bad group_by", *request("GET", "/v1/usage?group_by=hour", key=key), 400, "invalid_request")
    expect_error("bad from", *request("GET", "/v1/usage?from=yesterday", key=key), 400, "invalid_request")
    expect_error("range too long",
                 *request("GET", "/v1/usage?from=2026-01-01T00:00:00Z&to=2026-06-01T00:00:00Z", key=key),
                 400, "invalid_request")
    empty = usage()
    check("no usage yet", empty["usage"] == [] and empty["total"]["vcpu_s"] == 0 and empty["tenant"] == tenant, empty)

    status, sb = request("POST", "/v1/sandboxes", {}, key=key)
    check("create", status == 201, (status, sb))
    created = time.monotonic()
    sid = sb["id"]
    status, info = request("GET", f"/v1/tenants/{tenant}")
    vcpus, gib = info["usage"]["running_vcpus"], info["usage"]["running_memory_mib"] / 1024
    out = run_as(key, sid, "head -c 1048576 /dev/urandom > ~/written && "
                 "curl -sS -o /dev/null -w '%{http_code}' https://example.com")
    check("download", out["stdout"] == "200", out)
    # Disks are measured every 10 s.
    deadline = time.monotonic() + 15
    time.sleep(3)
    got = usage()
    while got["total"]["disk_gib_h"] == 0 and time.monotonic() < deadline:
        time.sleep(1)
        got = usage()
    elapsed = time.monotonic() - created
    total = got["total"]
    check("vcpu seconds match the reserved size", abs(total["vcpu_s"] - vcpus * elapsed) <= vcpus * 1.5,
          (total, vcpus, elapsed))
    check("memory GiB-seconds match", abs(total["mem_gib_s"] - gib * elapsed) <= gib * 1.5, (total, gib, elapsed))
    check("disk is counted", total["disk_gib_h"] > 0, total)
    check("egress is counted", total["egress_bytes"] > 1000, total)
    check("rows are per tenant and hour", got["usage"] and all(
        r["tenant"] == tenant and "sandbox" not in r and r["hour"].endswith(":00:00.000Z") for r in got["usage"]), got)
    by = usage("?group_by=sandbox")
    check("group_by=sandbox", by["usage"] and all(r["sandbox"] == sid for r in by["usage"]), by)

    status, _ = request("POST", f"/v1/sandboxes/{sid}:pause", key=key)
    check("pause", status == 200, status)
    before = usage()["total"]
    time.sleep(3)
    after = usage()["total"]
    check("paused sandboxes use no vCPU or memory",
          after["vcpu_s"] == before["vcpu_s"] and after["mem_gib_s"] == before["mem_gib_s"], (before, after))
    check("paused sandboxes store a snapshot", after["disk_gib_h"] > before["disk_gib_h"], (before, after))
    status, info = request("GET", f"/v1/tenants/{tenant}")
    stored = info["usage"]["snapshot_storage_bytes"]
    check("tenant shows snapshot storage", stored > 0 and info["usage"]["monthly_egress_bytes"] > 1000, info)

    quotas(snapshot_storage_gib=0)
    status, got = request("POST", f"/v1/sandboxes/{sid}:resume", key=key)
    check("resume", status == 200 and got["state"] == "running", (status, got))
    expect_error("pause over snapshot quota", *request("POST", f"/v1/sandboxes/{sid}:pause", key=key),
                 429, "quota_exceeded")
    quotas(snapshot_storage_gib=None)

    quotas(monthly_egress_bytes=1)
    out = run_as(key, sid, "curl -sS -m 10 -o /dev/null -w '%{http_code}' https://example.com")
    check("egress over quota is refused", out["exit_code"] != 0, out)
    def quota_blocked(evs):
        return any(e["attrs"].get("reason") == "egress quota" for e in evs)

    deadline = time.monotonic() + 15
    while True:
        status, got = request("GET", f"/v1/sandboxes/{sid}/events?type=net.blocked", key=key)
        if status != 200 or quota_blocked(got["events"]) or time.monotonic() > deadline:
            break
        time.sleep(0.3)
    check("net.blocked for egress quota", status == 200 and quota_blocked(got["events"]), (status, got))
    expect_error("create over egress quota", *request("POST", "/v1/sandboxes", {}, key=key), 429, "quota_exceeded")
    quotas(monthly_egress_bytes=None)
    out = run_as(key, sid, "curl -sS -m 10 -o /dev/null -w '%{http_code}' https://example.com")
    check("egress works again", out["stdout"] == "200", out)

    status, _ = request("DELETE", f"/v1/sandboxes/{sid}", key=key)
    check("delete sandbox", status == 204, status)
    request("DELETE", f"/v1/keys/{tk['id']}")
    request("DELETE", f"/v1/keys/{rk['id']}")
    status, _ = request("DELETE", f"/v1/tenants/{tenant}")
    check("delete tenant", status == 204, status)
    got = usage(f"?tenant={tenant}&group_by=sandbox", as_key=KEY)
    check("a deleted tenant's usage stays readable", got["usage"] and got["usage"][0]["sandbox"] == sid, got)
    got = usage("", as_key=KEY)
    check("org keys see every tenant", any(r["tenant"] == tenant for r in got["usage"]) and got["tenant"] is None, got)


def volume_checks():
    expect_error("volume without name", *request("POST", "/v1/volumes", {}), 400, "invalid_request")
    expect_error(
        "bad volume name", *request("POST", "/v1/volumes", {"name": "Bad_Name"}), 400, "invalid_request"
    )
    expect_error(
        "volume too small",
        *request("POST", "/v1/volumes", {"name": "tiny", "size_gib": 0}),
        400,
        "invalid_request",
    )
    status, vol = request("POST", "/v1/volumes", {"name": "smoke-data", "size_gib": 1})
    check("create volume", status == 201 and vol["size_gib"] == 1 and vol["backend"] is None, (status, vol))
    expect_error(
        "duplicate volume", *request("POST", "/v1/volumes", {"name": "smoke-data"}), 409, "conflict"
    )
    status, vol2 = request("POST", "/v1/volumes", {"name": "smoke-other", "size_gib": 2})
    check("create second volume", status == 201, (status, vol2))
    status, listed = request("GET", "/v1/volumes")
    names = {v["name"] for v in listed["volumes"]}
    check("list volumes", status == 200 and {"smoke-data", "smoke-other"} <= names, listed)

    for name, mounts in [
        ("mount on /proc", [{"volume": "smoke-data", "path": "/proc/x"}]),
        ("relative mount path", [{"volume": "smoke-data", "path": "data"}]),
        ("root mount path", [{"volume": "smoke-data", "path": "/"}]),
        (
            "overlapping mount paths",
            [{"volume": "smoke-data", "path": "/a"}, {"volume": "smoke-other", "path": "/a/b"}],
        ),
        (
            "same volume twice",
            [{"volume": "smoke-data", "path": "/a"}, {"volume": "smoke-data", "path": "/b"}],
        ),
    ]:
        expect_error(name, *request("POST", "/v1/sandboxes", {"volumes": mounts}), 400, "invalid_request")
    expect_error(
        "unknown volume",
        *request("POST", "/v1/sandboxes", {"volumes": [{"volume": "nope", "path": "/data"}]}),
        404,
        "not_found",
    )

    status, got = request("GET", "/v1/templates/smoke-jq")
    template = "smoke-jq" if status == 200 else None
    with_template = {"template": template} if template else {}

    a = create({"volumes": [{"volume": "smoke-data", "path": "/data"}]})
    check("view lists volumes", a["volumes"] == [{"volume": "smoke-data", "path": "/data", "read_only": False}], a)
    out = run(a["id"], "echo hello > /data/note && cat /data/note && stat -c %U /data && df -B1G --output=size /data | tail -1")
    check("volume is writable by the user", out["stdout"].split() == ["hello", "user", "1"], out)
    status, got = request("GET", "/v1/volumes/smoke-data")
    check(
        "volume shows its mount",
        status == 200 and got["mounts"] == [{"sandbox": a["id"], "read_only": False}] and got["backend"],
        got,
    )
    expect_error(
        "second writer is refused",
        *request("POST", "/v1/sandboxes", {"volumes": [{"volume": "smoke-data", "path": "/data"}]}),
        409,
        "conflict",
    )
    expect_error(
        "reader beside a writer is refused",
        *request("POST", "/v1/sandboxes", {"volumes": [{"volume": "smoke-data", "path": "/data", "read_only": True}]}),
        409,
        "conflict",
    )
    expect_error("delete volume in use", *request("DELETE", "/v1/volumes/smoke-data"), 409, "conflict")
    status, _ = request("DELETE", f"/v1/sandboxes/{a['id']}")
    check("delete writer", status == 204, status)

    ro = {"volumes": [{"volume": "smoke-data", "path": "/data", "read_only": True}]}
    b = create(ro)
    c = create(ro)
    for sid in (b["id"], c["id"]):
        out = run(sid, "cat /data/note")
        check("data outlives its sandbox", out["stdout"] == "hello\n", out)
    out = run(b["id"], "echo x > /data/new", user="root")
    check("read-only mount refuses writes", out["exit_code"] != 0, out)
    expect_error(
        "writer beside readers is refused",
        *request("POST", "/v1/sandboxes", {"volumes": [{"volume": "smoke-data", "path": "/data"}]}),
        409,
        "conflict",
    )
    for sid in (b["id"], c["id"]):
        request("DELETE", f"/v1/sandboxes/{sid}")

    d = create(
        {
            **with_template,
            "timeout_s": 900,
            "volumes": [
                {"volume": "smoke-data", "path": "/data"},
                {"volume": "smoke-other", "path": "/home/user/other"},
            ],
        }
    )
    if template:
        out = run(d["id"], "jq -n 7")
        check("template layer works beside volumes", out["stdout"] == "7\n", out)
    out = run(
        d["id"],
        "cat /data/note && echo two > /home/user/other/f && df -B1G --output=size /home/user/other | tail -1",
    )
    check("two volumes mount apart", out["stdout"].split() == ["hello", "2"], out)
    run(d["id"], "echo before-pause >> /data/note")
    pause(d["id"], "pause sandbox with volumes")
    out = run(d["id"], "cat /data/note /home/user/other/f")
    check("volumes survive pause and resume", out["stdout"] == "hello\nbefore-pause\ntwo\n", out)
    run(d["id"], "echo after-resume >> /data/note")
    pause(d["id"], "pause again")
    status, _ = request("DELETE", f"/v1/sandboxes/{d['id']}")
    check("delete paused sandbox", status == 204, status)

    e = create({"volumes": [{"volume": "smoke-data", "path": "/data", "read_only": True}]})
    out = run(e["id"], "cat /data/note")
    check(
        "writes before a paused delete are kept",
        out["stdout"] == "hello\nbefore-pause\nafter-resume\n",
        out,
    )
    request("DELETE", f"/v1/sandboxes/{e['id']}")

    for name in ("smoke-data", "smoke-other"):
        status, _ = request("DELETE", f"/v1/volumes/{name}")
        check(f"delete volume {name}", status == 204, status)
    expect_error("deleted volume is gone", *request("GET", "/v1/volumes/smoke-data"), 404, "not_found")


def run_as(key, sandbox_id, cmd):
    status, body = request("POST", f"/v1/sandboxes/{sandbox_id}/exec", {"cmd": cmd}, key=key)
    check(f"exec {cmd[:40]!r} returns 200", status == 200, (status, body))
    return body


if MODE == "api":
    api_checks()
elif MODE == "templates":
    template_checks()
elif MODE == "interactive":
    interactive_checks()
elif MODE == "pause":
    pause_checks()
elif MODE == "egress":
    egress_checks()
elif MODE == "tenants":
    tenant_checks()
elif MODE == "events":
    event_checks()
elif MODE == "usage":
    usage_checks()
elif MODE == "volumes":
    volume_checks()
elif MODE == "restart":
    restart_checks(sys.argv[4], sys.argv[5])
else:
    sys.exit(f"unknown mode {MODE!r}")

report["pass"] = True
print(json.dumps(report, indent=2))
