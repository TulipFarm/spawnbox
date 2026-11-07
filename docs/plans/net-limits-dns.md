# Bandwidth limits and DNS logging

Status: done. Tested on the primary and a worker: `getent` and a TCP query
to 9.9.9.9 both reach the forwarder and record `net.dns` with answers; an
allowlist sandbox gets `REFUSED` and a `deny` event for other names;
template builds resolve names; with 20/40 Mbit/s limits a sandbox sends at
19.3 and receives at 38.3 Mbit/s, also after pause and resume; `0` is
refused.

## Goal

Record every DNS query a sandbox makes, refuse names the policy denies, and
let a policy cap how fast a sandbox sends and receives.

## DNS

- `spawn-egress/src/dns.rs` is a UDP and TCP forwarder on `--dns-port`
  (default 15053). It finds the sandbox by source IP, as the proxy does. An
  unknown source gets no reply.
- The host nft prerouting redirects every port-53 query from `sbx*` links,
  to any address, to the forwarder. The input chain accepts the port only
  from `sbx*` links.
- A name that the server policy or the registration's policies deny gets
  `REFUSED`. Others go to `--dns` over the same transport with a 5 s
  timeout; a failure gives `SERVFAIL`.
- Each query is an `Activity::Dns`. The hub records `net.dns` (`name`,
  `type`, `verdict`, `rcode`, `answers`, `duration_ms`) for `sbx_`
  sandboxes and counts `spawnbox_dns_queries_total{verdict}`.
- `deny_all` still drops DNS inside the namespace.
- Checking resolved IPs against the policy is out of scope.

## Bandwidth

- `Policy` gains `max_egress_mbps` and `max_ingress_mbps` (1 to 100000,
  left out of JSON when unset). The lowest value over the server, tenant
  and sandbox policies wins (`policy::rates`).
- `Netns::set_rates` puts a `tbf` qdisc on the queue each direction leaves:
  received traffic on the host link `sbx{index}`, sent traffic on `veth0`
  inside the namespace. Shaping, not policing: an ingress policer gave TCP
  only half the rate.
- The runtime calls `Vm::set_rates` after create (warm and cold) and
  resume, before the guest fixups. No limit runs no command. The qdiscs go
  away with the link.
