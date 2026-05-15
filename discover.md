---
title: discover — TCP-ping service inventory across a subnet
command: discover
category: discovery
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-15
related: [lan-scan, scan, ping, ports, netinfo]
---

# `discover` — TCP-ping service inventory across a subnet

`discover <port>` sweeps the local /24 (or a subnet you specify),
attempting a TCP connect to a single port on every host. Each
responder is labelled with its MAC vendor and hostname. The
result is a one-shot inventory: *"every host on this network with
this service open."*

```
discover 22        # find SSH hosts
discover 445       # find SMB hosts  (file shares, Windows machines)
discover 80        # find web servers
discover 3389      # find RDP hosts  (Windows servers)
discover 5900      # find VNC servers
discover 8080 --subnet=10.0.0.0/24 --conc=100
```

## What it does

`discover` is `lan-scan`'s sibling — same scaffolding, same two-
phase pattern, same MAC and hostname enrichment. The single
difference: *liveness is detected by TCP-connect to a chosen port,
not by ICMP echo*. That difference matters more than it sounds.

| Flag                   | Meaning                                  | Default   |
|------------------------|------------------------------------------|-----------|
| `<port>`               | TCP port to probe (positional, required) | —         |
| `--subnet=X.Y.Z.0/24`  | subnet to sweep                          | local /24 |
| `--conc=N`             | concurrent dial workers                  | `96`      |
| `--timeout=MS`         | per-host TCP-connect timeout (ms)        | `500`     |

The probe is a full TCP three-way handshake. If it completes, the
port is open *and* the host is alive — `discover` reports both
findings together. If it doesn't, the host either doesn't exist
on that address, is firewalled, or simply doesn't have that port
listening.

## What it answers

**Defender:** *"Which machines on my network expose this service?"*
The canonical neighbourhood-audit question with a service-shaped
filter. `discover 22` finds every SSH-listening box; `discover 445`
finds every SMB host (file shares, NAS, Windows endpoints); `discover
3389` finds every Windows machine running RDP. A home network where
the answer to `discover 445` includes a smart TV is a finding.

**Recon (authorized testing only):** *"Which hosts are running the
service I want to investigate?"* After a foothold, the operator's
first lateral-movement question is "where's the next SSH/SMB/web
target?" `discover` answers that in one shot, narrowing the field
from 254 candidates to the handful actually running the service.

**Operational:** *"Where did I deploy that thing?"* When the
documentation says *"the new dev server is somewhere on the LAN
running Postgres"* and nobody remembers the IP, `discover 5432`
finds it in three seconds.

**The ICMP-filtered case.** ICMP is filtered widely — Windows
firewalls drop inbound ping by default, many security appliances
suppress it, IoT devices often ignore it deliberately. `lan-scan`
misses these hosts entirely. `discover` finds them, *if* they're
running the service you probe for. The pair complement each
other: when `lan-scan` shows fewer hosts than the network has,
`discover 22` or `discover 80` often turns up the rest.

## How it works

### TCP-connect as the liveness probe

The probe itself is the simplest possible thing:

```go
func dial(ctx context.Context, ip string, port int, timeout time.Duration) (bool, float64) {
    dctx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()
    t0 := time.Now()
    conn, err := net.Dialer{}.DialContext(dctx, "tcp",
        net.JoinHostPort(ip, strconv.Itoa(port)))
    if err != nil {
        return false, 0
    }
    rtt := time.Since(t0).Seconds() * 1000
    conn.Close()
    return true, rtt
}
```

A full TCP connect: SYN → SYN/ACK → ACK, then `conn.Close()`
which sends FIN. The handshake completion is the signal that
"this host exists *and* this port is open." The RTT is the
time from dial-start to the connection becoming usable.

No raw sockets, no CAP_NET_RAW, no CGO — the same architectural
constraint that runs through every Cathedral probe tool. The
tradeoff is the same too: full handshake means the target sees
you. There is no stealth.

### Why TCP-ping beats ICMP-ping for service inventory

Two reasons to prefer TCP-connect over ICMP echo when you're
already looking for a specific service:

1. **ICMP is filtered far more often than TCP.** A host that
   silently drops `ping` will happily complete a TCP handshake
   on its open ports. Hosts behind Windows Defender, AWS
   security groups, corporate firewalls — these commonly answer
   TCP and ignore ICMP.
2. **You get free service confirmation.** ICMP says *"the host
   is up."* TCP-connect to port 22 says *"the host is up and
   running SSH right now."* Two findings for the same probe
   cost.

The cost: you only probe one port at a time. To learn what
*else* is running on a discovered host, follow up with
[`scan`](scan.md) targeting that single IP across many ports.
The two tools have inverse shapes — `discover` is *one port,
many hosts*; `scan` is *one host, many ports*.

### Two-phase: probe first, enrich after

Same pattern as [`lan-scan`](lan-scan.md):

1. **Sweep**: concurrent TCP-connect probes (semaphore-bounded
   by `--conc`), report alive count via 200 ms progress ticks.
2. **Enrich**: after every probe completes, read the kernel's
   ARP cache (the connect attempts populated it as a side
   effect of routing) and run a 500 ms reverse-DNS lookup per
   live host.

The MAC-from-ARP trick is the same Cathedral pattern: don't
implement ARP, let the kernel do it as a routing side effect,
then read `/proc/net/arp` once the work is done. Self appears
with empty MAC for the same reason — the kernel never ARPs its
own address.

The OUI vendor table is shared with `lan-scan` (the curated
~200 entries covering common LAN, IoT, and networking
hardware). Locally-administered MACs — phones with privacy-
randomized addresses — return empty vendor and rely on the
hostname for attribution.

### Concurrency and timing

Defaults are tuned for fast LAN sweeps: 96 concurrent dials,
500 ms timeout each. A /24 (254 hosts) completes in roughly
3–6 seconds depending on how many hosts are present and how
many are slow to refuse connections.

The 30-second global timeout protects against pathological
slow networks; for an entire /16 (`--subnet=10.0.0.0/16`,
65k hosts) you'll want to raise concurrency *and* the global
timeout, or sweep in chunks.

## Worked example

A continuation of the [`lan-scan`](lan-scan.md) worked example —
same network, asking the follow-up question:

```
> sweeping 192.168.1.0/24 for tcp:22 — 254 hosts

  · 20%  (54/254 probed, 0 responding)
  · 40%  (102/254 probed, 2 responding)
  · 80%  (199/254 probed, 2 responding)
  [OPEN] 192.168.1.176                       0.55 ms  workstation.lan
  [OPEN] 192.168.1.184  bc:5b:d5:a6:91:91    1.79 ms

discovery complete — 2 hosts responding on tcp:22
```

Two open SSH servers in the LAN — and now we know what
`192.168.1.184` is. In the `lan-scan` output it appeared as an
unknown device: no hostname, MAC `bc:5b:d5:a6:91:91`, no vendor
in the curated table. `discover 22` reveals it's running SSH on
port 22 with sub-2ms latency — almost certainly a Linux box of
some kind. The natural next step is `scan 192.168.1.184 --top=20`
to learn what else it's exposing, then `ssh-audit 192.168.1.184`
to inspect the SSH service specifically.

That cross-tool flow — `lan-scan` for host inventory,
`discover` for service-shaped questions, `scan` for per-host
depth — is the canonical Cathedral LAN-audit pattern.

Note also that the scanner's own machine appears as alive on
port 22 (port 22 is open locally) with an empty MAC, same as
in `lan-scan`. The kernel never ARPs its own address.

## Output protocol

```
{"event":"start",    "subnet":"…","port":N,"hosts":N}
{"event":"progress", "done":N,"total":N,"alive":N}*
{"event":"host",     "ip":"…","port":N,"rtt_ms":N,
                     "mac":"…","vendor":"…","hostname":"…"}*
{"event":"done",     "alive":N,"total":N,"port":N}
```

`host` events arrive in TCP-completion order, which is
roughly latency-sorted. The `port` field is the same on every
event — the single port being probed — so per-host enrichment
keys cleanly by `ip`.

Build a CSV inventory across multiple ports:

```
$ for p in 22 80 443 445 3389; do
    ./assets/bin/discover $p -j |
      jq -r --argjson port "$p" '
        select(.event=="host") |
        [$port, .ip, .hostname, .vendor] | @csv'
  done | sort -t, -k1 -n
```

Or filter to non-router responders only:

```
$ discover 22 -j | jq -r 'select(.event=="host" and (.hostname | test("router|gateway") | not)) | .ip'
```

## Limitations

- **Single port per invocation.** `discover` probes one TCP port
  across many hosts; it doesn't enumerate multiple ports per host.
  For that, run `discover` multiple times (one per port of
  interest) or use [`scan`](scan.md) against discovered hosts.
- **TCP-only.** No UDP service discovery in v1. UDP "ping" is
  protocol-specific (DNS query, SNMP getRequest, etc.) and varies
  per service — better handled by dedicated tools when needed.
- **Filtered ports look like closed ports.** A host that
  `DROP`s incoming SYNs to that port is indistinguishable from a
  host that simply doesn't have the port open. Cathedral can't
  tell which without raw-socket access.
- **Locally-administered MACs cannot be attributed.** Same as
  `lan-scan`: phones and modern devices randomize MAC for
  privacy, and the randomization is the entire point of the
  feature. Hostname is the only attribution available.
- **Reverse DNS depends on local resolution.** Networks without
  dnsmasq / OpenWrt / mDNS won't supply hostnames; the field
  comes back empty.
- **30-second global timeout.** Larger subnets need higher
  concurrency or chunked sweeps.
- **Self isn't in ARP.** The scanner's machine shows up with
  empty MAC if it has the probed port open locally — faithful
  to how the kernel sees its own address.

## Authorized use

`discover` is active. It opens TCP connections to 254 hosts in
under 10 seconds at default settings. Every host that has the
target port open completes a three-way handshake from your real
source IP — visible to that host's firewall, IDS, and any
service listening on the port.

**On a network you own, this is unremarkable.** Sweeping your
home LAN for SSH or SMB hosts is the same shape of activity as
the self-audit work `discover` is primarily designed for.

**On a network you don't own, the calculus is different.**
Probing port 22 against every IP in a hotel's network discovers
what other guests are running. Whether that's acceptable is a
question of local law, the network's terms of service, and any
engagement rules you're operating under. Same posture as the
rest of Cathedral's active tooling: target what you own, or
have written authorization to probe.

**The probe is more attributable than ICMP.** A TCP SYN that
completes the handshake is more durable in logs than an ICMP
echo — application-layer software on the target sees the
connection, not just the kernel. If you're testing a target's
"can they detect a scan" posture, expect to be detected.

**Captive networks rate-limit.** Hotels, airports, and conference
WiFi often throttle clients aggressively. 96-concurrent TCP
dials will trip those limits and may briefly disconnect you.
Drop `--conc=10 --timeout=2000` for misbehaving networks.

## Further reading

- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793) — the handshake `discover` depends on
- [Nmap host discovery techniques](https://nmap.org/book/man-host-discovery.html) — broader theory of liveness probing
- Related Cathedral commands: [`lan-scan`](lan-scan.md) (ICMP host inventory — the sibling),
  [`scan`](scan.md) (one host, many ports — the inverse shape),
  [`ports`](ports.md) (the defender side: what is *this* machine listening on),
  [`ping`](ping.md) (reachability check against a single host),
  [`netinfo`](netinfo.md) (subnet detection: which /24 to sweep)
