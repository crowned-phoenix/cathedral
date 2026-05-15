---
title: scan — TCP port scanner with banner grab
command: scan
category: discovery
status: shipped
version-introduced: 1.0
authorized-use: medium
last-updated: 2026-05-13
related: [ports, banner, tech, ssh-audit, discover]
---

# `scan` — TCP port scanner with banner grab

`scan` opens TCP connections to a list of ports on a target and
reports which ones answered. Each open port is announced as it's
found, with a one-line service banner where the service was chatty
enough to produce one. Default is the top 100 most-common ports;
flags expand to custom lists or the full 1–65535 sweep.

```
scan example.com
scan 192.168.1.1 --top=20
scan target.example.com --ports=22,80,443,8000-8100
scan internal.dev --full --conc=200
```

## What it does

`scan` attempts a full TCP connect to each requested port on the
target. A successful three-way handshake means the port is **open**;
a refused connection or timeout means it's closed or filtered.
For each open port, Cathedral grabs a short banner (up to 256 bytes,
700 ms window) so you can tell what's actually listening — not just
that *something* is.

| Flag             | Meaning                                                 | Default |
|------------------|---------------------------------------------------------|---------|
| `--top=N`        | scan the top N most-common TCP ports                    | `100`   |
| `--ports=…`      | explicit list with ranges (`22,80,443,8000-8100`)       | unset   |
| `--full`         | sweep all 65535 ports                                   | unset   |
| `--conc=N`       | concurrent connection workers                           | `50`    |
| `--timeout=MS`   | per-port connect timeout in milliseconds                | `800`   |

The "top 100" list is the same well-trodden set Nmap uses for its
default fast scan — ports observed open on the public internet most
often. Useful baseline; not exhaustive.

## What it answers

**Defender:** *"What's listening on this host?"* The first question
of any host hardening exercise. A box you administered three years
ago that you assumed was running just `sshd` and `nginx` may, today,
also be listening on `:6379` (an unprotected Redis), `:9200` (an open
Elasticsearch), or `:2375` (a Docker socket exposed to the world).
`scan` finds these. Quickly.

**Recon:** *"What's exposed on this target?"* The second question
of any audit. After identification (`geoip` / `asn` / `whois`),
attack surface enumeration is what tells you whether to keep
investigating. A host with `:22` and `:443` open is a different
target from one with `:22`, `:80`, `:445`, `:3306`, and `:5900` open
— the latter has *opinions*.

**Operational triage:** *"Is the service I expect actually up?"*
When a deploy fails or a load balancer misbehaves, `scan host:port`
is faster than logging into the box.

## How it works

### Plain TCP connect, no raw sockets

Cathedral's `scan` uses `net.DialTimeout("tcp", addr)` — a normal,
unprivileged TCP connect attempt. No SYN scan, no raw sockets, no
CAP_NET_RAW, no root. The tradeoff is that *every successful
connection completes the three-way handshake*, which means:

1. The connection is logged on the target's side. The target's
   firewall, IDS, and any application listening on the port all see
   you connecting and disconnecting.
2. The source IP is fully attributable. There is no spoofing.
3. The scan is not stealthy. This is intentional — Cathedral is not
   a tool for evading detection.

For half-open SYN scanning, you want `nmap -sS` with root. Cathedral
does not implement this and never will; the static-binary pure-Go
property is worth more than a stealth option that 90% of users would
never need.

### Concurrency and timing

The scan runs a worker pool sized by `--conc` (default 50). Each
worker dials, optionally grabs a banner, and reports. A semaphore
channel rate-limits dial parallelism so the OS doesn't run out of
ephemeral source ports during a `--full` sweep:

```go
sem := make(chan struct{}, conc)
for _, p := range ports {
    sem <- struct{}{}
    go func(port int) {
        defer func() { <-sem }()
        ok, banner := scanPort(ip.String(), port, timeout)
        if ok { emit(event{"event":"open", "port":port, ...}) }
    }(p)
}
```

A progress ticker fires every 150 ms with `done / total / open`
counts so the UI can animate even when no new ports are opening.
The Cathedral console filters this to 25 / 50 / 75 / 100% milestones
to keep the terminal output sane.

### Banner-grab heuristics

Different services have different conversational styles. SSH,
SMTP, FTP, IRC, MySQL, Redis — these all *speak first*; just
reading the socket after connect produces a useful banner. HTTP
servers don't; they wait for a request. So `scan` differentiates:

```go
switch port {
case 80, 8080, 8000, 8008, 8081, 8888, 3000, 4000, 5000, 9000, 9090:
    _, _ = conn.Write([]byte("GET / HTTP/1.0\r\n…\r\n\r\n"))
}
buf := make([]byte, 256)
n, _ := conn.Read(buf)
```

For HTTP-ish ports, a minimal `GET /` is sent first. For everything
else, the scanner simply reads what shows up. Both modes wait up to
700 ms, then capture the first 256 bytes.

### Text vs binary detection

Many protocols return binary payloads (RDP, DNS-over-TCP, MQTT, raw
SSL handshakes). Printing those as text fills the terminal with
mojibake and tells the reader nothing. So the scanner sniffs:

```go
func isTextish(b []byte) bool {
    if !utf8.Valid(b) { return false }
    for _, c := range b {
        if c == '\r' || c == '\n' || c == '\t' { continue }
        if c < 0x20 || c == 0x7f { return false }
    }
    return true
}
```

Valid UTF-8 with only printable runes and the standard whitespace
controls → render as text, trimmed at the first CR/LF, capped at 120
chars. Anything else → render as a compact hex preview:
`<binary 64 B · 16 03 01 00 3b 01 00 00 37 03 03 … >`. Same line
count, different shape, never noisy.

### Service identification is name-only

The `service` field on each `open` event comes from a hardcoded
port-number → service-name map (~70 entries: `22:ssh`, `443:https`,
`6379:redis`, `27017:mongodb`, …). This is **labeling, not
fingerprinting** — Cathedral doesn't probe the protocol to confirm.
For real protocol fingerprinting (a service running on a non-standard
port), reach for `banner <host:port>` or, for HTTP specifically,
[`tech`](./tech.md).

## Worked example

The canonical legal scan target is `scanme.nmap.org` — Fyodor (the
author of Nmap) explicitly authorizes scanning of this host for
educational purposes. The cookbook uses it for exactly this reason:

```
$ scan scanme.nmap.org --top=20
> scanning scanme.nmap.org (45.33.32.156) — 20 ports

  [OPEN]    22  (ssh)
         └─ SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  [OPEN]    80  (http)
         └─ HTTP/1.1 200 OK

scan complete — 2/20 ports open
```

Two open ports, two banners, two real teaching moments:

- **The SSH banner** identifies not just the service but the
  software version (`OpenSSH_6.6.1p1`) *and the distribution version*
  (`Ubuntu-2ubuntu2.13`). OpenSSH 6.6.1p1 is from 2014; the trailing
  `2ubuntu2.13` confirms Ubuntu 14.04 LTS. That's a host that has not
  been package-updated in years. Whether that matters depends on
  context, but the banner alone tells you something about how the
  target is maintained.
- **The HTTP banner** is just the response status line. To learn what
  the actual web server is, the server version, the technology
  stack, and the security headers, reach for [`headers`](./headers.md)
  and [`tech`](./tech.md) — both are HTTP-aware in a way `scan` is
  deliberately not.

This is the cookbook's intended workflow: `scan` finds the open
ports; specialised tools investigate each one.

## Output protocol

```
{"event":"start",    "target":"…","ip":"…","total":N}
{"event":"progress", "done":N,"total":N,"open":N}*
{"event":"open",     "port":N,"service":"…","banner":"…"}*
{"event":"done",     "open":N,"total":N}
```

`open` events arrive as ports respond, *not in port-number order* —
a worker pool produces results in completion order, which is
roughly latency-sorted. The Cathedral UI doesn't reorder; piping
through `sort` is straightforward:

```
$ scan target.example.com --top=200 -j | jq -r '
    select(.event=="open") | "\(.port)\t\(.service)\t\(.banner)"
  ' | sort -n
```

`progress` events are throttled UI-side to 25/50/75/100% milestones
to keep the console output readable.

## Limitations

- **Connect scan only.** No SYN-half-open, no UDP, no stealth.
  Filtered ports (firewalled with `DROP` rather than `REJECT`) show
  up as "closed" because the connection times out — Cathedral can't
  distinguish closed-by-RST from filtered-by-DROP without raw
  sockets.
- **Default timeout is 800 ms.** Right for LAN and most internet
  targets. High-latency targets (satellite, deep mobile networks)
  may produce false negatives — open ports that don't answer fast
  enough. Bump `--timeout=2000` for those.
- **Service name is port-based, not protocol-based.** A web server
  running on port 8888 is labeled `http-alt` — but the same port
  could be running Jupyter, a backdoor, or anything else. The label
  is a hint, not an assertion.
- **No rate limiting** (only concurrency). The semaphore caps
  simultaneous connections but doesn't pace them — bumping
  `--conc=200` on a sensitive target generates 200 dials in parallel
  and will register on every IDS in the path. There's no `--rps`
  flag in v1.
- **IPv4 preferred.** Dual-stack targets are scanned on their v4
  address; v6-only targets work but the rest of the cookbook
  ecosystem (`geoip`, `asn`) is v4-stronger.
- **Banner cap is 256 bytes / 700 ms.** Multi-line banners (mail
  servers, some FTP daemons) are truncated at the first newline.
  For a full banner read, reach for [`banner`](./banner.md).
- **DNS resolution is fatal.** If the target hostname doesn't
  resolve, the scan errors and exits. There is no `--ip-only` flag
  to skip resolution.

## Authorized use

`scan` is the first Cathedral command where the authorized-testing
posture matters in practice. Three honest notes:

**Every connection is attributable.** The TCP three-way handshake
completes from your real source IP. The target's firewall, IDS, and
listening services all see you. There is no "stealth mode."

**Default settings register on IDS.** Top-100 scan with the default
concurrency completes in roughly two seconds and produces ~100 TCP
SYN packets in that window. Any half-competent IDS treats that
shape as port-scan activity. `--full` at high concurrency is
unambiguously a scan event in every network's logs.

**The packet itself is the legal exposure.** In many jurisdictions,
the unauthorized port scan against a host you don't own constitutes
a violation regardless of whether anything was actually accessed.
The Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK),
the equivalents across the EU and elsewhere — these laws were
written broadly. *This is not legal advice; talk to a lawyer if it
matters.* The operational guidance is straightforward: scan what
you own, or scan what you have explicit written authorization to
scan.

**Safe targets for learning the tool:** your own machines
(`scan 127.0.0.1`, `scan 192.168.1.1`), CTF/lab environments, and
the explicitly-authorized public test targets — `scanme.nmap.org`
is the standard. Don't scan random IPs to "see what's there." That
is what the banner *literally* says is bad.

**Cathedral does not currently emit an authorized-use prompt before
scanning.** This is a deliberate v1 choice — adding interactive
prompts to a command-line tool breaks scripting. The expectation is
that the operator already knows the rules of their engagement.

## Further reading

- [Nmap top ports list](https://nmap.org/book/performance-port-selection.html) — origin of the default top-100
- [scanme.nmap.org](http://scanme.nmap.org) — the canonical authorized test target
- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793) — the handshake `scan` depends on
- Related Cathedral commands: [`ports`](./ports.md) (local listening ports — defender side),
  [`banner`](./banner.md) (deeper single-port banner grab),
  [`tech`](./tech.md) (HTTP technology fingerprinting),
  [`ssh-audit`](./ssh-audit.md) (SSH cipher/algorithm audit),
  [`discover`](./discover.md) (host discovery, the step before)
