---
title: ping — ICMP latency probe with sparkline rendering
command: ping
category: reachability
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-13
related: [trace, discover, scan]
---

# `ping` — ICMP latency probe with sparkline rendering

`ping` sends ICMP echo requests to a host and reports per-packet
round-trip time, sequencing, and loss. Cathedral renders each reply
as a phosphor sparkline bar so latency *shape* is visible at a
glance — drift, spikes, jitter, and loss read differently from a wall
of numbers.

```
ping 1.1.1.1
ping example.com -c 20 -i 200
ping 10.0.0.1 -t 30
```

## What it does

`ping` is Cathedral's wrapper around the system `ping(8)` utility
(iputils on Linux, BSD ping on macOS). It runs a configurable
sequence of ICMP echo probes, parses the line-oriented output, and
re-emits it as a structured JSON-line event stream the Cathedral UI
renders as a live sparkline.

| Flag      | Meaning                                | Default |
|-----------|----------------------------------------|---------|
| `-c N`    | number of probes                       | `10`    |
| `-i MS`   | interval between probes (milliseconds) | `1000`  |
| `-t SEC`  | total time budget, bounds the run      | unset   |

Intervals below 200 ms are clamped to 200 ms — iputils requires root
for sub-200 ms intervals and Cathedral never elevates privileges.

## What it answers

Two recurring questions, similar shape:

**Defender:** *"Is this path healthy right now?"* A handful of
probes against a known endpoint (1.1.1.1, the default gateway, an
internal service) tells you whether the network is reachable, how
much latency the path adds, and whether jitter or loss is creeping
in. Baseline-and-watch is the entire reason `ping` has been in every
operator's toolbox for forty years.

**Recon:** *"Is this host alive — and what kind of host is it?"*
Reachability is one signal; the **TTL** of the reply is another. A
fresh echo reply from a fresh host has an initial TTL that hints at
the OS family:

| Initial TTL | Likely OS family            |
|-------------|-----------------------------|
| 64          | Linux, BSD, macOS, Android  |
| 128         | Windows                     |
| 255         | Network gear (Cisco, Juniper)|

You don't see the initial TTL directly — the value in the reply has
been decremented once per hop. But if a reply comes back with TTL 58,
the original was almost certainly 64 (Linux/BSD) and there are six
hops in between. TTL 122 ⇒ Windows, six hops. TTL 248 ⇒ network gear,
seven hops. Cathedral surfaces the raw TTL so you can do the
arithmetic; reading it as a fingerprint is on you.

## How it works

### Wrapping, not reimplementing

Cathedral does not implement ICMP in Go. The system `ping` already
does it correctly, handles IPv6, knows about CAP_NET_RAW on Linux and
the BPF device on macOS, and has been hardened against every weird
network for decades. Reimplementing it would mean either (a) requiring
root / CAP_NET_RAW at runtime, or (b) requiring CGO and libpcap. Both
break Cathedral's static-binary property for a tool that the OS
already ships.

The tradeoff is that Cathedral's `ping` *depends on* the system
`ping` being installed and producing parseable output. On a
container minimal-image with `ping` absent, Cathedral's `ping` fails.
On a system where `ping` is symlinked to a wrapper that prints in a
different format, the regex parser silently produces fewer events.

### The regex protocol layer

The work is in translating iputils' free-text output into structured
events. Six patterns cover the reply types:

```go
reStart    = regexp.MustCompile(`^PING\s+(\S+)\s+\(([^)]+)\)`)
reReply    = regexp.MustCompile(`(\d+)\s+bytes from\s+([^:]+):\s+icmp_seq=(\d+)\s+ttl=(\d+)\s+time=([\d.]+)\s*ms`)
reUnreach  = regexp.MustCompile(`From\s+([\d\.]+)\s+icmp_seq=(\d+)\s+(.*)`)
reTimeout  = regexp.MustCompile(`(?i)request timeout.*icmp_seq\s*=?\s*(\d+)`)
reStatsPct = regexp.MustCompile(`(\d+)\s+packets transmitted,\s+(\d+)\s+received,\s+([\d.]+)%\s+packet loss`)
reRtt      = regexp.MustCompile(`rtt\s+min/avg/max/(?:mdev|stddev)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms`)
```

Each pattern maps a line to one event. The `mdev|stddev` alternation
handles BSD ping's `stddev` versus iputils' `mdev`. Anything that
doesn't match is silently dropped — including the `From … icmp_seq=N
Destination Net Unreachable` line, which becomes an `unreachable`
event with `reason` captured verbatim.

### Three failure modes

A probe that doesn't come back as a normal reply is one of three things:

- **`reply`** — echo reply received, parsed.
- **`unreachable`** — an ICMP Type 3 came back from a router on the
  path. The `reason` field carries the specifics (*Network
  Unreachable*, *Host Unreachable*, *Communication Administratively
  Prohibited*). The reply came from the router, not the target — the
  `from` field is the router's address.
- **`timeout`** — nothing came back within the 2-second per-reply
  window (`-W 2`, hardcoded). Could mean the target is down, ICMP is
  filtered at the edge, or the response was dropped somewhere.

Distinguishing *down* from *ICMP-filtered* requires `discover tcp`
against the same host — if it responds on a TCP port, ICMP is
filtered but the host is up.

### The sparkline

Cathedral's UI renders each `reply` event as a unicode bar in
addition to the numeric RTT. The renderer:

```dart
String rttBar(double ms, {int maxChars = 20, double msPerChar = 10}) {
  final blocks = (ms / msPerChar).round().clamp(0, maxChars);
  return '█' * blocks + '·' * (maxChars - blocks);
}
```

10 ms per character, capped at 20 characters. A LAN reply (under
2 ms) shows as `··················· ·` (one block); a transcontinental
reply (around 150 ms) fills the bar. Drift and jitter become
visually obvious — three consecutive replies of 8 / 9 / 8 ms followed
by one of 84 ms is unmissable as a stair-step.

## Worked example

```
$ ping 1.1.1.1 -c 6
> pinging 1.1.1.1 (1.1.1.1) — 6 packets @ 1000ms

  seq=  1  ttl= 60     3.42 ms  ███·················
  seq=  2  ttl= 60     3.18 ms  ███·················
  seq=  3  ttl= 60    12.04 ms  ████████████········
  seq=  4  ttl= 60     3.31 ms  ███·················
  seq=  5  ── [timeout] ──
  seq=  6  ttl= 60     3.27 ms  ███·················

5 / 6 received  ·  17% loss
rtt  min 3.18  avg 5.04  max 12.04  mdev 3.47 ms
```

The TTL of 60 suggests a Linux/BSD host with 4 hops between you and
the target (initial TTL 64, decremented per hop). The single timeout
and the one outlier reply at 12 ms are both clearly visible as
visual breaks in the bar pattern.

## Output protocol

```
{"event":"start",       "target":"…","ip":"…","count":N,"interval_ms":N}
{"event":"reply",       "seq":N,"ttl":N,"bytes":N,"from":"…","rtt_ms":N}*
{"event":"unreachable", "seq":N,"from":"…","reason":"…"}*
{"event":"timeout",     "seq":N}*
{"event":"stats",       "sent":N,"received":N,"loss_pct":N}
{"event":"rtt",         "min_ms":N,"avg_ms":N,"max_ms":N,"mdev_ms":N}
{"event":"done"}
```

`stats` and `rtt` arrive only on successful completion of the run.
If `ping` itself errors (unknown host, network down, missing
binary), an `error` event is emitted instead and the stream ends.

Composes well with `jq`:

```
$ ping 1.1.1.1 -c 100 -j | jq -r 'select(.event=="reply") | .rtt_ms' | datamash mean 1 max 1
```

## Limitations

- **Requires the system `ping` binary.** No fallback. On stripped
  container images (`alpine:minimal`, distroless), Cathedral's
  `ping` is unusable until `iputils-ping` (or equivalent) is
  installed.
- **iputils output format only.** BSD ping output is *mostly*
  compatible — the `mdev|stddev` regex alternation covers the
  summary line, but minor format drifts may produce missing events
  rather than errors.
- **No IPv6 toggle.** The system `ping` decides between v4 and v6
  based on the target. Forcing `-4` or `-6` is not exposed yet.
- **Per-reply timeout hardcoded to 2 seconds.** A truly slow link
  (satellite, intermittent VPN) will register false timeouts. Not
  configurable in v1.
- **Sub-200 ms intervals clamp to 200 ms.** iputils requires root
  for faster cadence and Cathedral never elevates.
- **No hop-name resolution.** Cathedral passes `-n` to the
  underlying ping so the `from` field on `unreachable` events is an
  IP, not a hostname. Use `whois` or `geoip` on it if you want
  attribution.

## Authorized use

Echo probes against an arbitrary host are not by themselves
problematic — `ping` traffic is unremarkable on every network and
"alive check" is not a hostile act. At scale (continuous probes,
hundreds of targets, or sub-second cadence sustained for minutes) it
becomes noisier and can register on IDS as part of a sweep. The
authorized-testing posture applies the same way it applies to any
recon tool: target only what you own or have permission to probe.

## Further reading

- [RFC 792 — Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792)
- [RFC 1812 §5.3.4 — Time to Live handling](https://www.rfc-editor.org/rfc/rfc1812)
- Related Cathedral commands: [`trace`](./trace.md) (path discovery), [`discover`](./discover.md) (TCP-ping when ICMP is filtered), [`scan`](./scan.md) (port-level reachability)
