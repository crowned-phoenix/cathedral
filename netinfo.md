---
title: netinfo — local network introspection with live sparklines
command: netinfo
aliases: [ip, ifconfig]
category: discovery
status: shipped
version-introduced: 1.0
authorized-use: none
last-updated: 2026-05-15
related: [ports, conns, ping, lan-scan, geoip]
---

# `netinfo` — local network introspection with live sparklines

`netinfo` answers the first orienting question of any session:
*where am I on the network right now?* It enumerates every
interface, its addresses, MAC, MTU, link speed, and live traffic
rate — sampled for roughly a second and a half — then renders the
result as a single table with per-interface sparklines showing
RX/TX activity over the sample window.

```
netinfo
netinfo --v6     # show IPv6 addresses under each interface
ip               # alias
ifconfig         # alias
```

## What it does

`netinfo` does four things in parallel and joins them at the end:

1. **Host facts** — hostname, OS, architecture.
2. **Primary egress** — which local IP does outbound traffic
   actually leave from, what's the default gateway, what DNS
   resolvers is the system configured to use.
3. **Interfaces** — every network interface on the box, with
   addresses (v4 always, v6 when `--v6` is passed), MAC, up/down
   state, MTU, and link speed where the driver exposes it.
4. **Traffic** — a 1.5-second sampling window reading
   `/proc/net/dev` at 200 ms intervals; the resulting per-second
   byte rates are emitted alongside each interface so the UI can
   render an 8-cell sparkline of RX + TX activity.

| Flag      | Meaning                                          |
|-----------|--------------------------------------------------|
| `--v6`    | also list IPv6 addresses under each interface    |
| `--text`  | legacy line-per-field rendering (no table)       |

No arguments. The aliases `ip` and `ifconfig` exist because they're
what Linux operators reach for instinctively; Cathedral binds them
to the same command rather than fight muscle memory.

## What it answers

**Operational:** *"Where am I, and is my network sane?"* The
primary IP, gateway, and DNS line tells you in three values whether
you're on a normal network. If your `primary ip` is `10.0.0.5` and
your gateway is `10.0.0.1`, you're in a normal LAN. If your primary
is `100.64.x.x`, you're on a CGNAT'd carrier network. If it's
`172.30.x.x` and the gateway is the same IP, you're inside a
container. The triplet orients you instantly.

**Debugging:** *"Why isn't this working?"* When a VPN appears not to
be up, when a Docker container can't reach the outside, when
"my internet is broken" — netinfo tells you whether the relevant
interface exists, has an address, and is moving bytes. The
sparkline is the difference between "the interface is up but
nothing is happening" and "the interface is up and active."

**Discovery:** *"What's on this box that I forgot about?"* A
developer machine accumulates network interfaces — Docker bridges
for every compose project, WireGuard tunnels left from the last
debugging session, ZeroTier networks, VPN remnants, virtual
adapters. `netinfo` enumerates them all in one pass.

This is not a recon tool. It looks at the machine it runs on,
nothing else. No remote probes, no network packets sent (the
primary-IP detection sends *zero bytes* — see below).

## How it works

### The UDP-dial trick for primary IP

The clever bit is finding the *primary* IP — the one outbound
traffic actually uses — without sending any traffic. Cathedral asks
the kernel to set up a UDP socket toward `1.1.1.1:80`, then reads
back the local address the kernel chose:

```go
func primaryIP() string {
    conn, err := net.Dial("udp", "1.1.1.1:80")
    if err != nil { return "" }
    defer conn.Close()
    return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
```

UDP is connectionless. `net.Dial("udp", …)` does not send a
packet — it only consults the kernel's routing table to decide
which local interface and which local source address *would* be
used if a packet were sent. The socket is closed immediately
afterward. Cathedral never transmits anything; the answer comes
from the kernel's routing decision alone.

This is the right way to detect "which interface is primary"
because it matches what the kernel will actually do for outbound
traffic. Checking `ip route show default` and inferring is fragile;
parsing `/proc/net/route` is worse. The UDP dial is one syscall
and produces the answer the operating system itself would.

### Sampling `/proc/net/dev` for traffic rates

Linux exposes per-interface cumulative byte counters in
`/proc/net/dev`:

```
Inter-|   Receive          |  Transmit
 face | bytes packets …    | bytes packets …
   lo: 12345678   12345    | 12345678   12345
wlp0:  98765432   54321    | 12345678    9876
```

Per-second rates aren't there directly — you have to read the
counters at intervals and diff them. Cathedral reads `/proc/net/dev`
eight times, 200 ms apart, computes seven deltas, and converts
each delta to bytes-per-second:

```go
delta := rxNow - rxPrev
bps := int64(float64(delta) / sampleInterval.Seconds())
```

Counter wraparound (on interface restart, very old hardware, etc.)
is detected as a negative delta and clamped to zero — better a
single zero in the sparkline than a billion-bps spike. The whole
sampling window is run on a goroutine in parallel with the
metadata gather, so wall time is bounded by the sampling and not
the sum of work.

### The sparkline

Each interface gets eight RX+TX sample points alongside its
metadata. The Cathedral UI renders these as a column of Unicode
block characters using the partial-block range:

```
█ ▇ ▆ ▅ ▄ ▃ ▂ ▁
```

Magnitudes are scaled per interface — a quiet loopback and a busy
WiFi look different in absolute terms but each renders its own
activity shape relative to itself. The columns `RX/s` and `TX/s`
carry the absolute magnitudes; the sparkline carries the *shape*.

### Gateway and DNS

The default gateway comes from parsing `ip route show default`. DNS
resolvers come from `/etc/resolv.conf`. Both are conventional Linux
data sources; both work on every Linux distro and most BSDs that
ship `ip(8)`. If `ip` isn't on `$PATH` or `/etc/resolv.conf` isn't
readable, the relevant field is empty rather than fatal — `netinfo`
emits what it can and continues.

## Worked example

Captured on a developer's laptop with Docker, ZeroTier, and an
active WiFi connection. Globally-routable IPv6 addresses are
redacted for the cookbook; everything else is real.

```
> scanning local interfaces (sampling rx/tx ~1.5s)...
[ NETWORK RECONNAISSANCE ]
─────────────────────────────────────────────────────────────────────────────────
  hostname:    workstation               os/arch:  linux/amd64
  primary ip:  192.168.1.176             gateway:  192.168.1.1
  dns:         127.0.0.53

[ INTERFACES ]   18 total · 18 up
─────────────────────────────────────────────────────────────────────────────────
   NAME              ST    IPV4                MAC                MTU     SPD       RX/s       TX/s  ACT
 * wlp0s20f3         UP    192.168.1.176/24    28:6b:35:51:f3:74  1500       —    245 KB     62 KB  ▆▇█▆▅▇▆
   docker0           UP    172.17.0.1/16       1a:66:07:af:a5:4c  1500       —         0         0  ─────
   br-191ea5e1233a   UP    172.26.0.1/16       96:b0:fc:a3:41:1f  1500       —         0         0  ─────
   br-810ed353e496   UP    172.18.0.1/16       5a:00:53:31:84:cb  1500       —         0         0  ─────
   (… 12 more Docker bridges …)
   ztlqctvcvu        UP    10.147.17.4/24      72:e8:25:8e:0b:b6  2800    10Gb         0         0  ─────
   lo                UP    127.0.0.1/8         —                 65536       —     1.0 KB    1.0 KB  ▁▁▁▂▁▁▁

scan complete.
```

Four things this output tells you in one glance:

- **`wlp0s20f3` is the primary** (marked `*`). WiFi PCIe slot 0, slot
  20, function 3 — that's the systemd predictable name for the
  built-in WiFi card on a typical laptop. It's the only interface
  moving real bytes, and the sparkline shows steady traffic with a
  small peak.
- **Fifteen Docker bridges exist.** Every `br-<hex>` is a network
  Docker created for one running compose project. They're all
  idle. If `netinfo` showed traffic on one of them, you'd know
  *which container* is busy without `docker stats`.
- **`ztlqctvcvu` is a ZeroTier interface** (the `zt` prefix and the
  10/8 address are giveaways). MTU 2800 is non-standard — ZeroTier
  uses jumbo-ish frames inside its overlay. The "10 Gb" speed is a
  software-declared value, not real link speed.
- **Loopback shows constant ~1 KB/s in both directions.** That's
  background daemons chatting to localhost services. Normal.

If the WiFi sparkline were flat and the loopback were busy, the
story would be "network is down, but everything internal is fine."
If a Docker bridge had traffic, the story would be "this specific
container is moving data right now."

## Output protocol

```
{"event":"start", "hostname":"…","os":"…","arch":"…",
                  "primary_ip":"…","gateway":"…","dns":[…]}
{"event":"iface", "name":"…","up":bool,"loopback":bool,"is_primary":bool,
                  "mtu":N,"speed_mbps":N,"mac":"…",
                  "ipv4":[…],"ipv6":[…],
                  "rx_bps":[N,…7…],"tx_bps":[N,…7…]}*
{"event":"done",  "count":N}
```

`rx_bps` and `tx_bps` are 7-element arrays (8 samples, 7 deltas).
The Cathedral UI pads to 8 cells for display alignment. `speed_mbps`
is `0` when the driver doesn't expose link speed — loopback,
virtual bridges, most WiFi cards.

For scripting:

```
$ netinfo -j | jq -r 'select(.event=="iface" and .is_primary) | .ipv4[0]'
192.168.1.176/24
```

Strip CIDR with `cut -d/ -f1` for the bare IP. This is a common
shell idiom in Cathedral scripts that need "my primary IP" as a
shell variable.

## Limitations

- **Linux-specific in implementation.** `/proc/net/dev` is Linux
  only; `ip route show default` is Linux. macOS and BSD support
  would mean alternate code paths — not in v1. The Flutter app
  itself runs everywhere; `netinfo` shipping non-empty results
  only does so on Linux.
- **1.5-second sampling window is fixed.** You can't trade latency
  for accuracy — every `netinfo` invocation waits roughly that long
  before printing. For instant "what's my IP" with no traffic
  shape, the trick is `netinfo -j | jq 'select(.event=="start")'`
  which prints the header line as soon as it arrives.
- **Sparklines are per-interface scaled, not global.** A quiet
  loopback and a busy WiFi don't look proportionally different;
  each interface scales to its own range. The RX/s and TX/s
  columns carry the absolute values for that reason.
- **Docker proliferation is a real visual problem.** A developer
  machine with fifteen idle compose projects has fifteen idle
  bridges. The UI shows them all. There's no `--active-only`
  filter in v1; piping through `jq` is the workaround.
- **No remote operation.** `netinfo` is local to the machine
  running Cathedral. For remote-host inventory, you want SSH
  forwarding + remote `netinfo`, or other tools.
- **Speed field is unreliable.** It comes from
  `/sys/class/net/<iface>/speed`, which the driver chooses to
  populate or not. WiFi cards almost always return 0; bonded
  interfaces report the underlying physical link; virtual bridges
  report nothing. Treat as a hint, not a measurement.

## Authorized use

`netinfo` makes no network requests, reads local kernel files, and
runs `ip route` on the local machine. The risk profile is the same
as `ifconfig` or `ip addr` — pure local introspection. No
authorized-testing posture applies; no banner is emitted.

The one thing worth noting: `netinfo`'s output *does* describe
your network position in some detail, including private addresses,
MAC addresses, internal Docker subnet layouts, and VPN endpoints.
That output is fine for local consumption and screenshots in your
own debugging session; it's the kind of thing you'd redact before
pasting into a public bug report. Cathedral does not redact for
you.

## Further reading

- [`/proc/net/dev` format](https://www.kernel.org/doc/html/latest/networking/snmp_counter.html) — the counter source
- [systemd predictable network interface names](https://systemd.io/PREDICTABLE_INTERFACE_NAMES/) — why `wlp0s20f3`
- Related Cathedral commands: [`ports`](./ports.md) (local listening sockets),
  [`conns`](./conns.md) (active TCP connections with owning processes),
  [`ping`](./ping.md) (reachability from this box),
  [`lan-scan`](./lan-scan.md) (host enumeration on the primary subnet),
  [`geoip`](./geoip.md) (where the world thinks your primary IP is)
