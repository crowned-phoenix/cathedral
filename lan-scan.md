---
title: lan-scan — local subnet sweep with vendor identification
command: lan-scan
category: discovery
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-15
related: [netinfo, ping, oui, reverse-dns, discover]
---

# `lan-scan` — local subnet sweep with vendor identification

`lan-scan` pings every host in the local /24 (or a subnet you
specify), records which addresses respond, then enriches each live
host with its MAC address, manufacturer, and reverse-DNS hostname.
Output is a labelled inventory of everything alive on your network:
*what's there, what kind of device it is, and what it calls itself.*

```
lan-scan
lan-scan --subnet=10.0.0.0/24
lan-scan --conc=64 --timeout=400
```

## What it does

A two-phase sweep:

1. **Ping every host** in the target subnet concurrently. Each
   responding host is recorded as alive with its RTT.
2. **Enrich** each alive host with three additional facts pulled
   from local sources — MAC from the kernel's ARP cache, vendor
   from a curated OUI lookup, hostname from reverse DNS.

| Flag                   | Meaning                                  | Default |
|------------------------|------------------------------------------|---------|
| `--subnet=X.Y.Z.0/24`  | subnet to sweep                          | local /24 |
| `--conc=N`             | concurrent ping workers                  | `64`    |
| `--timeout=MS`         | per-host ping timeout (milliseconds)     | `800`   |

When no subnet is provided, `lan-scan` discovers the local /24 using
the same UDP-dial trick `netinfo` uses — derive the primary outbound
IPv4 from the kernel's routing decision, then enumerate `.1` to
`.254` in that subnet.

## What it answers

**Defender (most common):** *"What's actually on my network?"* The
canonical neighbourhood-audit question. A home network "should
have" maybe eight devices — laptop, phone, router, TV, two smart
plugs, doorbell, NAS. If `lan-scan` shows fifteen, there's a story
worth knowing. IoT devices accumulate quietly. Forgotten
Raspberry Pis stay online for years. Guest devices that were
"temporary" never leave.

**Operational:** *"Where did that new device land?"* When you
attach an IoT camera, a 3D printer, a development board, it gets
a DHCP lease — `lan-scan` finds it by IP and labels it by vendor.
Faster than logging into the router.

**Recon (authorized testing only):** *"What's the layout of this
internal network?"* After gaining a foothold inside a target's
network, the first lateral-movement question is what other hosts
are reachable from here. `lan-scan` answers that quickly, with
vendor labels that suggest which boxes to investigate first
(`Cisco` → likely router; `Synology` → file server; `Hewlett
Packard` → printer or workstation; `Apple` → endpoint).

## How it works

### Liveness via ICMP, same pattern as `ping`

Each host gets a single system-`ping` probe with a configurable
timeout. Same architectural decision as Cathedral's
[`ping`](ping.md) — no raw sockets, no CAP_NET_RAW, no CGO. The
tradeoff is the same too: depends on the system `ping` binary
being present, and full ICMP echo means every device sees the
probe.

Concurrency is bounded by a semaphore channel sized by `--conc`
(default 64). 254 hosts at 64 concurrency completes in roughly 4–8
seconds on a healthy LAN — the slowest hosts dominate, not the
serial count.

### The ARP cache is the MAC source

The clever part is *where the MAC addresses come from*. Cathedral
doesn't send ARP requests directly (that would require raw
sockets again). Instead:

1. The ping sweep itself causes the kernel to ARP-resolve every
   responding host on its way out the wire.
2. Once the sweep completes, the kernel's ARP cache contains a
   fresh entry for every alive host.
3. `lan-scan` reads `/proc/net/arp` and joins the table to the
   live-host list by IP.

```go
func readArpTable() map[string]string {
    m := make(map[string]string)
    f, _ := os.Open("/proc/net/arp")
    defer f.Close()
    s := bufio.NewScanner(f)
    first := true
    for s.Scan() {
        if first { first = false; continue } // skip header
        fields := strings.Fields(s.Text())
        if len(fields) < 4 { continue }
        ip, mac := fields[0], fields[3]
        if mac != "00:00:00:00:00:00" { m[ip] = mac }
    }
    return m
}
```

This is a much smaller surface than implementing ARP — and it
produces the same result, because the ping *was* the ARP trigger.
The OS does the work; Cathedral reads the answer.

The one quirk this introduces: the scanner's *own* IP doesn't get
an ARP entry, because the kernel never ARPs its own address. So
your machine appears in the result list with an empty MAC field.
This is faithful to how the kernel sees the world.

### Vendor identification from OUI

The first three octets of a MAC address — the OUI — identify the
manufacturer. Cathedral ships a curated table of ~200 vendor
mappings covering common consumer LAN devices, networking gear,
and IoT brands:

```go
var ouiTable = map[string]string{
    "00:03:93": "Apple",
    "F0:18:98": "Apple",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "00:1A:11": "Google",
    "00:50:F2": "Microsoft",
    // …
}
```

This is intentionally a hand-picked subset of the IEEE OUI registry
(which has ~30,000 entries). The curated list is small enough to
embed in the binary without a data file; trade-off is that some
enterprise vendors won't resolve. For the full lookup, see
[`oui`](oui.md), which carries a much larger table.

**Locally-administered MACs return no vendor.** Modern devices
randomize their MAC for privacy — iOS by default since 14, Android
since 10, macOS since Ventura. Randomized MACs set the "locally
administered" bit (bit 1 of the first octet) and have no
manufacturer prefix to look up. The vendor field comes back empty;
this is a feature, not a bug. The hostname (if mDNS provides one)
is the only attribution available for such devices.

### Hostnames from reverse DNS

For each alive host, Cathedral does a reverse-DNS lookup with a
700 ms timeout. On home networks with OpenWrt, dnsmasq, or a similar
DHCP-aware DNS server, this resolves DHCP-leased hostnames into
`.lan` or `.local` suffixes (`iPhone.lan`, `OpenWrt.lan`,
`NAS.local`). On networks without local DNS, this returns nothing
and the host shows up without a name — still useful, just less
labeled.

## Worked example

Captured on a real residential network:

```
> sweeping 192.168.1.0/24 — 254 hosts

  · 20%  (51/254 probed, 2 responding)
  · 40%  (108/254 probed, 4 responding)
  · 60%  (152/254 probed, 5 responding)
  · 80%  (203/254 probed, 6 responding)
  [ALIVE] 192.168.1.1     d4:35:1d:d1:31:0b   1.01 ms  OpenWrt.lan
  [ALIVE] 192.168.1.2     d6:35:1d:d1:31:0c  10.70 ms  TeliaLXC.lan
  [ALIVE] 192.168.1.170   f0:18:98:1b:7e:24  99.70 ms  guido.lan  (Apple)
  [ALIVE] 192.168.1.176                       0.13 ms  workstation.lan
  [ALIVE] 192.168.1.184   bc:5b:d5:a6:91:91   3.05 ms
  [ALIVE] 192.168.1.231   52:b3:47:be:9e:e1  41.20 ms  iPhone.lan

sweep complete — 6 alive / 254 probed
```

Six hosts, five real teaching moments:

- **`OpenWrt.lan` at .1 with a `d4:35:1d:...` MAC** is the router.
  The hostname comes from the router serving its own name over
  dnsmasq.
- **`TeliaLXC.lan` at .2 with `d6:35:1d:d1:31:0c`** — note how
  close the MAC is to the router's `d4:35:1d:d1:31:0b`. Same OUI
  (`d4:35:1d` vs `d6:35:1d` differ only in one bit), nearly
  sequential serials. This is the ISP-managed device that ships
  paired with the router from the same manufacturer batch.
- **`guido.lan` at .170 with `f0:18:98:...`** — the `f0:18:98` OUI
  resolves to Apple in the curated table. RTT of 99.7 ms on a LAN
  is the giveaway for a device in low-power mode (iPad on standby,
  MacBook lid closed). Healthy LAN RTT is under 5 ms.
- **`workstation.lan` at .176 with empty MAC** is the scanner's
  own machine. The kernel never ARPs its own address, so there's
  no ARP entry to read. RTT of 0.13 ms confirms it's local.
- **`iPhone.lan` at .231 with `52:b3:47:...`** — note the first
  octet is `52`, which in binary is `01010010`. The second-least
  bit is set — that's the *locally administered* flag. This is a
  privacy-randomized MAC, almost certainly from iOS Private WiFi
  Address. No vendor lookup is possible; the `iPhone.lan` hostname
  is the only attribution.

The unknown device at .184 (no hostname, no vendor in the curated
table) is exactly the kind of finding that motivates a `lan-scan`
on your own network: *what is that?* Worth investigating.

## Output protocol

```
{"event":"start",    "subnet":"…", "hosts":N}
{"event":"progress", "done":N, "total":N, "alive":N}*
{"event":"host",     "ip":"…", "rtt_ms":N, "mac":"…",
                     "vendor":"…", "hostname":"…"}*
{"event":"done",     "alive":N, "total":N}
```

`host` events arrive in roughly RTT-sorted order (because they're
emitted as ping replies complete and the goroutine pool fans out
to fastest-respondent first). Order is not guaranteed; sort
deterministically with `jq` and `sort -t. -k4 -n` if you need it.

Filter to non-Apple devices on the LAN:

```
$ lan-scan -j | jq -r '
    select(.event=="host" and .vendor != "Apple") |
    "\(.ip)\t\(.mac)\t\(.hostname)"
  ' | sort -t. -k4 -n
```

Build a CSV inventory of the whole subnet:

```
$ lan-scan -j | jq -r '
    select(.event=="host") |
    [.ip, .mac, .vendor, .hostname, .rtt_ms] | @csv
  '
```

## Limitations

- **ICMP-only liveness.** Devices that filter ICMP are invisible.
  Windows firewalls block inbound ping by default; some IoT devices
  intentionally don't respond to be quieter. False negatives are
  the rule, not the exception, for any non-trivial network.
- **Curated OUI table covers ~200 entries, not all 30k.** Apple,
  Raspberry Pi, common router/AP vendors, popular IoT brands are
  in. Enterprise gear (older Cisco, some HPE, niche industrial
  hardware) probably isn't. For richer attribution, run the
  resulting MACs through [`oui`](oui.md), which carries a much
  larger table.
- **Randomized MACs cannot be attributed.** This is the world we
  live in now — modern phones rotate their MAC on every network
  they join, and the rotation is the whole point of the feature.
  Cathedral correctly returns empty vendor for these and relies on
  the hostname for labeling.
- **Reverse DNS depends on local resolution.** Without dnsmasq,
  OpenWrt, mDNS, or a similar local DNS-with-DHCP-integration,
  hostnames come back empty for everything except the router.
  Cathedral can't supply names the network doesn't advertise.
- **Default sweep is /24.** Larger subnets (/16) are supported with
  `--subnet=10.0.0.0/16` but take much longer — 65k hosts at
  default concurrency is several minutes. Most home and small-
  office networks are /24 and the default is correct.
- **Self isn't in ARP.** The scanner's own IP appears with empty
  MAC and empty vendor. This is faithful — the kernel doesn't ARP
  its own address — but a first-time reader expects their own
  machine to be labelled and is briefly surprised.
- **45-second global timeout.** Slow-responding networks (cellular
  hotspots, satellite uplinks) may complete partially. The default
  timeout is right for residential and office LANs.

## Authorized use

`lan-scan` is active. It sends ICMP echo probes to 254 addresses
in roughly five seconds at default settings. Every device on the
target network sees them. Every IDS sees them. The source IP is
your own.

**On a network you own, this is unremarkable.** Pinging your own
home or office LAN to inventory devices is the same shape of
activity as `arp -a` or logging into the router's admin page.
Defender-side self-audit is the primary intended use.

**On a network you don't own, it's a different question.** Joining
a coffee shop or hotel WiFi and running `lan-scan` discovers the
other guests' devices. Whether that's acceptable depends on your
local laws, the network's terms of service, and the rules of any
engagement you're operating under. Cathedral does not gate this
behaviour, and the same posture applies as for any other active
recon tool: target what you own, or have written authorization to
probe.

**Captive networks may also rate-limit you.** Hotels and airports
often throttle clients to a few packets per second; `lan-scan` at
default concurrency will tip you over that limit and may briefly
disconnect you. Drop `--conc=10` for slow networks.

## Further reading

- [RFC 826 — Address Resolution Protocol](https://www.rfc-editor.org/rfc/rfc826) — the kernel-level mechanism the scan relies on
- [IEEE OUI registry](https://standards-oui.ieee.org/oui/oui.txt) — the source of vendor prefixes
- [Apple Private WiFi Address documentation](https://support.apple.com/en-us/HT211227) — why iPhones report locally-administered MACs
- Related Cathedral commands: [`netinfo`](netinfo.md) (the local network from your machine's perspective),
  [`oui`](oui.md) (richer MAC→vendor lookup),
  [`reverse-dns`](reverse-dns.md) (PTR sweep without the ping step),
  [`discover`](discover.md) (TCP-ping for hosts that filter ICMP)
