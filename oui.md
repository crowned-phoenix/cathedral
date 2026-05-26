---
title: oui — MAC address vendor lookup against a curated table
command: oui
category: identification
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-26
related: [netinfo, lan-scan, wifi, discover, sniff]
---

# `oui` — MAC address vendor lookup against a curated table

`oui` takes one or more MAC addresses, extracts the first three
octets (the **Organisationally Unique Identifier**, IEEE's
assigned-to-a-vendor prefix), and looks them up against a
115-entry curated table — common consumer brands, networking gear,
PC / server OEMs, smart-home devices, IoT / dev boards, and
virtualisation MAC ranges. Each hit also surfaces two
single-bit flags from the first byte: the **multicast/broadcast**
bit and the **locally-administered** bit, which tell you whether
the MAC is a real burned-in hardware address at all.

The table is hand-picked rather than the full ~36,000-entry IEEE
registry. Tradeoffs explicit: the curated set covers the MACs an
analyst actually encounters in 95% of real LAN / Wi-Fi
captures, fits in a few KB of embedded data, and ships inside
the binary with no external file lookup. The trade-off is the
long tail — an obscure industrial-controller vendor or a
recent Apple OUI added this month won't be in the table. For
those, the `lookup.json` from IEEE remains authoritative.

```
oui aa:bb:cc:dd:ee:ff
oui b8:27:eb:00:00:00            # Raspberry Pi
oui 02:42:ac:11:22:33            # Docker bridge
oui aabbccddeeff                 # no separator works too
oui aa:bb:cc:dd:ee:ff 11:22:33:44:55:66       # multiple
```

## What it does

For each input:

1. Strip every non-hex character (`:`, `-`, `.`, spaces),
   upper-case the rest. Take the first 6 hex chars. Re-insert
   colons as `AA:BB:CC`.
2. Look up the prefix against the curated table.
3. Decode the first byte's two relevant bits:
   - Bit 0 (`0x01`) — multicast/broadcast bit. Set means the
     MAC is a *group* address, not a station's unicast address.
   - Bit 1 (`0x02`) — locally-administered bit. Set means the
     MAC is *not* a burned-in IEEE-assigned address; some
     software / virtualisation layer / privacy-randomisation
     scheme created it.
4. Emit a result event with the OUI, the vendor (or "unknown"),
   and any flags that fired.

| Input form        | Example                | Result OUI    |
|-------------------|------------------------|---------------|
| Colon-separated   | `b8:27:eb:00:00:00`    | `B8:27:EB`    |
| Dash-separated    | `B8-27-EB-00-00-00`    | `B8:27:EB`    |
| Cisco-dotted      | `b827.eb00.0000`       | `B8:27:EB`    |
| No-separator      | `b827eb000000`         | `B8:27:EB`    |
| OUI-only (6 hex)  | `b8:27:eb`             | `B8:27:EB`    |

## What it answers

- Whose hardware is this MAC associated with?
- Is this a real burned-in MAC or a software-assigned one?
- Is this address actually a unicast destination, or a multicast
  group?
- Across a batch of MACs from `lan-scan` / `wifi` / `arp`, what
  vendors are represented?

## How it works

### The OUI bit layout

A 48-bit Ethernet MAC carries the vendor prefix in the **first
three octets** (24 bits). But two of those leading bits aren't
vendor identifier — they're flags.

```
First byte of MAC:    B  B  B  B  B  B  L  M
                      └───── 6 bits ─────┘ │  │
                       vendor-prefix high  │  │
                                           │  └─ multicast bit (lowest)
                                           └──── locally-administered bit
```

- **`M` (bit 0)** — multicast/broadcast. `0` = unicast (a real
  device's address); `1` = a group address. The broadcast MAC
  `FF:FF:FF:FF:FF:FF` has this set, as do all the
  `01:00:5E:…` IPv4 multicast addresses and `33:33:…` IPv6
  multicast addresses.
- **`L` (bit 1)** — locally administered. `0` = IEEE-assigned
  (a real burned-in address); `1` = locally assigned by
  software, virtualisation, or randomisation. Cathedral's own
  planned [MAC randomisation feature](../ROADMAP.md) sets this
  bit on every randomised address by IEEE convention; Docker /
  KVM / VirtualBox also set it on their virtual-NIC ranges;
  modern OSes set it on Wi-Fi-probe randomisation.

The OUI lookup uses the *full* first byte (including those two
bits) because IEEE assigns prefixes where `L=0` and the
multicast bit is whatever-the-vendor-needs. So the table is
keyed on real-byte values like `B8:27:EB` (Raspberry Pi
Foundation) — the bits being decoded separately don't change
the lookup; they're added context.

### The IEEE OUI registry

IEEE manages OUI assignment via three block sizes:

| Block type | Assignment size | Address space per assignment |
|------------|------------------|-------------------------------|
| **OUI**    | 24-bit prefix (3 octets) | 16 million MACs per vendor |
| **MA-M**   | 28-bit prefix    | 1 million MACs per vendor    |
| **MA-S**   | 36-bit prefix    | 4 thousand MACs per vendor   |

OUI is the traditional block — large vendors (Apple, Cisco,
Samsung) hold hundreds of separate OUIs. MA-M and MA-S exist
for vendors that need fewer addresses; an MA-M assignment
shares its leading 24 bits with other vendors' MA-M / MA-S
assignments under the same root.

Cathedral's curated table looks up the full 24-bit OUI form
only. MA-M and MA-S vendors that share a parent block aren't
distinguishable from the first three bytes alone — you'd need
the registry's full per-block deltas to disambiguate. For the
analyst use case (identifying common consumer / networking /
virtualisation devices), the 24-bit lookup covers the
overwhelming majority of practical hits; MA-M / MA-S vendors
typically operate in industrial / specialised hardware where
the operator is already grepping a different catalogue.

### Why a curated table

The IEEE [OUI registry](https://standards-oui.ieee.org/oui/oui.txt)
is about 4 MB of plain text — roughly 36,000 OUI assignments
covering every vendor that ever asked. Embedding it as-is
would bloat Cathedral's static binary by several MB per
sidecar that wanted to do MAC lookups (lan-scan, wifi, sniff
could all want one).

The curated 115 entries cover the realistic surface:

- **Apple** — 20 of the ~800 Apple OUIs, the most common
  ones found on real Macs / iPhones / iPads.
- **Samsung, Cisco, Cisco Meraki, Netgear, TP-Link, D-Link,
  ASUSTek, Linksys, Belkin** — most common consumer routers
  and Wi-Fi gear.
- **Dell, HP, Lenovo, Intel** — PC / server NICs.
- **Roku, Sonos, Chromecast, Amazon Echo / Fire, Nest, Ring,
  Tesla, LIFX, Philips Hue** — common smart-home.
- **Raspberry Pi, Espressif (ESP32 / ESP8266), Arduino, Particle,
  Adafruit** — common dev boards.
- **VMware, Parallels, VirtualBox, Xen, KVM, Docker, Microsoft
  Hyper-V** — virtualisation / container ranges. These are
  important because they're often misread as "unknown
  hardware" in network sweeps.
- **HPE / Aruba** — enterprise wireless infrastructure.

The 4 MB IEEE list adds the long tail — industrial-controller
OEMs, specialty hardware, vendor name changes from the 2000s
that nobody remembers, defunct companies. Not zero value, but
much higher byte cost per practical lookup. If you find
yourself needing the full registry, `wget` it from IEEE and
grep — much like an analyst would.

### Multicast bit decoding

If the lowest bit of the first byte is set, the MAC isn't
addressing a *station*; it's a group address. The most common
patterns:

| First-byte pattern | Group                                  |
|--------------------|----------------------------------------|
| `01:00:5E:…`       | IPv4 multicast (mapped from 224.0.0.0/4 group address) |
| `01:80:C2:…`       | LLC bridge-group multicast (STP, LACP, LLDP destinations) |
| `33:33:…`          | IPv6 multicast                         |
| `FF:FF:FF:FF:FF:FF`| Ethernet broadcast (special case)      |

The `oui` command tags any such address with `multicast` so
downstream parsing knows not to interpret the "vendor" as a
device owner — a `01:00:5E:…` MAC has no owner; it's a routing
construct.

### Locally-administered bit decoding

If bit 1 of the first byte is set (mask `0x02`), the MAC is
locally administered. Real-world cases:

- **Virtualisation hypervisors** — VMware, KVM, Docker, Xen.
  Each assigns MACs to virtual NICs from a manufacturer-prefix
  range that has the LAA bit clear, *or* (more commonly for
  Docker / KVM bridges) from a random range with the LAA bit
  set so the virtual MAC can't collide with any real hardware
  on the network.
- **OS-level MAC randomisation** — modern macOS / iOS /
  Android set the LAA bit on the randomised MAC used for Wi-Fi
  probe requests, exactly so the probe target can't be tricked
  into thinking the device has a real burned-in OUI.
- **Manual override** — `ip link set eth0 address 02:11:22:…`
  by a sysadmin who wants a predictable MAC for VRRP or some
  legacy MAC-pinned firewall rule.

The flag is informational — locally-administered isn't bad,
it's just *not what an OUI lookup is for*. Cathedral surfaces it
so the operator doesn't waste time wondering why a `02:42:ac:…`
MAC doesn't match any consumer brand (it's a Docker bridge
range — locally administered by Docker).

### MAC format normalisation

The input parser accepts colon, dash, dot, no-separator, mixed
case, and any combination. It strips everything that isn't a hex
digit, upper-cases what remains, takes the first six chars, and
re-inserts colons:

```go
func normalizeOUI(mac string) string {
    clean := make([]byte, 0, 12)
    for i := 0; i < len(mac) && len(clean) < 6; i++ {
        c := mac[i]
        switch {
        case c >= '0' && c <= '9':
            clean = append(clean, c)
        case c >= 'a' && c <= 'f':
            clean = append(clean, c-32)  // → upper
        case c >= 'A' && c <= 'F':
            clean = append(clean, c)
        }
    }
    if len(clean) < 6 {
        return ""
    }
    return string(clean[0:2]) + ":" + string(clean[2:4]) + ":" + string(clean[4:6])
}
```

Anything that doesn't reduce to at least 6 hex chars returns
empty → the input is reported as `not a valid MAC`. This is
intentionally forgiving: pasting an IPv6 address (which is hex
+ colons) into `oui` won't crash, it'll either grab the first
6 hex chars (and likely produce a meaningless lookup) or
return a miss. The operator is expected to know what they
typed.

## What Cathedral doesn't do

- **No live IEEE-registry fetch.** The table is baked into the
  binary at compile time; there's no `oui --refresh` to pull
  the latest IEEE list. For vendors recently added to IEEE
  (the registry updates roughly weekly), the lookup will
  return "unknown" until Cathedral itself ships an updated
  table.
- **No MA-M / MA-S resolution.** For prefixes that fall in
  one of the shared MA-M (28-bit) or MA-S (36-bit) blocks,
  Cathedral has no way to disambiguate the vendor from just
  the 24-bit form. These typically read as "unknown" rather
  than as the parent registry's holder.
- **No reverse search** (vendor → OUIs). Could be added as
  `oui --vendor=Apple` listing all known Apple OUIs in the
  table, but the table is hand-curated, so the answer would
  always be incomplete vs. the IEEE registry.
- **No MAC validity check beyond hex-length.** A MAC of
  `00:00:00:00:00:00` is technically the "unspecified"
  Ethernet address and shouldn't appear in real traffic;
  Cathedral happily reports `00:00:00 → unknown` rather than
  flagging the sentinel.
- **No OUI history / acquisitions.** When one vendor acquires
  another, the IEEE registry sometimes shows the acquiring
  vendor's name on old OUIs; Cathedral's curated entries lock
  in the historical name when that's more recognisable
  (e.g. "Cisco" not "Cisco Systems" on Linksys-era prefixes;
  "ASUSTek" not "ASUSTeK Computer Inc."). The choice is
  stylistic — operators reading a `lan-scan` output want
  fast brand-recognition more than registry-precision.

## Worked example

### Single-MAC lookup

```
operator@cathedral:~$ oui b8:27:eb:00:00:00
> looking up 1 MAC(s) (table: 115 curated entries)

  b8:27:eb:00:00:00  →  B8:27:EB  Raspberry Pi
```

The canonical Raspberry Pi OUI (`B8:27:EB` is the original
Foundation block; recent Pi 4 / Pi 5 use `DC:A6:32` and
`D8:3A:DD` which are also in Cathedral's table). Useful when
sniffing a LAN where some unknown device just showed up —
sees Raspberry Pi, you can grep your IoT inventory.

### Docker bridge MAC (locally administered)

```
operator@cathedral:~$ oui 02:42:ac:11:22:33
> looking up 1 MAC(s) (table: 115 curated entries)

  02:42:ac:11:22:33  →  02:42:AC  Docker  [locally administered]
```

The classic Docker bridge MAC range. The leading byte `02`
has the LAA bit (`0x02`) set, so Cathedral tags it. Docker
generates MACs in `02:42:AC:11:00:00 / 16` for the default
bridge network; the LAA flag means "this is virtual, not
real burned-in hardware."

### IPv4 multicast (group address)

```
operator@cathedral:~$ oui 01:00:5e:00:00:01
> looking up 1 MAC(s) (table: 115 curated entries)

  01:00:5e:00:00:01  →  01:00:5E  (unknown — not in curated table)  [multicast/broadcast]
```

The lowest bit of `01` is set → multicast flag. The OUI itself
isn't in Cathedral's curated table (no vendor "owns" the
multicast block as a vendor), so "unknown" is correct. The
`multicast` tag is the actually-useful signal — this isn't a
device, it's an IPv4 multicast group address mapped from the
IP space `224.0.0.0/24` (low-order 23 bits map straight to
the MAC's low bits).

### Multiple MACs from a `lan-scan` output

```
operator@cathedral:~$ oui aa:bb:cc:dd:ee:ff 3c:15:c2:a1:b2:c3 b8:27:eb:11:22:33 00:50:56:c0:00:01
> looking up 4 MAC(s) (table: 115 curated entries)

  aa:bb:cc:dd:ee:ff  →  AA:BB:CC  (unknown — not in curated table)  [locally administered]
  3c:15:c2:a1:b2:c3  →  3C:15:C2  Apple
  b8:27:eb:11:22:33  →  B8:27:EB  Raspberry Pi
  00:50:56:c0:00:01  →  00:50:56  VMware
```

Four MACs covering the four classes a real sweep encounters:
unknown-but-LAA-flagged (probably someone's manual override
or a privacy-randomised Wi-Fi probe), real Apple device, real
Raspberry Pi, virtualised VMware NIC.

### Cisco-dotted notation

```
operator@cathedral:~$ oui b827.eb11.2233
> looking up 1 MAC(s) (table: 115 curated entries)

  b827.eb11.2233  →  B8:27:EB  Raspberry Pi
```

Cisco gear traditionally prints MACs as three dotted groups of
four hex chars. The normaliser strips the dots same as any
other separator.

### Pipe in from another command

```
operator@cathedral:~$ lan-scan --json | jq -r '.mac // empty' | xargs oui
> looking up 12 MAC(s) (table: 115 curated entries)

  3c:15:c2:0a:1b:2c  →  3C:15:C2  Apple
  b8:27:eb:11:22:33  →  B8:27:EB  Raspberry Pi
  00:50:56:c0:00:01  →  00:50:56  VMware
  02:42:ac:11:00:02  →  02:42:AC  Docker  [locally administered]
  …
```

The natural pairing: `lan-scan` produces MACs alongside IPs;
piping them through `oui` resolves the vendor column.
`lan-scan` itself bakes the same lookup table inline so the
manual `xargs oui` step is mostly for ad-hoc post-processing.

### Invalid input

```
operator@cathedral:~$ oui not-a-mac
> looking up 1 MAC(s) (table: 115 curated entries)

  not-a-mac: not a valid MAC
```

The normaliser couldn't extract 6 hex characters from the
input. Anything that *does* contain at least 6 hex chars will
match (silently maybe-wrongly) — `oui deadbeef` happily
returns `DE:AD:BE` (which isn't a real OUI), no input
validation beyond "got enough hex digits."

## Output protocol

Line-oriented JSON. Event types:

| Event   | Fields                                                                       |
|---------|------------------------------------------------------------------------------|
| `start` | `count`, `table_size`                                                         |
| `result`| `input`, `oui`, `vendor`, `known`, `multicast?`, `locally_administered?`     |
| `miss`  | `input`, `reason` — malformed input (not enough hex chars)                   |
| `done`  | sentinel                                                                      |

Pipe-friendly with `jq`:

```
# Just vendor names
oui aa:bb:cc:dd:ee:ff 3c:15:c2:a1:b2:c3 | jq -r 'select(.event=="result") | .vendor'

# Map MAC → vendor, suitable for joining to other data
oui $(cat macs.txt) | jq -r 'select(.event=="result") | "\(.input)\t\(.vendor)"'

# Find all locally-administered MACs in a batch
oui $(cat macs.txt) | jq -r 'select(.locally_administered == true) | .input'

# Tally vendor counts across many MACs
oui $(cat macs.txt) | jq -r 'select(.event=="result") | .vendor' | sort | uniq -c | sort -rn
```

## Limitations

- **115-entry curated table.** Long-tail vendors not in the
  table return "unknown" even when they have a perfectly valid
  IEEE-assigned OUI. For comprehensive lookups, `curl
  https://standards-oui.ieee.org/oui/oui.txt | grep -i <oui>`.
- **No live registry refresh.** Tied to the Cathedral release;
  if a vendor gets a new OUI assigned this month, Cathedral
  picks it up at the next release that updates `vendors.go`.
- **No MA-M / MA-S disambiguation.** Vendors assigned a 28-bit
  or 36-bit block share their parent 24-bit OUI with other
  small-block holders; Cathedral has no path to distinguish.
- **No CIDR-style block search.** `oui 00:50:56:*` to list all
  MACs in the VMware ESXi range isn't supported.
- **No fuzzy / partial matching.** The first 6 hex chars are
  required; you can't pass just 4 chars and hope for a
  best-match.
- **Cisco-dotted notation works but is undocumented in the
  help text.** Not really a limitation — the help shows the
  three common forms — but worth noting that pasting `aaaa.bbbb.cccc`
  also works.

## Authorized use

MAC lookup against a static table is read-only computation on
bytes the operator already possesses. The authorization
considerations are essentially nil:

- **Looking up MACs from your own LAN's `arp` table** — fine,
  this is the normal admin use.
- **Looking up MACs from `lan-scan` / `wifi` output** — same;
  Cathedral's own discovery commands produce the MACs you'd
  feed in.
- **Looking up MACs that came from a packet capture** — the
  capture-acquisition question is upstream (see
  [`sniff`](sniff.md)'s authorized-use section). Once you have
  a MAC, identifying its vendor is just bookkeeping.
- **There's no privacy concern with the OUI** itself — the
  vendor prefix is a public IEEE registry entry. The privacy
  question lives in the *full* MAC, which uniquely identifies
  a device on a network; the vendor prefix is shared by
  millions of devices from that manufacturer.

## Further reading

- [IEEE — Public OUI registry](https://standards-oui.ieee.org/oui/oui.txt)
  — the authoritative source. Plain text, ~4 MB, updated
  roughly weekly. The line format is `<prefix>   (hex)   <vendor-name>`.
- [IEEE — MA-S / MA-M registries](https://standards.ieee.org/products-programs/regauth/)
  — the smaller-block registries with weekly updates and
  full-vendor-attribution. Live HTML lookup tool included.
- [Wikipedia — MAC address](https://en.wikipedia.org/wiki/MAC_address)
  — the I/G (multicast) and U/L (locally-administered) bit
  semantics are written up clearly. The historical context
  (why the bits live in the *first* byte, why the lowest one
  is multicast) goes back to the original Ethernet
  specifications.
- [RFC 7042 — IANA considerations for the IEEE 802 OUI](https://datatracker.ietf.org/doc/html/rfc7042)
  — the most precise statement of the multicast / U/L bits in
  network terms, including the IPv4 / IPv6 multicast MAC
  derivation rules.
- [Apple's MAC randomisation paper](https://support.apple.com/en-us/HT211227)
  — explains the LAA-bit convention iOS uses for Wi-Fi probe
  randomisation. Modern Android / Windows / macOS all follow
  the same pattern.
- [`lan-scan`](lan-scan.md) — ARP-style sweep that's the
  natural producer of MAC addresses to pipe into `oui`.
  Also bakes the same 115-entry table inline so the vendor
  column appears without a separate `oui` invocation.
- [`wifi`](wifi.md) — wireless scanner. Each detected AP
  has a BSSID (the AP's MAC), which can be passed through
  `oui` to learn the AP hardware vendor.
- [`netinfo`](netinfo.md) — shows your own host's MACs.
  Useful for confirming the local MAC bit-flags (most
  laptop Wi-Fi adapters now run with the LAA bit set during
  probes).
- [`sniff`](sniff.md) — for ARP frames, the sender / target
  IPs are surfaced; the MACs in the Ethernet header are not
  directly printed. Pair `sniff` with `tcpdump -e` if you need
  the full MAC view.
