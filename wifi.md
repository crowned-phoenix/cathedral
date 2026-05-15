---
title: wifi — wireless network scanner with band, channel, security, vendor
command: wifi
category: discovery
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-15
related: [netinfo, lan-scan, oui]
---

# `wifi` — wireless network scanner with band, channel, security, vendor

`wifi` enumerates the wireless access points your machine can hear
right now — every SSID, every BSSID, signal strength, band,
channel, security mode, and the manufacturer of the access point.
A passive scan: Cathedral listens to the broadcast beacons every
AP transmits, and labels what it hears.

```
wifi
```

No flags. The tool decides which backend to use, picks the
wireless interface automatically, and sorts results by signal
strength so the strongest networks are at the top.

## What it does

`wifi` does a one-shot scan of the local RF neighbourhood. For
each access point in range it reports:

- **SSID** — the network name (empty for hidden networks)
- **BSSID** — the MAC address of the AP itself
- **Band** — 2.4 / 5 / 6 GHz, derived from the operating frequency
- **Channel** — the 802.11 channel number
- **Signal** — dBm (precise) or percentage (coarse), depending on backend
- **Security** — WPA3 / WPA2 / WPA / WEP / Open / Enterprise variants
- **Standard** — 802.11 a / b / g / n / ac / ax / be (Wi-Fi 7) when detectable
- **Vendor** — manufacturer of the AP, via OUI lookup
- **In-use marker** — `*` next to the network you're currently associated with

Two backends, one output. Cathedral tries `iw` first (rich data,
needs CAP_NET_ADMIN), falls back to `nmcli` (works without
privileges, less detail) if `iw` isn't available or permitted.

## What it answers

**Operational:** *"Which network is strongest where I am?"* The
table is sorted by signal — top of the list is the best
candidate for an association. For roaming decisions, looking at
the same SSID on multiple BSSIDs across bands tells you which
radio to prefer.

**Defender:** *"Is anything unusual broadcasting near me?"* A home
office "should have" a handful of recognised SSIDs — yours, your
neighbours', the building's guest network. An unfamiliar SSID
running on the same band with strong signal — especially one
imitating a network name you trust ("MyHome-WiFi-Extender") — is
the classic shape of a rogue AP or evil-twin attack. `wifi` makes
the local RF landscape legible so anomalies are visible.

**Recon (authorized testing only):** *"What does the wireless
landscape look like at this site?"* During an authorised wireless
assessment, the first question is what's broadcasting — count of
APs, encryption mix (any WEP or Open networks?), vendor
distribution (one vendor's branded APs everywhere suggests a
unified install; many vendors suggests BYOD or organic growth),
hidden networks, 5/6 GHz adoption.

**Curiosity:** This is the only Cathedral command where "what's
out there?" is a complete answer. You don't always need a
follow-up question.

## How it works

### Two backends, automatic fallback

Linux exposes WiFi scanning through two stacks, and they have
opposite tradeoffs:

| Backend | Signal     | 802.11 detection | Country code | Privileges |
|---------|------------|------------------|--------------|------------|
| `iw`    | dBm        | yes (HT/VHT/HE/EHT) | yes      | needs `CAP_NET_ADMIN` |
| `nmcli` | percentage | coarse (band guess) | no       | no privileges |

Cathedral tries `iw` first because the data is meaningfully
richer — dBm is a precise measurement (an `iw` reading of −47 dBm
is unambiguous; an `nmcli` reading of "83%" is a vendor-specific
interpretation). If `iw` fails (missing binary, permission
denied), Cathedral falls through to `nmcli` automatically and
emits a `backend_skip` event noting what went wrong:

```
{"event":"backend_skip","name":"iw","reason":"… permission denied"}
{"event":"backend","name":"nmcli","count":12,"has_dbm":false}
```

To enable the `iw` backend without running Cathedral as root:

```
sudo setcap cap_net_admin+eip $(which iw)
```

This grants `iw` the network-admin capability persistently — it
can scan without sudo for any user. Set once, forget.

### Picking the wireless interface

`/proc/net/wireless` is the kernel's list of wireless interfaces;
Cathedral picks the first one listed and uses it:

```go
func pickWirelessIface() string {
    data, _ := os.ReadFile("/proc/net/wireless")
    lines := strings.Split(string(data), "\n")
    for _, line := range lines[2:] { // skip 2 header lines
        if colon := strings.Index(line, ":"); colon >= 0 {
            return strings.TrimSpace(line[:colon])
        }
    }
    return ""
}
```

Most machines have one wireless interface; on multi-radio systems
(laptops with both internal WiFi and a USB adapter), Cathedral
takes the first listed. There's no flag to override yet.

### 802.11 standard inference

`iw scan` output includes capability blocks: `HT capabilities`
(Wi-Fi 4), `VHT capabilities` (Wi-Fi 5), `HE capabilities` (Wi-Fi
6), `EHT capabilities` (Wi-Fi 7). Cathedral walks the per-AP block,
tracks which capability bits appear, and labels the AP with the
highest-tier feature it advertised:

```go
switch {
case hasEHT: standard = "be" // Wi-Fi 7
case hasHE:  standard = "ax" // Wi-Fi 6 / 6E
case hasVHT: standard = "ac" // Wi-Fi 5
case hasHT:  standard = "n"  // Wi-Fi 4
default:
    if band == "5 GHz"   { standard = "a" }
    if band == "2.4 GHz" { standard = "g" }
}
```

`nmcli` doesn't expose the capability bits, so on that backend the
standard is a coarse guess from band — 6 GHz implies Wi-Fi 6E,
5 GHz could be ac or ax, 2.4 GHz could be n or g. The cookbook
admits this with a `?` prefix in the rendered standard column.

### Security labelling

The raw scan output exposes individual primitives — `RSN`, `WPA`,
`Privacy` flags, plus `Authentication suites` listing `SAE` (the
WPA3 handshake), `PSK` (WPA2-Personal pre-shared key), `802.1X`
(enterprise auth). Cathedral collapses these to a human label:

```go
switch {
case strings.Contains(auth, "SAE") && strings.Contains(auth, "PSK"):
    return "WPA2/3-Personal"
case strings.Contains(auth, "SAE"):
    return "WPA3-Personal"
case strings.Contains(auth, "802.1X"):
    return "WPA2-Enterprise"
case strings.Contains(auth, "PSK"):
    return "WPA2-Personal"
}
```

The transitional `WPA2/3-Personal` label is increasingly common —
APs broadcast both the SAE (WPA3) and PSK (WPA2) authentication
suites to support older clients. Pure WPA3-Personal networks (SAE
only, no PSK) are still rare in residential gear and more common
in enterprise re-deployments.

### Hidden networks

An AP with a non-empty SSID in its beacon is visible by name. An
AP that suppresses its SSID — what consumer router UIs call
"hidden network" — sends beacons with the SSID field set to
empty. Cathedral marks these as `Hidden: true` and renders the
SSID column as `*hidden*`. The BSSID, signal, channel, and
security are all still observable — *hiding* the SSID never made
the network actually invisible, only mildly inconvenient to
identify.

### Signal-strength normalisation

dBm is a negative-scale measurement (less negative = stronger).
`-50` dBm is excellent; `-90` dBm is barely audible. Percentage
is 0–100 (higher = stronger). For sorting, Cathedral converts
both to a unified score where higher means stronger:

```go
func signalScore(ap AP) float64 {
    if ap.SignalDBm != 0 {
        return ap.SignalDBm        // already in "more = stronger" order on the negative scale
    }
    return float64(ap.SignalPct - 100) // -100 to 0; same order
}
```

The UI renders four-cell signal bars derived from this score, so
mixed-backend outputs still rank visually.

### OUI vendor lookup

The first three octets of the BSSID identify the AP manufacturer.
Cathedral uses the same ~200-entry curated OUI table that
[`lan-scan`](lan-scan.md) and [`discover`](discover.md) use —
covers common consumer AP vendors, popular networking gear, and
ISP-branded boxes. Enterprise gear (Aruba, Ruckus, Meraki, Cisco
Catalyst) and niche manufacturers may not resolve; for richer
lookup, run BSSIDs through [`oui`](oui.md).

## Worked example

A residential scan on a machine using the `nmcli` backend
(percentage signal, ISP-managed network in use). BSSIDs and SSIDs
sanitised:

```
> scanning nearby WiFi networks
  interface : wlp0s20f3
  via nmcli — 5 networks visible  (signal %)

            SSID                        BSSID               BAND   CH   SECURITY          VENDOR
  ----------------------------------------------------------------------------------------------
  * ████  83% #ISP-D1310C                AA:BB:CC:D1:31:14   5 GHz  104  WPA2-Personal     —
    ███·  62%  Neighbour-2G              AA:BB:CC:D1:31:0E   2.4 GHz 11  WPA2/3-Personal   —
    ██··  57%  ISP-AE690A                AA:BB:CC:83:9A:C6   5 GHz   56  WPA2-Personal     —
    ██··  44%  *hidden*                  11:22:33:01:F4:90   5 GHz   36  WPA2-Personal     Apple
    █···  28%  CoffeeShop-Guest          AA:BB:CC:01:23:45   2.4 GHz  6  Open              —
```

Things this snapshot teaches:

- **The `*` marker** on the first row shows the active
  association. That's your current network; everything below is
  what else is reachable from here.
- **The first three rows share an OUI** (`AA:BB:CC`). The
  connected SSID and the second one have BSSIDs differing only
  in the last octet (`14` vs `0E`) — almost certainly the
  5 GHz and 2.4 GHz radios of *the same physical AP*. The same
  device often appears multiple times in a scan, once per radio.
- **A hidden network** on channel 36 is broadcasting beacons
  with no SSID. The BSSID is still legible (`11:22:33:01:F4:90`),
  the security and signal are still measurable. "Hidden" only
  hides the name — everything else about the network is in plain
  view of any passive listener.
- **An open network at the bottom** — `CoffeeShop-Guest` with no
  encryption. Traffic on this network is readable by anyone
  within radio range. The marker the cookbook reaches for here
  isn't *"this is bad"*; it's *"if you join this network, your
  traffic is observable to everyone in range, so use a VPN."*
- **Vendor labels are sparse** — most home APs in the curated
  OUI table are ISP-rebranded white-label hardware that doesn't
  match a recognised manufacturer prefix. The fourth row
  resolves to Apple because that OUI is in the curated table;
  the others don't.

The signal bars (full / partial / dim) double as a coarse
quality reading: full bars = strong association possible; one
bar = visible but unreliable.

## Output protocol

```
{"event":"start"}
{"event":"iface",        "name":"…"}
{"event":"backend_skip", "name":"…","reason":"…"}*
{"event":"backend",      "name":"iw|nmcli","count":N,"has_dbm":bool}
{"event":"ap",           "bssid":"…","ssid":"…","hidden":bool,"in_use":bool,
                         "mode":"…","channel":N,"freq":N,"band":"…",
                         "rate":"…","signal_pct":N,"signal_dbm":N,
                         "bars":"…","security":"…","standard":"…",
                         "width_mhz":N,"country":"…","vendor":"…"}*
{"event":"done",         "total":N,"backend":"…"}
```

`signal_dbm` and `signal_pct` are mutually exclusive in practice
— check `has_dbm` from the `backend` event to know which to read.
`width_mhz`, `country`, and the precise `standard` are only
populated when the `iw` backend wins.

Build an inventory of all open networks within range:

```
$ wifi -j | jq -r '
    select(.event=="ap" and .security=="Open") |
    "\(.ssid)\t\(.bssid)\t\(.signal_pct)%"
  '
```

Count the security mix:

```
$ wifi -j | jq -r 'select(.event=="ap") | .security' |
    sort | uniq -c | sort -rn
      4 WPA2-Personal
      2 WPA2/3-Personal
      1 Open
      1 WPA3-Personal
```

## Limitations

- **Linux-specific.** The implementation reads `/proc/net/wireless`,
  invokes `iw` or `nmcli`, both Linux-only stacks. The Flutter
  app itself runs on macOS / Windows, but the `wifi` command
  produces results only on Linux. Native backends for the other
  platforms are not in v1.
- **iw needs `CAP_NET_ADMIN`.** Without it, only `nmcli` works.
  The setcap one-liner is the standard fix; setting it once
  during machine setup gets you the richer backend permanently.
- **nmcli loses the 802.11 standard detection.** Output shows
  `?ac/ax` or similar for 5 GHz APs because nmcli doesn't expose
  capability bits. The band is reliable; the precise standard is
  not.
- **Snapshot-only scanning.** `wifi` returns what beacons it
  hears in a single scan window — typically 1–3 seconds. APs
  that don't beacon during that window (some low-power IoT APs,
  or APs that have just transmitted and gone quiet) are missed.
  No channel-hopping monitor mode; no continuous capture.
- **Hidden SSIDs stay hidden by name.** Cathedral reports
  `*hidden*` but doesn't attempt to unmask via deauth + reassoc
  observation. That would require monitor mode and is
  intentionally out of scope.
- **No probe-request or client analysis.** `wifi` reads beacons
  only — it does not log which clients are probing for which
  networks (a separate, more invasive technique that needs raw
  monitor-mode capture). Cathedral's posture stays passive.
- **No location / triangulation.** Single-radio scanning means a
  signal strength reading is "how strong is this AP from this
  spot", not a position. Wardriving-style mapping is a separate
  problem domain.
- **Single wireless interface assumed.** If your machine has
  multiple radios (internal + USB adapter), Cathedral picks the
  first one and doesn't expose a way to choose otherwise yet.

## Authorized use

`wifi` is a **passive** scan: Cathedral receives the broadcast
beacons every nearby AP transmits to announce itself, and labels
what it hears. No probes are sent, no traffic is injected, no
clients are deauthenticated. The risk profile is the same as
walking through a building and reading the names on the doors —
the information is being broadcast to the world.

That said, two notes worth attaching:

**Some jurisdictions regulate even passive RF reception.** In
most of the world, listening to public broadcast beacons is
legal and unremarkable. In a handful of places, RF capture
without authorisation can be ambiguous. Familiarise yourself
with local rules if it matters.

**The output describes your physical location.** A `wifi` scan
output uniquely identifies a place: the set of nearby BSSIDs is
essentially a fingerprint of where you were standing when you
ran the command. Treat the output the same way you'd treat a
GPS log. Don't paste it into public bug reports without
redacting.

## Further reading

- [802.11 frame format reference](https://en.wikipedia.org/wiki/802.11_Frame_Types) — what beacons carry
- [Wi-Fi Alliance Wi-Fi 7 (802.11be) spec summary](https://www.wi-fi.org/discover-wi-fi/wi-fi-7) — the EHT capability bits
- [`iw` documentation](https://wireless.wiki.kernel.org/en/users/documentation/iw) — the backend command reference
- Related Cathedral commands: [`netinfo`](netinfo.md) (your machine's WiFi association from the inside),
  [`lan-scan`](lan-scan.md) (once associated, what's on the LAN),
  [`oui`](oui.md) (richer MAC→vendor lookup for unrecognised BSSIDs)
