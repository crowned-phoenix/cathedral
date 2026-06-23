---
title: rf-recon — passive monitor-mode 802.11 situational awareness
command: rf-recon
category: discovery
status: draft
version-introduced: unreleased
authorized-use: medium
last-updated: 2026-06-22
related: [wifi, sniff, oui, discover, lan-scan]
---

# `rf-recon` — passive monitor-mode 802.11 situational awareness

> **Draft — unreleased.** The parsing and presence-tracking layers are
> implemented and unit-tested; the live capture path (monitor-mode entry,
> channel hopping, raw 802.11 reads) was written without a monitor-capable
> adapter on hand and has **not yet been exercised against a real radio**.
> The worked examples below are illustrative, not captures. Treat command
> output shapes as the intended contract, subject to change once the tool
> runs on hardware.

`rf-recon` turns a monitor-mode-capable wireless adapter into a passive
sensor of the radio space around the operator. Where [`wifi`](wifi.md) gives
you a one-shot list of *APs you could associate with*, `rf-recon` reads the
raw 802.11 air: every nearby station's beacons, probe requests, and data-frame
headers — and builds a live picture of who is present, what they're connected
to, and which networks their devices remember.

It operates in **monitor mode**, which is the dividing line from Cathedral's
two existing radio/capture tools:

- [`wifi`](wifi.md) scans in **managed mode** via `iw`/`nmcli` — it sees AP
  beacons only, on a 1–3 s scan-cache window.
- [`sniff`](sniff.md) captures in **managed mode** via `AF_PACKET` — it sees
  IP frames addressed to *our own host*.
- `rf-recon` captures in **monitor mode** — it sees *every* station's raw
  802.11 management/control/data frames, addressed to anyone.

That extra visibility is exactly what makes it more invasive; see
[Authorized use](#authorized-use).

```
rf-recon map                                   # passive neighbourhood map, 2.4+5 GHz, 30 s
rf-recon map --iface=wlan0
rf-recon map --band=2.4,5,6                     # include 6 GHz (6E PSC channels)
rf-recon map --band=2.4 --dwell=400            # linger 400 ms per channel
rf-recon map --duration=120                    # capture for two minutes
```

`rf-recon motion` (RSSI-variance motion radar) is reserved for a later build
and currently returns a "not implemented" error.

## What it does

For one `rf-recon map` invocation:

1. **Pick the interface.** `--iface=NAME` if supplied, else the first entry in
   `/proc/net/wireless`.
2. **Check preconditions.** `iw` and `ip` must be in `PATH` (the tool drives
   monitor mode by shelling out to them), and the adapter/driver must advertise
   monitor mode. If either fails, it emits a clear `error` and stops — it never
   silently produces nothing.
3. **Enter monitor mode.** Records the interface's original mode to a state
   file (for crash recovery), brings it down, sets type `monitor`, brings it
   up. The state file lets a later run restore an interface a crashed capture
   left in monitor mode.
4. **Channel-hop + capture.** A hopper tunes the interface across the band plan
   (configurable dwell); meanwhile a raw `AF_PACKET` socket reads radiotap-
   prefixed 802.11 frames. Each frame is decoded and folded into running AP /
   client / probe / presence tables.
5. **Stream deltas.** Emits `ap` / `client` / `probe` / `presence` events as
   *new information* appears — not a full table redraw every frame.
6. **Restore + summarise.** On exit (including Ctrl-C), restores the interface
   to its original mode and clears the state file, then emits `done` with the
   tallies.

| Flag             | Meaning                                        | Default       |
|------------------|------------------------------------------------|---------------|
| `--iface=NAME`   | Interface to capture on                        | first in `/proc/net/wireless` |
| `--band=LIST`    | Comma list of `2.4` / `5` / `6`                | `2.4,5`       |
| `--dwell=MS`     | Milliseconds to linger per channel before hop  | `250`         |
| `--duration=SEC` | Stop after SEC seconds                         | `30`          |

## What it answers

- What APs are actually transmitting here — including ones `wifi`'s short scan
  window misses, and hidden-SSID APs that only reveal themselves in
  association traffic?
- Which client devices are present, and which AP is each one talking to?
- What networks is a nearby device hunting for — i.e. where has it been? A
  probe for `Marriott_GUEST` or `CorpNet-Internal` leaks travel/employer
  history.
- Is a particular device approaching or leaving (rising vs falling RSSI)?

## How it works

### Monitor mode vs managed mode

A managed-mode interface only hands its driver frames addressed to the host
(plus AP beacons during a scan). Monitor mode disables that filtering: the
adapter reports *every* 802.11 frame it can demodulate on the current channel,
with a radiotap header describing the reception (signal, channel, rate). This
is the standard ante for every serious 802.11 recon tool (kismet, airodump-ng)
— and a hardware/driver capability, not something software can synthesise. Many
built-in laptop chips support it; some don't, which is why `rf-recon` probes
for it and fails loudly when it's absent.

### The pure-Go capture path

Like [`sniff`](sniff.md), `rf-recon` reaches the wire through a raw
`AF_PACKET` socket — no libpcap, no CGO, static binary preserved. The only
difference is what arrives: on a monitor-mode interface, each frame is prefixed
with a **radiotap** header, then the raw 802.11 frame.

```go
fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index})
```

### Parsing radiotap

The radiotap header is self-describing: a little-endian "present" bitmap names
which fields follow, in ascending bit order, each aligned to its natural size
*relative to the start of the header*. `rf-recon` walks that bitmap to the two
fields it needs — channel frequency (bit 3) and signal dBm (bit 5):

```go
rtLen := binary.LittleEndian.Uint16(buf[2:4]) // total radiotap length
// …walk present-flag fields with per-field alignment to DBM_ANTSIGNAL…
dot11 := buf[rtLen:]                           // 802.11 frame starts here
```

The alignment walk is the fiddly part (a field at an odd offset must be padded
to its 2/4/8-byte boundary), and it's the most heavily unit-tested code in the
tool.

### Parsing 802.11

The frame-control byte gives type (management / control / data) and subtype.
From there:

- **Beacons / probe-responses** carry the BSSID plus tagged information
  elements — SSID (tag 0), RSN (tag 48) and vendor WPA (tag 221) for the
  security label, and the capability-info privacy bit.
- **Probe requests** carry the SSID a device is searching for — its Preferred
  Network List, one entry per request.
- **Data frames** reveal client↔AP association through the `ToDS`/`FromDS`
  bits, which decide whether `addr1/2/3` are the BSSID, the station, or the
  far endpoint:

  | ToDS | FromDS | addr1 | addr2 | addr3 | → resolves to        |
  |------|--------|-------|-------|-------|----------------------|
  | 0    | 0      | DA    | SA    | BSSID | STA=addr2, BSSID=addr3 (IBSS) |
  | 1    | 0      | BSSID | SA    | DA    | STA=addr2, BSSID=addr1 (to AP) |
  | 0    | 1      | DA    | BSSID | SA    | STA=addr1, BSSID=addr2 (from AP) |
  | 1    | 1      | RA    | TA    | DA    | WDS — no simple STA/BSSID |

  This client-mapping is the piece `wifi` fundamentally cannot do: managed-mode
  scanning never sees other stations' frames.

Vendor tagging reuses Cathedral's curated OUI table (see [`oui`](oui.md)), so a
probing MAC is labelled with its manufacturer where known.

### Presence table and RSSI smoothing

Per MAC, `rf-recon` keeps first-seen / last-seen / smoothed RSSI / association.
Raw monitor-mode RSSI jitters ±5 dBm frame-to-frame, which would drown any
trend, so each MAC's signal is run through an EWMA:

```go
smoothed = alpha*sample + (1-alpha)*smoothed   // alpha = 0.3
```

A rising smoothed RSSI reads as **approaching**, falling as **leaving**, and a
settled signal as **steady** — emitted as `presence` deltas only when the trend
changes, not every frame. This is coarse by design: RSSI says "this device's
link got stronger," not "the device is 3.2 m away."

### Channel hopping

Monitor mode hears one channel at a time, so the hopper steps through the band
plan, tuning by absolute frequency (`iw dev <iface> set freq`) to stay
unambiguous where 2.4/5/6 GHz channel numbers overlap. The 6 GHz plan uses the
6E Preferred Scanning Channels rather than every channel — hitting all of 6 GHz
would make a dwell pass impractically long, and 6E APs are required to beacon
on PSCs. Frames whose radiotap omits channel are attributed to the hopper's
current frequency.

### Privilege model

Two capabilities are needed, granted the same way Cathedral's existing radio
tools document:

- **`iw` / `ip` need `CAP_NET_ADMIN`** — they own the monitor-mode switch and
  channel tuning. This is the same grant [`wifi`](wifi.md) already needs for
  `iw`.
- **The `rf-recon` binary needs `CAP_NET_RAW`** — for the `AF_PACKET` capture
  socket, exactly like [`sniff`](sniff.md).

```
sudo setcap cap_net_admin+eip "$(command -v iw)" "$(command -v ip)"
sudo setcap cap_net_raw+ep    /path/to/rf-recon
```

On a permission error, the tool prints the exact `setcap` line for its own
installed path. A dedicated capability-carrying helper (`cathedral-rfmon`)
that isolates these privileges from the parsing logic is the eventual target
(see [ROADMAP.md](../ROADMAP.md)); the shell-to-`iw` approach above is the
get-to-real-data-first path.

## What Cathedral doesn't do

- **No CSI sensing.** The through-wall presence / breathing / pose tricks that
  inspired this tool need Channel State Information, which consumer Wi-Fi chips
  don't expose to drivers. `rf-recon` deliberately does **not** claim them. An
  optional ESP32-over-serial CSI bridge is an investigation item, not a
  feature — see [ROADMAP.md](../ROADMAP.md).
- **No injection / deauth / association.** Purely passive. It listens; it never
  transmits 802.11 management frames.
- **No vitals or pose, ever.** Even the planned `motion` subcommand is scoped to
  "coarse motion presence near this link," never breathing-rate or posture.
- **Not a kismet replacement.** No GPS wardriving logs, no PCAP output, no WIDS
  alerting, no plugin ecosystem. It's a focused neighbourhood-map + presence
  tool.

## Worked example

> Illustrative output (the tool is unreleased and hardware-untested). The
> rendered view below is what the HUD is intended to show; the underlying
> stream is line-oriented JSON (see [Output protocol](#output-protocol)).

### A passive map of the local airspace

```
operator@cathedral:~$ rf-recon map --band=2.4,5 --duration=30
> monitor mode on wlan0 — 2.4+5 GHz, 38 channels, 250 ms dwell, 30 s

  ACCESS POINTS
  BSSID              SSID                CH   BAND     SEC         RSSI  VENDOR
  -----------------  ------------------  ---  -------  ----------  ----  -------------
  a4:2b:8c:11:90:ff  Loft-5G               44  5 GHz    WPA2/WPA3   -41  TP-Link
  a4:2b:8c:11:90:fe  Loft                   6  2.4 GHz  WPA2/WPA3   -43  TP-Link
  3c:84:6a:22:1d:07  <hidden>              11  2.4 GHz  WPA2/WPA3   -67  Netgear
  e0:cc:7a:55:33:90  CoffeeGuest            1  2.4 GHz  Open        -72  Ubiquiti

  CLIENTS
  STATION            ASSOCIATED TO       RSSI  VENDOR
  -----------------  -----------------   ----  -------------
  9e:1f:33:ab:cd:01  a4:2b:8c:11:90:ff   -49  (randomised)
  44:65:0d:aa:bb:cc  a4:2b:8c:11:90:fe   -55  Amazon
  6c:40:08:12:34:56  3c:84:6a:22:1d:07   -70  Apple

  PROBE REQUESTS (preferred-network-list leaks)
  STATION            PROBING FOR         VENDOR
  -----------------  ------------------  -------------
  6c:40:08:12:34:56  Heathrow-WiFi       Apple
  6c:40:08:12:34:56  CorpNet-Internal    Apple
  72:aa:19:e4:7b:20  Marriott_GUEST      (randomised)

  > presence: 9e:1f:33:ab:cd:01 approaching (-58 → -49)
  > presence: 6c:40:08:12:34:56 leaving (-61 → -70)

map complete — 4 APs, 3 clients, 3 probe SSIDs over 1,284 frames
```

The hidden-SSID AP (`3c:84:…`) shows up despite never broadcasting its name —
its clients' association traffic reveals the BSSID even though `wifi`'s scan
would list it as `<hidden>` with nothing else. The Apple device probing for
`Heathrow-WiFi` and `CorpNet-Internal` has leaked both a travel history and an
employer. Two stations show `(randomised)` vendors — modern phones rotate MAC
addresses precisely to defeat this kind of tracking, and a locally-administered
(randomised) MAC has no real OUI to look up.

### Including 6 GHz and lingering longer

```
operator@cathedral:~$ rf-recon map --band=2.4,5,6 --dwell=400 --duration=60
> monitor mode on wlan0 — 2.4+5+6 GHz, 53 channels, 400 ms dwell, 60 s

  ACCESS POINTS
  BSSID              SSID                CH   BAND     SEC         RSSI  VENDOR
  -----------------  ------------------  ---  -------  ----------  ----  -------------
  a4:2b:8c:11:90:fd  Loft-6E              37  6 GHz    WPA2/WPA3   -52  TP-Link
  …
```

A longer dwell catches APs that beacon less often, at the cost of revisiting
each channel less frequently — fewer hops per second means a fast-moving device
can slip between visits. 6 GHz hopping covers PSC channels only.

### The unsupported-adapter path

```
operator@cathedral:~$ rf-recon map
error: this adapter/driver does not support monitor mode: adapter/driver does not list monitor in supported interface modes
```

The honest hardware gate. Some chips simply can't do monitor mode; the tool
says so rather than entering a half-broken state that captures nothing.

### The missing-tooling path

```
operator@cathedral:~$ rf-recon map
error: `iw` not found in PATH — rf-recon drives monitor mode via iw/ip (install: sudo apt install iw iproute2)
```

## Output protocol

Line-oriented JSON. Event types:

| Event      | Fields                                                                          |
|------------|---------------------------------------------------------------------------------|
| `start`    | `iface`, `bands`, `channels`, `dwell_ms`, `duration_s`                          |
| `iface`    | `name`, `monitor`                                                               |
| `ap`       | `bssid`, `ssid`, `hidden`, `security`, `channel`, `band`, `freq`, `rssi`, `vendor` |
| `client`   | `mac`, `bssid`, `vendor`, `rssi`                                                |
| `probe`    | `mac`, `ssid`, `vendor`, `rssi`                                                 |
| `presence` | `mac`, `bssid`, `rssi`, `trend` (`approaching` / `leaving`)                     |
| `recover`  | `iface`, `message` — restoring an interface a prior run left in monitor mode    |
| `done`     | `frames`, `decoded`, `aps`, `clients`, `probes`                                 |
| `error`    | `message`                                                                       |

`ap` / `client` / `probe` events are deltas: re-emitted only when something new
is learned (a new BSSID, a newly-revealed SSID, a changed association), not on
every frame. Pipe-friendly with `jq`:

```
# Just the probe-request PNL leaks, "MAC wants SSID"
rf-recon map --duration=120 | jq -r 'select(.event=="probe") | "\(.mac) → \(.ssid)"'

# Devices currently approaching
rf-recon map --duration=60 | jq -r 'select(.event=="presence" and .trend=="approaching") | .mac'

# Count clients per AP
rf-recon map --duration=60 | jq -r 'select(.event=="client") | .bssid' | sort | uniq -c | sort -rn
```

## Limitations

- **Needs a monitor-mode-capable adapter.** Hardware/driver fact, not a
  software limitation. No adapter, no tool.
- **One channel at a time.** Channel hopping means any single channel is only
  observed for `dwell` ms out of each full pass. Short-lived frames on a
  channel you're not currently parked on are missed. A device that probes once,
  on a channel you visit briefly, can slip through — longer captures and
  shorter dwells trade against each other.
- **RSSI motion is coarse.** `presence` trends say "the link got stronger /
  weaker," nothing finer. Multipath, antenna orientation, and the device's own
  transmit-power changes all move RSSI without the device moving.
- **MAC randomisation defeats device tracking.** Modern phones rotate their MAC
  for probe requests and sometimes per-association, so a `(randomised)` station
  can't be followed across sessions or labelled by vendor.
- **Security label is coarse.** RSN presence is reported as the combined
  `WPA2/WPA3` bucket; distinguishing the two needs RSN AKM-suite inspection,
  which is deferred.
- **Linux only.** `AF_PACKET` and nl80211 monitor mode are Linux-specific.
- **No injection, no PCAP, no GPS.** See [What Cathedral doesn't
  do](#what-cathedral-doesnt-do).

## Authorized use

Passive monitor-mode 802.11 capture is **medium-plus** dual-use — more invasive
than `wifi`'s beacon scan, because it observes every nearby station's
management frames, not just AP broadcasts.

- **Mapping airspace you own or are authorized to test** is fine: your home /
  lab, or an engagement with written scope covering wireless reconnaissance.
  This is what the tool is for.
- **Probe-request harvesting is the sharp edge.** A device's Preferred Network
  List reveals where its owner has been — homes, employers, hotels, airports.
  Collecting it is the textbook "deanonymise the people in this room" technique,
  and in many jurisdictions capturing it without consent is wiretap-shaped even
  though the frames arrived on your card unbidden (the US Wiretap Act, the UK
  Investigatory Powers Act, the EU ePrivacy Directive all bear on this
  differently).
- **Capturing in a space you don't control** — a café, an office you're
  visiting, a conference — is exactly the scenario regulators treat most
  strictly. Don't.
- **The two capabilities are granted by an operator who understands the trust
  model.** Cathedral never sets them automatically; the `setcap` steps are a
  deliberate "yes, I intend to capture raw radio here" acknowledgement.

## Further reading

- [radiotap.org](https://www.radiotap.org/) — the radiotap header format:
  present-flags bitmap, field alignment rules, the full field table.
- [Linux nl80211 / cfg80211](https://wireless.wiki.kernel.org/en/developers/documentation/nl80211)
  — the kernel interface behind `iw` for monitor-mode entry and channel
  control.
- [IEEE 802.11 frame format](https://en.wikipedia.org/wiki/802.11_Frame_Types)
  — frame-control type/subtype and the addr1/2/3 + ToDS/FromDS addressing rules
  the client-mapping relies on.
- [packet(7)](https://man7.org/linux/man-pages/man7/packet.7.html) and
  [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
  — the `AF_PACKET` socket and the `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities.
- [`wifi`](wifi.md) — the managed-mode beacon scan. `rf-recon` is its
  monitor-mode counterpart that also sees clients and probes.
- [`sniff`](sniff.md) — managed-mode IP-frame capture. Same `AF_PACKET`
  plumbing, different layer.
- [`oui`](oui.md) — the vendor lookup `rf-recon` reuses to tag MACs.
