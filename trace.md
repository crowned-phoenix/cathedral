---
title: trace — path discovery with geolocation
command: trace
category: reachability
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-13
related: [ping, geoip, whois, asn, discover]
---

# `trace` — path discovery with geolocation

`trace` shows the network path between you and a target — every
router your packets pass through, the RTT to each one, and (by
default) the geographic location of each public hop pinned on the
Cathedral globe. The terminal table tells you *what* hops; the globe
view tells you *where*. Same data, two surfaces.

```
trace 1.1.1.1
trace github.com
trace example.com --no-geo
```

## What it does

`trace` runs a traceroute to `<host>` and emits each hop as a
structured event the moment it's discovered. Public hops are
asynchronously enriched with city / country / coordinates from a geo
service; private hops (RFC1918, link-local, loopback) are tagged
locally and never sent to the geo backend.

| Flag        | Meaning                                              |
|-------------|------------------------------------------------------|
| (target)    | hostname or IP to trace                              |
| `--no-geo`  | skip the geo lookups — purely local recon            |

The trace ends when the target IP is reached or after 30 hops,
whichever comes first.

## What it answers

**Defender / operator:** *"Why is this slow, or going through the
wrong place?"* A trace from a corporate laptop that suddenly routes
through three extra hops in a country you don't normally egress from
is a real signal — VPN misconfiguration, ISP rerouting after a fibre
cut, or someone's intercepting proxy quietly inserted itself. Reading
the geographic path is faster than reading the IP path.

**Recon:** *"What's between me and this target?"* The hop list reveals
the transit providers (Hurricane Electric, Cogent, Level3), the
hosting ASN, peering relationships, and edge architecture. A target
that terminates inside Cloudflare or Akamai looks completely
different from one running on a dedicated colocation.

**Education:** *"What does the internet actually look like?"* The
globe visualisation is the value here — seeing a packet hop from
your living room to a Cloudflare edge in Frankfurt to one in Sydney
in less than thirty milliseconds is the kind of thing that makes the
network legible. This is why the cookbook category is *reachability*
and not *recon* — most of the time you run `trace`, you run it to
understand something, not to attack it.

## How it works

### Wrapping MTR, not classic traceroute

Cathedral uses `mtr -l` (My Traceroute, raw output mode), not the
classic `traceroute(8)`. Three reasons:

1. **MTR is more robust on networks that drop UDP traceroute.** It
   defaults to ICMP and falls back smartly. Classic traceroute's UDP
   probes get dropped by half of modern firewalls.
2. **MTR's `-l` mode is line-by-line parseable.** Each line is one
   event keyed by hop number — exactly the shape Cathedral needs for
   streaming.
3. **MTR handles measurement consistently.** RTT is reported in
   microseconds with a stable format. No regex archaeology against
   six versions of `traceroute`'s output.

The cost is the same as `ping`: Cathedral depends on `mtr` being
installed (`apt install mtr-tiny` on Debian/Ubuntu). On a stripped
container or a system without MTR, `trace` fails with a clear
"mtr not found" error rather than silently degrading.

### The MTR raw protocol

MTR's `-l` flag emits one event per line, tagged with a single-letter
type:

```
h 0 192.168.1.1
p 0 1857
h 1 90.191.8.3
p 1 2882
h 4 1.1.1.1
p 4 3033
```

`h N IP` reports that hop N has been identified at this address.
`p N RTTus` reports the RTT for that hop in microseconds. Cathedral's
parser pairs them:

```go
case "h":
    h := get(n)
    if h.ip == "" { h.ip = fields[2] }
case "p":
    us, _ := strconv.Atoi(fields[2])
    h := get(n)
    h.rttUs = us
    tryEmit(n)
```

Once both halves arrive, the hop is emitted as a single `hop` event
with `rtt_ms` (float) and `private` (bool) flags computed locally.

### Silent hops are dropped

If a hop along the path doesn't reply to MTR's probes, it never gets
an `h` line and Cathedral never emits a `hop` event for it. You'll
see hops 1, 2, 3, 5 with hop 4 absent — that's a router that
declined to send ICMP Time Exceeded responses. This is common,
especially through cloud network gear; reporting "* * *" the way
classic traceroute does adds noise without adding signal. Cathedral
prefers the cleaner gap.

### Geo enrichment

For every public hop, Cathedral fires an asynchronous HTTP request to
`ip-api.com` to look up city / country / coordinates. The request
goes out on its own goroutine so the trace itself doesn't block
waiting for the geo service:

```go
if !noGeo && !private && parsed != nil && !h.geoFired {
    h.geoFired = true
    wg.Add(1)
    go func(hi int, ipStr string) {
        defer wg.Done()
        geoLookup(hi, ipStr)
    }(n+1, h.ip)
}
```

When the lookup returns, a separate `geo` event arrives carrying the
same hop number. The UI joins it back to the hop entry by `n`. Geo
events can arrive *after* the hop event — the cookbook entry's worked
example below shows this clearly. The UI handles late-arriving geo
gracefully.

**Anycast addresses lie.** `1.1.1.1` is a Cloudflare anycast address;
the geo lookup returns Cloudflare's registered-company location
(Brisbane, Australia) even though the actual server you're hitting is
the nearest edge to *you* (probably the same continent, possibly the
same city). Anycast is invisible to geo databases. Read the location
as "who runs this IP block" rather than "where is the physical box."

### Private hops never leak

Loopback, link-local, RFC1918, and unspecified addresses are detected
locally:

```go
func isPrivate(ip net.IP) bool {
    return ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
           ip.IsPrivate() || ip.IsUnspecified()
}
```

A private hop gets tagged `private: true` in the `hop` event and is
*never* sent to ip-api.com. Your home router's internal IP, corporate
VPN concentrators, internal-cloud transit — none of it goes to a
third party. This matters because the geo backend is a free public
service; assume it logs.

## Worked example

```
$ trace 1.1.1.1
> tracing route to 1.1.1.1 (1.1.1.1)

   1  192.168.1.1       1.86 ms  [local]
   2  90.191.8.3        2.88 ms
   3  194.126.123.2     2.70 ms
   5  1.1.1.1           3.03 ms  [final]

  · hop 2 located: Tallinn, Estonia
  · hop 3 located: Tallinn, Estonia
  · hop 5 located: South Brisbane, Australia

trace complete.
```

Five hops to Cloudflare in 3 ms. Hop 4 didn't reply — typical, and
not a problem. Hop 5's geo location reads "South Brisbane, Australia"
because that's where Cloudflare is incorporated; the actual server
serving the response is on the same continent as the requester. Use
`asn 1.1.1.1` to get the carrier (Cloudflare, AS13335); use
`geoip 1.1.1.1` with a local MMDB to cross-check the geo result
without round-tripping a third party.

## Output protocol

```
{"event":"start", "target":"…", "ip":"…"}
{"event":"hop",   "n":N, "ip":"…", "rtt_ms":N, "private":bool, "final":bool}*
{"event":"geo",   "n":N, "ip":"…", "city":"…", "country":"…", "lat":N, "lon":N}*
{"event":"geo",   "n":N, "ip":"…", "error":"…"}*
{"event":"done"}
```

`hop` events arrive in network order as MTR reports them. `geo`
events arrive asynchronously after the corresponding `hop`,
correlated by `n`. The `geo` event may carry an `error` field
instead of location data if the lookup failed (rate-limit, network
issue, no record for the IP) — the rest of the trace continues.

Filter for the final destination's geo with `jq`:

```
$ trace github.com -j | jq -r 'select(.event=="geo" and .n==(input_filename | length))'
```

Or strip all geo to get a pure path:

```
$ trace github.com -j | jq -r 'select(.event=="hop") | "\(.n)\t\(.ip)\t\(.rtt_ms)"'
```

## Limitations

- **Requires the system `mtr` binary** (`mtr-tiny` package on
  Debian/Ubuntu, `mtr` on macOS via Homebrew). Without it, the tool
  errors immediately and clearly.
- **Geo backend is `ip-api.com`, HTTP not HTTPS.** The lookups go in
  plaintext over the network. For privacy-sensitive traces use
  `--no-geo` and post-process captured hops with `geoip` against a
  local MMDB instead.
- **Anycast addresses geolocate to the registered owner**, not the
  actual edge serving you. Cloudflare → Brisbane; Google →
  Mountain View; Fastly → San Francisco. Read accordingly.
- **One probe per hop** (`mtr -c 1`). RTT measurements are
  single-shot; a hop with high jitter will read inconsistently
  between runs. Use classic `mtr` interactively if you need
  statistical reliability.
- **Max 30 hops.** Targets behind more than 30 hops of intermediate
  routing don't complete — rare in practice, since the global
  internet rarely exceeds ~25 hops.
- **IPv6 paths untested.** The tool resolves IPv4 first and prefers
  it; IPv6-only targets work in principle but the geo backend is v4-
  oriented and may return empty data.
- **No port specification.** Classic MTR can target TCP/UDP probes to
  specific ports — useful when ICMP is filtered. Cathedral's `trace`
  does ICMP only in v1.

## Authorized use

Traceroute is recon-grade and unremarkable on every network — packets
to a known destination, on a normal cadence. The authorized-testing
posture is the same as `ping`: target what you own or have permission
to probe.

**One privacy note specific to `trace`:** the geo lookup sends every
public hop IP to `ip-api.com`. For a trace from your laptop to
`github.com`, that's around ten public IPs telling a third party
"someone at $YOUR_IP just ran a trace toward this path." If that's
not acceptable for an engagement (or for personal reasons), use
`--no-geo` and feed the resulting IPs through `geoip` against a local
MaxMind database — Cathedral ships with one and `geoip` works
offline.

## Further reading

- [RFC 1393 — Traceroute Using an IP Option](https://www.rfc-editor.org/rfc/rfc1393)
- [`mtr` manual](https://www.bitwizard.nl/mtr/) — the underlying tool
- ip-api.com [terms and rate limits](https://ip-api.com/docs/legal)
- Related Cathedral commands: [`ping`](./ping.md) (per-hop reachability),
  [`geoip`](./geoip.md) (offline IP→location), [`whois`](./whois.md)
  (registry / owner lookup), [`asn`](./asn.md) (autonomous-system
  attribution), [`discover`](./discover.md) (when ICMP is filtered)
