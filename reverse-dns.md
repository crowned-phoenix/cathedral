---
title: reverse-dns — PTR record sweep across a subnet
command: reverse-dns
category: discovery
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-15
related: [lan-scan, discover, dns, whois, asn]
---

# `reverse-dns` — PTR record sweep across a subnet

`reverse-dns` asks the DNS resolver "what's the hostname of this
IP?" for every address in a subnet, then reports the IPs that
answer. It's a passive sweep: nothing is sent to the targets
themselves — only to whichever DNS server your machine is
configured to talk to. Results reveal the *DNS-registered*
inventory of a network, which often differs from the *currently-
online* inventory in interesting ways.

```
reverse-dns                              # sweep local /24
reverse-dns --subnet=1.1.1.0/29
reverse-dns --subnet=10.0.0.0/24 --conc=64 --timeout=800
```

## What it does

For every address in the target subnet (`a.b.c.1` through
`a.b.c.254` for the default /24), Cathedral issues a PTR lookup
via the system resolver. PTR records map IP addresses back to
hostnames — the reverse of A/AAAA records, served from the
special `.in-addr.arpa.` zone. Cathedral reports any IP that
returns one or more names.

| Flag                  | Meaning                                  | Default   |
|-----------------------|------------------------------------------|-----------|
| `--subnet=X.Y.Z.0/24` | subnet to sweep (CIDR)                   | local /24 |
| `--conc=N`            | concurrent DNS queries                   | `32`      |
| `--timeout=MS`        | per-lookup timeout (ms)                  | `1500`    |

The default /24 is detected via the same UDP-dial trick `netinfo`
uses — derive the primary outbound IPv4, then build the /24
around it.

## What it answers

**Defender:** *"What hosts in my network are *registered* in
DNS?"* This is a subtly different question from *"what's online
right now"*. On a network running OpenWrt, dnsmasq, or any DHCP
server that also serves DNS, every DHCP lease becomes a PTR
record. The sweep finds devices that *had* a lease — even
phones currently in low-power mode, laptops that briefly joined
last week, IoT devices that drop off WiFi for hours. `lan-scan`
shows currently-responsive hosts; `reverse-dns` shows the union
of registered names. The diff between the two is often
revealing.

**Recon (authorized testing only):** *"What's the structure of
this network according to DNS?"* For external IP blocks owned by
a target, PTR records frequently leak organisational structure
that no active probe would reveal. Common patterns: `mail-`,
`vpn-`, `db-`, `jenkins-`, `staging-`, `prod-`. Cloud-managed
infrastructure gets even more verbose: `ec2-13-209-…compute.eu-
central-1.amazonaws.com` tells you region, IP class, and
provider in one record. *Passive recon* — you didn't touch the
target's machines, only its public DNS records.

**Investigation:** *"What's at this IP block?"* When triaging a
suspicious connection in a log, `reverse-dns --subnet=X.Y.Z.0/24`
on the source's prefix often reveals adjacent infrastructure
that names the owner — a single PTR might be uninformative, but
the cluster around it can be unmistakable.

**Identification:** *"Did this network change?"* PTR records are
stable enough that periodic snapshots compose well into a
baseline. The set of names in a /24 today vs a month ago is a
real signal — new entries, removed entries, renamed roles all
correspond to operational changes.

## How it works

### PTR records: the reverse zone

DNS has two halves. The forward zone maps names to IPs
(`example.com → 93.184.216.34`); the reverse zone maps IPs back
to names. The mechanics: for IP `1.2.3.4`, the resolver queries
`4.3.2.1.in-addr.arpa.` (octets reversed, special zone suffix),
expecting a PTR record. The owner of the IP block is responsible
for setting these — DNS does not synthesise them automatically.

That ownership requirement is why coverage varies so wildly:

- **Local DHCP-as-DNS** (OpenWrt, dnsmasq, Active Directory,
  pfSense): every leased address gets a PTR for the lease
  duration. Coverage is essentially 100% of registered devices.
- **Major cloud providers**: AWS, GCP, Azure auto-generate
  descriptive PTRs (`ec2-…`, `vm-…`, `vnet-…`). Coverage is
  usually 100% but the names are infrastructural, not
  organisational.
- **Most production networks**: sparse. A datacentre might set
  PTRs for mail servers (to pass SPF/RDNS checks), VPN
  endpoints, and load balancers — and leave the rest empty.
- **Home and small-office WANs**: typically just the ISP's
  default name (`1.2.3.4 → static-1-2-3-4.isp.tld`); useful for
  attribution, useless for inventory.

The cookbook reader should expect *any* of these patterns when
sweeping an unfamiliar subnet.

### The sweep loop

The whole tool is essentially this:

```go
for _, ip := range hosts {
    sem <- struct{}{}
    go func(ip string) {
        defer func() { <-sem }()
        ctx, cancel := context.WithTimeout(context.Background(),
            time.Duration(*timeoutFlag)*time.Millisecond)
        defer cancel()
        names, err := net.DefaultResolver.LookupAddr(ctx, ip)
        if err != nil || len(names) == 0 { return }
        emit(event{"event":"host", "ip":ip, "names":names})
    }(ip)
}
```

`net.DefaultResolver.LookupAddr` is the system resolver — your
machine's configured DNS server handles the lookup. Cathedral
issues the queries; it doesn't make DNS decisions. That means
results depend on which resolver `/etc/resolv.conf` points to:

- Local resolver (`127.0.0.53` from systemd-resolved on most
  modern Linux desktops): forwards to upstream, often caches
  aggressively.
- Network resolver (`192.168.1.1` on a typical home router):
  serves local PTR records itself plus forwards external
  queries.
- Public resolver (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`): always
  external, never sees local PTR records.

The cookbook entry for [`dns`](dns.md) covers explicit resolver
selection if you want to choose deliberately.

### Concurrency and timing

Default is 32 concurrent lookups with a 1500 ms timeout each.
The timeout is meaningfully longer than `ping`'s or `discover`'s
because DNS responses can be slow on cold caches — first query
against a resolver pays the full upstream round-trip; subsequent
queries return from cache.

A full /24 sweep at default settings completes in 5–15 seconds
depending on resolver speed and how many cache misses occur.
The 30-second-shape of larger subnets is roughly:

| Subnet | Hosts   | Approx wall time at defaults |
|--------|---------|------------------------------|
| /24    | 254     | 5–15 s                       |
| /22    | 1,022   | 30–60 s                      |
| /20    | 4,094   | 2–4 min                      |
| /16    | 65,534  | 30–60 min                    |

Raise `--conc` for larger subnets if your resolver can handle
it; reduce `--timeout` if you'd rather miss slow responders than
wait.

### What Cathedral *doesn't* do

The roadmap entry for the broader `dns rev` subcommand adds
**FCrDNS** (Forward-Confirmed Reverse DNS): for each PTR result,
resolve the returned hostname back to an A record and confirm
the original IP appears in the answer set. Mismatches are a
finding — a PTR claiming `mail.example.com` whose A record
doesn't include the queried IP is a misconfigured or stale
record, often a spam-filtering tell.

`reverse-dns` v1 reports the raw PTR result without
forward-confirming. That's a deliberate simplification — the
common case (local LAN inventory, cloud provider attribution)
doesn't need FCrDNS, and the tool stays small and fast. For
audit work where PTR integrity matters, the planned `dns rev`
subcommand will be the right reach.

## Worked example

Two contrasting subnets show the spread of what PTR sweeps
actually find.

### Local home network

```
$ reverse-dns
> PTR sweep 192.168.1.0/24 — 254 hosts (conc 32, timeout 1500ms)

  192.168.1.1     OpenWrt.lan
  192.168.1.2     TeliaLXC.lan
  192.168.1.103   Galaxy-S22.lan
  192.168.1.170   guido.lan
  192.168.1.176   crowned-phoenix.lan
  192.168.1.214   JC.lan
  192.168.1.231   iPhone.lan

sweep complete — 7 PTR records / 254 hosts
```

Seven devices — and three of them
(`Galaxy-S22.lan`, `JC.lan`, plus one more on a soft-quiet
interface) didn't show up in the equivalent `lan-scan` sweep
because they weren't actively responding to ICMP at the moment
of probe. PTR records persist while the lease does, even when
the device is asleep, off WiFi, or filtering ICMP.

This is the cookbook lesson: **PTR sweep and ICMP sweep see
different things**. The union of the two is the closest you'll
get to "everyone who's been on this network recently".

### Cloudflare's public DNS prefix

```
$ reverse-dns --subnet=1.1.1.0/29
> PTR sweep 1.1.1.0/29 — 6 hosts (conc 32, timeout 1500ms)

  1.1.1.1   one.one.one.one
  1.1.1.2   security.cloudflare-dns.com
  1.1.1.3   family.cloudflare-dns.com

sweep complete — 3 PTR records / 6 hosts
```

Three documented services in adjacent IPs — Cloudflare's public
resolver (`1.1.1.1`), their malware-blocking variant (`.2`), and
their family-safe variant (`.3`). The /29 holds eight addresses;
`.0` is the network address and `.7` is broadcast, the other
five (`.4` through `.6` and the network/broadcast pair) have no
PTRs because no service answers there.

The names themselves are self-documenting — Cloudflare
deliberately publishes descriptive PTR records for these IPs.
That's the *good* case. Most public IP ranges look more like:

```
  203.0.113.42  static-203-0-113-42.isp.example.tld
  203.0.113.43  static-203-0-113-43.isp.example.tld
```

— uniform, ISP-generated, useless for attribution beyond
"someone at this ISP."

## Output protocol

```
{"event":"start",    "subnet":"…","hosts":N,"conc":N,"timeout":N}
{"event":"progress", "done":N,"total":N,"found":N}*
{"event":"host",     "ip":"…","names":[…]}*
{"event":"done",     "total":N,"found":N}
```

`names` is an array because a single IP can have multiple PTR
records — relatively rare but valid. Trailing dots on canonical
names are stripped (`mail.example.com.` becomes
`mail.example.com`).

Pipe to roles-summary across a target's block:

```
$ reverse-dns --subnet=203.0.113.0/24 -j |
    jq -r 'select(.event=="host") | .names[0]' |
    grep -oP '^[a-z]+(?=-)' |
    sort | uniq -c | sort -rn
     18 db
     12 web
      4 mail
      2 vpn
```

Diff two sweeps a week apart to spot infrastructure changes:

```
$ reverse-dns --subnet=10.0.0.0/24 -j |
    jq -r 'select(.event=="host") | "\(.ip)\t\(.names[0])"' |
    sort > /tmp/ptr-today.tsv

# … one week later …

$ diff /tmp/ptr-last-week.tsv /tmp/ptr-today.tsv
```

## Limitations

- **PTR coverage is owner-controlled and often sparse.** A /24
  with zero PTR results doesn't mean the network is empty — it
  means the owner didn't set reverse records. For attribution of
  silent networks, [`whois`](whois.md) and [`asn`](asn.md) reach
  further.
- **Result depends on which resolver you ask.** A query through
  your home router sees that router's local zone; the same query
  through `1.1.1.1` doesn't. Cathedral uses the system resolver;
  for explicit choice, see [`dns`](dns.md).
- **No forward-confirmation (FCrDNS).** A PTR record can claim
  anything; Cathedral takes it at face value. For mismatched
  records and integrity checks, the planned `dns rev` subcommand
  is the right tool.
- **Slow on large subnets.** A /16 at default settings takes
  ~45 minutes. Raise `--conc` substantially or sweep in chunks.
- **IPv4 only.** PTR for IPv6 lives in `.ip6.arpa.` with a
  different reverse-octet layout; Cathedral v1 doesn't sweep v6.
  Individual v6 PTR lookups via [`dns`](dns.md) work fine.
- **System resolver caches.** Re-running `reverse-dns` against
  the same subnet within the resolver's TTL window returns from
  cache. Timings are not repeatable; results are.
- **Some resolvers rate-limit PTR queries.** 32-concurrent
  sweeps against public resolvers can trip server-side limits —
  occasional timeouts during a sweep often mean the resolver
  throttled, not that the target IP lacks a PTR. Drop
  `--conc=8` if you suspect this.

## Authorized use

`reverse-dns` is **passive recon**: every query goes to a DNS
resolver, never to the IP being asked about. The risk profile is
the same as running `host` or `dig` repeatedly — DNS queries are
unremarkable and the targets of the sweep never see the activity.

Three notes worth attaching:

**Your resolver sees what you ask.** The sweep is invisible to
the target subnet but very visible to whichever DNS server
handles your queries. Local home router, corporate DNS, ISP
resolver, public service — pick deliberately based on what
you're comfortable showing up in their query logs.

**Wide sweeps look like reconnaissance.** A /16 PTR sweep
against a target's allocation produces 65k queries against
whatever resolver you used. Public DNS providers don't generally
treat this as hostile, but some corporate resolvers will. If
you're auditing infrastructure across an authorised engagement,
use the target's own resolver or a public one — not your
employer's.

**The data is genuinely public.** Reverse DNS records are
authoritative-published data. Reading them is no more
remarkable than reading the same target's forward DNS. Cathedral
collates a view of public records, nothing more.

## Further reading

- [RFC 1035 §3.5 — IN-ADDR.ARPA domain](https://www.rfc-editor.org/rfc/rfc1035#section-3.5) — the reverse-zone mechanism
- [RFC 8499 §2 — Forward-Confirmed Reverse DNS](https://www.rfc-editor.org/rfc/rfc8499) — what FCrDNS adds
- Related Cathedral commands: [`lan-scan`](lan-scan.md) (active ICMP sweep — complementary, different visibility),
  [`discover`](discover.md) (TCP-ping sweep — finds hosts that filter ICMP but answer a service),
  [`dns`](dns.md) (forward DNS queries, explicit resolver choice),
  [`whois`](whois.md) (registry / owner attribution for IPs without PTR),
  [`asn`](asn.md) (autonomous-system attribution)
