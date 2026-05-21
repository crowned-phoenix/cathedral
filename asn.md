---
title: asn — BGP-table attribution for IPs and hostnames
command: asn
category: identification
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-20
related: [whois, dns, reverse-dns, geoip]
---

# `asn` — BGP-table attribution for IPs and hostnames

`asn` asks the global routing table *"who announces this address?"*
and returns the Autonomous System number, the announcing
organisation's name, the announced prefix, the regional internet
registry that allocated the prefix, and the country code on the
allocation record. Where [`whois`](whois.md) tells you who *owns*
an address (the registry's allocation record), `asn` tells you who
*announces* it (the operator actively routing it on the public
internet). The two often agree; when they disagree, the
disagreement is itself the signal.

Cathedral uses Team Cymru's DNS-based ASN service — no API key, no
local database, no rate limits beyond the recursive resolver's
own — and the lookup completes in a handful of DNS round-trips.

```
asn 8.8.8.8                                      # single IP
asn acme-supplies.example                        # hostname (resolved first)
asn 1.1.1.1 8.8.8.8 9.9.9.9                       # batch of IPs
asn 2606:4700::1111                              # IPv6 works the same way
```

## What it does

For each target Cathedral takes one of two paths:

- If the target is an IP literal (v4 or v6), look it up directly.
- If the target is a hostname, resolve it via the system resolver
  first, then look up the first returned address. The resolved IP
  is reported in a `resolved` event so you can see what was asked
  about.

The lookup itself is a TXT query against Team Cymru's `origin.asn.
cymru.com` zone (or `origin6.asn.cymru.com` for IPv6). The response
encodes the BGP origin record as pipe-delimited fields:
`ASN | BGP-prefix | CC | RIR | allocation-date`. Cathedral parses
those, then issues a second TXT query (`AS<num>.asn.cymru.com`) to
recover the human-readable AS name. The whole round-trip is two
small DNS queries; on a warm-cache resolver it returns in under
50 ms.

## What it answers

**Defender:** *"Who is actually carrying traffic for our brand
domain right now?"* Routing changes are operationally invisible
unless you look for them. A domain CNAMed to a CDN endpoint that
gets re-pointed to a different CDN provider shows up in `asn` as
the new origin AS — even before the DNS TTL flips for downstream
caches. Periodic `asn` snapshots against your own infrastructure
catch BGP-hijack incidents, CDN provider migrations, and
mistargeted DNS changes quickly.

**Recon (authorized testing only):** *"What hosting stack is this
target on?"* Web app at `acme-supplies.example`, IP behind it
announced by AS16509 (Amazon) — it's on AWS. Same IP announced by
AS54113 (Fastly) — it's on Fastly's CDN, which is in front of
something else. The AS name alone tells you the hosting layer; the
prefix tells you which provider allocation it sits in (Amazon's
`52.84.0.0/15` is CloudFront-specific). For larger targets the
mix of multiple announcing ASes across the asset footprint maps
the entire vendor stack.

**Investigation:** *"Is this IP being routed from where its
registry record claims?"* Whois says ARIN-allocated to a US
company; ASN says announced by a Russian AS. That mismatch is
worth attention — it can mean a recent transfer, leased
infrastructure, or a BGP hijack. The pattern of *legitimate*
mismatches is well-known (anycast CDN prefixes, multi-region
deployments); patterns that don't fit it deserve a closer look.

**Identification:** *"What category of infrastructure is this?"*
ASN-level attribution is the canonical input to most threat-intel
and abuse-handling pipelines. *Hosting provider* / *eyeball ISP*
/ *CDN edge* / *tor exit* / *cloud function backend* are all
distinguishable by their announcing ASes. A `asn` lookup is often
the first reach after seeing an unfamiliar IP in a log.

## How it works

### The BGP table and what an ASN is

The internet routes traffic between **autonomous systems** — large
network operators (ISPs, cloud providers, CDNs, enterprises with
their own multihomed connectivity) each operating one or more
**autonomous system numbers** (ASNs). The Border Gateway Protocol
(BGP) is how ASes tell each other which IP prefixes they can
reach: each operator announces "I have a route to prefix X via my
AS", and the global routing table is the union of all those
announcements. There are roughly 75,000 active ASNs as of 2026 and
roughly a million unique prefixes in the IPv4 table.

For any reachable IP, exactly one (occasionally two or three) AS
*announces* the most-specific prefix that contains it — the
**origin AS**. That's the AS that's actually responsible for
carrying traffic to that IP. The same IP block may have been
*allocated* to one organisation by a registry (visible via whois)
and *announced* by a different organisation in BGP — the
allocation record and the routing reality are independent.

`asn` queries the routing reality.

### Team Cymru's DNS-based ASN service

The global routing table is a fast-moving dataset — hundreds of
prefix changes per second — and most APIs that publish it require
authentication and have rate limits. Team Cymru (a non-profit
network research outfit) publishes the table as a public DNS zone,
which makes lookups free, cacheable, anycast-served, and
firewall-friendly:

```go
const (
    v4Zone = "origin.asn.cymru.com"
    v6Zone = "origin6.asn.cymru.com"
    asZone = "asn.cymru.com"
)
```

The IPv4 query format is the same reverse-octet form as
`in-addr.arpa` PTR lookups. For `8.8.8.8`:

```
4.3.2.1.origin.asn.cymru.com   →   TXT   "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
```

The IPv6 query uses reverse-nibble form (the same as `ip6.arpa`)
against the `origin6.asn.cymru.com` zone:

```
1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.6.0.6.2.origin6.asn.cymru.com
```

Both yield the same five fields, pipe-delimited. The AS name lookup
is a second TXT query against `asn.cymru.com`:

```
AS15169.asn.cymru.com   →   TXT   "15169 | US | arin | 2000-03-30 | GOOGLE, US"
```

Cathedral combines the two queries into a single user-facing
result.

### Reverse-octet IPv4, reverse-nibble IPv6

```go
func reverseQuery(ip net.IP) (string, string) {
    if v4 := ip.To4(); v4 != nil {
        return joinReversed([]string{
            byteDec(v4[3]), byteDec(v4[2]), byteDec(v4[1]), byteDec(v4[0]),
        }), v4Zone
    }
    v6 := ip.To16()
    var nibbles []string
    for i := 15; i >= 0; i-- {
        b := v6[i]
        nibbles = append(nibbles, string(hexDigits[b&0xf]))
        nibbles = append(nibbles, string(hexDigits[b>>4]))
    }
    return strings.Join(nibbles, "."), v6Zone
}
```

The IPv4 path mirrors the well-known PTR reverse-octet convention.
The IPv6 path emits 32 nibbles separated by dots — long, but
exactly the same shape as `ip6.arpa` PTR queries, which means any
resolver that handles reverse v6 DNS handles Cymru's v6 ASN
service without special configuration.

### Resolution chain: host → IP → origin → AS name

When the target is a hostname rather than an IP, Cathedral does an
A/AAAA lookup first:

```go
if ip == nil {
    ips, err := r.LookupIP(ctx, "ip", target)
    if err != nil || len(ips) == 0 {
        emit(event{"event": "miss", "target": target,
            "error": "could not resolve"})
        return
    }
    ip = ips[0]
    emit(event{"event": "resolved", "target": target,
        "ip": ip.String()})
}
```

Only the first returned address is looked up. For round-robin
domains (multiple A records pointing at different prefixes), only
the first slice of the rotation is examined per query — if you
need attribution for every backend, pass each IP explicitly:

```
asn $(dns acme-supplies.example -j |
    jq -r 'select(.event=="record" and .type=="A") | .value')
```

### Multi-AS origin

A small but real fraction of prefixes are announced from more than
one AS at once. This is normal for:

- **Anycast deployments** where the same IP block is announced
  from many geographically-distributed POPs — often by the same
  organisation under one ASN, but sometimes by different
  organisations cooperatively (some root DNS server operators do
  this).
- **Recent transfers** where the announcing AS is in the middle
  of changing and both the old and new ASes are temporarily
  announcing the same prefix.
- **Path-divergent leaks** where a downstream AS is mistakenly
  re-originating a prefix it transits.

The Cymru response in those cases is a space-separated ASN list in
the first field. Cathedral splits on space and looks up each AS
name separately:

```go
asnList := strings.Split(asnNum, " ")
for _, a := range asnList {
    nm, _ := lookupASName(ctx, r, a)
    asNames = append(asNames, "AS"+a+"  "+nm)
}
```

The result table shows every announcing AS on its own row, so the
shared origin is immediately visible. For an anycast prefix
operated by a single organisation across multiple ASNs the rows
share an organisational suffix; for a path-divergent leak the
rows often disagree on country or RIR, which is the diagnostic
hint.

### Why DNS-based, not WHOIS or HTTP API

Three reasons:

- **Caching.** DNS responses are cached at every layer between
  Cathedral and Cymru. A bulk `asn` sweep against many IPs in the
  same prefix returns the second-and-onwards results from local
  cache — no network round-trip. WHOIS over TCP/43 has no
  intermediate caching; HTTP APIs cache only if every layer
  cooperates.
- **Rate limits.** Cymru's DNS service has no per-source rate
  limit beyond what your recursive resolver enforces.
  WHOIS-over-TCP/43 to ARIN rate-limits aggressively (~30 queries
  per hour from a single source IP). Most ASN HTTP APIs require an
  account and impose tiered quotas.
- **Cathedral has no API-key surface.** Every Cathedral command
  runs without configuration on a fresh install. A DNS-based
  service that doesn't require credentials is a much better fit
  than a paid API endpoint.

The trade-off is that the Cymru service is best-effort with no SLA
— it occasionally has brief outages — and that the data lags the
real-time BGP table by minutes to hours. For incident-response use
where seconds-to-minutes BGP currency matters, RIPEstat's BGPlay
service is the right reach. For everyday attribution `asn` is
plenty current.

## What Cathedral doesn't do

A few deferred features worth flagging:

- **BGP path information.** Cymru's service returns the origin AS
  only — not the AS_PATH (the chain of ASes a route traverses) or
  community tags. Origin alone covers most attribution questions;
  for path-aware diagnostics (hijack detection, route-leak
  analysis), RIPEstat or `bgp.tools` is the right reach.
- **Historical attribution.** The Cymru service answers "who
  announces this now?" — not "who announced this last Tuesday?"
  For historical BGP data, RIPEstat's RIS archive goes back to
  1999.
- **Prefix-input mode.** Currently `asn` takes IPs and hostnames.
  A `--prefix=` flag for looking up *all* prefixes announced by a
  given AS is on the roadmap (Cymru exposes that view through a
  separate zone, `peeringdb.com` exposes it via API).
- **Multiple resolved IPs.** When a hostname resolves to multiple
  addresses, only the first is looked up. Iterate explicitly if
  you need attribution per backend.
- **Direct BGP-peer queries.** True real-time BGP data lives on
  the routers themselves and via looking-glass services. Cathedral
  doesn't speak BGP; it consumes Cymru's DNS-published snapshot.
- **Bulk Cymru WHOIS.** Cymru also offers a WHOIS-style bulk
  interface (TCP/43, multiple IPs per session). Cathedral uses the
  DNS interface only because single-target latency is better and
  the caching properties are better.

## Worked example

A single IP, then a hostname, then a mixed batch, then the
not-routed case.

### A single IP

```
operator@cathedral:~$ asn 8.8.8.8
> ASN lookup 1 target(s) via Team Cymru

[ 8.8.8.8 → 8.8.8.8 ]
  AS15169  GOOGLE, US
  prefix : 8.8.8.0/24
  origin : US / arin   (assigned 2023-12-28)

lookup complete.
```

Two lines of attribution: AS15169 (Google) announces `8.8.8.0/24`
out of ARIN-allocated space, with the most recent allocation
record dated 2023-12-28. Cross-referencing against `whois 8.8.8.8`:
the allocation record agrees (`Org: Google LLC (GOGL)`). The same
party that owns the block also announces it — the canonical
unremarkable case.

### A hostname

```
operator@cathedral:~$ asn acme-supplies.example
> ASN lookup 1 target(s) via Team Cymru

  acme-supplies.example → 104.21.18.42

[ acme-supplies.example → 104.21.18.42 ]
  AS13335  CLOUDFLARENET, US
  prefix : 104.16.0.0/13
  origin : US / arin   (assigned 2014-03-20)

lookup complete.
```

The `resolved` line (`acme-supplies.example → 104.21.18.42`) shows
exactly which address Cathedral asked about — useful when a
domain has multiple A records and you want to know which one ended
up examined. The site is fronted by Cloudflare (AS13335 announces
the `104.16.0.0/13` superprefix, which holds Cloudflare's anycast
HTTP frontends).

The hostname-vs-IP distinction matters for attribution: a single
hostname can resolve to different IPs at different times (DNS load
balancing) or from different network locations (geoDNS, anycast).
`asn` answers the question for the IP it actually got, not for the
domain in the abstract.

### Mixed batch

```
operator@cathedral:~$ asn 8.8.8.8 acme-supplies.example 2606:4700::1111
> ASN lookup 3 target(s) via Team Cymru

[ 8.8.8.8 → 8.8.8.8 ]
  AS15169  GOOGLE, US
  prefix : 8.8.8.0/24
  origin : US / arin   (assigned 2023-12-28)

  acme-supplies.example → 104.21.18.42
[ acme-supplies.example → 104.21.18.42 ]
  AS13335  CLOUDFLARENET, US
  prefix : 104.16.0.0/13
  origin : US / arin   (assigned 2014-03-20)

[ 2606:4700::1111 → 2606:4700::1111 ]
  AS13335  CLOUDFLARENET, US
  prefix : 2606:4700::/32
  origin : US / arin   (assigned 2011-11-01)

lookup complete.
```

Three targets, three result blocks. The two Cloudflare entries
(`acme-supplies.example` at the IPv4 anycast frontend and a direct
IPv6 query against `2606:4700::1111`) share an AS but sit in
different prefixes — `104.16.0.0/13` for v4, `2606:4700::/32` for
v6. Cloudflare publishes one set of anycast prefixes per address
family.

### Not routed

```
operator@cathedral:~$ asn 10.0.0.1 192.168.1.1 169.254.42.1
> ASN lookup 3 target(s) via Team Cymru

  10.0.0.1: no origin record
  192.168.1.1: no origin record
  169.254.42.1: no origin record

lookup complete.
```

RFC 1918 private space (`10.0.0.0/8`, `192.168.0.0/16`) and
link-local (`169.254.0.0/16`) are not announced in the global BGP
table — they're addressable inside individual networks only. The
Cymru service correctly returns NXDOMAIN for these and Cathedral
reports `no origin record`. The same response category applies to
DOCUMENTATION ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), CG-NAT (`100.64.0.0/10`), and any IP space that
isn't currently being announced anywhere.

## Output protocol

```
{"event":"start",    "targets":N,"service":"Team Cymru"}
{"event":"resolved", "target":"…","ip":"…"}                                *
{"event":"result",   "target":"…","ip":"…","asn":"…","prefix":"…",         *
                     "country":"…","rir":"…","date":"…","as":["AS… NAME"]}
{"event":"miss",     "target":"…","ip":"…","error":"…"}                    *
{"event":"done"}
{"event":"error",    "message":"…"}
```

`asn` in the result event is a space-separated string from Cymru
(typically one AS, occasionally several). `as` is the resolved
list with names — one entry per announcing AS.

Pipe to a quick provider distribution across a list of targets:

```
$ asn $(cat targets.txt) -j |
    jq -r 'select(.event=="result") | .as[0]' |
    awk '{print $2}' | sort | uniq -c | sort -rn
     18 CLOUDFLARENET,
     11 AMAZON-02,
      4 GOOGLE,
      3 FASTLY,
      2 AKAMAI-ASN1,
      1 OVH,
```

Detect provider migrations between two snapshots a week apart:

```
$ asn $(cat targets.txt) -j |
    jq -r 'select(.event=="result") | "\(.target)\t\(.as[0])"' |
    sort > /tmp/asn-today.tsv
# … one week later …
$ diff /tmp/asn-last-week.tsv /tmp/asn-today.tsv
< api.acme-supplies.example  AS16509 AMAZON-02, US
> api.acme-supplies.example  AS14618 AMAZON-AES, US
```

Cross-check ASN against whois for hijack detection:

```
$ ip=185.220.101.42
$ asn_org=$(asn "$ip" -j | jq -r 'select(.event=="result") | .as[0]')
$ whois_org=$(whois "$ip" -j |
    jq -r 'select(.event=="summary") | .data.org')
$ echo "BGP: $asn_org"
$ echo "WHOIS: $whois_org"
```

When the two strings name different organisations on the same IP,
that's the start of an investigation.

## Limitations

- **Snapshot lag.** Cymru's data is refreshed every few minutes
  from real-time BGP feeds. For an incident in progress (hijack,
  route leak, large-scale provider outage) the data may be 5–15
  minutes behind reality. For everyday attribution this is
  invisible.
- **No SLA.** The Cymru service is a free public utility. Rare
  outages are possible. The `error` event covers DNS failures
  generically; if you depend on `asn` for monitoring, treat the
  data source as best-effort.
- **First-IP-only resolution.** When a hostname has multiple A
  records, only the first is looked up. For per-IP attribution
  across all backends, query each IP explicitly (see the recipe
  above).
- **IPv6 nibble queries are long.** A v6 reverse-nibble FQDN is
  ~75 characters. A handful of misconfigured resolvers reject DNS
  names beyond 64 characters per label — the IPv6 path can
  silently fail in those environments. The IPv4 path doesn't have
  this issue.
- **No path information.** Cymru returns the origin AS only.
  AS_PATH, community attributes, and MED values are not in the
  response. For path-aware questions (which transit providers
  carry traffic between two ASes, where in the world traffic
  egresses) use a looking-glass or RIPEstat.
- **Country code is registry-claimed.** The CC field is the
  country code on the *RIR allocation record*, not where the
  prefix is physically routed. An anycast prefix announced from
  six continents still shows the single registry-assigned
  country.
- **No CDN-backend visibility.** When traffic reaches a CDN edge,
  the AS is the CDN's — the *origin* server behind the CDN is
  invisible to `asn`. CloudFront-fronted AWS workloads all
  attribute to AS16509 (or AS14618 for CloudFront-specific
  prefixes); the actual EC2 instance ASN sits behind the curtain.
- **Recently-transferred prefixes may show stale data.** A prefix
  that changed ASNs in the last hour or two may still show the
  old origin in Cymru's snapshot. Cross-check against
  RIPEstat for fresher data when timing matters.

## Authorized use

`asn` is **passive recon against a public dataset**. Every query
goes to Cymru's DNS service; the IP being attributed never sees
the activity. The global BGP table is published data by design —
every router on the public internet receives the same
announcements that Cymru republishes via DNS.

Two notes worth attaching:

**Your resolver sees what you ask.** Cymru's queries are
unencrypted DNS. A network operator between you and the recursive
resolver, or the recursive resolver itself, sees the IPs you're
asking about. For sensitive recon route through a DoH/DoT-enabled
resolver, or use Cymru's TCP/43 bulk WHOIS interface over a
trusted path.

**Volume.** Single queries are free of meaningful side-effect.
Bulk sweeps against many thousands of IPs are unremarkable to
Cymru (the service is designed for it) but may saturate your
local recursive resolver's cache or run into the resolver's own
rate limits. For very large lookups, query in batches with the
resolver's TTL window in mind, or switch to Cymru's bulk WHOIS
mode (not yet wired into Cathedral).

## Further reading

- [RFC 4271 — A Border Gateway Protocol 4 (BGP-4)](https://www.rfc-editor.org/rfc/rfc4271) — the inter-AS routing protocol
- [Team Cymru — IP to ASN Mapping service](https://team-cymru.com/community-services/ip-asn-mapping/) — the data source Cathedral queries
- [RIPEstat data API](https://stat.ripe.net/) — historical and path-aware BGP queries
- [bgp.tools](https://bgp.tools/) — interactive BGP explorer; complementary, web-based
- Related Cathedral commands: [`whois`](whois.md) (registry allocation — complements ASN origin),
  [`dns`](dns.md) (forward resolution — the input to attribution),
  [`reverse-dns`](reverse-dns.md) (PTR sweep — name layer to ASN's number layer),
  [`geoip`](geoip.md) (offline location attribution — pairs naturally with ASN org attribution)
