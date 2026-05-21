---
title: dns — forward DNS lookups for A/AAAA/MX/NS/TXT/CNAME
command: dns
category: dns-identity
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-20
related: [reverse-dns, dnsbl, spf, dmarc, mx-rep, whois, asn]
---

# `dns` — forward DNS lookups for A/AAAA/MX/NS/TXT/CNAME

`dns` asks a resolver six questions about a domain in one shot and
renders the answers as a single table. Where `host` or `dig` give you
one record type per invocation, `dns` lays out the whole identity of
a domain — addresses, mail exchangers, authoritative name servers,
text records, canonical aliases — in the order you read it.

```
dns example.com                                # all six types via system resolver
dns example.com --types=MX,TXT                 # just mail + text
dns example.com --server=1.1.1.1               # bypass local DNS
dns _dmarc.example.com --types=TXT             # query a labelled subdomain
```

## What it does

For a given domain, Cathedral issues lookups for each of six record
types in sequence — `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME` — and
streams the results into a table grouped by type. Each section header
shows the record count; sections with no answers render a single
em-dash row so the absence is visible rather than implicit.

| Flag             | Meaning                                | Default     |
|------------------|----------------------------------------|-------------|
| `--types=A,…`    | comma-separated subset of record types | all six     |
| `--server=X`     | resolver to use (`host[:port]`)        | system      |

Without `--server`, Cathedral asks Go's `net.DefaultResolver`, which
follows your OS DNS configuration — `/etc/resolv.conf`,
systemd-resolved, `/etc/hosts`, and any local stubs in between. With
`--server=1.1.1.1`, queries skip the OS path entirely and dial UDP/53
on the named host directly. The distinction matters more often than
people expect; see *Resolver selection* below.

## What it answers

**Defender:** *"What does my domain say about itself?"* The DNS
records you publish describe you to the rest of the internet — what
addresses serve your traffic, who handles your mail, who can sign
mail on your behalf (SPF, DKIM), what you've claimed ownership of
(verification tokens). `dns` produces the same view an attacker
sees at the start of a reconnaissance pass. Reading your own DNS the
way a stranger reads it surfaces things that drift out of sync over
time — a stale SPF entry pointing at a vendor you no longer use, an
NS record still listing a name server from a migration two years
ago, a CNAME shadowing an A record that was meant to take over.

**Recon (authorized testing only):** *"What's the operational
surface of this domain?"* MX records identify the mail provider; NS
records identify the DNS provider; A/AAAA records identify the
hosting provider or CDN. TXT records frequently leak third-party
relationships — `google-site-verification=…`, `MS=ms…`,
`atlassian-domain-verification=…` each name a service the
organisation uses. Cathedral renders all of them as one table so the
relationship pattern is legible at a glance.

**Investigation:** *"Is this domain claiming to be what it says?"*
Phishing domains often have mismatched signals: an MX record at a
mailbox provider that doesn't match the brand, a TXT record claiming
verification with a service the real organisation doesn't use, a
CNAME chain pointing at unrelated infrastructure. The full record
table makes mismatches obvious; per-type queries hide them.

**Identification:** *"What infrastructure does this domain run
on?"* The combination of NS, MX, and TXT records typically pins
down hosting / mail / SaaS vendors with high precision. A domain on
Cloudflare NS records, Fastmail MX, and Google verification tokens
has a particular vendor profile; a domain on AWS Route 53 NS, Amazon
SES MX, and Atlassian verification has another. The table view is
the input to that pattern-matching.

## How it works

### The six record types

DNS has dozens of record types. Cathedral queries the six that
account for nearly all everyday questions about a domain:

- **A** — IPv4 address. Most domains publish at least one; CDN-fronted
  domains publish four or more for round-robin balancing.
- **AAAA** — IPv6 address. Same semantics as A, different address
  family. Increasingly common; absent from a surprising number of
  small-business domains.
- **MX** — mail exchanger. Lists the hosts that accept mail for the
  domain, with a priority (lower = preferred). A domain with no MX
  records cannot receive mail; a domain with one MX of `0 .` is
  asserting it refuses mail (see *Null MX* below).
- **NS** — name server. Lists the authoritative DNS servers for the
  domain. These are the servers your resolver eventually asks if it
  can't answer from cache.
- **TXT** — arbitrary text. Originally for free-form notes; now
  almost entirely repurposed for machine-readable metadata. SPF
  policies, DKIM keys, DMARC policies (on the `_dmarc` subdomain),
  domain-verification tokens, and ad-hoc `_acme-challenge` entries
  all live here.
- **CNAME** — canonical name. An alias that says *"resolve this
  name as if it were that name"*. Apex (`example.com`) domains can't
  carry CNAMEs per RFC, but subdomains often do — `www.example.com`
  CNAMEd to a CDN endpoint is the canonical pattern.

Two notable omissions: **SRV** records (used by Active Directory,
Jabber/XMPP, and SIP for service discovery) and **CAA** records (used
by certificate authorities to determine who's allowed to issue
certs). Both are deferred to the broader `dns` subcommands on the
roadmap — see *What Cathedral doesn't do* below.

### The query kernel

Each record type has a dedicated query function. The pattern is the
same for all six:

```go
func queryA(ctx context.Context, r *net.Resolver, domain string) {
    ips, err := r.LookupIP(ctx, "ip4", domain)
    if err != nil {
        emit(event{"event": "section", "type": "A", "count": 0})
        emit(event{"event": "error",   "type": "A", "message": err.Error()})
        return
    }
    emit(event{"event": "section", "type": "A", "count": len(ips)})
    for _, ip := range ips {
        emit(event{"event": "record", "type": "A", "value": ip.String()})
    }
}
```

The lookup is synchronous — Cathedral waits for each type to
complete before starting the next, so sections arrive in a
predictable order. That ordering is what lets the renderer compose a
table: each `section` event opens a logical group of rows, and the
`record` events that follow belong to it. The Go standard library's
`net.Resolver` handles wire format, retries, and timeout; Cathedral
issues semantic queries and labels the results.

### Resolver selection

The default resolver path is Go's `net.DefaultResolver`, which
delegates to the OS:

```go
func makeResolver(server string) *net.Resolver {
    if server == "" {
        return net.DefaultResolver
    }
    addr := server
    if !strings.Contains(addr, ":") {
        addr = addr + ":53"
    }
    return &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
            d := net.Dialer{Timeout: 3 * time.Second}
            return d.DialContext(ctx, "udp", addr)
        },
    }
}
```

When `--server` is set, Cathedral builds a fresh resolver with
`PreferGo: true` (use Go's own DNS client, not the C library) and a
`Dial` function that ignores the requested network/address and
substitutes the chosen server. Every lookup made through this
resolver goes to UDP/53 on that host, regardless of `/etc/resolv.conf`.

The choice matters in three common situations:

- **Split-horizon zones.** A domain often resolves differently from
  inside its corporate network than from outside — internal hosts
  (`mail.corp.example.com`) live in a private zone that's only
  visible to internal resolvers. `dns example.com` from a laptop on
  the corporate network sees the internal view; the same query with
  `--server=1.1.1.1` sees what the public internet sees. Querying
  both is the fastest way to map the split-horizon surface.

- **mDNS / `.local`.** On Linux desktops with Avahi or
  systemd-resolved, `*.local` queries are answered over multicast
  DNS by hosts on the LAN, not by `/etc/resolv.conf`. The system
  resolver knows this; a public resolver doesn't. If you're
  debugging "why does `mybox.local` work locally but not from the
  VPN", `dns mybox.local --server=1.1.1.1` returns `no_records` and
  the answer becomes obvious.

- **Caching effects.** A response from `127.0.0.53` may be cached
  locally for the record's TTL; a fresh query against `1.1.1.1`
  is the public resolver's idea of "current", which itself may be
  cached for some time. Neither is more authoritative than the
  domain's own NS, but the difference between them is sometimes the
  signal you want.

### Null MX (RFC 7505)

A small but informative edge case. Some domains publish exactly one
MX record with priority 0 and hostname `.`:

```
example.com.   MX   0   .
```

This is the *null MX* per RFC 7505 — an explicit declaration that
the domain does not accept mail. Common publishers: parked domains,
brand-protection registrations, infrastructure-only zones
(`cdn.example.com`, `api.example.com`), and the IANA-reserved
example domains (`example.com`, `example.org`, `example.net`).

Cathedral surfaces this case explicitly. The Go side flags the
record:

```go
if m.Host == "." {
    emit(event{
        "event":    "record",
        "type":     "MX",
        "value":    "",
        "priority": int(m.Pref),
        "null":     true,
    })
    continue
}
```

…and the renderer substitutes `. (null MX — domain refuses mail)` in
the VALUE column. Without this treatment the row would read as a
priority-0 record with an empty hostname, which is visually
indistinguishable from a malformed record. The annotation is the
difference between "this looks broken" and "this is deliberate".

### Streaming and ordering

The Go binary writes one JSON event per line and the Flutter renderer
consumes them as they arrive. Within a section, records appear in the
order the resolver returned them — for A records that's effectively
arbitrary (the resolver typically rotates the order on each query for
load-balancing reasons), for NS and MX records it's whatever order
the authoritative server published. Cathedral preserves that order
rather than sorting; if a record arrangement matters to you, sort
externally.

Between sections, types appear in the order specified by `--types`
(or the default `A,AAAA,MX,NS,TXT,CNAME` order if unspecified). The
typewriter cadence in the renderer is purely cosmetic — it doesn't
delay the lookups themselves, only the rate at which already-arrived
records are painted to the console.

### Caching considerations

DNS responses carry a TTL (time-to-live) that tells caching resolvers
how long to remember the answer. Cathedral doesn't display TTL — Go's
high-level `LookupIP` / `LookupMX` / `LookupTXT` calls return the
values without the TTL — but the TTL is the reason `dns` is not
repeatable as a *measurement* tool. The first query of the day
against a long-TTL domain pays a full upstream lookup; the second
returns instantly from cache; the third does the same until the TTL
expires.

For repeatable measurements — *how long does it take to resolve this
domain from a cold cache?* — `dig +trace` is the right tool. `dns`
is the right tool for *what does this domain say about itself right
now*, which is what most operators most often want.

## What Cathedral doesn't do

A few deferred features worth flagging:

- **DNSSEC validation.** Cathedral takes the resolver's answer at
  face value. A DNSSEC-validating resolver (most major public
  resolvers, plus systemd-resolved when configured for it) returns
  `SERVFAIL` on validation failure, which appears as an error
  event — but Cathedral does not display the AD (authenticated-data)
  bit on successful responses, so you can't tell from the table
  whether the answer was DNSSEC-validated or not. The planned `dns
  --dnssec` flag will surface this.

- **SRV and CAA records.** Both are useful in specific contexts —
  SRV for service discovery, CAA for certificate-authority
  authorisation — but neither is part of everyday domain inspection.
  Planned as `--types=SRV,CAA` once the renderer supports the
  additional columns those records need (port and weight for SRV,
  tag and flag for CAA).

- **ANY queries.** Some older recipes suggest a single ANY query to
  fetch all record types at once. Modern resolvers — Cloudflare,
  Google, Quad9 — return `HINFO RFC8482` rather than honouring ANY,
  on the rationale that ANY queries enable amplification attacks and
  the cache-only response is misleading. Cathedral does six discrete
  queries by design.

- **PTR records.** The reverse lookup is its own command —
  [`reverse-dns`](reverse-dns.md) — because the sweep semantics are
  different from a single-domain inspection.

- **Authoritative-server queries.** Cathedral always asks a recursive
  resolver; it doesn't talk to a domain's own NS records directly.
  For authoritative-only views (useful when chasing TTL discrepancies
  or comparing what NS servers actually publish vs what resolvers
  return), `dig @ns1.example.com example.com` remains the right
  tool. The planned `dns --auth` flag will pick an NS from the NS
  response and re-query through it for cross-comparison.

## Worked example

A domain with rich DNS, then a contrasting domain that refuses mail.

### A typical operational domain

```
operator@cathedral:~$ dns acme-supplies.example
> querying DNS for acme-supplies.example (via system resolver)

[ DNS · acme-supplies.example ]
──────────────────────────────────────────────────────────────────
  TYPE     PRIO  VALUE
  ─────   ────  ──────────────────────────────────────────────────
  A             104.21.42.18
  A             172.67.198.204
  ─
  AAAA          2606:4700:3036::6815:2a12
  AAAA          2606:4700:3037::ac43:c6cc
  ─
  MX        10  inbound.fastmail.com
  MX        20  inbound2.fastmail.com
  ─
  NS            april.ns.cloudflare.com
  NS            sasha.ns.cloudflare.com
  ─
  TXT           v=spf1 include:spf.messagingengine.com -all
  TXT           google-site-verification=Vp7nQs8YkqLh2RbXc9zJ
  TXT           atlassian-domain-verification=hf2p9Xr4Lc3vBa
  ─
  CNAME         —
──────────────────────────────────────────────────────────────────
11 records · 5/6 types · query complete
```

The four-line table reads as a vendor stack:

- **Cloudflare** in front of the website (`104.21.…`, `172.67.…`
  are Cloudflare's anycast prefixes; the NS pair `*.ns.cloudflare.com`
  confirms it).
- **Fastmail** for mail (`inbound.fastmail.com` MX, SPF includes
  `spf.messagingengine.com` which is Fastmail's outbound infrastructure).
- **Google Workspace** for collaboration (`google-site-verification=…`
  is the token proving domain ownership during Workspace setup).
- **Atlassian** for issue tracking / wiki (`atlassian-domain-verification=…`
  serves the same role for Jira / Confluence).

No CNAME at the apex — RFC-correct, since apex CNAMEs aren't
allowed. CNAMEs appear when you query subdomains:
`dns www.acme-supplies.example` would typically show
`www → acme-supplies.example` or `www → some-cdn.net`.

### A domain that refuses mail

```
operator@cathedral:~$ dns example.com
> querying DNS for example.com (via system resolver)

[ DNS · example.com ]
──────────────────────────────────────────────────────────────────
  TYPE     PRIO  VALUE
  ─────   ────  ──────────────────────────────────────────────────
  A             93.184.215.14
  ─
  AAAA          2606:2800:21f:cb07:6820:80da:af6b:8b2c
  ─
  MX         0  . (null MX — domain refuses mail)
  ─
  NS            a.iana-servers.net
  NS            b.iana-servers.net
  ─
  TXT           v=spf1 -all
  TXT           _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9
  ─
  CNAME         —
──────────────────────────────────────────────────────────────────
8 records · 5/6 types · query complete
```

The MX row is the headline finding — IANA explicitly publishes a
null MX for the example domains, asserting that `example.com` does
not accept mail. The SPF record (`v=spf1 -all`) makes the same
declaration on the outbound side: no host is authorised to send mail
*as* `example.com`. Both records together are belt-and-braces; either
alone would suffice.

The second TXT record is a Cloudflare domain-verification token,
left over from a previous transfer or testing. It's harmless but
illustrates a real-world pattern: TXT records accumulate over the
lifetime of a domain and rarely get cleaned up. A `dns` sweep is
often the moment someone discovers a verification token for a
service they stopped using two years ago.

### Bypassing the local resolver

When local DNS is doing something unexpected, the `--server` flag
short-circuits the OS path:

```
operator@cathedral:~$ dns intranet.corp.example --server=1.1.1.1
> querying DNS for intranet.corp.example (via 1.1.1.1)

[ DNS · intranet.corp.example ]
──────────────────────────────────────────────────────────────────
  TYPE     PRIO  VALUE
  ─────   ────  ──────────────────────────────────────────────────
  A             —
  ─
  AAAA          —
  ─
  MX            —
  ─
  NS            —
  ─
  TXT           —
  ─
  CNAME         —
──────────────────────────────────────────────────────────────────
0 records · 0/6 types · query complete
```

Empty across the board from `1.1.1.1`. Re-run without `--server`
from the same machine and the records appear — confirming that the
zone is internal-only. The same diagnostic pattern works for
mDNS hosts (`*.local`), `/etc/hosts` entries, and corporate
split-horizon names.

### Targeted queries

For a quick look at just one or two types, the `--types` flag
suppresses the rest:

```
operator@cathedral:~$ dns _dmarc.acme-supplies.example --types=TXT
> querying DNS for _dmarc.acme-supplies.example (via system resolver)

[ DNS · _dmarc.acme-supplies.example ]
──────────────────────────────────────────────────────────────────
  TYPE     PRIO  VALUE
  ─────   ────  ──────────────────────────────────────────────────
  TXT           v=DMARC1; p=reject; rua=mailto:dmarc@acme-supplies.example; adkim=s; aspf=s
──────────────────────────────────────────────────────────────────
1 record · 1/1 types · query complete
```

DMARC policies live on the `_dmarc` subdomain by convention; this
one declares `p=reject` (mail failing DMARC alignment should be
rejected outright) with strict alignment on both DKIM and SPF.
That's the most aggressive DMARC posture a domain can publish, and
it's the right one for domains that send transactional mail.

For DKIM keys, the equivalent pattern is
`dns selector._domainkey.acme-supplies.example --types=TXT` — DKIM
selectors live on per-key subdomains rather than at the apex.

## Output protocol

```
{"event":"start",      "domain":"…","server":"","types":[…]}
{"event":"section",    "type":"A|AAAA|MX|NS|TXT|CNAME","count":N}
{"event":"record",     "type":"…","value":"…"}                    # most types
{"event":"record",     "type":"MX","value":"…","priority":N}      # MX
{"event":"record",     "type":"MX","value":"","priority":0,"null":true}  # null MX
{"event":"no_records", "type":"…"}                                # empty section
{"event":"error",      "type":"…","message":"…"}                  # query failed
{"event":"done"}
```

`section` arrives before any records of that type, carrying a `count`
field — the renderer uses this to show `(2)` next to the section
header without waiting for all records to stream in. `count` is `0`
for sections that have no records *or* that errored.

Pipe to count records by type:

```
$ dns acme-supplies.example -j |
    jq -r 'select(.event=="record") | .type' |
    sort | uniq -c | sort -rn
      3 TXT
      2 NS
      2 MX
      2 AAAA
      2 A
```

Compare two domains' MX stacks:

```
$ for d in domain-a.example domain-b.example; do
    echo "=== $d ==="
    dns "$d" --types=MX -j |
        jq -r 'select(.event=="record") | "\(.priority)\t\(.value)"'
  done
```

Audit your own domain for DMARC alignment:

```
$ dns _dmarc.mydomain.example --types=TXT -j |
    jq -r 'select(.event=="record") | .value' |
    grep -oE 'p=(none|quarantine|reject)'
p=reject
```

## Limitations

- **System-resolver caching is invisible.** Cathedral can't tell you
  whether an answer came from cache or from a fresh upstream lookup.
  For TTL-aware diagnostics, use `dig +trace` or `delv` directly.
- **TTL is not displayed.** Go's `net.Resolver` returns values
  without TTL; surfacing it requires dropping to a wire-format library
  like `miekg/dns`. Deferred until the broader `dns` subcommand set.
- **No DNSSEC AD-bit surfacing.** Validation happens in the resolver;
  Cathedral renders whatever the resolver returns and doesn't expose
  the authenticated-data bit. Planned for `dns --dnssec`.
- **Six types only.** SRV, CAA, NAPTR, SVCB/HTTPS, and DNSKEY are
  out of scope for v1. Use `dig` for those.
- **No CNAME chasing.** If `www.example.com` is a CNAME to
  `cdn.example.net` which is a CNAME to `actual-origin.example.org`,
  Cathedral reports the first hop only. `dig` follows the chain
  fully; `dns +chain` is planned.
- **UDP only, no TCP fallback.** Truncated responses (DNS-over-UDP
  is limited to 512 bytes without EDNS0) may produce incomplete
  results for domains with very large TXT records or many NS records.
  The Go resolver does fall back to TCP in some configurations, but
  the behaviour is not deterministic across platforms. Use `dig +tcp`
  for definitive results on hot-DNS domains.
- **No reverse lookups.** `dns 1.2.3.4` queries the domain `1.2.3.4`
  literally and returns nothing useful; use [`reverse-dns`](reverse-dns.md)
  for PTR lookups.

## Authorized use

`dns` is **passive recon**: every query goes to a DNS resolver,
never to the target's own servers (with the partial exception of
`--server=<their-ns>`, which is still answering on its public
authoritative port and is no different from any other resolver
calling it). DNS queries are unremarkable internet traffic; the
target sees nothing on its application infrastructure.

Two notes worth attaching:

**Your resolver sees what you ask.** A `dns` sweep is invisible to
the target but very visible to whichever DNS server handles your
queries. Local home router, corporate DNS, ISP resolver, public
service — pick deliberately based on what you're comfortable showing
up in their query logs. For sensitive recon, route through a public
DoH/DoT-enabled resolver via `--server=1.1.1.1` or similar.

**The data is genuinely public.** Forward DNS records are
authoritative-published data — the domain owner deliberately put
them there, intending them to be served to anyone who asks. Reading
them is no more remarkable than reading the same target's website.
Cathedral collates a view of public records, nothing more.

## Further reading

- [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035) — the foundational DNS spec
- [RFC 7505 — A "Null MX" No Service Resource Record for Domains That Accept No Mail](https://www.rfc-editor.org/rfc/rfc7505) — the null MX convention
- [RFC 7208 — Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208) — TXT-record-based outbound mail authorisation
- [RFC 6376 — DomainKeys Identified Mail (DKIM) Signatures](https://www.rfc-editor.org/rfc/rfc6376) — TXT-record-based mail signing keys
- [RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489) — TXT-record-based alignment policy
- [RFC 8482 — Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY](https://www.rfc-editor.org/rfc/rfc8482) — why ANY queries are discouraged
- Related Cathedral commands: [`reverse-dns`](reverse-dns.md) (PTR sweep, complementary visibility),
  [`dnsbl`](dnsbl.md) (IP reputation across DNS-based blocklists),
  [`spf`](spf.md) *(planned — SPF policy expansion)*,
  [`dmarc`](dmarc.md) *(planned — DMARC policy parser)*,
  [`mx-rep`](mx-rep.md) (MX-host reputation check),
  [`whois`](whois.md) (registry / owner attribution),
  [`asn`](asn.md) (autonomous-system attribution)
