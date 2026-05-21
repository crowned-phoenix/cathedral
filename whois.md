---
title: whois — registry and ownership lookup for domains and IPs
command: whois
category: dns-identity
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-20
related: [dns, reverse-dns, asn, dnsbl, mx-rep]
---

# `whois` — registry and ownership lookup for domains and IPs

`whois` asks the registration system who owns a name or an address.
For a domain it returns the registrar, the lifecycle dates, the
delegated name servers, and the abuse contact. For an IP it returns
the allocation holder, the address range, and the issuing regional
internet registry. Cathedral walks the IANA referral chain
automatically, parses the heterogeneous response formats into a
single labelled card, and folds the legal boilerplate into a
collapsed marker — so the answer to *"who is this?"* fits on one
screen.

```
whois acme-supplies.example                # domain lookup
whois 8.8.8.8                              # IP allocation lookup
whois acme-supplies.example --raw          # full unparsed response
```

## What it does

For a given query, Cathedral opens a TCP connection on port 43 to
`whois.iana.org`, sends the query string followed by CRLF, and reads
until the server closes. IANA's response carries a referral to the
authoritative server for that name or address — for a `.com` domain
that's `whois.verisign-grs.com`; for an IPv4 address in 8.0.0.0/8
that's `whois.arin.net`. Cathedral follows the referral, then
follows one additional level if the registry refers to a sponsoring
registrar (Verisign frequently does this for .com).

The final response is parsed twice: once into a normalised summary
card (registrar, dates, name servers, abuse contact for domains;
netname, org, range, country for IPs), and once as a line-by-line
passthrough with the legal disclaimer paragraphs collapsed into
single markers.

| Flag      | Meaning                                          | Default     |
|-----------|--------------------------------------------------|-------------|
| `--raw`   | skip the summary; show the full unparsed record  | off         |

`--raw` is the escape hatch for when the parser misses a field, when
the response is from an exotic ccTLD with unusual formatting, or
when the boilerplate itself is what you're inspecting.

## What it answers

**Defender:** *"Who owns my domain, and when does it expire?"* The
quickest way to discover that a brand-protection registration has
silently lapsed, that a domain is up for renewal in the next 30
days, or that the registrar of record has been changed without
your knowledge. The expiry hint (`(in ~4y 1m)`, `(in 17 days)`,
`(EXPIRED 3m ago)`) makes lifecycle status legible without mental
date arithmetic.

**Recon (authorized testing only):** *"What organisation is on
the other end of this name or address?"* Forward DNS gives you the
hostname-to-IP mapping; whois gives you the IP-to-organisation
mapping. For a domain, the registrar identifies what brand-protection
tier the owner uses (a domain at MarkMonitor or CSC suggests a
Fortune 500; a domain at Namecheap or Porkbun suggests a smaller
operator). For an IP, the allocation org and AS together pin down
the hosting provider, datacentre, or cloud region.

**Investigation:** *"When was this domain registered, and is the
record consistent?"* Domains registered within the last 30 days are
a strong phishing-risk indicator on their own — the *new-domain*
signal underlies most modern abuse heuristics. A whois lookup
surfaces the creation date directly. Mismatches between the
registrar's claimed identity and the IP allocation (a domain at a
US registrar resolving to an IP allocated in a sanctioned country,
for instance) are findings the table view makes immediately
visible.

**Identification:** *"What infrastructure provider runs this?"*
The combination of registrar (domain) and net allocation org (IP)
typically identifies the operational stack. A domain at Cloudflare
Registrar with IPs in Cloudflare's `104.16.0.0/13` is Cloudflare
end-to-end; the same domain with IPs in AWS `52.84.0.0/15` is
CloudFront in front of Cloudflare DNS — a more revealing two-vendor
configuration. The whois table is one of two inputs to that
attribution (the other is [`asn`](asn.md)).

## How it works

### The WHOIS protocol

WHOIS is the oldest still-active internet directory protocol —
RFC 3912, three pages long, defined in 2004 but in continuous use
since the 1980s. The wire format is a single line of text from
client to server (the query) followed by an arbitrary text response
from server to client, terminated by connection close. No
authentication, no structured response, no encryption. The protocol
predates almost everything around it.

Cathedral's client is correspondingly small:

```go
func query(server, q string) (string, error) {
    conn, err := net.DialTimeout("tcp", server+":43", 6*time.Second)
    if err != nil {
        return "", err
    }
    defer conn.Close()
    _ = conn.SetDeadline(time.Now().Add(10 * time.Second))
    if _, err := conn.Write([]byte(q + "\r\n")); err != nil {
        return "", err
    }
    data, err := io.ReadAll(conn)
    return string(data), err
}
```

That's the whole network layer. The complexity in `whois` is not
the network — it's the *content* of the response, which has never
been standardised in any meaningful way.

### The IANA referral chain

There is no single WHOIS server that knows about every domain or
IP. The protocol does no automatic delegation — the client picks a
server, asks, and reads what comes back. To find the *right* server
to ask, Cathedral starts at IANA's root:

- For a **gTLD domain** (`.com`, `.net`, `.org`, `.io`, …),
  `whois.iana.org` knows which registry runs that TLD and emits a
  `refer:` line pointing to it.
- For a **ccTLD** (`.uk`, `.de`, `.jp`, …), IANA points to the
  national registry's WHOIS server.
- For an **IPv4 address**, IANA points to the regional internet
  registry (RIR) that holds the relevant block — ARIN, RIPE, APNIC,
  AFRINIC, or LACNIC.

For `.com` specifically, there's an additional hop: Verisign (the
registry) often points to the *sponsoring registrar*'s WHOIS server
in a second `refer:` line. Cathedral follows up to two referrals so
the canonical record is reached in one user-facing query:

```go
if m := reReferral.FindStringSubmatch(resp); m != nil {
    ref := strings.TrimSpace(m[1])
    emit(event{"event": "referral", "server": ref})
    if r2, err := query(ref, q); err == nil { resp = r2; … }
    // and once more for ARIN/Verisign chains
}
```

The `referral` events in the output stream let you see which servers
were actually consulted — useful when a record looks wrong and you
need to know whether you're reading the registry's view or the
registrar's view (they can differ during transfer or renewal).

### The summary card and the raw record

Whois responses are formatted however each registry felt like
formatting them in the 1990s. The .com format puts each field on
its own line as `Key: Value`. The RIPE format uses lowercase keys
with explicit field repetition. JPNIC's format is multilingual.
DENIC redacts most personal information per German privacy law.
There is no schema.

Cathedral imposes one: a curated `keyAliases` map identifies the
common normalised fields across registries.

```go
var keyAliases = map[string]string{
    // Domain identity
    "domain name":         "domain",
    "registrar":           "registrar",
    "sponsoring registrar": "registrar",
    "registrar iana id":   "registrar_iana",
    // Lifecycle dates
    "creation date":       "created",
    "created":             "created",
    "registered":          "created",
    "updated date":        "updated",
    "last modified":       "updated",
    "registry expiry date": "expires",
    "expiry date":         "expires",
    // Delegation
    "name server":         "name_server",
    "nserver":             "name_server",
    // IP whois
    "netname":             "netname",
    "inetnum":             "net_range",
    "cidr":                "cidr",
    "orgname":             "org",
    "organisation":        "org",
    // … and so on
}
```

When the parser encounters a `Key: Value` line, it lowercases the
key, looks up the normalised name, and accumulates the value. Multi-
valued fields (name servers, statuses) collect into a list with
de-duplication. Dates pass through a normalisation pass that
recognises ISO 8601, RFC 3339, the `dd-Mon-yyyy` form some
registries still use, and a handful of others — the output is
always `YYYY-MM-DD`.

The parsed data is rendered as the summary card. The raw response
is also streamed line-by-line below it (under a `[ raw record ]`
header) so the parser is never the *only* source of truth — if a
field is missing or wrong, the original is one screen down.

### Boilerplate detection

Most registry responses end with multiple paragraphs of legal
disclaimer text. Verisign's .com response includes a four-line
`NOTICE:` block and a twenty-something-line `TERMS OF USE:` block,
the same on every query, mandated by the ICANN registry agreement.
ARIN's response is bookended by Terms-of-Use comment blocks. RIPE's
response includes a multi-line copyright notice.

These blocks are functionally noise — they don't carry information
that varies between queries. Cathedral detects them by their
opening line (`NOTICE:`, `TERMS OF USE:`, locale variants) and
collapses any block longer than 2 lines into a single marker:

```
  [ NOTICE — 6 lines collapsed; --raw to expand ]
  [ TERMS OF USE — 25 lines collapsed; --raw to expand ]
```

The marker tells you the block exists and how long it is. If you
need to read it (you almost never do, but ICANN compliance work
sometimes requires checking the exact disclaimer text), `--raw`
shows everything.

### `--raw` mode

Three reasons to reach for `--raw`:

- **An unfamiliar ccTLD** whose format Cathedral's parser doesn't
  cover. The summary card may render mostly empty; the raw record
  has the data in whatever shape the registry uses.
- **A redacted record** (most EU domains under GDPR, the RDAP
  transition, registries that have moved registrant detail behind
  per-request access). Some redactions leave a `REDACTED FOR
  PRIVACY` placeholder where the parser expects a value;
  cross-checking the raw response confirms what's been suppressed
  versus what's missing entirely.
- **A genuine parser bug**, where Cathedral's normalisation
  mis-categorises a field. Raw mode is the diagnostic path; please
  flag it as an issue if you encounter one.

`--raw` skips both the summary card and the boilerplate
collapse — everything the server sent is rendered verbatim.

## What Cathedral doesn't do

A few deliberate omissions:

- **RDAP.** The Registration Data Access Protocol (RFC 7480) is
  the structured-JSON successor to WHOIS. Many gTLDs now publish
  both; some ccTLDs publish only one. Cathedral v1 speaks WHOIS
  only — RDAP support is on the roadmap as a separate `rdap`
  command rather than transparently fronting the same query, because
  the response shapes are different enough that conflating them
  hides useful detail.
- **WHOIS-over-HTTPS.** Some registries (notably Verisign for
  `.com` and `.net`) offer an HTTPS endpoint as well as TCP/43.
  Cathedral always uses TCP/43 because it's what every registry
  supports.
- **Recursive following past two referrals.** The IANA → RIR →
  org-WHOIS chain or IANA → registry → registrar chain almost
  always resolves in two hops. Pathological chains (rare) bail out
  at the second referral and report the deepest server reached.
- **Bulk querying.** WHOIS servers enforce rate limits, and
  Cathedral doesn't try to circumvent them. For batch lookups
  across many domains, you want bulk-WHOIS data files from the
  registry or a paid API; `whois` is for one-domain-at-a-time
  investigation.
- **Historical records.** Cathedral queries live state. For the
  history of a domain (who owned it five years ago, when ownership
  changed, what name servers it used in 2019), DomainTools and
  similar archives are the right reach.
- **DNSSEC chain validation.** The `dnssec: signed` field in a
  whois record is registry-provided metadata, not a live
  cryptographic check. Cathedral surfaces it because it's part of
  the registry's claim; for actual validation, use
  [`dns`](dns.md) with a DNSSEC-validating resolver.

## Worked example

A typical .com domain, then an IP allocation, then the `--raw`
escape hatch.

### A .com domain

```
operator@cathedral:~$ whois acme-supplies.example
> whois acme-supplies.example  (via whois.iana.org)
  → referred to whois.verisign-grs.com

[ WHOIS · acme-supplies.example ]
────────────────────────────────────────────────────────────────
  domain:        ACME-SUPPLIES.EXAMPLE
  registrar:     MarkMonitor Inc.    (IANA #292)
  status:        clientTransferProhibited  (+2 more)
  dnssec:        signedDelegation

  created:       2003-08-14
  updated:       2026-02-04
  expires:       2028-08-14    (in ~2y 2m)

  name servers:  ns1.acme-supplies.example
                 ns2.acme-supplies.example
                 ns3.acme-supplies.example
                 ns4.acme-supplies.example

  abuse:         abusecomplaints@markmonitor.com  ·  +1.2086851750

  source:        whois.markmonitor.com
────────────────────────────────────────────────────────────────

[ raw record ]
   Domain Name: ACME-SUPPLIES.EXAMPLE
   Registry Domain ID: 102849312_DOMAIN_EXAMPLE-VRSN
   Registrar WHOIS Server: whois.markmonitor.com
   ...
   DNSSEC: signedDelegation
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
   >>> Last update of whois database: 2026-05-20T14:18:27Z <<<

   For more information on Whois status codes, please visit https://icann.org/epp

   [ NOTICE — 6 lines collapsed; --raw to expand ]

   [ TERMS OF USE — 25 lines collapsed; --raw to expand ]

whois complete.
```

The card identifies the operational stack at a glance: this is a
**MarkMonitor**-registered domain (a brand-protection registrar
used almost exclusively by large enterprises — its presence on a
domain is itself a signal about the owner), with **DNSSEC enabled**
in `signedDelegation` mode, **own-zone authoritative name servers**
(rather than the more common ns-cloud-provider pattern), and **two
years to expiry** with a recent update (the 2026-02-04 update
hints at a January renewal cycle).

The `(+2 more)` next to the status field means there are three
total `clientTransferProhibited`-class statuses — typical for a
mature domain at a brand-protection registrar (transfer, update,
and delete all locked). To see all three, `--raw` shows the full
list; for everyday triage, the headline status is enough.

### An IP allocation

```
operator@cathedral:~$ whois 8.8.8.8
> whois 8.8.8.8  (via whois.iana.org)
  → referred to whois.arin.net

[ WHOIS · 8.8.8.8 ]
────────────────────────────────────────────────────────────────
  netname:       GOGL
  org:           Google LLC (GOGL)
  range:         8.8.8.0 - 8.8.8.255
  country:       US

  source:        whois.arin.net
────────────────────────────────────────────────────────────────

[ raw record ]
   NetRange:       8.8.8.0 - 8.8.8.255
   CIDR:           8.8.8.0/24
   NetName:        GOGL
   NetHandle:      NET-8-8-8-0-1
   Parent:         LVLT-GOGL-8-8-8 (NET-8-8-8-0-2)
   NetType:        Direct Allocation
   OriginAS:       AS15169
   Organization:   Google LLC (GOGL)
   RegDate:        2023-12-28
   Updated:        2023-12-28
   ...

whois complete.
```

The card answers *"who runs 8.8.8.8?"* with the four
fields most operators want: the net name, the responsible
organisation, the address range, and the country. The raw record
below carries the additional ARIN-specific detail — `OriginAS`,
`NetType`, `NetHandle`, parent allocation — for cases where the
attribution chain matters (acquisitions, reassignments,
provider-of-providers patterns).

For attribution at the AS level, [`asn`](asn.md) is the more
focused tool — it queries the routing table directly rather than
the registry. Whois and ASN often agree but diverge in interesting
ways when IPs are leased or BGP-announced through a different
operator than the one that holds the allocation.

### When the parser misses

Some ccTLDs use formats Cathedral's parser doesn't fully cover.
`--raw` is the escape hatch:

```
operator@cathedral:~$ whois example.ee --raw
> whois example.ee  (via whois.iana.org)
  → referred to whois.tld.ee

Domain:
name:       example.ee
status:     ok
registered: 2010-04-14 13:00:00 +03:00
changed:    2024-11-22 09:32:14 +02:00
expire:     2026-04-15

Registrar:
name:       Zone Media OÜ
url:        https://www.zone.ee
phone:      +372 6886886

Registrant:
name:       Private Person
email:      Not Disclosed - Visit www.internet.ee for webform

...

whois complete.
```

EIS (the .ee registry) publishes a block-structured format with
section headers, not the flat key-value style Cathedral's parser
expects. The summary card would render thin; `--raw` shows the data
in its native shape. The `[Domain]` / `[Registrar]` / `[Registrant]`
section structure is human-readable as-is.

ccTLDs where this matters in practice: `.ee`, `.de` (DENIC's
abbreviated format since the GDPR redactions), `.uk` (Nominet's
multi-line records), `.fi`, `.jp` (multilingual responses).

## Output protocol

```
{"event":"start",           "query":"…","server":"whois.iana.org"}
{"event":"referral",        "server":"…"}                              *
{"event":"summary",         "data":{…}}                                # not in --raw
{"event":"body_start"}                                                 # not in --raw
{"event":"line",            "kind":"key|comment|blank|text","text":"…"}*
{"event":"collapsed_block", "title":"NOTICE|TERMS OF USE","lines":N}   *
{"event":"done"}
{"event":"error",           "message":"…"}
```

`summary.data` is a flat map. Domain queries populate `domain`,
`registrar`, `registrar_iana`, `created`, `updated`, `expires`,
`name_server` (list), `status` (list), `dnssec`, `abuse_email`,
`abuse_phone`, `registrar_url`, `registrar_whois`, `_source`.
IP queries populate `netname`, `org`, `net_range`, `cidr`,
`country`, `origin_as`, `_source`. Both sets coexist when present.

Pipe to extract just the expiry date:

```
$ whois acme-supplies.example -j |
    jq -r 'select(.event=="summary") | .data.expires'
2028-08-14
```

Sweep a portfolio for domains expiring in the next 90 days:

```
$ for d in $(cat domains.txt); do
    exp=$(whois "$d" -j | jq -r 'select(.event=="summary") | .data.expires')
    days=$(( ( $(date -d "$exp" +%s) - $(date +%s) ) / 86400 ))
    [ "$days" -lt 90 ] && echo "$d  $exp  ($days days)"
  done
acme-supplies.example  2026-07-12  (53 days)
old-redirect.example   2026-05-31  (11 days)
```

Identify newly-registered domains in a list (the new-domain abuse
signal):

```
$ for d in $(cat suspicious.txt); do
    created=$(whois "$d" -j | jq -r 'select(.event=="summary") | .data.created')
    age=$(( ( $(date +%s) - $(date -d "$created" +%s) ) / 86400 ))
    [ "$age" -lt 30 ] && echo "$d  registered $created  (${age}d ago)"
  done
```

## Limitations

- **Rate limits.** WHOIS servers enforce per-source-IP rate limits,
  typically generous (dozens of queries per hour from a single
  origin), but a tight loop will trip them. Verisign limits its
  TCP/43 endpoint more aggressively than ARIN; APNIC and RIPE are
  the most permissive. For batch work, space queries with `sleep
  1` minimum.
- **Heterogeneous formats.** Cathedral's parser handles ICANN gTLDs
  cleanly and the four major IP registries acceptably. ccTLDs are
  hit-or-miss: `.com`, `.net`, `.org`, `.io`, `.co`, `.me`, `.tv`
  and most other reseller-friendly TLDs parse cleanly because they
  use the ICANN thick-WHOIS format. `.uk`, `.de`, `.fr`, `.jp`,
  `.ru` and most ccTLDs use registry-specific formats that may
  render thin summaries — fall back to `--raw`.
- **No live cryptographic validation.** The `dnssec:` field is
  registry-claimed, not validated. The `status:` field reflects the
  registry's view, which can lag the registrar's view during
  transfer or renewal operations by hours or days.
- **Redacted records.** Most EU domains under GDPR redact registrant
  detail (name, email, phone). Many gTLDs follow ICANN's redaction
  policy and replace registrant contact info with the registrar's
  abuse address. Cathedral renders whatever the registry returns;
  redaction is the registry's choice, not a parser limitation.
- **No referral cycles.** Cathedral follows up to two referrals.
  Pathological referral chains beyond two hops are treated as the
  second server's response; the chain is not unrolled further.
- **TCP/43 only.** Some networks block outbound TCP/43; the
  protocol is old enough that egress filters sometimes drop it as
  unrecognised. If `whois` consistently times out from a particular
  network, port 43 is the first thing to check.
- **No internationalisation handling.** Cathedral renders responses
  as UTF-8. Some registries (JPNIC notably) return mixed-encoding
  responses (Shift-JIS and UTF-8 in the same record); these may
  render with replacement characters. `--raw` shows the same bytes
  the server sent.

## Authorized use

`whois` is **passive recon against a public directory**. Every
query goes to a registry's published WHOIS server; the target of
the query never sees the activity. The protocol predates the
internet's modern surveillance posture and was designed for
unfettered public lookup. WHOIS records are deliberately published
data.

Three notes worth attaching:

**Volume.** Single queries are unremarkable. Bulk sweeps from a
single source IP will hit rate limits and may be logged as recon.
For volume work, the registry's bulk data feed (where available) or
a commercial WHOIS API is the right tool — both are designed for
the use case.

**Privacy of the *querier*.** WHOIS queries go in cleartext over
TCP/43 and any network operator between you and the registry can
see what you asked. For sensitive recon, route through a VPN or use
RDAP over HTTPS when the registry supports it.

**GDPR and registrant detail.** EU registries redact registrant
personal information by default. This is not a failure of the
protocol — it's a policy choice. Cathedral surfaces whatever the
registry returns; if you need verified registrant identity (for
legal process, abuse handling), the registry has a tiered-access
pathway that requires application.

## Further reading

- [RFC 3912 — WHOIS Protocol Specification](https://www.rfc-editor.org/rfc/rfc3912) — the three-page protocol
- [RFC 7480 — HTTP Usage in the Registration Data Access Protocol (RDAP)](https://www.rfc-editor.org/rfc/rfc7480) — the JSON successor
- [ICANN Thick WHOIS Policy](https://www.icann.org/resources/pages/thick-whois-2016-01-20-en) — the .com/.net data-storage transition that made registry-side WHOIS canonical
- [IANA WHOIS service](https://whois.iana.org/) — the root of the referral chain
- Related Cathedral commands: [`dns`](dns.md) (forward DNS — the operational counterpart to whois's registration view),
  [`reverse-dns`](reverse-dns.md) (PTR sweep — IP-to-name from the resolver, not the registry),
  [`asn`](asn.md) (BGP-table attribution, often diverges from whois in revealing ways),
  [`dnsbl`](dnsbl.md) (reputation lookup),
  [`mx-rep`](mx-rep.md) (mail-host reputation across RBLs)
